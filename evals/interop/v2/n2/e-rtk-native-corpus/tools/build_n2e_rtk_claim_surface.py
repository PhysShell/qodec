#!/usr/bin/env python3
"""Build n2e-rtk-claim-surface-v1.json from the pinned RTK source and binary.

For every N2-E target command scenario this records:
  - original_command / original_argv
  - explicit_rtk_argv (the native RTK-native command)
  - expected_rewrite + rewrite_exit_code, obtained by invoking the pinned
    `rtk rewrite "<original>"` (exit 0=allow, 1=passthrough, 2=deny, 3=ask)
  - command_family / command_subfamily
  - rtk_module (source path of the implementing wrapper)
  - rtk_support_classification
      RTK_NATIVE_SPECIALIZED | RTK_GENERIC_TEST_WRAPPER | RTK_PASSTHROUGH_CONTROL
  - RTK's own estimated savings claim + claim_source (rules.rs:<line>)

Requires (via environment, never hard-coded transient paths):
  RTK_BIN      path to the pinned rtk binary (sha256 asserted == mission pin)
  RTK_SRC_DIR  path to the pinned rtk source tree (commit 5d32d07)

RTK's percentage is recorded as a *claim*, never as measured truth.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import rtk_rules_parser as rp  # noqa: E402

OUT = N2E_DIR / "n2e-rtk-claim-surface-v1.json"
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
RTK_BINARY_SHA256 = "41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf"

SPECIALIZED = "RTK_NATIVE_SPECIALIZED"
GENERIC = "RTK_GENERIC_TEST_WRAPPER"
PASSTHROUGH = "RTK_PASSTHROUGH_CONTROL"

# N2-E target scenarios. `expected_rewrite` is NOT hard-coded: for hook-mode
# scenarios it is captured live from the pinned binary so the record cannot
# silently drift from real rewrite behavior. Log/filter scenarios use RTK's
# dedicated native filter interface (`rtk log`, invoked explicitly per §13),
# which the rewrite hook does not auto-trigger; those set explicit_argv and
# mode="explicit_native_interface".
def S(original, family, subfamily, module, explicit_argv=None, mode="hook"):
    return {
        "original": original, "family": family, "subfamily": subfamily,
        "module": module, "explicit_argv": explicit_argv, "mode": mode,
    }


SCENARIOS = [
    # files / search
    S("ls -la", "files_search", "ls", "src/cmds/system/ls.rs"),
    S("tree", "files_search", "tree", "src/cmds/system/tree.rs"),
    S("cat README.md", "files_search", "read", "src/cmds/system/read.rs"),
    S("grep -rn TODO .", "files_search", "grep", "src/cmds/system/search.rs"),
    S("rg TODO", "files_search", "rg", "src/cmds/system/search.rs"),
    S("find . -name '*.rs'", "files_search", "find", "src/cmds/system/find_cmd.rs"),
    # git
    S("git status", "git", "status", "src/cmds/git/git.rs"),
    S("git diff", "git", "diff", "src/cmds/git/diff_cmd.rs"),
    S("git log", "git", "log", "src/cmds/git/git.rs"),
    S("git show", "git", "show", "src/cmds/git/git.rs"),
    S("git add .", "git", "add", "src/cmds/git/git.rs"),
    S("git commit -m msg", "git", "commit", "src/cmds/git/git.rs"),
    S("git push", "git", "push", "src/cmds/git/git.rs"),
    # rust / cargo
    S("cargo test", "rust_cargo", "test", "src/cmds/rust/cargo_cmd.rs"),
    S("cargo build", "rust_cargo", "build", "src/cmds/rust/cargo_cmd.rs"),
    S("cargo check", "rust_cargo", "check", "src/cmds/rust/cargo_cmd.rs"),
    S("cargo clippy", "rust_cargo", "clippy", "src/cmds/rust/cargo_cmd.rs"),
    # python
    S("pytest", "python", "pytest", "src/cmds/python/pytest_cmd.rs"),
    S("ruff check .", "python", "ruff", "src/cmds/python/ruff_cmd.rs"),
    # js / ts
    S("jest", "js_ts", "jest", "src/cmds/js/mod.rs"),
    S("vitest", "js_ts", "vitest", "src/cmds/js/vitest_cmd.rs"),
    S("tsc", "js_ts", "tsc", "src/cmds/js/tsc_cmd.rs"),
    S("eslint .", "js_ts", "lint", "src/cmds/js/lint_cmd.rs"),
    S("pnpm run build", "js_ts", "pnpm", "src/cmds/js/pnpm_cmd.rs"),
    S("npm test", "js_ts", "npm", "src/cmds/js/npm_cmd.rs"),  # expected passthrough control
    # go
    S("go test ./...", "go", "test", "src/cmds/go/go_cmd.rs"),
    S("go build ./...", "go", "build", "src/cmds/go/go_cmd.rs"),
    S("go vet ./...", "go", "vet", "src/cmds/go/go_cmd.rs"),
    # jvm
    S("mvn test", "jvm", "mvn", "src/cmds/jvm/mvn_cmd.rs"),
    S("gradle test", "jvm", "gradlew", "src/cmds/jvm/gradlew_cmd.rs"),
    # logs — dedicated native filter interface (explicit invocation, not hook)
    S("cat app.log", "logs", "log", "src/cmds/system/log_cmd.rs",
      explicit_argv=["rtk", "log", "app.log"], mode="explicit_native_interface"),
    # containers
    S("docker ps", "containers", "ps", "src/cmds/cloud/container.rs"),
    S("docker images", "containers", "images", "src/cmds/cloud/container.rs"),
    S("docker logs c1", "containers", "logs", "src/cmds/cloud/container.rs"),
]


def sh_split(s: str) -> list[str]:
    import shlex
    return shlex.split(s)


def rtk_rewrite(rtk_bin: str, cmd: str) -> tuple[str, int]:
    proc = subprocess.run([rtk_bin, "rewrite", cmd], capture_output=True, text=True)
    return proc.stdout, proc.returncode


def native_subcommand_exists(rtk_bin: str, sub: str) -> bool:
    proc = subprocess.run([rtk_bin, sub, "--help"], capture_output=True, text=True)
    return proc.returncode == 0


def classify(rewrite: str, exit_code: int) -> str:
    if exit_code == 1 or not rewrite.strip():
        return PASSTHROUGH
    toks = rewrite.split()
    if len(toks) >= 2 and toks[0] == "rtk" and toks[1] == "test":
        return GENERIC
    return SPECIALIZED


def build(rtk_bin: str, rtk_src: Path) -> dict:
    actual = c.sha256_file(rtk_bin)
    if actual != RTK_BINARY_SHA256:
        raise SystemExit(f"RTK_BIN sha256 {actual} != pinned {RTK_BINARY_SHA256}")

    rules = rp.parse_rules(rtk_src / "src/discover/rules.rs")
    scenarios = []
    for sc in SCENARIOS:
        original = sc["original"]
        if sc["mode"] == "explicit_native_interface":
            # Dedicated filter interface (e.g. rtk log) — invoked explicitly, not
            # hook-rewritten. Record the raw rewrite for provenance but the native
            # argv and classification come from the explicit interface.
            rewrite, code = rtk_rewrite(rtk_bin, original)
            explicit_rtk_argv = sc["explicit_argv"]
            classification = SPECIALIZED
            claim_tokens = explicit_rtk_argv
        else:
            rewrite, code = rtk_rewrite(rtk_bin, original)
            rewrite = rewrite.strip()
            classification = classify(rewrite, code)
            explicit_rtk_argv = rewrite.split() if rewrite else None
            claim_tokens = explicit_rtk_argv
        rewrite = (rewrite or "").strip()
        # RTK's claimed savings, keyed on the native rtk_cmd (first two tokens).
        claim = None
        if claim_tokens and len(claim_tokens) >= 2 and claim_tokens[0] == "rtk":
            rtk_cmd = f"rtk {claim_tokens[1]}"
            subcmd = claim_tokens[2] if len(claim_tokens) >= 3 else None
            claim = rp.claim_for(rules, rtk_cmd, subcmd)
        scenarios.append({
            "original_command": original,
            "original_argv": sh_split(original),
            "explicit_rtk_argv": explicit_rtk_argv,
            "expected_rewrite": rewrite or None,
            "rewrite_exit_code": code,
            "rewrite_mode": sc["mode"],
            "command_family": sc["family"],
            "command_subfamily": sc["subfamily"],
            "rtk_module": sc["module"],
            "rtk_support_classification": classification,
            "rtk_savings_claim": claim,  # RTK's OWN estimate — not measured truth
        })

    body = c.envelope(
        record_type="n2e-rtk-claim-surface",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_rtk_claim_surface.py",
        purpose=(
            "Align N2-E command scenarios to the pinned RTK's own command surface and "
            "published savings claims, derived from the pinned source and verified "
            "against the pinned binary's real `rtk rewrite` behavior. RTK's percentages "
            "are recorded as claims, never as measured truth."
        ),
        rtk_source_commit=RTK_SOURCE_COMMIT,
        rtk_binary_sha256=RTK_BINARY_SHA256,
        claim_sources={
            "rules_rs": {
                "path": "src/discover/rules.rs",
                "sha256": c.sha256_file(rtk_src / "src/discover/rules.rs"),
            },
            "registry_rs": {
                "path": "src/discover/registry.rs",
                "sha256": c.sha256_file(rtk_src / "src/discover/registry.rs"),
            },
            "readme": {
                "path": "README.md",
                "sha256": c.sha256_file(rtk_src / "README.md"),
            },
        },
        classification_vocabulary=[SPECIALIZED, GENERIC, PASSTHROUGH],
        scenario_count=len(scenarios),
        scenarios=scenarios,
    )
    return body


def main() -> int:
    rtk_bin = os.environ.get("RTK_BIN")
    rtk_src = os.environ.get("RTK_SRC_DIR")
    if not rtk_bin or not rtk_src:
        print("RTK_BIN and RTK_SRC_DIR must be set (pinned binary + source tree)", file=sys.stderr)
        return 2
    c.write_record(OUT, build(rtk_bin, Path(rtk_src)))
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name} record_sha256={rec['record_sha256']} scenarios={rec['scenario_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
