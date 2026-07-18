"""Normative effective-execution-contract resolver (correction #3).

This is the SINGLE source of truth for how a frozen scenario's command is turned
into the effective RAW/RTK argv, scheduler configuration, and offline-enforcing
environment. The driver (runtime), the execution-contract builder, and the
independent verifier all call `resolve()` so an effective argv is only ever
accepted when it is mechanically derivable from the frozen contract plus this
declared, versioned resolver policy.

Declared resolution rules (n2e-argv-resolver-v1):
  * frozen_argv_verbatim  -- effective RAW/RTK are exactly the frozen argv; only
    an offline/determinism ENV (never a command edit) is added, applied identically
    to both arms. Families: rust_cargo, go, python, git, files_search, logs,
    containers.
  * test_runner_from_package_json+sequential_scheduler -- authorized by the
    scenario's rtk_argv_resolution for js_ts/test: resolve the package manager and
    the committed test runner from package.json, and run that runner with a
    deterministic SEQUENTIAL scheduler on BOTH arms (never filtering tests).
  * build_system_from_repo -- for jvm/test: resolve the repo's actual build system
    (gradle unless a pom.xml is present) and its offline, single-worker test
    invocation, symmetrically for both arms.

`resolve(scen)` (no repo) returns the static resolution or, for the two runtime-
resolved rules, the rule id with effective argv = None. `resolve(scen, repo_dir)`
returns the concrete effective argv. Scheduler flags/env are identical for RAW and
RTK and are recorded as part of the environment identity.
"""
from __future__ import annotations

from pathlib import Path

import n2e_publisher_registry as pub
import n2e_execution_control as xctl

RESOLVER_POLICY_ID = "n2e-argv-resolver-v1"


def _publisher_scheduler_env(recipe: dict) -> dict:
    fam = recipe["language"]  # already rust_cargo/go/js_ts/jvm
    env = dict(scheduler_env(fam, "test"))
    tc = recipe.get("toolchain") or {}
    if fam == "rust_cargo" and tc.get("version"):
        env["RUSTUP_TOOLCHAIN"] = tc["version"]
    env.update(recipe.get("test_env") or {})  # e.g. RUSTFLAGS, applied to both arms
    return env


def scheduler_env(fam: str, sub: str) -> dict:
    """Offline + deterministic-scheduler ENV, applied IDENTICALLY to RAW and RTK.
    Never edits the command; only constrains network + parallelism reproducibly."""
    if fam == "rust_cargo":
        return {"CARGO_NET_OFFLINE": "true", "RUST_TEST_THREADS": "1", "CARGO_BUILD_JOBS": "1"}
    if fam == "go":
        # -mod=readonly: measurement must NOT update go.mod/go.sum; GOPROXY=off: offline
        return {"GOFLAGS": "-mod=readonly", "GOPROXY": "off"}
    if fam == "python":
        return {"PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"}
    return {}


def _vitest_seq() -> list:
    return ["--no-file-parallelism", "--sequence.concurrent=false", "--sequence.shuffle=false"]


def _js_resolve(repo_dir: Path) -> tuple[str, str]:
    pj = repo_dir / "package.json"
    txt = pj.read_text(errors="replace") if pj.exists() else ""
    pm = "pnpm" if ((repo_dir / "pnpm-lock.yaml").exists() or "catalog:" in txt or '"workspace:' in txt) else "npm"
    runner = "jest" if ('"jest"' in txt and "vitest" not in txt) else ("vitest" if "vitest" in txt else "jest")
    return pm, runner


def resolve(scen: dict, repo_dir: Path | None = None) -> dict:
    fam, sub = scen["command_family"], scen["command_subfamily"]
    raw0 = scen["original_argv"]
    rtk0 = scen.get("explicit_rtk_argv")
    senv = scheduler_env(fam, sub)
    base = {"resolver_policy_id": RESOLVER_POLICY_ID, "scheduler_env": senv,
            "original_raw_argv": raw0, "original_rtk_argv": rtk0,
            "frozen_rtk_resolution": scen.get("rtk_argv_resolution")}

    # PUBLISHER RECIPE (highest precedence for SWE-bench cases): the effective command
    # is the publisher-scoped test command from the self-hash-locked registry, extracted
    # from pinned upstream source, NEVER a generic whole-suite command. Bound by EXACT
    # case_id -- a recipe never overrides another scenario sharing the same instance.
    recipe = pub.recipe_for_case(scen["case_id"])
    if recipe:
        # binding agreement: the recipe must describe THIS scenario, not merely its instance
        assert recipe["instance_id"] == (scen.get("source_image_identity") or {}).get("instance_id")
        assert recipe["command_family"] == fam and recipe["command_subfamily"] == sub
        assert recipe["snapshot_variant"] == scen.get("snapshot_variant")
        argv = pub.parse_command(recipe["test_cmd"][0])
        # execution-control (e.g. lucene-randomized-seed-v1): a mechanically-derived
        # fixed seed appended IDENTICALLY to both arms (no test-membership change).
        seed_pol = xctl.policy_for_case(scen["case_id"])
        seed = [seed_pol["arg"]] if seed_pol else []
        return {**base, "resolution_rule": "publisher_recipe",
                "runtime_resolved": False, "publisher_recipe": recipe["source"]["spec_dict"],
                "scheduler_env": _publisher_scheduler_env(recipe),
                "execution_control": seed_pol,
                "effective_raw_argv": [*argv, *seed], "effective_rtk_argv": ["rtk", *argv, *seed]}

    if fam == "js_ts" and sub == "test":
        rule = "test_runner_from_package_json+sequential_scheduler"
        if repo_dir is None:
            return {**base, "resolution_rule": rule, "runtime_resolved": True,
                    "effective_raw_argv": None, "effective_rtk_argv": None, "scheduler_flags": None}
        pm, runner = _js_resolve(repo_dir)
        seq = _vitest_seq() if runner == "vitest" else ["--runInBand"]
        exec_pfx = ["corepack", "pnpm", "exec"] if pm == "pnpm" else ["npx"]
        return {**base, "resolution_rule": rule, "runtime_resolved": True,
                "package_manager": pm, "runner": runner, "scheduler_flags": seq,
                "effective_raw_argv": exec_pfx + [runner, "run", *seq],
                "effective_rtk_argv": ["rtk", runner, *seq]}

    if fam == "jvm" and sub == "test":
        rule = "build_system_from_repo"
        if repo_dir is None:
            return {**base, "resolution_rule": rule, "runtime_resolved": True,
                    "effective_raw_argv": None, "effective_rtk_argv": None, "build_system": None}
        build_system = "maven" if (repo_dir / "pom.xml").exists() else "gradle"
        if build_system == "gradle":
            raw = ["./gradlew", "test", "--offline", "--no-daemon", "--console=plain", "--max-workers=1"]
            rtk = ["rtk", "gradlew", "test"]
        else:
            raw = ["mvn", "-o", "-B", "test"]
            rtk = ["rtk", "mvn", "test"]
        return {**base, "resolution_rule": rule, "runtime_resolved": True,
                "build_system": build_system, "effective_raw_argv": raw, "effective_rtk_argv": rtk}

    # static families: the frozen argv IS the effective argv (verbatim), only ENV added
    return {**base, "resolution_rule": "frozen_argv_verbatim", "runtime_resolved": False,
            "effective_raw_argv": list(raw0), "effective_rtk_argv": (list(rtk0) if rtk0 else None)}
