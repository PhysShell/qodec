#!/usr/bin/env python3
"""Focused publisher-recipe consistency probe for tokio-rs__tokio-4384.

The publisher-provided Cargo.lock, copied byte-for-byte, is rejected by the publisher's
own `--locked` install ("the lock file needs to be updated"). That does NOT yet
distinguish a harness reconstruction defect from an internally inconsistent publisher
recipe, so this probe gathers the terminal evidence WITHOUT choosing a lock:

  A. exact pre-install state (identities of every input to the locked command);
  B. the exact failure of the pinned `--locked` install (+ `cargo metadata --locked`);
  C. in a DISPOSABLE copy only, what `cargo` wants to change (structured lock diff from a
     network, non---locked resolution) -- never used for qualification;
  D. reproduction through the pinned upstream SWE-bench harness path (commit f7bbbb2)
     using the exact dataset row / base commit / rust 1.83 / fixture bytes / upstream
     setup, with no gold/test patch before install.

Classification is NOT decided here -- the record carries the evidence and a
`classification_input` block; a human/reviewer applies the boundary:
  * upstream-equivalent succeeds  -> HARNESS_DEFECT (diff + fix the N2-E reconstruction);
  * upstream-equivalent fails identically AND all identities match -> DISQUALIFIED_
    ENVIRONMENT_UNREPRODUCIBLE (publisher recipe internally inconsistent for the pinned
    substrate);
  * dataset revision + harness commit are not a compatible published pair -> source-
    provenance defect (pin the matching pair first).
Network is ENABLED (diagnostic, not a measurement).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_publisher_registry as pub  # noqa: E402

INSTANCE = "tokio-rs__tokio-4384"
CASE_ID = "tokio-rs__tokio-4384::rust_cargo::test::fixed"
CHANNEL = "1.83.0"
OUT = N2E_DIR / "tokio-4384-publisher-recipe-consistency-v1.json"
PINS = N2E_DIR / "n2e-source-pins-v1.json"


def _run(argv, cwd=None, env=None, tmo=1800, shell=False):
    try:
        p = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=tmo, shell=shell)
        out, err = p.stdout, p.stderr
        return {"argv": argv if not shell else str(argv), "exit": p.returncode,
                "stdout": out.decode("utf-8", "replace"), "stderr": err.decode("utf-8", "replace"),
                "stdout_sha256": hashlib.sha256(out).hexdigest(),
                "stderr_sha256": hashlib.sha256(err).hexdigest(),
                "stdout_bytes": len(out), "stderr_bytes": len(err)}
    except subprocess.TimeoutExpired as e:
        return {"argv": argv if not shell else str(argv), "exit": None, "timed_out": True,
                "stdout": (e.stdout or b"").decode("utf-8", "replace")[-4000:],
                "stderr": (e.stderr or b"").decode("utf-8", "replace")[-4000:]}


def _sha_file(p: Path):
    return c.sha256_file(str(p)) if p.is_file() else None


def _git(cwd, *args, env=None):
    return _run(["git", "-C", str(cwd), *args], env=env)


def _hf_row(instance_id, revision):
    off = 0
    while off < 300:
        u = ("https://datasets-server.huggingface.co/rows?dataset=SWE-bench%2FSWE-bench_Multilingual"
             f"&config=default&split=test&offset={off}&length=100&revision={revision}")
        with urllib.request.urlopen(urllib.request.Request(u, headers={"Accept": "application/json"}),
                                    context=c.ssl_context(), timeout=90) as r:
            d = json.loads(r.read())
        for item in d["rows"]:
            if item["row"]["instance_id"] == instance_id:
                return item["row"]
        off += len(d["rows"]) or 300
    raise SystemExit(f"instance {instance_id} not found at revision {revision}")


def _cargo_env(home: Path) -> dict:
    e = {"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
         "CARGO_HOME": str(home / ".cargo"), "RUSTUP_TOOLCHAIN": CHANNEL,
         "RUSTFLAGS": "-Awarnings"}
    for k in ("RUSTUP_HOME",):
        if os.environ.get(k):
            e[k] = os.environ[k]
    return e


def _member_manifests(repo: Path) -> dict:
    return {str(p.relative_to(repo)): _sha_file(p) for p in sorted(repo.rglob("Cargo.toml"))}


def _parse_lock(text: str) -> dict:
    """Minimal Cargo.lock parse: {name: {version, source, checksum}} + format version."""
    pkgs, cur, fmt = {}, None, None
    for ln in text.splitlines():
        s = ln.strip()
        if s == "[[package]]":
            cur = {}
        elif s.startswith("version = ") and cur is not None and "name" in cur and "version" not in cur:
            cur["version"] = s.split("=", 1)[1].strip().strip('"')
        elif s.startswith("version = ") and cur is None:
            fmt = s.split("=", 1)[1].strip().strip('"')
        elif s.startswith("name = ") and cur is not None:
            cur["name"] = s.split("=", 1)[1].strip().strip('"')
            pkgs[cur["name"]] = cur
        elif s.startswith("source = ") and cur is not None:
            cur["source"] = s.split("=", 1)[1].strip().strip('"')
        elif s.startswith("checksum = ") and cur is not None:
            cur["checksum"] = s.split("=", 1)[1].strip().strip('"')
    return {"format_version": fmt, "packages": pkgs}


def _lock_diff(before: str, after: str) -> dict:
    a, b = _parse_lock(before), _parse_lock(after)
    ap, bp = a["packages"], b["packages"]
    added = sorted(set(bp) - set(ap))
    removed = sorted(set(ap) - set(bp))
    changed = []
    for name in sorted(set(ap) & set(bp)):
        da = {k: ap[name].get(k) for k in ("version", "source", "checksum")}
        db = {k: bp[name].get(k) for k in ("version", "source", "checksum")}
        if da != db:
            changed.append({"name": name, "before": da, "after": db})
    return {"format_version_before": a["format_version"], "format_version_after": b["format_version"],
            "format_changed": a["format_version"] != b["format_version"],
            "packages_added": added, "packages_removed": removed, "packages_changed": changed,
            "added_count": len(added), "removed_count": len(removed), "changed_count": len(changed)}


def part_a_and_b(base: str, recipe: dict, workroot: Path) -> dict:
    repo = workroot / "repo"
    home = workroot / ".home"
    home.mkdir()
    env = _cargo_env(home)
    # base checkout
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    _git(repo, "fetch", "-q", "--depth", "1", f"https://github.com/tokio-rs/tokio.git", base)
    _git(repo, "checkout", "-q", "FETCH_HEAD")
    head = _git(repo, "rev-parse", "HEAD")["stdout"].strip()
    manifests_pristine = _member_manifests(repo)
    # materialize the publisher lock via the exact pre_install command(s)
    for cmd in recipe.get("pre_install", []):
        _run(["bash", "-c", cmd], cwd=str(repo), env=env, tmo=300)
    lock = repo / "Cargo.lock"
    lock_bytes = lock.read_bytes() if lock.is_file() else b""
    # toolchain identity actually reachable
    which_cargo = _run(["rustup", "which", "--toolchain", CHANNEL, "cargo"], env=env)
    which_path = which_cargo["stdout"].strip()
    cargo_vv = _run(["cargo", f"+{CHANNEL}", "-Vv"], env=env)
    pre_install_state = {
        "base_commit": base, "head": head, "head_matches_base": head == base,
        "tracked_status_clean": _git(repo, "status", "--porcelain", "--untracked-files=no")["stdout"].strip() == "",
        "workspace_member_manifests_pristine": manifests_pristine,
        "cargo_config": {rel: _sha_file(repo / rel) for rel in
                         (".cargo/config", ".cargo/config.toml")},
        "rust_toolchain": {rel: _sha_file(repo / rel) for rel in
                           ("rust-toolchain", "rust-toolchain.toml")},
        "publisher_fixture_sha256": recipe.get("toolchain", {}),
        "materialized_cargo_lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "materialized_cargo_lock_bytes": len(lock_bytes),
        "no_gold_or_test_patch_applied": True,
        "cwd": str(repo), "PATH": env["PATH"],
        "command_v_cargo": _run(["bash", "-c", "command -v cargo"], env=env)["stdout"].strip(),
        "cargo_shim_sha256": _sha_file(Path(env["CARGO_HOME"]) / "bin" / "cargo"),
        "rustup_which_toolchain_cargo": which_path,
        "real_cargo_binary_sha256": _sha_file(Path(which_path)) if which_path else None,
        "cargo_version_verbose": cargo_vv["stdout"],
    }
    # exact publisher install command, verbatim
    install_cmd = recipe["install"][0]
    env2, argv = pub.split_env(install_cmd)
    locked = _run([f"cargo" if argv[0] == "cargo" else argv[0], *argv[1:]] if argv[0] != "cargo"
                  else ["cargo", f"+{CHANNEL}", *argv[1:]], cwd=str(repo), env={**env, **env2}, tmo=2400)
    metadata = _run(["cargo", f"+{CHANNEL}", "metadata", "--locked", "--format-version", "1"],
                    cwd=str(repo), env=env, tmo=900)
    return {"pre_install_state": pre_install_state,
            "locked_install": {"command": install_cmd, **locked},
            "cargo_metadata_locked": {"exit": metadata["exit"],
                                      "stderr_tail": metadata["stderr"][-2000:],
                                      "ok": metadata["exit"] == 0}}, repo, env, lock_bytes


def part_c(base: str, recipe: dict, workroot: Path, publisher_lock: bytes) -> dict:
    """DISPOSABLE copy: what does cargo want to change? (never used for qualification)."""
    disp = workroot / "disposable"
    home = workroot / ".home"
    env = _cargo_env(home)
    subprocess.run(["git", "init", "-q", str(disp)], check=True)
    _git(disp, "fetch", "-q", "--depth", "1", "https://github.com/tokio-rs/tokio.git", base)
    _git(disp, "checkout", "-q", "FETCH_HEAD")
    for cmd in recipe.get("pre_install", []):
        _run(["bash", "-c", cmd], cwd=str(disp), env=env, tmo=300)
    (disp / "Cargo.lock").write_bytes(publisher_lock)  # start from the publisher lock
    env2, argv = pub.split_env(recipe["install"][0])
    unlocked_argv = ["cargo", f"+{CHANNEL}", *[a for a in argv[1:] if a != "--locked"]]
    unlocked = _run(unlocked_argv, cwd=str(disp), env={**env, **env2}, tmo=2400)
    regenerated = (disp / "Cargo.lock").read_bytes()
    diff = _lock_diff(publisher_lock.decode("utf-8", "replace"),
                      regenerated.decode("utf-8", "replace"))
    return {"unlocked_install_exit": unlocked["exit"],
            "unlocked_install_stderr_tail": unlocked["stderr"][-2000:],
            "regenerated_lock_sha256": hashlib.sha256(regenerated).hexdigest(),
            "structured_lock_diff": diff,
            "note": "regenerated lock is DIAGNOSTIC ONLY -- never used for qualification"}


def part_d(base: str, row: dict, revision: str) -> dict:
    """Reproduce through the pinned upstream SWE-bench harness (commit f7bbbb2)."""
    harness = pub.load()["harness"]
    attempt = {"harness_commit": harness["commit"], "dataset_revision": revision,
               "approach": "install pinned SWE-bench@f7bbbb2; derive tokio-4384 setup from its "
                           "constants; run env setup on the pinned base with no gold/test patch"}
    pipp = _run([sys.executable, "-m", "pip", "install", "--quiet",
                 f"git+https://github.com/SWE-bench/SWE-bench.git@{harness['commit']}"], tmo=1200)
    attempt["pip_install_exit"] = pipp["exit"]
    attempt["pip_install_stderr_tail"] = pipp["stderr"][-1500:]
    if pipp["exit"] != 0:
        attempt["status"] = "harness_install_failed"
        return attempt
    # derive the upstream setup for this instance directly from the pinned constants
    probe = (
        "import json,sys\n"
        "from swebench.harness.constants.rust import MAP_REPO_VERSION_TO_SPECS_RUST as M\n"
        "specs=M.get('tokio-rs/tokio',{})\n"
        "print(json.dumps({'has_4384': '4384' in specs, 'spec': specs.get('4384')}))\n")
    up = _run([sys.executable, "-c", probe], tmo=120)
    attempt["upstream_spec_probe"] = up["stdout"].strip() or up["stderr"][-1500:]
    attempt["status"] = "upstream_spec_read" if up["exit"] == 0 else "upstream_spec_unreadable"
    return attempt


def build() -> dict:
    revision = next(h["revision"] for h in c.load_record(PINS)["hf_datasets"]
                    if h["source_id"] == "swe-bench-multilingual")
    recipe = pub.recipe_for_case(CASE_ID)
    if recipe is None:
        raise SystemExit("no tokio recipe in registry")
    row = _hf_row(INSTANCE, revision)
    row_hash = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
    base = row["base_commit"]
    workroot = Path(tempfile.mkdtemp(prefix="tokio-probe-"))
    try:
        ab, repo, env, publisher_lock = part_a_and_b(base, recipe, workroot)
        c_res = part_c(base, recipe, workroot, publisher_lock)
        d_res = part_d(base, row, revision)
    finally:
        shutil.rmtree(workroot, ignore_errors=True)

    locked_exit = ab["locked_install"]["exit"]
    n2e_locked_failed = locked_exit not in (0, None)
    classification_input = {
        "n2e_locked_install_failed": n2e_locked_failed,
        "n2e_locked_exit": locked_exit,
        "upstream_reproduction_status": d_res.get("status"),
        "identities_match_note": "compare pre_install_state identities to the upstream harness "
                                 "environment before classifying",
        "boundary": {
            "upstream_succeeds": "HARNESS_DEFECT (diff + fix N2-E reconstruction)",
            "upstream_fails_identically_and_identities_match": "DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE",
            "revision_harness_incompatible_pair": "source-provenance defect (pin matching pair)",
        },
        "classification": None,  # decided by reviewer from this evidence
    }
    return c.envelope(
        record_type="tokio-4384-publisher-recipe-consistency",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/probe_tokio_recipe_consistency.py",
        purpose="Distinguish a harness reconstruction defect from an internally inconsistent "
                "publisher recipe for the pinned tokio-4384 substrate; classification deferred.",
        instance_id=INSTANCE, case_id=CASE_ID, dataset_revision=revision,
        instance_row_sha256=row_hash, base_commit=base, rust_channel=CHANNEL,
        publisher_recipe=recipe["source"], registry_sha256=pub.registry_sha256(),
        part_a_pre_install_state=ab["pre_install_state"],
        part_b_locked_failure=ab["locked_install"],
        part_b_cargo_metadata=ab["cargo_metadata_locked"],
        part_c_disposable_lock_diff=c_res,
        part_d_upstream_harness=d_res,
        classification_input=classification_input,
    )


def main() -> int:
    rec = build()
    c.write_record(OUT, rec)
    print(f"wrote {OUT.name}: locked_exit={rec['part_b_locked_failure']['exit']} "
          f"upstream={rec['part_d_upstream_harness'].get('status')}")
    diff = rec["part_c_disposable_lock_diff"]["structured_lock_diff"]
    print(f"  lock diff: +{diff['added_count']} -{diff['removed_count']} "
          f"~{diff['changed_count']} format_changed={diff['format_changed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
