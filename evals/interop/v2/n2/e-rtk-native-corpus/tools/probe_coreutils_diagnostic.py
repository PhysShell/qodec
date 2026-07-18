#!/usr/bin/env python3
"""Focused Coreutils-6731 diagnostic probe (contract steps 2, 5-13).

OUTCOME-NEUTRAL diagnostic (NOT canonical acceptance). It establishes: exact rust 1.81.0
toolchain identity; two genuinely-independent acquisitions A/B and their parity; the exact
publisher-install Cargo.lock mutation behaviour; a deterministic final measurement input;
RAW qualification via a native Cargo target-execution proof; primary RAW+RTK streams; and
pinned RTK Cargo-filter source provenance. Because the Rust RTK dialect is not yet approved
the diagnostic outcome is RTK_DIALECT_UNPROVEN / acceptance_pass=false -- never a semantic
disagreement and never a candidate disqualification. The JOB succeeds when the diagnostic
COMPLETED and emitted all required evidence (completeness != corpus acceptance).

Runs in CI (network-enabled acquisition; network-denied measurement). Emits
coreutils-6731-diagnostic-v1.json + primary streams + a file manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_canon_policies as canon  # noqa: E402
import n2e_oracles as ora  # noqa: E402
import n2e_resolved_loader as loader  # noqa: E402
import run_canary_case as drv  # noqa: E402  (isolation primitives, canon, run_isolated)

CASE_ID = "uutils__coreutils-6731::rust_cargo::test::fixed"
INSTANCE_ID = "uutils__coreutils-6731"
REPO = "uutils/coreutils"
CHANNEL = "1.81.0"
HOST = "x86_64-unknown-linux-gnu"
ROW = N2E_DIR / "evidence" / "coreutils-6731" / "uutils__coreutils-6731.row.json"
CHANNEL_MANIFEST_URL = "https://static.rust-lang.org/dist/channel-rust-1.81.0.toml"
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
CANON_POLICY = "cargo-test-v1"
REPS = 3
_FIXED = Path(tempfile.gettempdir()) / "n2e-fixedwork"


def _run(argv, cwd=None, env=None, tmo=1800):
    try:
        p = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=tmo)
        return {"exit": p.returncode, "stdout": p.stdout, "stderr": p.stderr, "timed_out": False}
    except subprocess.TimeoutExpired as e:
        return {"exit": 124, "stdout": e.stdout or b"", "stderr": e.stderr or b"", "timed_out": True}


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _git(cwd, *args, env=None):
    return _run(["git", "-C", str(cwd), *args], env=env, tmo=600)


def _git_env(home: Path) -> dict:
    return {"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_AUTHOR_NAME": "n2e", "GIT_AUTHOR_EMAIL": "n2e@local",
            "GIT_COMMITTER_NAME": "n2e", "GIT_COMMITTER_EMAIL": "n2e@local",
            "GIT_AUTHOR_DATE": "2026-07-17T00:00:00+0000", "GIT_COMMITTER_DATE": "2026-07-17T00:00:00+0000"}


# ---------------------------- step 5: rust 1.81.0 identity ----------------------------
def _verify_channel_manifest() -> dict:
    """Fetch the pinned channel manifest, verify its sha256, extract the cargo/rustc
    component artifact hashes. This verifies the DISTRIBUTION ARTIFACTS; installed
    executable identities are captured SEPARATELY (never compared to these)."""
    import tomllib
    try:
        with urllib.request.urlopen(urllib.request.Request(CHANNEL_MANIFEST_URL),
                                    context=c.ssl_context(), timeout=120) as r:
            data = r.read()
    except Exception as e:  # noqa: BLE001
        return {"fetched": False, "error": str(e)}
    m = tomllib.loads(data.decode("utf-8"))

    def comp(name):
        t = m["pkg"][name]["target"][HOST]
        return {"available": t.get("available"), "hash": t.get("hash"), "xz_hash": t.get("xz_hash")}
    return {"fetched": True, "manifest_sha256": _sha(data), "manifest_date": m.get("date"),
            "cargo": comp("cargo"), "rustc": comp("rustc"), "rust": comp("rust")}


def _install_rust(rustup_home: Path, cargo_home: Path) -> dict:
    env = {**os.environ, "RUSTUP_HOME": str(rustup_home), "CARGO_HOME": str(cargo_home),
           "RUSTUP_TOOLCHAIN": CHANNEL}
    ins = _run(["rustup", "toolchain", "install", CHANNEL, "--profile", "minimal",
                "--no-self-update"], env=env, tmo=900)
    which_cargo = _run(["rustup", "which", "--toolchain", CHANNEL, "cargo"], env=env)["stdout"].decode().strip()
    which_rustc = _run(["rustup", "which", "--toolchain", CHANNEL, "rustc"], env=env)["stdout"].decode().strip()
    shim = shutil.which("cargo")

    def ident(p):
        return {"path": p, "sha256": (c.sha256_file(p) if p and Path(p).exists() else None),
                "realpath": (os.path.realpath(p) if p else None)}
    cargo_vv = _run(["cargo", f"+{CHANNEL}", "-Vv"], env=env)["stdout"].decode("utf-8", "replace")
    rustc_vv = _run(["rustc", f"+{CHANNEL}", "-Vv"], env=env)["stdout"].decode("utf-8", "replace")
    comps = _run(["rustup", "component", "list", "--installed", "--toolchain", CHANNEL],
                 env=env)["stdout"].decode("utf-8", "replace").split()
    host = None
    for ln in rustc_vv.splitlines():
        if ln.startswith("host:"):
            host = ln.split(":", 1)[1].strip()
    return {"install_exit": ins["exit"], "rustup_home": str(rustup_home), "cargo_home": str(cargo_home),
            "resolved_channel_exact": CHANNEL, "host_target": host,
            "cargo_which": which_cargo, "rustc_which": which_rustc,
            "cargo_binary": ident(which_cargo), "rustc_binary": ident(which_rustc),
            "rustup_shim_path": shim, "rustup_shim_realpath": (os.path.realpath(shim) if shim else None),
            "rustup_realpath_sha256": (c.sha256_file(os.path.realpath(shim))
                                       if shim and Path(os.path.realpath(shim)).exists() else None),
            "cargo_version_verbose": cargo_vv, "rustc_version_verbose": rustc_vv,
            "installed_components": comps, "_env": env}


# ---------------------------- step 6: complete dependency state ----------------------------
def _dep_state(repo_dir: Path, ge: dict, cargo_env: dict | None = None) -> dict:
    def tracked_cargo_tomls():
        out = _git(repo_dir, "ls-files", "*Cargo.toml", env=ge)["stdout"].decode("utf-8", "replace")
        res = {}
        for rel in sorted(x for x in out.splitlines() if x.strip()):
            f = repo_dir / rel
            res[rel] = c.sha256_file(str(f)) if f.is_file() else None
        return res

    def f_ident(rel):
        f = repo_dir / rel
        return {"present": f.is_file(), "bytes": (f.stat().st_size if f.is_file() else None),
                "sha256": (c.sha256_file(str(f)) if f.is_file() else None)}
    diff = _git(repo_dir, "diff", "HEAD", env=ge)["stdout"]
    status = [ln for ln in _git(repo_dir, "status", "--porcelain", "--untracked-files=no",
                                env=ge)["stdout"].decode("utf-8", "replace").splitlines() if ln.strip()]
    head = _git(repo_dir, "rev-parse", "HEAD", env=ge)["stdout"].decode().strip()
    members = None
    if cargo_env is not None:
        md = _run(["cargo", f"+{CHANNEL}", "metadata", "--no-deps", "--format-version", "1"],
                  cwd=str(repo_dir), env=cargo_env, tmo=300)
        if md["exit"] == 0:
            try:
                j = json.loads(md["stdout"])
                members = sorted(p["name"] for p in j.get("packages", []))
            except Exception:  # noqa: BLE001
                members = None
    return {"head": head, "workspace_cargo_tomls": tracked_cargo_tomls(),
            "cargo_lock": f_ident("Cargo.lock"),
            "cargo_config": f_ident(".cargo/config"), "cargo_config_toml": f_ident(".cargo/config.toml"),
            "rust_toolchain": f_ident("rust-toolchain"), "rust_toolchain_toml": f_ident("rust-toolchain.toml"),
            "tracked_status": status, "tracked_diff_sha256": _sha(diff), "tracked_diff_bytes": len(diff),
            "cargo_metadata_members": members}


# ---------------------------- step 9: one acquisition ----------------------------
def _acquire(label: str, root: Path, recipe: dict, base: str) -> dict:
    home = root / "home"; cargo_home = root / "cargo-home"; rustup_home = root / "rustup"
    repo_dir = root / "repo"
    for d in (home, cargo_home, rustup_home):
        d.mkdir(parents=True, exist_ok=True)
    ge = _git_env(home)
    tc = _install_rust(rustup_home, cargo_home)
    cargo_env = {**tc.pop("_env"), **ge, "CARGO_NET_OFFLINE": "false"}
    # base checkout
    _run(["git", "init", "-q", str(repo_dir)], env=ge)
    fe = _git(repo_dir, "fetch", "-q", "--depth", "1", f"https://github.com/{REPO}.git", base, env=ge)
    _git(repo_dir, "checkout", "-q", "FETCH_HEAD", env=ge)
    head_ok = _git(repo_dir, "rev-parse", "HEAD", env=ge)["stdout"].decode().strip() == base
    pristine = _dep_state(repo_dir, ge, cargo_env)
    # publisher install (network-enabled), pre_install is empty for coreutils
    inst_env, inst_argv = drv.pub.split_env(recipe["install"][0])
    install = _run(["cargo", f"+{CHANNEL}", *inst_argv[1:]] if inst_argv[0] == "cargo" else inst_argv,
                   cwd=str(repo_dir), env={**cargo_env, **inst_env}, tmo=1800)
    post = _dep_state(repo_dir, ge, cargo_env)
    return {
        "label": label, "root": str(root), "base_commit": base, "head_matches_base": head_ok,
        "fetch_exit": fe["exit"], "toolchain": tc,
        "install": {"argv": inst_argv, "exit": install["exit"], "timed_out": install["timed_out"],
                    "stdout_sha256": _sha(install["stdout"]), "stderr_sha256": _sha(install["stderr"]),
                    "stdout_bytes": len(install["stdout"]), "stderr_bytes": len(install["stderr"]),
                    "stderr_tail": install["stderr"][-1200:].decode("utf-8", "replace")},
        "pristine_state": pristine, "post_install_state": post,
        "_repo_dir": str(repo_dir), "_ge": ge, "_cargo_env": cargo_env,
    }


def _acq_public(a: dict) -> dict:
    return {k: v for k, v in a.items() if not k.startswith("_")}


# ---------------------------- step 9/10: parity + snapshot classification ----------------------------
def _classify_acquisitions(A: dict, B: dict) -> dict:
    if A["install"]["exit"] != 0 or B["install"]["exit"] != 0:
        return {"outcome": "COREUTILS_ACQUISITION_INSTALL_FAILURE",
                "a_exit": A["install"]["exit"], "b_exit": B["install"]["exit"]}
    pa, pb = A["post_install_state"], B["post_install_state"]
    manifests_equal = pa["workspace_cargo_tomls"] == pb["workspace_cargo_tomls"]
    metadata_equal = pa["cargo_metadata_members"] == pb["cargo_metadata_members"]
    lock_equal = pa["cargo_lock"] == pb["cargo_lock"]
    toolchain_equal = (A["toolchain"]["cargo_binary"]["sha256"] == B["toolchain"]["cargo_binary"]["sha256"]
                       and A["toolchain"]["rustc_binary"]["sha256"] == B["toolchain"]["rustc_binary"]["sha256"])
    # did the install create/modify Cargo.lock vs pristine?
    lock_created = (not A["pristine_state"]["cargo_lock"]["present"]) and pa["cargo_lock"]["present"]
    lock_modified = (A["pristine_state"]["cargo_lock"]["present"] and pa["cargo_lock"]["present"]
                     and A["pristine_state"]["cargo_lock"]["sha256"] != pa["cargo_lock"]["sha256"])
    tracked_mutation = pa["tracked_status"] != A["pristine_state"]["tracked_status"]
    parity_ok = manifests_equal and metadata_equal and toolchain_equal
    if not parity_ok or not lock_equal:
        return {"outcome": "COREUTILS_ACQUISITION_NONDETERMINISTIC",
                "manifests_equal": manifests_equal, "metadata_equal": metadata_equal,
                "lock_equal": lock_equal, "toolchain_equal": toolchain_equal,
                "note": "harness/acquisition investigation state, not a candidate disqualification"}
    if lock_created or lock_modified:
        snap = pa["cargo_lock"]
        return {"outcome": "publisher_install_dependency_snapshot", "install_locked": False,
                "lock_created": lock_created, "lock_modified": lock_modified,
                "tracked_dependency_mutation": tracked_mutation,
                "frozen_lock_sha256": snap["sha256"], "frozen_lock_bytes": snap["bytes"],
                "byte_identical_across_A_B": lock_equal, "workspace_metadata_equal": metadata_equal}
    return {"outcome": "pristine_dependency_state", "install_locked": False,
            "tracked_dependency_mutation": tracked_mutation,
            "note": "no tracked dependency mutation from the publisher install"}


# ---------------------------- step 10: patches -> final measurement input ----------------------------
def _finalize(a: dict, gold: bytes, test: bytes, base: str) -> dict:
    repo_dir = Path(a["_repo_dir"]); ge = a["_ge"]
    applied = []

    def apply(name, blob):
        pf = repo_dir.parent / f"{name}.diff"
        pf.write_bytes(blob)
        r = _git(repo_dir, "apply", str(pf), env=ge)
        applied.append({"name": name, "sha256": _sha(blob), "apply_exit": r["exit"],
                        "stderr": r["stderr"][-300:].decode("utf-8", "replace")})
        return r["exit"]

    gold_exit = apply("gold_patch", gold) if gold else 0
    test_files = drv._diff_modified_files(test) if test else []
    existing, reset_paths, reset_failed = drv._reset_test_files(repo_dir, ge, base, test_files)
    test_exit = apply("test_patch", test) if test else 0
    diff = _git(repo_dir, "diff", "HEAD", env=ge)["stdout"]
    return {"applied": applied, "gold_exit": gold_exit, "test_exit": test_exit,
            "test_patch_files": test_files, "reset_from_base": reset_paths, "reset_failed": reset_failed,
            "existing_at_base": existing,
            "final_measurement_input_diff_sha256": _sha(diff), "final_input_bytes": len(diff),
            "all_ok": (gold_exit == 0 and test_exit == 0 and not reset_failed)}


# ---------------------------- steps 7/8/11/12: measurement arm ----------------------------
def _rep_state(work_repo: Path, ge: dict) -> dict:
    return _dep_state(work_repo, ge, cargo_env=None)


def _measure_arm(is_rtk: bool, frozen_env: Path, argv: list, wrapper: list, off_env: dict,
                 target_ids: list, evidence: Path) -> dict:
    role = "rtk" if is_rtk else "raw"
    ge = _git_env(_FIXED / "home")
    runs, canon_hashes, streams, per_rep, mut = [], [], [], [], []
    evidence.mkdir(parents=True, exist_ok=True)
    for i in range(REPS):
        if _FIXED.exists():
            shutil.rmtree(_FIXED, ignore_errors=True)
        # fresh writable copy of the complete frozen env root at a FIXED path
        shutil.copytree(frozen_env, _FIXED, symlinks=True)
        work_repo = _FIXED / "repo"
        pre = _rep_state(work_repo, ge)
        env_extra = {**off_env, "HOME": str(_FIXED / "home"),
                     "CARGO_HOME": str(_FIXED / "cargo-home"), "RUSTUP_HOME": str(_FIXED / "rustup"),
                     "RUSTUP_TOOLCHAIN": CHANNEL}
        r = drv.run_isolated(argv, str(work_repo), 900, wrapper, env_extra)
        post = _rep_state(work_repo, ge)
        combined = canon.rtk_envelope(r["combined"]) if is_rtk else r["combined"]
        cb = canon.canonicalize(combined, CANON_POLICY)
        # step 8: per-rep mutation guard (captured BEFORE the copy is deleted)
        reasons = []
        for key in ("workspace_cargo_tomls", "cargo_lock", "cargo_config", "cargo_config_toml",
                    "rust_toolchain", "rust_toolchain_toml", "tracked_status"):
            if pre[key] != post[key]:
                reasons.append(f"{key} changed during {role} rep{i}")
        mrec = {"rep": i, "pre_state_sha256": _sha(json.dumps(pre, sort_keys=True).encode()),
                "post_state_sha256": _sha(json.dumps(post, sort_keys=True).encode()),
                "tracked_status_before": pre["tracked_status"], "tracked_status_after": post["tracked_status"],
                "cargo_lock_before": pre["cargo_lock"], "cargo_lock_after": post["cargo_lock"],
                "cargo_config_before": pre["cargo_config"], "cargo_config_after": post["cargo_config"],
                "rust_toolchain_before": pre["rust_toolchain"], "rust_toolchain_after": post["rust_toolchain"],
                "workspace_manifests_before": pre["workspace_cargo_tomls"],
                "workspace_manifests_after": post["workspace_cargo_tomls"],
                "mutation_ok": not reasons, "mutation_reasons": reasons}
        mut.append(mrec)
        runs.append({"exit_code": r["exit_code"], "timed_out": r.get("timed_out", False),
                     "raw_combined_sha256": _sha(r["combined"]), "canonical_sha256": _sha(cb),
                     "canonical_bytes": len(cb)})
        canon_hashes.append(_sha(cb)); streams.append((r["combined"], cb))
        if not is_rtk:
            per_rep.append(ora.cargo_target_execution_proof(r["combined"], r["exit_code"], target_ids))
        # persist primary streams (raw capture + canonical)
        (evidence / f"{role}.rep{i}.zst").write_bytes(zlib.compress(cb, 9))
        (evidence / f"{role}.raw.rep{i}.zst").write_bytes(zlib.compress(r["combined"], 9))
    shutil.rmtree(_FIXED, ignore_errors=True)
    det = len(set(canon_hashes)) == 1
    out = {"role": role, "reps": REPS, "exit_stable": len({x["exit_code"] for x in runs}) == 1,
           "deterministic": det, "canonical_sha256": canon_hashes[0] if det else None,
           "timed_out_any": any(x["timed_out"] for x in runs), "runs": runs,
           "per_rep_mutation": mut, "mutation_ok_all": all(x["mutation_ok"] for x in mut)}
    if not is_rtk:
        exec_ids = [tuple(p["executed_ok_ids"]) for p in per_rep]
        out["cargo_execution_proof"] = per_rep
        out["executed_ids_deterministic"] = len(set(exec_ids)) == 1
        out["raw_qualified"] = (det and out["exit_stable"] and not out["timed_out_any"]
                                and out["mutation_ok_all"] and all(p["executed_ok"] for p in per_rep)
                                and out["executed_ids_deterministic"])
    return out


# ---------------------------- step 13: RTK cargo-filter source evidence ----------------------------
def _rtk_source_evidence(workroot: Path) -> dict:
    co = workroot / "rtk-src"
    _run(["git", "init", "-q", str(co)])
    fe = _run(["git", "-C", str(co), "fetch", "-q", "--depth", "1",
               "https://github.com/rtk-ai/rtk.git", RTK_SOURCE_COMMIT], tmo=300)
    if fe["exit"] != 0:
        return {"fetched": False, "commit": RTK_SOURCE_COMMIT,
                "error": fe["stderr"][-400:].decode("utf-8", "replace")}
    _run(["git", "-C", str(co), "checkout", "-q", "FETCH_HEAD"])
    tree = _run(["git", "-C", str(co), "rev-parse", "HEAD^{tree}"])["stdout"].decode().strip()
    # derive the cargo-filter source MECHANICALLY: files mentioning cargo test filtering
    hits = []
    for f in co.rglob("*"):
        if not f.is_file() or ".git" in f.parts:
            continue
        try:
            txt = f.read_bytes()
        except OSError:
            continue
        low = txt.lower()
        if b"cargo" in low and (b"test result:" in low or b"cargo test" in low or b"filter" in low):
            rel = str(f.relative_to(co))
            blob = _run(["git", "-C", str(co), "hash-object", str(f)])["stdout"].decode().strip()
            hits.append({"path": rel, "git_blob_sha1": blob, "sha256": _sha(txt), "bytes": len(txt)})
    return {"fetched": True, "commit": RTK_SOURCE_COMMIT, "tree": tree,
            "cargo_filter_source_candidates": sorted(hits, key=lambda x: x["path"])}


def _manifest(evidence: Path) -> list:
    out = []
    for f in sorted(evidence.rglob("*")):
        if f.is_file():
            out.append({"file": str(f.relative_to(evidence.parent)), "bytes": f.stat().st_size,
                        "sha256": c.sha256_file(str(f))})
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(N2E_DIR / "coreutils-6731-diagnostic-v1.json"))
    ap.add_argument("--evidence", default=str(N2E_DIR / "out" / "evidence" / "coreutils-6731"))
    args = ap.parse_args()
    out = Path(args.out); evidence = Path(args.evidence)

    bundle = loader.load_case_bundle(CASE_ID, "resolved")   # fail-closed resolved bundle
    recipe = bundle["publisher_recipe"]
    scen = bundle["scenario"]
    base = scen["base_commit"]
    target_ids = scen["target_test_ids"]
    row = c.load_record(ROW)
    gold = (row.get("patch") or "").encode()
    test = (row.get("test_patch") or "").encode()

    channel_manifest = _verify_channel_manifest()
    iso = drv.resolve_isolation()
    if iso is None:
        c.write_record(out, c.envelope(
            record_type="n2e-coreutils-diagnostic", generated_by="tools/probe_coreutils_diagnostic.py",
            case_id=CASE_ID, outcome="REJECTED_NO_ISOLATION", acceptance_pass=False))
        return 0  # diagnostic completed (with a typed no-isolation result)
    iso_method, wrapper = iso
    probe = drv.denial_probe(wrapper)

    workroot = Path(tempfile.mkdtemp(prefix="n2e-cu-diag-"))
    body = {"case_id": CASE_ID, "instance_id": INSTANCE_ID, "base_commit": base,
            "resolved_bundle_source": bundle["source"],
            "effective_record_hash_map": bundle["effective_record_hash_map"],
            "channel_manifest_verification": channel_manifest,
            "isolation": {"method": iso_method, "denial_probe": probe},
            "rtk_binary_sha256": (c.sha256_file(os.environ["RTK_BIN"]) if os.environ.get("RTK_BIN") else None)}
    try:
        A = _acquire("A", workroot / "A", recipe, base)
        B = _acquire("B", workroot / "B", recipe, base)
        classification = _classify_acquisitions(A, B)
        body["acquisition_A"] = _acq_public(A)
        body["acquisition_B"] = _acq_public(B)
        body["acquisition_classification"] = classification
        body["rtk_cargo_filter_source"] = _rtk_source_evidence(workroot)

        proceed = classification["outcome"] in ("publisher_install_dependency_snapshot",
                                                "pristine_dependency_state")
        if not proceed:
            body["outcome"] = classification["outcome"]
            body["acceptance_pass"] = False
            body["diagnostic_complete"] = True
            c.write_record(out, c.envelope(record_type="n2e-coreutils-diagnostic",
                           generated_by="tools/probe_coreutils_diagnostic.py", **body))
            print(f"coreutils-diagnostic: {classification['outcome']} (no measurement)")
            return 0

        finA = _finalize(A, gold, test, base)
        finB = _finalize(B, gold, test, base)
        final_input_equal = finA["final_measurement_input_diff_sha256"] == finB["final_measurement_input_diff_sha256"]
        body["finalize_A"] = finA; body["finalize_B"] = finB
        body["final_measurement_input_byte_identical_A_B"] = final_input_equal
        if not (finA["all_ok"] and finB["all_ok"] and final_input_equal):
            body["outcome"] = "COREUTILS_FINAL_INPUT_PARITY_FAILURE"
            body["acceptance_pass"] = False; body["diagnostic_complete"] = True
            c.write_record(out, c.envelope(record_type="n2e-coreutils-diagnostic",
                           generated_by="tools/probe_coreutils_diagnostic.py", **body))
            return 0

        # build the complete frozen-env root from acquisition A's finalized repo + caches
        frozen = workroot / "frozen-env"
        frozen.mkdir()
        shutil.copytree(Path(A["_repo_dir"]), frozen / "repo", symlinks=True)
        shutil.copytree(Path(A["root"]) / "cargo-home", frozen / "cargo-home", symlinks=True)
        (frozen / "home").mkdir()
        shutil.copytree(Path(A["root"]) / "rustup", frozen / "rustup", symlinks=True)
        off_env = {"CARGO_NET_OFFLINE": "true", "RUST_TEST_THREADS": "1", "CARGO_BUILD_JOBS": "1",
                   "RUSTFLAGS": recipe.get("test_env", {}).get("RUSTFLAGS", "")}
        off_env = {k: v for k, v in off_env.items() if v != ""}
        _env, test_argv = drv.pub.split_env(recipe["test_cmd"][0])
        raw = _measure_arm(False, frozen, ["cargo", f"+{CHANNEL}", *test_argv[1:]], wrapper,
                           {**off_env, **_env}, target_ids, evidence)
        body["raw_arm"] = raw
        if not raw["raw_qualified"]:
            body["outcome"] = "COREUTILS_RAW_NOT_QUALIFIED"; body["acceptance_pass"] = False
            body["diagnostic_complete"] = True; body["file_manifest"] = _manifest(evidence)
            c.write_record(out, c.envelope(record_type="n2e-coreutils-diagnostic",
                           generated_by="tools/probe_coreutils_diagnostic.py", **body))
            print("coreutils-diagnostic: RAW not qualified")
            return 0

        rtk_bin = os.environ.get("RTK_BIN")
        rtk = _measure_arm(True, frozen, [rtk_bin, "cargo", f"+{CHANNEL}", *test_argv[1:]], wrapper,
                           {**off_env, **_env}, target_ids, evidence)
        body["rtk_arm"] = rtk
        # step 12: rust RTK dialect not yet approved -> RTK_DIALECT_UNPROVEN (NOT disagreement)
        body["outcome"] = "RTK_DIALECT_UNPROVEN"
        body["acceptance_pass"] = False
        body["diagnostic_complete"] = True
        body["rust_rtk_dialect_status"] = "unproven (fail-closed; bind from pinned RTK source + these streams)"
        body["file_manifest"] = _manifest(evidence)
        c.write_record(out, c.envelope(record_type="n2e-coreutils-diagnostic",
                       generated_by="tools/probe_coreutils_diagnostic.py", **body))
        print(f"coreutils-diagnostic: complete outcome={body['outcome']} "
              f"raw_qualified={raw['raw_qualified']} acceptance_pass=False")
        return 0
    except Exception as e:  # noqa: BLE001 -- fail closed WITH a record
        import traceback
        body["outcome"] = "COREUTILS_DIAGNOSTIC_ERROR"; body["acceptance_pass"] = False
        body["error"] = f"{type(e).__name__}: {e}"; body["traceback"] = traceback.format_exc()[-2000:]
        c.write_record(out, c.envelope(record_type="n2e-coreutils-diagnostic",
                       generated_by="tools/probe_coreutils_diagnostic.py", **body))
        print(f"coreutils-diagnostic: ERROR {e}")
        return 0
    finally:
        shutil.rmtree(workroot, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
