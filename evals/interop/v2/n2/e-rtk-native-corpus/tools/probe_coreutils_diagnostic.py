#!/usr/bin/env python3
"""Focused Coreutils-6731 diagnostic probe v2 (corrected; contract steps 1-10 of the
correction set on top of the original steps 2,5-13).

OUTCOME-NEUTRAL diagnostic, NOT canonical acceptance. Corrections applied:
  1. dependency-state capture is strictly PASSIVE (no cargo/build command); cargo metadata
     is probed in a DISPOSABLE copy and never mutates the normative repo.
  2. the EXACT committed argv/env are executed (plain `cargo test backslash --no-fail-fast`
     + RUSTUP_TOOLCHAIN=1.81.0; no `+1.81.0` in argv) and recorded as == the contract.
  3. the resolved toolchain pins (channel manifest + component + xz artifact hashes,
     date, host, versions) are ENFORCED before any repository acquisition.
  4. acquisition A/B parity is a GATE over complete normalized post-install records; the
     only authorized tracked mutation is a deterministic Cargo.lock create/modify.
  5. the complete final measurement environments (repo + cargo-home-seed + home-seed +
     rustup) must have equal normalized stable manifests A==B before measurement.
  6. per-repetition mutation guard covers repo + cargo cache stable content + toolchain
     immutability.
  7. RTK Cargo-filter source provenance is a derived dispatch->filter->parser->formatter
     chain from the pinned checkout, not a broad candidate scan.
Because the Rust RTK dialect is not yet approved the outcome is RTK_DIALECT_UNPROVEN /
acceptance_pass=false. The JOB gates on diagnostic COMPLETENESS via an independent verifier.
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
import run_canary_case as drv  # noqa: E402

CASE_ID = "uutils__coreutils-6731::rust_cargo::test::fixed"
INSTANCE_ID = "uutils__coreutils-6731"
REPO = "uutils/coreutils"
CHANNEL = "1.81.0"
HOST = "x86_64-unknown-linux-gnu"
ROW = N2E_DIR / "evidence" / "coreutils-6731" / "uutils__coreutils-6731.row.json"
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
CANON_POLICY = "cargo-test-v2"
REPS = 3
# exact committed argv/env (correction 2)
CONTRACT_RAW_ARGV = ["cargo", "test", "backslash", "--no-fail-fast"]
CONTRACT_ENV = {"RUSTUP_TOOLCHAIN": "1.81.0", "CARGO_NET_OFFLINE": "true",
                "RUST_TEST_THREADS": "1", "CARGO_BUILD_JOBS": "1"}
_FIXED = Path(tempfile.gettempdir()) / "n2e-fixedwork"
# explicitly enumerated ephemeral files excluded from stable manifests (corrections 5/6)
_EPHEMERAL_SUFFIX = (".lock",)
_EPHEMERAL_NAME = {".package-cache", ".package-cache-mutate", "config.json.lock",
                   ".crates2.json.lock"}


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


def _cargo_env(cargo_home: Path, extra: dict | None = None) -> dict:
    """Runtime env selecting the pinned toolchain via RUSTUP_TOOLCHAIN (NO +channel argv)."""
    e = {"HOME": str(cargo_home.parent / "home"), "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
         "CARGO_HOME": str(cargo_home), "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", ""),
         "RUSTUP_TOOLCHAIN": CHANNEL}
    if not e["RUSTUP_HOME"]:
        e.pop("RUSTUP_HOME")
    e.update(extra or {})
    return e


# ---------------------- correction 3: enforce toolchain pins BEFORE acquisition ----------------------
def enforce_toolchain(pins: dict) -> dict:
    """Fetch + verify the channel manifest and component/xz artifact hashes against the
    overlay pins, install rust 1.81.0 into the default RUSTUP_HOME, and capture installed
    identities SEPARATELY. Returns {ok, ...}; ok=False means fail before acquisition."""
    import tomllib
    reasons = []
    cm = pins["channel_manifest"]; comps = pins["components_x86_64_unknown_linux_gnu"]
    try:
        with urllib.request.urlopen(urllib.request.Request(cm["url"]), context=c.ssl_context(),
                                    timeout=120) as r:
            data = r.read()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reasons": [f"manifest fetch failed: {e}"]}
    man_sha = _sha(data)
    if man_sha != cm["sha256"]:
        reasons.append(f"manifest sha {man_sha} != pinned {cm['sha256']}")
    m = tomllib.loads(data.decode("utf-8"))
    if m.get("date") != cm["manifest_date"]:
        reasons.append(f"manifest date {m.get('date')} != {cm['manifest_date']}")
    artifact = {}
    for name in ("cargo", "rustc", "rust"):
        t = (m.get("pkg", {}).get(name, {}).get("target", {}) or {}).get(HOST, {})
        if not t.get("available"):
            reasons.append(f"component {name} unavailable")
            continue
        artifact[name] = {"hash": t.get("hash"), "xz_hash": t.get("xz_hash")}
        if t.get("hash") != comps[name]["hash"]:
            reasons.append(f"{name} component hash mismatch")
        if t.get("xz_hash") != comps[name]["xz_hash"]:
            reasons.append(f"{name} xz artifact hash mismatch")
    if reasons:
        return {"ok": False, "reasons": reasons, "manifest_sha256": man_sha}
    # install into default RUSTUP_HOME (shared immutable toolchain root, verified identical)
    ins = _run(["rustup", "toolchain", "install", CHANNEL, "--profile", "minimal", "--no-self-update"],
               env={**os.environ, "RUSTUP_TOOLCHAIN": CHANNEL}, tmo=900)
    if ins["exit"] != 0:
        return {"ok": False, "reasons": [f"rustup install exit {ins['exit']}",
                                         ins["stderr"][-400:].decode("utf-8", "replace")]}
    env = {**os.environ, "RUSTUP_TOOLCHAIN": CHANNEL}
    which_cargo = _run(["rustup", "which", "--toolchain", CHANNEL, "cargo"], env=env)["stdout"].decode().strip()
    which_rustc = _run(["rustup", "which", "--toolchain", CHANNEL, "rustc"], env=env)["stdout"].decode().strip()
    if not which_cargo or not which_rustc:
        return {"ok": False, "reasons": ["rustup which failed"]}
    cargo_vv = _run(["cargo", "-Vv"], env=env)["stdout"].decode("utf-8", "replace")
    rustc_vv = _run(["rustc", "-Vv"], env=env)["stdout"].decode("utf-8", "replace")
    host = next((ln.split(":", 1)[1].strip() for ln in rustc_vv.splitlines() if ln.startswith("host:")), None)
    if host != HOST:
        reasons.append(f"host {host} != {HOST}")
    if f"cargo {CHANNEL}" not in cargo_vv.splitlines()[0] if cargo_vv else True:
        reasons.append("cargo version not 1.81.0")
    if f"rustc {CHANNEL}" not in rustc_vv.splitlines()[0] if rustc_vv else True:
        reasons.append("rustc version not 1.81.0")
    shim = shutil.which("cargo")
    rustup_exe = shutil.which("rustup")
    installed = {
        "resolved_channel_exact": CHANNEL, "host_target": host,
        # installed executable identities (captured INDEPENDENTLY of artifact hashes)
        "cargo_binary_path": which_cargo,
        "cargo_binary_sha256": (c.sha256_file(which_cargo) if Path(which_cargo).exists() else None),
        "rustc_binary_path": which_rustc,
        "rustc_binary_sha256": (c.sha256_file(which_rustc) if Path(which_rustc).exists() else None),
        "cargo_shim_path": shim, "cargo_shim_realpath": (os.path.realpath(shim) if shim else None),
        "rustup_executable_path": rustup_exe,
        "rustup_executable_sha256": (c.sha256_file(rustup_exe) if rustup_exe and Path(rustup_exe).exists() else None),
        "cargo_version_verbose": cargo_vv, "rustc_version_verbose": rustc_vv,
        "installed_components": _run(["rustup", "component", "list", "--installed", "--toolchain", CHANNEL],
                                     env=env)["stdout"].decode("utf-8", "replace").split(),
    }
    for k in ("cargo_binary_sha256", "rustc_binary_sha256"):
        if not installed[k]:
            reasons.append(f"missing {k}")
    return {"ok": not reasons, "reasons": reasons, "manifest_sha256": man_sha,
            "manifest_date": m.get("date"), "distribution_artifacts": artifact,
            "installed_identity": installed, "rustup_home": os.environ.get("RUSTUP_HOME")}


# ---------------------- correction 1: passive dependency state ----------------------
def capture_dependency_state_passive(repo_dir: Path, ge: dict) -> dict:
    """FILESYSTEM + GIT observations ONLY -- executes no cargo/build command."""
    tomls = {}
    for rel in sorted(x for x in _git(repo_dir, "ls-files", "*Cargo.toml",
                                      env=ge)["stdout"].decode("utf-8", "replace").splitlines() if x.strip()):
        f = repo_dir / rel
        tomls[rel] = c.sha256_file(str(f)) if f.is_file() else None

    def fi(rel):
        f = repo_dir / rel
        return {"present": f.is_file(), "bytes": (f.stat().st_size if f.is_file() else None),
                "sha256": (c.sha256_file(str(f)) if f.is_file() else None)}
    diff = _git(repo_dir, "diff", "HEAD", env=ge)["stdout"]
    status = [ln for ln in _git(repo_dir, "status", "--porcelain", "--untracked-files=no",
                                env=ge)["stdout"].decode("utf-8", "replace").splitlines() if ln.strip()]
    return {"head": _git(repo_dir, "rev-parse", "HEAD", env=ge)["stdout"].decode().strip(),
            "tracked_status": status, "tracked_diff_sha256": _sha(diff), "tracked_diff_bytes": len(diff),
            "workspace_cargo_tomls": tomls, "cargo_lock": fi("Cargo.lock"),
            "cargo_config": fi(".cargo/config"), "cargo_config_toml": fi(".cargo/config.toml"),
            "rust_toolchain": fi("rust-toolchain"), "rust_toolchain_toml": fi("rust-toolchain.toml")}


def probe_cargo_metadata_disposable(repo_dir: Path, cargo_home: Path, offline: bool) -> dict:
    """Copy the repo + cargo env to a DISPOSABLE dir, capture passive pre-state, run
    cargo metadata, capture passive post-state, require no mutation, discard the copy.
    Never runs cargo metadata against the normative repo (correction 1)."""
    tmp = Path(tempfile.mkdtemp(prefix="n2e-cu-md-"))
    try:
        drepo = tmp / "repo"; dch = tmp / "cargo-home"
        shutil.copytree(repo_dir, drepo, symlinks=True)
        if cargo_home.exists():
            shutil.copytree(cargo_home, dch, symlinks=True)
        ge = _git_env(tmp / "home")
        (tmp / "home").mkdir(exist_ok=True)
        has_lock = (drepo / "Cargo.lock").is_file()
        if offline and not has_lock:
            return {"available": False, "reason": "no lockfile; not created in normative repo"}
        argv = ["cargo", "metadata", "--no-deps", "--format-version", "1"]
        if offline:
            argv = ["cargo", "metadata", "--offline", "--locked", "--no-deps", "--format-version", "1"]
        pre = capture_dependency_state_passive(drepo, ge)
        md = _run(argv, cwd=str(drepo), env=_cargo_env(dch), tmo=300)
        post = capture_dependency_state_passive(drepo, ge)
        members = None
        if md["exit"] == 0:
            try:
                members = sorted(p["name"] for p in json.loads(md["stdout"]).get("packages", []))
            except Exception:  # noqa: BLE001
                members = None
        return {"available": md["exit"] == 0, "argv": argv, "exit": md["exit"], "offline": offline,
                "members": members, "disposable_no_mutation": pre == post,
                "stderr_tail": md["stderr"][-400:].decode("utf-8", "replace")}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------- stable manifests (corrections 5/6) ----------------------
def _stable_manifest(root: Path) -> dict:
    """Normalized content manifest of a directory tree: relpath -> sha256 for every file
    EXCEPT the explicitly-enumerated ephemeral files (lock/access-time markers) and .git."""
    out = {}
    if not root.exists():
        return out
    for f in sorted(root.rglob("*")):
        if not f.is_file() or f.is_symlink():
            continue
        parts = f.relative_to(root).parts
        if ".git" in parts:
            continue
        if f.name in _EPHEMERAL_NAME or f.name.endswith(_EPHEMERAL_SUFFIX):
            continue
        try:
            out[str(f.relative_to(root))] = c.sha256_file(str(f))
        except OSError:
            pass
    return out


def _manifest_hash(man: dict) -> str:
    return _sha(json.dumps(man, sort_keys=True).encode())


# ---------------------- correction 9: external artifact manifest ----------------------
def _artifact_manifest(evidence: Path, record_path: Path) -> list:
    out = []
    for f in sorted(list(evidence.rglob("*")) + [record_path]):
        if f.is_file():
            out.append({"file": str(f.relative_to(N2E_DIR)), "bytes": f.stat().st_size,
                        "sha256": c.sha256_file(str(f))})
    return out


# ---------------------- correction 9/7: acquisition ----------------------
def _acquire(label: str, root: Path, recipe: dict, base: str) -> dict:
    home = root / "home"; cargo_home = root / "cargo-home"
    repo_dir = root / "repo"
    for d in (home, cargo_home):
        d.mkdir(parents=True, exist_ok=True)
    ge = _git_env(home)
    _run(["git", "init", "-q", str(repo_dir)], env=ge)
    fe = _git(repo_dir, "fetch", "-q", "--depth", "1", f"https://github.com/{REPO}.git", base, env=ge)
    _git(repo_dir, "checkout", "-q", "FETCH_HEAD", env=ge)
    head_ok = _git(repo_dir, "rev-parse", "HEAD", env=ge)["stdout"].decode().strip() == base
    pristine = capture_dependency_state_passive(repo_dir, ge)
    pre_md = probe_cargo_metadata_disposable(repo_dir, cargo_home, offline=False)
    # publisher install: EXACT committed argv shape (plain cargo, RUSTUP_TOOLCHAIN env)
    inst_env, inst_argv = drv.pub.split_env(recipe["install"][0])   # ['cargo','test','backslash','--no-run']
    install = _run(inst_argv, cwd=str(repo_dir),
                   env=_cargo_env(cargo_home, {**inst_env, "CARGO_NET_OFFLINE": "false"}), tmo=1800)
    post = capture_dependency_state_passive(repo_dir, ge)
    post_md = probe_cargo_metadata_disposable(repo_dir, cargo_home, offline=post["cargo_lock"]["present"])
    return {
        "label": label, "base_commit": base, "head_matches_base": head_ok, "fetch_exit": fe["exit"],
        "install": {"argv": inst_argv, "env": inst_env, "exit": install["exit"], "timed_out": install["timed_out"],
                    "stdout_sha256": _sha(install["stdout"]), "stderr_sha256": _sha(install["stderr"]),
                    "stdout_bytes": len(install["stdout"]), "stderr_bytes": len(install["stderr"]),
                    "stderr_tail": install["stderr"][-1500:].decode("utf-8", "replace")},
        "pristine_state": pristine, "post_install_state": post,
        "pre_install_metadata": pre_md, "post_install_metadata": post_md,
        "cargo_cache_stable_manifest_hash": _manifest_hash(_stable_manifest(cargo_home)),
        "_root": str(root), "_repo_dir": str(repo_dir), "_cargo_home": str(cargo_home), "_ge": ge,
    }


def _acq_public(a: dict) -> dict:
    return {k: v for k, v in a.items() if not k.startswith("_")}


def _classify_acquisitions(A: dict, B: dict, tool_ident: dict) -> dict:
    if A["install"]["exit"] != 0 or B["install"]["exit"] != 0:
        return {"outcome": "COREUTILS_ACQUISITION_INSTALL_FAILURE",
                "a_exit": A["install"]["exit"], "b_exit": B["install"]["exit"]}
    pa, pb = A["post_install_state"], B["post_install_state"]
    # complete normalized post-install parity (correction 4)
    parity = {
        "workspace_manifests_equal": pa["workspace_cargo_tomls"] == pb["workspace_cargo_tomls"],
        "cargo_lock_equal": pa["cargo_lock"] == pb["cargo_lock"],
        "cargo_config_equal": (pa["cargo_config"] == pb["cargo_config"]
                               and pa["cargo_config_toml"] == pb["cargo_config_toml"]),
        "rust_toolchain_equal": (pa["rust_toolchain"] == pb["rust_toolchain"]
                                 and pa["rust_toolchain_toml"] == pb["rust_toolchain_toml"]),
        "tracked_status_equal": pa["tracked_status"] == pb["tracked_status"],
        "tracked_diff_equal": pa["tracked_diff_sha256"] == pb["tracked_diff_sha256"],
        "metadata_members_equal": (A["post_install_metadata"].get("members")
                                   == B["post_install_metadata"].get("members")),
        "install_semantics_equal": (A["install"]["exit"] == B["install"]["exit"]
                                    and A["install"]["timed_out"] == B["install"]["timed_out"]),
        "cargo_cache_seed_equal": (A["cargo_cache_stable_manifest_hash"]
                                   == B["cargo_cache_stable_manifest_hash"]),
    }
    # authorized tracked mutation = ONLY Cargo.lock create/modify, deterministic A==B
    def tracked_nonlock_changed(a):
        base_status = a["pristine_state"]["tracked_status"]
        now_status = a["post_install_state"]["tracked_status"]
        changed = set(now_status) - set(base_status)
        return sorted(x for x in changed if "Cargo.lock" not in x)
    a_nonlock, b_nonlock = tracked_nonlock_changed(A), tracked_nonlock_changed(B)
    cfg_or_tc_mutated = not (parity["cargo_config_equal"] and parity["rust_toolchain_equal"]) or bool(a_nonlock or b_nonlock)
    if cfg_or_tc_mutated:
        return {"outcome": "COREUTILS_ACQUISITION_UNAUTHORIZED_MUTATION", "parity": parity,
                "a_nonlock_tracked": a_nonlock, "b_nonlock_tracked": b_nonlock,
                "note": "only Cargo.lock create/modify is authorized during publisher install"}
    if not all(parity.values()):
        return {"outcome": "COREUTILS_ACQUISITION_NONDETERMINISTIC", "parity": parity,
                "note": "harness/acquisition investigation state, not a candidate disqualification"}
    lock_created = (not A["pristine_state"]["cargo_lock"]["present"]) and pa["cargo_lock"]["present"]
    lock_modified = (A["pristine_state"]["cargo_lock"]["present"] and pa["cargo_lock"]["present"]
                     and A["pristine_state"]["cargo_lock"]["sha256"] != pa["cargo_lock"]["sha256"])
    tracked_dependency_mutation = lock_created or lock_modified
    if tracked_dependency_mutation:
        return {"outcome": "publisher_install_dependency_snapshot", "install_locked": False,
                "parity": parity, "lock_created": lock_created, "lock_modified": lock_modified,
                "tracked_dependency_mutation": True,
                "frozen_lock_sha256": pa["cargo_lock"]["sha256"], "frozen_lock_bytes": pa["cargo_lock"]["bytes"],
                "byte_identical_across_A_B": parity["cargo_lock_equal"]}
    return {"outcome": "pristine_dependency_state", "install_locked": False, "parity": parity,
            "tracked_dependency_mutation": False}


# ---------------------- correction 5: finalize + complete env parity ----------------------
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
    final_state = capture_dependency_state_passive(repo_dir, ge)
    final_md = probe_cargo_metadata_disposable(repo_dir, Path(a["_cargo_home"]),
                                               offline=final_state["cargo_lock"]["present"])
    return {"applied": applied, "gold_exit": gold_exit, "test_exit": test_exit,
            "test_patch_files": test_files, "reset_from_base": reset_paths, "reset_failed": reset_failed,
            "existing_at_base": existing, "final_state": final_state, "final_metadata": final_md,
            "all_ok": (gold_exit == 0 and test_exit == 0 and not reset_failed)}


def _final_env_parity(A, B, finA, finB) -> dict:
    p = {
        "final_repo_state_equal": finA["final_state"] == finB["final_state"],
        "final_tracked_diff_equal": finA["final_state"]["tracked_diff_sha256"] == finB["final_state"]["tracked_diff_sha256"],
        "final_cargo_lock_equal": finA["final_state"]["cargo_lock"] == finB["final_state"]["cargo_lock"],
        "final_manifests_equal": finA["final_state"]["workspace_cargo_tomls"] == finB["final_state"]["workspace_cargo_tomls"],
        "final_metadata_equal": finA["final_metadata"].get("members") == finB["final_metadata"].get("members"),
        "cargo_cache_seed_equal": A["cargo_cache_stable_manifest_hash"] == B["cargo_cache_stable_manifest_hash"],
    }
    p["all_equal"] = all(p.values())
    return p


# ---------------------- corrections 6/7/8: measurement arm ----------------------
def _rustup_manifest(rustup_home: str) -> str:
    root = Path(rustup_home) / "toolchains" if rustup_home else None
    return _manifest_hash(_stable_manifest(root)) if root else ""


def _measure_arm(is_rtk: bool, frozen_env: Path, argv: list, wrapper: list, off_env: dict,
                 target_ids: list, evidence: Path, rustup_home: str) -> dict:
    role = "rtk" if is_rtk else "raw"
    ge = _git_env(_FIXED / "home")
    runs, canon_hashes, per_rep, mut = [], [], [], []
    evidence.mkdir(parents=True, exist_ok=True)
    seed_cargo = _manifest_hash(_stable_manifest(frozen_env / "cargo-home"))
    seed_toolchain = _rustup_manifest(rustup_home)
    contract_argv_ok = (argv[1:] == CONTRACT_RAW_ARGV[1:] if is_rtk else argv == CONTRACT_RAW_ARGV)
    for i in range(REPS):
        if _FIXED.exists():
            shutil.rmtree(_FIXED, ignore_errors=True)
        shutil.copytree(frozen_env, _FIXED, symlinks=True)
        work_repo = _FIXED / "repo"
        pre_repo = capture_dependency_state_passive(work_repo, ge)
        pre_cargo = _manifest_hash(_stable_manifest(_FIXED / "cargo-home"))
        env_extra = {**off_env, "HOME": str(_FIXED / "home"), "CARGO_HOME": str(_FIXED / "cargo-home"),
                     "RUSTUP_HOME": rustup_home, "RUSTUP_TOOLCHAIN": CHANNEL}
        r = drv.run_isolated(argv, str(work_repo), 900, wrapper, env_extra)
        post_repo = capture_dependency_state_passive(work_repo, ge)
        post_cargo = _manifest_hash(_stable_manifest(_FIXED / "cargo-home"))
        post_toolchain = _rustup_manifest(rustup_home)
        combined = canon.rtk_envelope(r["combined"]) if is_rtk else r["combined"]
        cb = canon.canonicalize(combined, CANON_POLICY)
        removed_diag = canon.cargo_test_v2_removed_diag(combined)  # diagnostic evidence
        repo_ok = pre_repo == post_repo
        cache_ok = pre_cargo == post_cargo
        tc_ok = (seed_toolchain == post_toolchain)
        mrec = {"rep": i, "repo_mutation_ok": repo_ok, "cargo_cache_stable_content_ok": cache_ok,
                "toolchain_immutable": tc_ok, "mutation_ok": repo_ok and cache_ok and tc_ok,
                "pre_repo_state_sha256": _sha(json.dumps(pre_repo, sort_keys=True).encode()),
                "post_repo_state_sha256": _sha(json.dumps(post_repo, sort_keys=True).encode()),
                "cargo_lock_before": pre_repo["cargo_lock"], "cargo_lock_after": post_repo["cargo_lock"],
                "tracked_status_before": pre_repo["tracked_status"], "tracked_status_after": post_repo["tracked_status"],
                "cargo_cache_before": pre_cargo, "cargo_cache_after": post_cargo,
                "toolchain_manifest": post_toolchain}
        mut.append(mrec)
        runs.append({"exit_code": r["exit_code"], "timed_out": r.get("timed_out", False),
                     "raw_combined_sha256": _sha(r["combined"]), "canonical_sha256": _sha(cb),
                     "canonical_bytes": len(cb), "canon_removed_lines": removed_diag})
        canon_hashes.append(_sha(cb))
        if not is_rtk:
            per_rep.append(ora.cargo_target_execution_proof(r["combined"], r["exit_code"], target_ids))
        (evidence / f"{role}.rep{i}.zst").write_bytes(zlib.compress(cb, 9))
        (evidence / f"{role}.raw.rep{i}.zst").write_bytes(zlib.compress(r["combined"], 9))
        with open(evidence / f"{role}.mutation.rep{i}.json", "w") as fh:
            json.dump(mrec, fh, sort_keys=True)
    shutil.rmtree(_FIXED, ignore_errors=True)
    det = len(set(canon_hashes)) == 1
    out = {"role": role, "reps": REPS, "actual_argv": argv,
           "canonicalization_policy": CANON_POLICY,
           "actual_argv_equal_contract": contract_argv_ok,
           "exit_stable": len({x["exit_code"] for x in runs}) == 1, "deterministic": det,
           "canonical_sha256": canon_hashes[0] if det else None,
           "timed_out_any": any(x["timed_out"] for x in runs), "runs": runs,
           "per_rep_mutation": mut, "mutation_ok_all": all(x["mutation_ok"] for x in mut),
           "cargo_cache_seed_hash": seed_cargo, "toolchain_seed_hash": seed_toolchain}
    if not is_rtk:
        exec_ids = [tuple(p["executed_ok_ids"]) for p in per_rep]
        out["cargo_execution_proof"] = per_rep
        out["executed_ids_deterministic"] = len(set(exec_ids)) == 1
        out["raw_qualified"] = (det and out["exit_stable"] and not out["timed_out_any"]
                                and out["mutation_ok_all"] and contract_argv_ok
                                and all(p["executed_ok"] for p in per_rep) and out["executed_ids_deterministic"])
    return out


# ---------------------- correction 7: precise RTK cargo-filter provenance ----------------------
def _rtk_source_evidence(workroot: Path, evidence: Path) -> dict:
    co = workroot / "rtk-src"
    _run(["git", "init", "-q", str(co)])
    fe = _run(["git", "-C", str(co), "fetch", "-q", "--depth", "1",
               "https://github.com/rtk-ai/rtk.git", RTK_SOURCE_COMMIT], tmo=300)
    if fe["exit"] != 0:
        return {"fetched": False, "commit": RTK_SOURCE_COMMIT, "head_proven": False,
                "error": fe["stderr"][-400:].decode("utf-8", "replace")}
    _run(["git", "-C", str(co), "checkout", "-q", "FETCH_HEAD"])
    head = _run(["git", "-C", str(co), "rev-parse", "HEAD"])["stdout"].decode().strip()
    tree = _run(["git", "-C", str(co), "rev-parse", "HEAD^{tree}"])["stdout"].decode().strip()

    def ident(f: Path):
        blob = _run(["git", "-C", str(co), "hash-object", str(f)])["stdout"].decode().strip()
        return {"path": str(f.relative_to(co)), "git_blob_sha1": blob,
                "sha256": c.sha256_file(str(f)), "bytes": f.stat().st_size}

    # role signals -> derive the dispatch->filter->parser->formatter chain mechanically
    roles = {"cli_dispatch_cargo_test": [], "cargo_filter": [], "cargo_parser": [], "summary_formatter": []}
    src_bytes = {}
    for f in co.rglob("*"):
        if not f.is_file() or ".git" in f.parts:
            continue
        try:
            txt = f.read_bytes()
        except OSError:
            continue
        low = txt.lower()
        rel = str(f.relative_to(co))
        # dispatch: routes the "cargo" subcommand / "cargo test" to a handler
        if (b"cargo" in low and (b"subcommand" in low or b"match " in low or b"command" in low)
                and b"test" in low):
            roles["cli_dispatch_cargo_test"].append(rel); src_bytes[rel] = ident(f)
        # native cargo parser: recognizes cargo's own "test result:" line
        if b"test result:" in low:
            roles["cargo_parser"].append(rel); src_bytes[rel] = ident(f)
        # filter selection for cargo test
        if b"cargo" in low and b"filter" in low:
            roles["cargo_filter"].append(rel); src_bytes[rel] = ident(f)
        # formatter emitting the RTK summary grammar (e.g. "Go test:", "Pytest:", "<Tool> test:")
        if b" passed" in low and (b" failed" in low or b"packages" in low) and (
                b"format" in low or b"write" in low or b"println" in low or b"summary" in low):
            roles["summary_formatter"].append(rel); src_bytes[rel] = ident(f)
    # copy the identified source bytes into the PERSISTED evidence dir for retention
    ev_dir = evidence / "rtk-source-evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for rel in sorted(src_bytes):
        dst = ev_dir / rel.replace("/", "__")
        try:
            dst.write_bytes((co / rel).read_bytes())
            copied.append(dst.name)
        except OSError:
            pass
    complete = all(len(v) >= 1 for v in roles.values())
    return {"fetched": True, "commit": RTK_SOURCE_COMMIT, "head": head, "tree": tree,
            "head_proven": head == RTK_SOURCE_COMMIT, "roles": roles,
            "source_identities": src_bytes, "copied_evidence_files": sorted(copied),
            "chain_complete": complete,
            "chain": "rtk cargo test -> selected filter -> native cargo parser -> emitted RTK summary grammar"}


def _emit(out: Path, body: dict):
    c.write_record(out, c.envelope(record_type="n2e-coreutils-diagnostic",
                   generated_by="tools/probe_coreutils_diagnostic.py", **body))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(N2E_DIR / "coreutils-6731-diagnostic-v1.json"))
    ap.add_argument("--evidence", default=str(N2E_DIR / "out" / "evidence" / "coreutils-6731"))
    args = ap.parse_args()
    out = Path(args.out); evidence = Path(args.evidence); evidence.mkdir(parents=True, exist_ok=True)

    bundle = loader.load_case_bundle(CASE_ID, "resolved")
    recipe = bundle["publisher_recipe"]; scen = bundle["scenario"]
    base = scen["base_commit"]; target_ids = scen["target_test_ids"]
    pins = loader.validate_resolved_closure()["overlays"]["toolchain"]["resolved_rust_toolchain"]
    row = c.load_record(ROW)
    gold = (row.get("patch") or "").encode(); test = (row.get("test_patch") or "").encode()

    body = {"case_id": CASE_ID, "instance_id": INSTANCE_ID, "base_commit": base,
            "diagnostic_classification": "COREUTILS_DIAGNOSTIC_NONCANONICAL",
            "resolved_bundle_source": bundle["source"],
            "effective_record_hash_map": bundle["effective_record_hash_map"],
            "contract_raw_argv": CONTRACT_RAW_ARGV, "contract_env": CONTRACT_ENV,
            "rtk_binary_sha256": (c.sha256_file(os.environ["RTK_BIN"]) if os.environ.get("RTK_BIN") else None)}

    # correction 3: enforce toolchain pins BEFORE acquisition
    tool = enforce_toolchain(pins)
    body["toolchain_enforcement"] = tool
    if not tool["ok"]:
        body["outcome"] = "COREUTILS_TOOLCHAIN_PINS_UNVERIFIED"; body["acceptance_pass"] = False
        _emit(out, body); print("coreutils-diagnostic:", body["outcome"], tool["reasons"]); return 0
    os.environ["RUSTUP_HOME"] = os.environ.get("RUSTUP_HOME") or str(Path.home() / ".rustup")
    rustup_home = os.environ["RUSTUP_HOME"]

    iso = drv.resolve_isolation()
    if iso is None:
        body["outcome"] = "REJECTED_NO_ISOLATION"; body["acceptance_pass"] = False
        _emit(out, body); return 0
    iso_method, wrapper = iso
    body["isolation"] = {"method": iso_method, "denial_probe": drv.denial_probe(wrapper)}

    workroot = Path(tempfile.mkdtemp(prefix="n2e-cu-diag-"))
    try:
        A = _acquire("A", workroot / "A", recipe, base)
        B = _acquire("B", workroot / "B", recipe, base)
        cls = _classify_acquisitions(A, B, tool)
        body["acquisition_A"] = _acq_public(A); body["acquisition_B"] = _acq_public(B)
        body["acquisition_classification"] = cls
        body["rtk_cargo_filter_source"] = _rtk_source_evidence(workroot, evidence)

        if cls["outcome"] not in ("publisher_install_dependency_snapshot", "pristine_dependency_state"):
            body["outcome"] = cls["outcome"]; body["acceptance_pass"] = False
            body["file_manifest"] = _artifact_manifest(evidence, out)
            _emit(out, body); print("coreutils-diagnostic:", body["outcome"]); return 0

        finA = _finalize(A, gold, test, base); finB = _finalize(B, gold, test, base)
        parity = _final_env_parity(A, B, finA, finB)
        body["finalize_A"] = finA; body["finalize_B"] = finB
        body["final_env_parity"] = parity
        if not (finA["all_ok"] and finB["all_ok"] and parity["all_equal"]):
            body["outcome"] = "COREUTILS_FINAL_INPUT_PARITY_FAILURE"; body["acceptance_pass"] = False
            body["file_manifest"] = _artifact_manifest(evidence, out)
            _emit(out, body); print("coreutils-diagnostic:", body["outcome"]); return 0

        # complete frozen-env root: repo + cargo-home-seed + home-seed + rustup(shared, read-only)
        frozen = workroot / "frozen-env"; frozen.mkdir()
        shutil.copytree(Path(A["_repo_dir"]), frozen / "repo", symlinks=True)
        shutil.copytree(Path(A["_cargo_home"]), frozen / "cargo-home", symlinks=True)
        (frozen / "home").mkdir()
        off = {k: v for k, v in CONTRACT_ENV.items()}
        rustflags = recipe.get("test_env", {}).get("RUSTFLAGS")
        if rustflags:
            off["RUSTFLAGS"] = rustflags
        _env, test_argv = drv.pub.split_env(recipe["test_cmd"][0])
        body["actual_environment_equal_contract"] = all(off.get(k) == v for k, v in CONTRACT_ENV.items())
        raw = _measure_arm(False, frozen, list(CONTRACT_RAW_ARGV), wrapper, {**off, **_env},
                           target_ids, evidence, rustup_home)
        body["raw_arm"] = raw
        body["actual_raw_argv_equal_contract"] = raw["actual_argv_equal_contract"]
        if not raw["raw_qualified"]:
            body["outcome"] = "COREUTILS_RAW_NOT_QUALIFIED"; body["acceptance_pass"] = False
            body["file_manifest"] = _artifact_manifest(evidence, out)
            _emit(out, body); print("coreutils-diagnostic: RAW not qualified"); return 0

        rtk_bin = os.environ.get("RTK_BIN")
        rtk = _measure_arm(True, frozen, [rtk_bin, *CONTRACT_RAW_ARGV], wrapper, {**off, **_env},
                           target_ids, evidence, rustup_home)
        body["rtk_arm"] = rtk
        body["actual_rtk_argv_equal_contract"] = rtk["actual_argv_equal_contract"]
        body["outcome"] = "RTK_DIALECT_UNPROVEN"; body["acceptance_pass"] = False
        body["rust_rtk_dialect_status"] = "unproven (fail-closed; bind from pinned RTK source + these streams)"
        body["file_manifest"] = _artifact_manifest(evidence, out)
        _emit(out, body)
        print(f"coreutils-diagnostic: complete outcome={body['outcome']} raw_qualified={raw['raw_qualified']}")
        return 0
    except Exception as e:  # noqa: BLE001
        import traceback
        body["outcome"] = "COREUTILS_DIAGNOSTIC_ERROR"; body["acceptance_pass"] = False
        body["error"] = f"{type(e).__name__}: {e}"; body["traceback"] = traceback.format_exc()[-2000:]
        try:
            body["file_manifest"] = _artifact_manifest(evidence, out)
        except Exception:  # noqa: BLE001
            pass
        _emit(out, body); print("coreutils-diagnostic: ERROR", e); return 0
    finally:
        shutil.rmtree(workroot, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
