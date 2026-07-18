#!/usr/bin/env python3
"""Run one canary case with a fail-closed RAW-before-RTK state machine (§13-§19).

State machine:
  1. acquire + verify environment identity (network-enabled acquisition phase,
     incl. per-ecosystem offline warm: fetch/build/install deps);
  2. establish the network-denied measurement boundary and run a POSITIVE denial
     probe (an outbound connect must fail);
  3. RAW x3 in fresh copies of the frozen environment;
  4. RAW acceptance: exactly 3 reps, declared successful outcome, stable exit,
     canonical determinism, RAW semantic oracle, verified acquisition + isolation;
  5. on any RAW failure -> emit RAW_REJECTED and exit non-zero (NO RTK arm);
  6. RTK x3 (only after RAW passes);
  7. RTK acceptance: 3 reps, stable exit, declared outcome, canonical determinism,
     RTK-vs-RAW oracle agreement, pinned RTK binary identity;
  8. PASS only when both arms satisfy their full contracts.

One canonical byte stream per arm: canonicalize(combined) under the frozen per-
tool policy id; determinism, oracle input, o200k metering, and recorded
length/sha256 ALL use that canonical stream. Raw-capture hashes are also stored.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_measure as m  # noqa: E402
import n2e_oracles as ora  # noqa: E402
import n2e_canon_policies as canon  # noqa: E402
import n2e_argv_resolver as resolver  # noqa: E402
import n2e_publisher_registry as pub  # noqa: E402
import n2e_execution_control as xctl  # noqa: E402

SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
CANARY = N2E_DIR / "n2e-canary-membership-v1.json"
PINS = N2E_DIR / "n2e-source-pins-v1.json"
RTK_BINARY_SHA256 = "41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf"
REPS = 3
# FIXED per-rep work path: run_arm rebuilds this exact path (a fresh copy of the
# frozen env) for every rep. Publisher jvm cases point GRADLE_USER_HOME at a cache
# seed *inside* the frozen env, so each rep gets a fresh writable copy of that seed
# at a stable per-rep path (no shared mutable gradle home across reps).
_FIXEDWORK = Path(tempfile.gettempdir()) / "n2e-fixedwork"
_GRADLE_SEED_DIRNAME = ".n2e-gradle-home"


def _git_env(home: Path | None = None) -> dict:
    e = {"GIT_TERMINAL_PROMPT": "0", "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
         "GIT_AUTHOR_NAME": "n2e", "GIT_AUTHOR_EMAIL": "n2e@local",
         "GIT_COMMITTER_NAME": "n2e", "GIT_COMMITTER_EMAIL": "n2e@local",
         "GIT_AUTHOR_DATE": "2026-07-17T00:00:00+0000",
         "GIT_COMMITTER_DATE": "2026-07-17T00:00:00+0000",
         "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
    if home:
        e["HOME"] = str(home)
    return e


# ---- correction #2: exact environment identity + protected-file mutation guards ----
_PROTECTED_FILES = {
    "rust_cargo": ["Cargo.lock", "Cargo.toml"],
    "go": ["go.mod", "go.sum"],
    "js_ts": ["package.json", "pnpm-lock.yaml", "package-lock.json", "yarn.lock"],
    "python": ["requirements.txt", "setup.py", "setup.cfg", "pyproject.toml", "poetry.lock"],
    "jvm": ["build.gradle", "build.gradle.kts", "settings.gradle", "gradle.lockfile", "pom.xml"],
}
_TOOL_VERSION_ARGV = {"rustc": ["-Vv"], "cargo": ["--version"], "go": ["version"],
                      "node": ["--version"], "corepack": ["--version"], "java": ["-version"],
                      "python3": ["-VV"], "pip": ["--version"]}


def _tool_identity(exe: str, path: str | None = None) -> dict:
    path = path or shutil.which(exe)
    if not path or not Path(path).exists():
        return {"present": False}
    try:
        p = subprocess.run([path] + _TOOL_VERSION_ARGV.get(exe, ["--version"]),
                           capture_output=True, text=True, timeout=60)
        ver = (p.stdout + p.stderr).strip()
    except Exception as e:  # noqa: BLE001
        ver = f"<version error: {e}>"
    return {"present": True, "path": path, "sha256": c.sha256_file(path), "version": ver}


def _rustup_which(exe: str, channel: str | None) -> str | None:
    """Resolve the REAL toolchain binary (NOT the ~/.cargo/bin rustup shim) so its
    SHA-256 matches the component-tarball binary pinned in the toolchain lock."""
    args = ["rustup", "which"]
    if channel:
        args += ["--toolchain", channel]
    args.append(exe)
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=60,
                           env={**os.environ, **({"RUSTUP_TOOLCHAIN": channel} if channel else {})})
        path = p.stdout.strip()
        return path or None
    except Exception:  # noqa: BLE001
        return None


def _toolchain_identity(fam: str, repo_dir: Path, venv_bin: str | None = None,
                        rust_channel: str | None = None) -> dict:
    tc: dict = {}
    if fam == "rust_cargo":
        # hash the REAL toolchain rustc/cargo (via rustup which), never the shim
        tc["rustc"] = _tool_identity("rustc", _rustup_which("rustc", rust_channel))
        tc["cargo"] = _tool_identity("cargo", _rustup_which("cargo", rust_channel))
    elif fam == "go":
        tc["go"] = _tool_identity("go")
    elif fam == "js_ts":
        tc["node"], tc["corepack"] = _tool_identity("node"), _tool_identity("corepack")
        # pnpm executes both acquisition and measurement -> pin its identity too
        pnpm_path = shutil.which("pnpm")
        tc["pnpm"] = _tool_identity("pnpm", pnpm_path)
    elif fam == "python":
        # the case-pinned venv interpreter/pip if provisioned, else the runner default
        py = f"{venv_bin}/python" if venv_bin else None
        pip = f"{venv_bin}/pip" if venv_bin else None
        tc["python3"] = _tool_identity("python3", py)
        tc["pip"] = _tool_identity("pip", pip)
    elif fam == "jvm":
        tc["java"] = _tool_identity("java")
        gw = repo_dir / "gradlew"
        props = repo_dir / "gradle" / "wrapper" / "gradle-wrapper.properties"
        jar = repo_dir / "gradle" / "wrapper" / "gradle-wrapper.jar"
        if gw.exists():
            dist = None
            if props.exists():
                for ln in props.read_text(errors="replace").splitlines():
                    if ln.startswith("distributionUrl"):
                        dist = ln.split("=", 1)[1].strip()
            tc["gradlew_or_mvn"] = {"present": True, "path": str(gw), "sha256": c.sha256_file(str(gw)),
                                    "version": dist or "gradle-wrapper", "kind": "gradle-wrapper",
                                    "wrapper_properties_sha256": c.sha256_file(str(props)) if props.exists() else None,
                                    "wrapper_jar_sha256": c.sha256_file(str(jar)) if jar.is_file() else None}
        else:
            tc["gradlew_or_mvn"] = _tool_identity("mvn")
    return tc


def _protected_hashes(repo_dir: Path, fam: str) -> dict:
    out = {}
    for rel in _PROTECTED_FILES.get(fam, []):
        f = repo_dir / rel
        out[rel] = c.sha256_file(str(f)) if f.is_file() else None
    return out


def _worktree_modified(repo_dir: Path, home: Path) -> list:
    """Tracked files MODIFIED/DELETED in the worktree (untracked acquisition
    artifacts like .egg-info or build dirs are not a mutation of frozen inputs)."""
    p = subprocess.run(["git", "-C", str(repo_dir), "status", "--porcelain", "--untracked-files=no"],
                       capture_output=True, text=True, env=_git_env(home))
    return [ln for ln in p.stdout.splitlines() if ln.strip()]


def _platform_identity(fam: str) -> dict:
    ident = {"uname": platform.platform(), "machine": platform.machine(), "system": platform.system()}
    if fam == "go":
        for k in ("GOOS", "GOARCH"):
            r = subprocess.run(["go", "env", k], capture_output=True, text=True)
            ident[k] = r.stdout.strip()
    if fam == "rust_cargo":
        r = subprocess.run(["rustc", "-vV"], capture_output=True, text=True)
        for ln in r.stdout.splitlines():
            if ln.startswith("host:"):
                ident["rust_target"] = ln.split(":", 1)[1].strip()
    return ident


def _post_measurement_state(repo_dir: Path, home: Path, fam: str, env_id: dict) -> dict:
    """Compare the worktree + committed protected files AFTER the measurement arms
    against the constructed frozen-input baseline captured during acquisition. New
    tracked drift, or a change to a committed protected file, is a real mutation."""
    deps = (env_id.get("dependencies") or {})
    baseline_tracked = ((env_id.get("construction") or {}).get("baseline_tracked_status")) or []
    after_acq = deps.get("after_acquisition") or {}
    final_tracked = _worktree_modified(repo_dir, home)
    final_protected = _protected_hashes(repo_dir, fam)
    new_tracked = sorted(set(final_tracked) - set(baseline_tracked))
    protected_changed = sorted(k for k, h in after_acq.items()
                               if h is not None and final_protected.get(k) != h)
    reasons = []
    if new_tracked:
        reasons.append(f"measured command mutated tracked input(s) beyond the "
                       f"declared-patch baseline: {new_tracked}")
    if protected_changed:
        reasons.append(f"measured command changed committed protected file(s): {protected_changed}")
    return {"ok": not reasons, "reasons": reasons,
            "final_tracked_status": final_tracked, "new_tracked": new_tracked,
            "final_protected": final_protected, "protected_changed": protected_changed}


def _git_acquisition_evidence(repo_dir: Path, home: Path, commit: str, sub: str,
                              depth: int, effective_argv: list) -> dict:
    """Correction #2 (RuboCop `git show` merge representation): capture the pinned
    commit, its EXACT direct parent list, the fetch depth + fetched-object evidence,
    the effective `git show` argv, and the canonical byte length + SHA-256 of the
    output. This proves the emitted diff is the intended *merge* representation
    (parents present -> history-relative combined diff) and not a shallow-root
    whole-tree dump. Byte-length shrinkage alone is diagnostic, not sufficient; the
    parent list + object count + reproducible SHA-256 are the semantic proof."""
    ge = _git_env(home)

    def _git(*args):
        return subprocess.run(["git", "-C", str(repo_dir), *args],
                              capture_output=True, text=True, env=ge)

    parents_line = _git("rev-list", "--parents", "-n", "1", "HEAD").stdout.strip().split()
    parents = parents_line[1:] if parents_line else []
    commit_type = _git("cat-file", "-t", "HEAD").stdout.strip()
    is_merge = len(parents) >= 2
    # parents must actually be present as objects (depth>=2 guarantees this); if a
    # parent object is missing the tip is treated as a root -> whole-tree diff.
    parents_present = {}
    for p in parents:
        parents_present[p] = _git("cat-file", "-e", p).returncode == 0
    obj_count = _git("rev-list", "--objects", "--all").stdout.count("\n")
    ev = {
        "pinned_commit": commit,
        "head_matches_pin": _git("rev-parse", "HEAD").stdout.strip() == commit,
        "commit_type": commit_type,
        "direct_parents": parents,
        "parent_count": len(parents),
        "is_merge_commit": is_merge,
        "parents_present_as_objects": parents_present,
        "all_parents_present": bool(parents) and all(parents_present.values()),
        "fetch_depth": depth,
        "fetched_object_count": obj_count,
    }
    if sub == "show":
        # exact effective argv + reproducible output identity for the show output
        p = _git(*effective_argv[1:]) if effective_argv and effective_argv[0] == "git" \
            else _git("show")
        out = (p.stdout + p.stderr).encode("utf-8", "replace")
        ev["show_effective_argv"] = effective_argv or ["git", "show"]
        ev["show_output_bytes"] = len(out)
        ev["show_output_sha256"] = hashlib.sha256(out).hexdigest()
        ev["show_exit_code"] = p.returncode
        ev["intended_merge_representation"] = (
            (not is_merge) or ev["all_parents_present"])
    return ev


# ---- network isolation: run a child with no network + a positive denial probe ----
# Two mechanisms, tried in order, so it works both under an unprivileged-userns
# container AND on GitHub-hosted runners (which restrict unprivileged userns but
# grant passwordless sudo):
#   unshare-rn     : unprivileged user+net namespace (child already maps to the
#                    caller's real uid outside the ns -> files stay caller-owned)
#   unshare-n-root : `unshare -n` as root, then DROP back to the caller's uid/gid
#   sudo-unshare-n : `sudo -n unshare -n` (passwordless-sudo netns), then DROP
# The root-based mechanisms MUST drop privileges with setpriv before running the
# workload: otherwise the measured command runs as root over a runner-owned repo,
# which (a) makes git abort with "detected dubious ownership" (exit 128, and the
# message embeds the per-rep tempdir path -> non-deterministic), and (b) leaves
# root-owned build artifacts that break the per-rep TemporaryDirectory cleanup.
_UID, _GID = os.getuid(), os.getgid()
_DROP = ["setpriv", "--reuid", str(_UID), "--regid", str(_GID), "--clear-groups", "--"]
# Bring LOOPBACK up inside the fresh netns before running the workload: `unshare -n`
# creates a namespace whose `lo` is DOWN, so hermetic tests/servers that bind or
# connect to 127.0.0.1/::1 fail spuriously. External network stays denied (the ns
# has no route off-box), which the positive denial probe still confirms. `ip` needs
# CAP_NET_ADMIN, held (real root via sudo, or mapped-root in the userns) BEFORE the
# setpriv drop, so the lo-up runs first, then `exec "$@"` continues to the drop.
_LO = 'ip link set lo up 2>/dev/null || true; exec "$@"'
_ISO_CANDIDATES = [
    ("unshare-rn", ["unshare", "-rn", "--", "sh", "-c", _LO, "sh"]),
    ("unshare-n-root", ["unshare", "-n", "--", "sh", "-c", _LO, "sh"] + _DROP),
    ("sudo-unshare-n", ["sudo", "-n", "unshare", "-n", "--", "sh", "-c", _LO, "sh"] + _DROP),
]


def _env_i(env: dict) -> list[str]:
    return ["env", "-i"] + [f"{k}={v}" for k, v in env.items()]


def resolve_isolation() -> tuple[str, list] | None:
    """Return (method_name, wrapper_prefix) for the first mechanism that both
    starts AND denies outbound network, else None."""
    for name, prefix in _ISO_CANDIDATES:
        try:
            r = subprocess.run(prefix + ["true"], capture_output=True, timeout=20)
            if r.returncode != 0:
                continue
        except Exception:
            continue
        if _probe(prefix)["denied"]:
            return name, prefix
    return None


def _probe(prefix: list) -> dict:
    probe = ("import socket,sys\n"
             "s=socket.socket();s.settimeout(4)\n"
             "try:\n"
             " s.connect(('1.1.1.1',53));print('REACHED');sys.exit(1)\n"
             "except OSError as e:\n"
             " print('DENIED',e.errno);sys.exit(0)\n")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    try:
        r = subprocess.run(prefix + _env_i(env) + [sys.executable, "-c", probe],
                           capture_output=True, text=True, timeout=30)
        return {"denied": r.returncode == 0, "output": (r.stdout or r.stderr).strip()}
    except Exception as e:
        return {"denied": False, "output": f"probe error: {e}"}


def denial_probe(prefix: list) -> dict:
    return _probe(prefix)


def run_isolated(argv, cwd, timeout, wrapper_prefix, env_extra=None):
    """Run argv network-denied via `wrapper_prefix` with an explicit env (env -i),
    so it is robust to sudo env-sanitization. A timeout is a first-class RAW/RTK
    outcome (recorded, exit 124, timed_out=True) -- never an uncaught crash."""
    env = m.measurement_env(env_extra)
    full = wrapper_prefix + _env_i(env) + list(argv)
    try:
        p = subprocess.run(full, cwd=cwd, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        combined = p.stdout + p.stderr
        return {"exit_code": p.returncode, "combined": combined, "timed_out": False}
    except subprocess.TimeoutExpired as e:
        combined = (e.stdout or b"") + (e.stderr or b"")
        return {"exit_code": 124, "combined": combined, "timed_out": True}


def run_arm(argv, frozen_dir: Path, policy_id: str, timeout: int, wrapper_prefix, env_extra=None,
            is_rtk: bool = False, jvm_proof_class: str | None = None) -> dict:
    """RAW or RTK arm: REPS runs in FRESH copies of the frozen env, network-denied.
    Canonicalize each combined stream under policy_id; the ACCEPTED stream is the
    canonical bytes (identical across reps when deterministic). For the RTK arm ONLY,
    the bounded rtk-envelope-v1 policy first normalizes the epoch inside RTK's own
    tee-log envelope line (recorded in the result).

    jvm_proof_class: when set (Gradle cases), each rep's output is checked to PROVE the
    target test task actually executed offline (not UP-TO-DATE / FROM-CACHE / NO-SOURCE
    / SKIPPED). A rep that short-circuited is an offline-execution failure, not a pass;
    because each rep runs against a fresh copy of the frozen env (including a fresh copy
    of the GRADLE_USER_HOME cache seed at _FIXEDWORK/.n2e-gradle-home), no surviving
    task history can make the target task UP-TO-DATE."""
    runs, canon_hashes, raw_hashes, canon_streams = [], [], [], []
    accepted_canonical = None
    timed_out_any = False
    per_rep_proof = []
    # FIXED work path across reps: many tools echo their absolute working directory
    # into output (e.g. vitest's "RUN vX /path"), so a per-rep random tempdir path
    # is itself a source of nondeterminism. Reusing one constant path removes that
    # variance WITHOUT masking any semantic difference (a real diff still differs).
    work = _FIXEDWORK
    try:
        for _ in range(REPS):
            if work.exists():
                shutil.rmtree(work, ignore_errors=True)
            shutil.copytree(frozen_dir, work, symlinks=True)
            r = run_isolated(argv, str(work), timeout, wrapper_prefix, env_extra)
            timed_out_any = timed_out_any or r.get("timed_out", False)
            combined = canon.rtk_envelope(r["combined"]) if is_rtk else r["combined"]
            cb = canon.canonicalize(combined, policy_id)
            runs.append({"exit_code": r["exit_code"],
                         "raw_combined_sha256": hashlib.sha256(r["combined"]).hexdigest(),
                         "canonical_sha256": hashlib.sha256(cb).hexdigest(),
                         "canonical_bytes": len(cb)})
            canon_hashes.append(hashlib.sha256(cb).hexdigest())
            raw_hashes.append(hashlib.sha256(r["combined"]).hexdigest())
            canon_streams.append(cb)
            accepted_canonical = cb  # identical across reps iff deterministic
            if jvm_proof_class:
                # prove THIS rep executed the target class offline (full output, not tail)
                per_rep_proof.append(_gradle_test_proof(
                    r["combined"].decode("utf-8", "replace"), jvm_proof_class))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    exit_stable = len({x["exit_code"] for x in runs}) == 1
    deterministic = len(set(canon_hashes)) == 1
    execution_ok = None
    if jvm_proof_class:
        execution_ok = all(p["executed_ok"] for p in per_rep_proof)
    return {
        "reps_completed": len(runs), "exit_code": runs[0]["exit_code"],
        "exit_code_stable": exit_stable, "canonical_deterministic": deterministic,
        "canonicalization_policy": policy_id, "timed_out": timed_out_any,
        "rtk_envelope_policy": (canon.RTK_ENVELOPE_POLICY_ID if is_rtk else None),
        "canonical_sha256": canon_hashes[0] if deterministic else None,
        "raw_capture_hashes": raw_hashes, "runs": runs,
        "nondeterminism_sample": _nd_sample(canon_streams) if not deterministic else None,
        "per_rep_execution_proof": per_rep_proof or None,
        "target_execution_ok": execution_ok,
        "_accepted_canonical": accepted_canonical if deterministic else None,
        "_output_tail": (canon_streams[-1][-2500:]).decode("utf-8", "replace") if canon_streams else "",
    }


def _nd_sample(streams: list[bytes]) -> str | None:
    """A compact unified diff between the first two DIFFERING canonical streams,
    so a nondeterministic arm reveals EXACTLY what varies across reps (per-rep
    path, ordering, address, ...) -- diagnostic only, never a gate."""
    import difflib
    base = streams[0]
    for other in streams[1:]:
        if other != base:
            a = base.decode("utf-8", "replace").splitlines()
            b = other.decode("utf-8", "replace").splitlines()
            diff = "\n".join(difflib.unified_diff(a, b, "rep0", "repN", lineterm="", n=1))
            return diff[:3000]
    return None


# --------------------------- stratum adapters ---------------------------
def acquire_loghub(scen, workroot):
    ident = scen["source_image_identity"]
    system = ident["key"].removesuffix(".zip")
    checksum, size = ident["checksum"], ident["size"]
    recid = next(z["record_id"] for z in c.load_record(PINS)["zenodo_records"] if z["source_id"] == "loghub-2.0")
    url = f"https://zenodo.org/api/records/{recid}/files/{system}.zip/content"
    with urllib.request.urlopen(urllib.request.Request(url), context=c.ssl_context(), timeout=300) as r:
        data = r.read()
    algo, _, hexv = checksum.partition(":")
    if len(data) != size or hashlib.new(algo, data).hexdigest() != hexv:
        raise SystemExit(f"loghub {system}: checksum/size mismatch")
    (workroot / f"{system}.zip").write_bytes(data)
    z = zipfile.ZipFile(workroot / f"{system}.zip")
    for n in z.namelist():
        if n.startswith("/") or ".." in Path(n).parts:
            raise SystemExit("unsafe archive path")
    z.extractall(workroot / "x")
    logf = next((workroot / "x").rglob("*.log"))
    slice_bytes = b"".join(logf.read_bytes().splitlines(keepends=True)[:1500])
    (workroot / f"{system}.log").write_bytes(slice_bytes)
    shutil.rmtree(workroot / "x")
    (workroot / f"{system}.zip").unlink()
    return {"identity_verified": True, "checksum": checksum,
            "slice_sha256": hashlib.sha256(slice_bytes).hexdigest(),
            "policy": canon.policy_for("logs", "log")}


def _git_fetch_checkout(repo_url, commit, dest, home, depth=2):
    # depth>=2: `git show`/`git log` need the target commit's PARENT(s) present, else
    # git treats the tip as a root commit and `git show` emits the ENTIRE tree as a
    # diff (e.g. a shallow-fetched merge commit -> 12MB instead of its true small
    # combined diff). depth 2 fetches the tip + its parents, yielding representative
    # history-relative output without unshallowing the whole repo.
    subprocess.run(["git", "init", "-q", str(dest)], check=True, env=_git_env(home))
    subprocess.run(["git", "-C", str(dest), "fetch", "-q", "--depth", str(depth), repo_url, commit],
                   check=True, env=_git_env(home))
    subprocess.run(["git", "-C", str(dest), "checkout", "-q", "FETCH_HEAD"], check=True, env=_git_env(home))
    head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                          capture_output=True, text=True, env=_git_env(home)).stdout.strip()
    if head != commit:
        raise SystemExit(f"checkout HEAD {head} != pinned {commit}")


def acquire_git(scen, workroot):
    ident = scen["source_image_identity"]
    repo, commit = ident["repository"], ident["base_commit"]
    home = workroot / ".home"
    home.mkdir()
    repo_dir = workroot / "repo"
    depth = 2
    _git_fetch_checkout(f"https://github.com/{repo}.git", commit, repo_dir, home, depth=depth)
    sub = scen["command_subfamily"]
    applied = _construct_git_state(scen, repo_dir, home)
    git_ev = _git_acquisition_evidence(repo_dir, home, commit, sub, depth,
                                       scen.get("original_argv") or ["git", sub])
    return {"identity_verified": True, "repository": repo, "commit": commit,
            "git_state": applied, "workdir": "repo", "home_local": True,
            "git_acquisition_evidence": git_ev,
            "policy": canon.policy_for("git", sub, git=True)}


def _construct_git_state(scen, repo_dir: Path, home: Path) -> dict:
    """Build the repository-local state each frozen git scenario requires (§6.2)."""
    sub = scen["command_subfamily"]
    ge = _git_env(home)
    info = {"subfamily": sub}
    # deterministic modification for status/diff/add/commit
    if sub in ("status", "diff", "add", "commit"):
        target = repo_dir / "N2E_DIRTY.txt"
        target.write_text("n2e deterministic dirty state\n")
        info["modified"] = ["N2E_DIRTY.txt"]
        if sub in ("add", "commit"):
            subprocess.run(["git", "-C", str(repo_dir), "add", "N2E_DIRTY.txt"], check=True, env=ge)
            info["staged"] = ["N2E_DIRTY.txt"]
    if sub == "push":
        bare = repo_dir.parent / "n2e-local.git"
        subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True, env=ge)
        subprocess.run(["git", "-C", str(repo_dir), "remote", "add", "n2e-local", str(bare)], check=True, env=ge)
        info["bare_remote"] = str(bare)
        pre = subprocess.run(["git", "-C", str(bare), "rev-parse", "HEAD"], capture_output=True, text=True, env=ge)
        info["remote_pre_ref"] = pre.stdout.strip() or None
    return info


def acquire_docker(scen, workroot):
    ident = scen["source_image_identity"]
    ref = f"{ident['repository'].replace('library/', '')}@{ident['child_digest']}"
    subprocess.run(["docker", "pull", ref], check=True, capture_output=True)
    name = scen["case_id"].split("::")[1] if "::" in scen["case_id"] else "n2e"
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", name, ref], check=True, capture_output=True)
    return {"identity_verified": True, "image_digest": ident["child_digest"],
            "container_name": name, "network_denied_note": "docker cases observe host-side docker; container runs with default net but measurement command is docker CLI read-only",
            "policy": canon.policy_for("containers", scen["command_subfamily"])}


def _hf_instance(instance_id, revision):
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
    raise SystemExit(f"instance {instance_id} not found")


def acquire_swebench(scen, workroot):
    ident = scen["source_image_identity"]
    repo, base, instance_id = ident["repository"], ident["base_commit"], ident["instance_id"]
    fam, sub = scen["command_family"], scen["command_subfamily"]
    revision = next(h["revision"] for h in c.load_record(PINS)["hf_datasets"] if h["source_id"] == "swe-bench-multilingual")
    row = _hf_instance(instance_id, revision)
    home = workroot / ".home"
    home.mkdir()
    repo_dir = workroot / "repo"
    _git_fetch_checkout(f"https://github.com/{repo}.git", base, repo_dir, home)
    # frozen-input baseline BEFORE any scenario construction (pristine checkout)
    protected_pristine = _protected_hashes(repo_dir, fam)
    # the declared patches: the GOLD (source/fix) patch is applied only for the ::fixed
    # snapshot; the test_patch always. They are NOT applied here -- for a publisher
    # recipe they are threaded into the ordered acquisition (gold + test AFTER the
    # publisher `--locked` install warms the frozen lockfile), so the publisher install
    # never sees a manifest the gold patch has already mutated.
    gold_blob = (row.get("patch") or "").encode() if scen["snapshot_variant"] == "fixed" else b""
    test_blob = (row.get("test_patch") or "").encode()
    # Publisher-recipe path: if this instance has a curated SWE-bench Multilingual
    # environment recipe, acquire + measure under the EXACT publisher toolchain +
    # scoped test command (never a generic whole-suite command). Record a Phase-A
    # scenario-ingestion defect where the frozen scenario command disagrees with the
    # publisher test command (corrected transparently via the derived contract).
    recipe = pub.recipe_for_case(scen["case_id"])  # EXACT case binding, never by instance
    phase_a_defect = None
    if recipe:
        assert recipe["instance_id"] == instance_id, "recipe/instance binding mismatch"
        warm, policy, offline_env, resolved, env_identity = _publisher_warm(
            recipe, fam, sub, scen, repo_dir, home, gold_blob, test_blob)
        applied = env_identity["acquisition_order"]["applied_patches"]
        pub_argv = pub.parse_command(recipe["test_cmd"][0])
        if list(scen.get("original_argv") or []) != pub_argv:
            phase_a_defect = {
                "typed_defect": "SCENARIO_INGESTION_WRONG_WORKLOAD",
                "frozen_original_argv": scen.get("original_argv"),
                "publisher_test_argv": pub_argv,
                "resolution": "publisher recipe is normative; effective command derived "
                              "from n2e-publisher-env-registry-v1.json, not the frozen argv",
                "publisher_recipe": recipe["source"]["spec_dict"] + "[" + recipe["source"]["spec_key"] + "]",
                "publisher_source": recipe["source"],
            }
    else:
        # No publisher recipe: apply the declared patches up-front (gold before test),
        # then warm generically. Their tracked worktree changes ARE the scenario.
        applied = []
        for name, blob in (("patch", gold_blob), ("test_patch", test_blob)):
            if not blob:
                continue
            pf = workroot / f"{name}.diff"
            pf.write_bytes(blob)
            subprocess.run(["git", "-C", str(repo_dir), "apply", str(pf)], check=True, env=_git_env(home))
            applied.append({name: hashlib.sha256(blob).hexdigest()})
        patch_paths = _worktree_modified(repo_dir, home)
        warm, policy, offline_env, resolved, env_identity = _warm_test_env(
            fam, sub, scen, repo_dir, home, protected_pristine, patch_paths)
    acq = {"identity_verified": True, "repository": repo, "base_commit": base,
           "instance_id": instance_id, "applied_patches": applied, "warm": warm,
           "resolved_raw_argv": resolved.get("raw_argv"), "resolved_rtk_argv": resolved.get("rtk_argv"),
           "jvm_proof_class": resolved.get("jvm_proof_class"),
           "offline_env": offline_env, "environment_identity": env_identity,
           "workdir": "repo", "home_local": True, "policy": policy}
    if recipe:
        acq["publisher_recipe"] = recipe["source"]["spec_dict"] + "[" + recipe["source"]["spec_key"] + "]"
        acq["publisher_case_id"] = recipe["case_id"]
        acq["pristine_checkout_protected"] = protected_pristine
    if phase_a_defect:
        acq["phase_a_scenario_ingestion_defect"] = phase_a_defect
    return acq


def _resolve_interpreter(python_version: str | None) -> str:
    """Resolve the case-PINNED CPython interpreter. CI exposes provisioned versions
    via N2E_PY_INTERPRETERS ({"3.8": "/path/to/python", ...}); otherwise try
    pythonX.Y on PATH, finally python3. The pin is the frozen environment identity
    (e.g. scrapy needs 3.8: inspect.getargspec was removed in 3.11)."""
    if not python_version:
        return "python3"
    mm = ".".join(python_version.split(".")[:2])  # "3.8.3" -> "3.8"
    try:
        table = json.loads(os.environ.get("N2E_PY_INTERPRETERS", "{}"))
    except Exception:  # noqa: BLE001
        table = {}
    if mm in table and Path(table[mm]).exists():
        return table[mm]
    cand = shutil.which(f"python{mm}")
    return cand or "python3"


def acquire_bugsinpy(scen, workroot):
    ident = scen["source_image_identity"]
    repo = ident["repository"]
    commit = ident.get("fixed_commit") if scen["snapshot_variant"] == "fixed" else ident.get("buggy_commit")
    bug = next((b for b in c.load_record(N2E_DIR / "n2e-bugsinpy-bugs-v1.json")["bugs"]
                if f"bugsinpy/{b['project']}" == repo), None)
    if not bug:
        raise SystemExit(f"bug record for {repo} not found")
    gh = bug["github_url"]
    interpreter = _resolve_interpreter(bug.get("python_version"))
    home = workroot / ".home"
    home.mkdir()
    repo_dir = workroot / "repo"
    _git_fetch_checkout(f"{gh}.git", commit, repo_dir, home)
    protected_pristine = _protected_hashes(repo_dir, "python")  # frozen-input baseline
    warm, policy, offline_env, resolved, env_identity = _warm_test_env(
        "python", scen["command_subfamily"], scen, repo_dir, home, protected_pristine, [],
        interpreter=interpreter)
    env_identity["python_version_pin"] = bug.get("python_version")
    return {"identity_verified": True, "repository": repo, "github_url": gh, "commit": commit,
            "warm": warm, "resolved_raw_argv": resolved.get("raw_argv"), "resolved_rtk_argv": resolved.get("rtk_argv"),
            "offline_env": offline_env, "environment_identity": env_identity,
            "workdir": "repo", "home_local": True, "policy": policy}


def _warm_test_env(fam, sub, scen, repo_dir: Path, home: Path,
                   protected_pristine: dict, patch_paths: list, interpreter=None):
    """Populate offline caches during the network-enabled acquisition phase. The
    MEASURED command stays the frozen scenario command (original_argv / explicit_
    rtk_argv); warm only fills dependency caches and `offline_env` enforces the
    network-denied execution of that exact command (identical for RAW and RTK).

    Frozen-input identity (correction #2): the frozen input for a SWE-bench/BugsInPy
    case is `base_commit + the declared patches`. `protected_pristine` is the
    protected-file hash map at the PRISTINE checkout (before any patch); `patch_paths`
    is the tracked worktree change set produced by the declared patches (the
    constructed scenario baseline, NOT a mutation). A protected file that was
    committed and is CHANGED by warm is a real mutation; a lockfile that was ABSENT
    and is GENERATED by warm (e.g. cargo fetch writing Cargo.lock) is deterministic
    dependency resolution, recorded transparently, not a mutation.

    Returns (warm, policy, offline_env, resolved, env_identity). `resolved` overrides
    argv ONLY where the frozen scenario explicitly intends build-system/runner
    resolution:
      - js_ts: rtk_argv_resolution 'test_runner_from_package_json' (explicit RTK
        argv is null) -> resolve runner for BOTH arms + record scheduler profile;
      - jvm:   'test' resolves to the repo's actual build system (gradle|maven).
    Any determinism control (single-thread scheduler) is applied identically to
    both arms and recorded as environment identity -- never filters/skips tests."""
    warm_extra = {"HOME": str(home), "CARGO_HOME": str(home / ".cargo"),
                  "GOFLAGS": "-mod=mod", "GOPATH": str(home / "go"),
                  "npm_config_cache": str(home / ".npm"),
                  "RUSTUP_TOOLCHAIN": os.environ.get("RUSTUP_TOOLCHAIN", "stable")}
    for k in ("JAVA_HOME", "RUSTUP_HOME"):
        if os.environ.get(k):
            warm_extra[k] = os.environ[k]
    env = m.measurement_env(warm_extra)
    warm = {"steps": []}
    venv_bin = None  # set only for python (case-pinned interpreter venv)
    protected_before = _protected_hashes(repo_dir, fam)  # post-construction, pre-warm

    def step(cmd, tmo=1200):
        try:
            r = subprocess.run(cmd, cwd=str(repo_dir), env=env, capture_output=True, timeout=tmo)
            tail = (r.stdout[-1200:] + r.stderr[-1200:]).decode("utf-8", "replace")
            warm["steps"].append({"cmd": cmd, "exit": r.returncode, "tail": tail})
            return r
        except subprocess.TimeoutExpired as e:
            tail = ((e.stdout or b"")[-1200:] + (e.stderr or b"")[-1200:]).decode("utf-8", "replace")
            warm["steps"].append({"cmd": cmd, "exit": None, "timed_out": True, "tail": tail})
            return None

    # WARM = network-enabled cache population ONLY. It NEVER defines the measured
    # command; the effective argv, scheduler, and offline env come from the single
    # normative resolver (n2e_argv_resolver) so they equal the execution contract.
    if fam == "rust_cargo":
        step(["cargo", "fetch"])
    elif fam == "go":
        step(["go", "mod", "download"])
    elif fam == "js_ts":
        pj = repo_dir / "package.json"
        pj_txt = pj.read_text(errors="replace") if pj.exists() else ""
        pnpm = (repo_dir / "pnpm-lock.yaml").exists() or "catalog:" in pj_txt or '"workspace:' in pj_txt
        if pnpm:
            step(["corepack", "pnpm", "install", "--frozen-lockfile"], tmo=1800)
            warm["js_package_manager"] = "pnpm"
        else:
            step(["npm", "ci", "--no-audit", "--no-fund"], tmo=1800)
            warm["js_package_manager"] = "npm"
    elif fam == "jvm":
        if (repo_dir / "pom.xml").exists():
            step(["mvn", "-B", "-DskipTests", "test-compile"], tmo=1800)
        else:
            step(["./gradlew", "testClasses", "--no-daemon", "--console=plain"], tmo=1800)
    elif fam == "python":
        # SWE-bench/BugsInPy tests are version-sensitive (e.g. scrapy calls
        # inspect.getargspec, removed in Python 3.11): run the FROZEN command against
        # the case's PINNED interpreter, not whatever python3 the runner defaults to.
        # A dedicated venv on that interpreter is built online during warm; the frozen
        # `pytest` then resolves to this venv offline (venv bin is prepended to PATH).
        interp = interpreter or "python3"
        venv = repo_dir.parent / ".venv"
        step([interp, "-m", "venv", str(venv)])
        vpy = str(venv / "bin" / "python")
        venv_bin = str(venv / "bin")
        step([vpy, "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"])
        step([vpy, "-m", "pip", "install", "-e", "."], tmo=1800)
        step([vpy, "-m", "pip", "install", "pytest"])
        warm["python_interpreter"] = interp
        warm["venv_bin"] = venv_bin
    else:
        raise SystemExit(f"no warm step for {fam}/{sub}")

    r = resolver.resolve(scen, repo_dir)
    warm["resolution_rule"] = r["resolution_rule"]
    warm["scheduler_flags"] = r.get("scheduler_flags")
    for k in ("package_manager", "runner", "build_system"):
        if r.get(k) is not None:
            warm[k] = r[k]
    policy = canon.policy_for(fam, sub, git=(fam == "git"),
                              jvm_build=r.get("build_system"), case_id=scen["case_id"])
    resolved = {"raw_argv": r["effective_raw_argv"], "rtk_argv": r["effective_rtk_argv"]}
    offline_env = dict(r["scheduler_env"])
    if venv_bin:
        # the frozen `pytest` must resolve to the case-pinned venv, offline
        offline_env["PATH"] = f"{venv_bin}:{os.environ.get('PATH', '/usr/bin:/bin')}"
    warm["ok"] = all(s.get("exit") == 0 for s in warm["steps"])
    protected_after = _protected_hashes(repo_dir, fam)  # AFTER acquisition/warm
    # classify every protected-file delta across acquisition:
    #   committed_mutated: was committed (pristine hash present) and warm CHANGED it
    #                      -> a real mutation of a frozen input;
    #   generated:         was ABSENT at pristine and warm produced it (e.g. cargo
    #                      fetch writing Cargo.lock) -> deterministic resolution.
    committed_mutated = sorted(k for k, h in protected_pristine.items()
                               if h is not None and protected_after.get(k) != h)
    generated = sorted(k for k, h in protected_pristine.items()
                       if h is None and protected_after.get(k) is not None)
    # the constructed baseline = the declared-patch tracked change set; the measured
    # command must not add tracked changes BEYOND this (checked post-measurement).
    baseline_tracked = _worktree_modified(repo_dir, home)
    env_identity = {
        "toolchain": _toolchain_identity(fam, repo_dir, venv_bin=venv_bin),
        "platform": _platform_identity(fam),
        "dependencies": {
            "protected_files": _PROTECTED_FILES.get(fam, []),
            "pristine_checkout": protected_pristine,
            "after_acquisition": protected_after,
            "committed_mutated": committed_mutated,   # real frozen-input mutations
            "generated": generated,                    # benign lockfile generation
            "mutation_guard_ok": committed_mutated == [],
        },
        "construction": {
            "declared_patch_tracked": patch_paths,        # the scenario itself
            "baseline_tracked_status": baseline_tracked,  # patches (+ any warm tracked)
        },
        "warm_commands": [{"cmd": s["cmd"], "exit": s.get("exit")} for s in warm["steps"]],
    }
    return warm, policy, offline_env, resolved, env_identity


# per-language toolchain selectors + offline scheduler env for the publisher path
def _publisher_lang_env(fam: str, home: Path, toolchain: dict) -> tuple[dict, dict]:
    """Return (warm_env_extra, offline_env) for a publisher-recipe language. warm
    env is network-enabled cache population; offline_env enforces the network-denied
    measurement. Both carry the EXACT pinned toolchain selector."""
    warm = {"HOME": str(home)}
    off = {}
    if fam == "rust_cargo":
        ver = toolchain.get("version", "stable")
        if ver.count(".") == 1:  # rustup channel needs the exact patch: 1.83 -> 1.83.0
            ver = ver + ".0"
        tc = {"RUSTUP_TOOLCHAIN": ver, "CARGO_HOME": str(home / ".cargo")}
        if os.environ.get("RUSTUP_HOME"):
            tc["RUSTUP_HOME"] = os.environ["RUSTUP_HOME"]
        warm.update(tc)
        off.update({**tc, "CARGO_NET_OFFLINE": "true",
                    "RUST_TEST_THREADS": "1", "CARGO_BUILD_JOBS": "1"})
    elif fam == "go":
        warm.update({"GOFLAGS": "-mod=mod", "GOPATH": str(home / "go")})
        off.update({"GOFLAGS": "-mod=readonly", "GOPROXY": "off", "GOPATH": str(home / "go")})
    elif fam == "js_ts":
        warm.update({"npm_config_cache": str(home / ".npm")})
        off.update({"CI": "1"})
    elif fam == "jvm":
        for k in ("JAVA_HOME",):
            if os.environ.get(k):
                warm[k] = off[k] = os.environ[k]
    return warm, off


def _gradle_test_proof(text: str, test_class: str) -> dict:
    """Prove a Gradle run actually EXECUTED the declared target test (item 6): the
    test task must have run (not UP-TO-DATE / FROM-CACHE / NO-SOURCE), the class must
    be discovered, and any non-zero must come from the test outcome -- not a Gradle
    start / JDK / dependency-resolution failure."""
    t = text or ""
    task_ran = ":test" in t or "> Task :" in t
    short = test_class.rsplit(".", 1)[-1]
    discovered = (test_class in t) or (short in t)
    skipped = any(m in t for m in (":test UP-TO-DATE", ":test FROM-CACHE", ":test NO-SOURCE",
                                   ":test SKIPPED"))
    gradle_started = ("Welcome to Gradle" in t) or ("> Task" in t) or ("BUILD " in t)
    # a start/JDK/dependency failure is a harness defect, NOT an acceptable prime
    infra_fail = any(m in t for m in ("Could not determine java version",
                                      "Unable to locate a Java Runtime", "command not found",
                                      "Could not resolve all files", "Could not download",
                                      "Plugin [id:", "Could not create service"))
    test_outcome_seen = any(m in t for m in ("There were failing tests", "tests completed",
                                             "BUILD SUCCESSFUL", "BUILD FAILED", "Tests failed:"))
    return {"gradle_started": gradle_started, "target_task_executed": task_ran and not skipped,
            "test_class_discovered": discovered, "skipped_markers": skipped,
            "infra_failure": infra_fail, "test_outcome_seen": test_outcome_seen,
            "target_test_class": test_class,
            "executed_ok": bool(gradle_started and task_ran and not skipped and discovered
                                and not infra_fail and test_outcome_seen)}


def _gradle_target_class(argv: list) -> str | None:
    if "--tests" in argv:
        i = argv.index("--tests")
        if i + 1 < len(argv):
            return argv[i + 1]
    return None


def _sanitize_gradle_seed(seed: Path | None) -> list:
    """Strip everything from a GRADLE_USER_HOME cache seed that would let a measured
    rep SHORT-CIRCUIT (build/output cache) or carry per-run mutable state (daemon,
    journal, locks, worker temp): keep only the reusable dependency + wrapper-dist +
    compiled-script caches. Combined with deleting the project `.gradle` task history,
    this guarantees no UP-TO-DATE / FROM-CACHE result can mask a rep that never
    executed the target class."""
    if not seed or not seed.exists():
        return []
    removed = []
    for rel in ("daemon", "notifications", "kotlin", "kotlin-profile", ".tmp",
                "workers", "caches/journal-1", "caches/build-cache-1"):
        p = seed / rel
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
            removed.append(rel)
    for lk in seed.rglob("*.lock"):
        try:
            lk.unlink()
            removed.append(str(lk.relative_to(seed)))
        except OSError:
            pass
    return removed


ACQ_ORDER_POLICY_ID = "publisher-acquisition-order-v1"


def _publisher_order_sequence(variant: str) -> list:
    """The one faithful gold-evaluation boundary order. The publisher `--locked`
    install warms the FROZEN lockfile on the pristine manifest; only AFTERWARDS is the
    gold (source/fix) patch applied (::fixed), then the test_patch, then measurement."""
    seq = ["base", "pre_install", "install_warm"]
    if variant == "fixed":
        seq.append("gold_patch")
    seq.append("test_patch")
    return seq


def _publisher_warm(recipe: dict, fam: str, sub: str, scen, repo_dir: Path, home: Path,
                    gold_blob: bytes = b"", test_blob: bytes = b""):
    """Acquire a SWE-bench case under its EXACT publisher recipe (source-derived) in the
    faithful gold-evaluation ORDER (correction / item 4):

        base checkout -> publisher pre_install (frozen lockfile heredoc / gradle edit)
        -> publisher install/warm (populate offline cache; rust compiles under `--locked`
           against the FROZEN lockfile, on the PRISTINE manifest)
        -> gold/source patch (::fixed only)
        -> publisher test_patch
        -> measured publisher test_cmd (offline).

    The critical invariant is that the `--locked` install runs BEFORE the gold patch
    mutates the manifest (Cargo.toml) -- applying the gold patch first makes `--locked`
    fail because Cargo.toml no longer matches the frozen Cargo.lock. sha256 + tracked
    worktree state are recorded at every boundary (`acquisition_order`) so the verifier
    can independently enforce the order. Returns the same 5-tuple as _warm_test_env."""
    tc_spec = recipe.get("toolchain") or {}
    spec_label = recipe["source"]["spec_dict"] + "[" + recipe["source"]["spec_key"] + "]"
    warm_extra, offline_env = _publisher_lang_env(fam, home, tc_spec)
    for k in ("JAVA_HOME", "RUSTUP_HOME"):
        if os.environ.get(k) and k not in warm_extra:
            warm_extra[k] = os.environ[k]
    gradle_seed = None
    if fam == "jvm":
        # network-enabled warm populates a GRADLE_USER_HOME cache seed INSIDE the frozen
        # env; run_arm then gives every measured rep a FRESH writable copy of that seed
        # at _FIXEDWORK/.n2e-gradle-home (no shared mutable gradle home across reps).
        gradle_seed = repo_dir / _GRADLE_SEED_DIRNAME
        warm_extra["GRADLE_USER_HOME"] = str(gradle_seed)
        offline_env["GRADLE_USER_HOME"] = str(_FIXEDWORK / _GRADLE_SEED_DIRNAME)
    env = m.measurement_env(warm_extra)
    warm = {"steps": [], "publisher_recipe": spec_label, "instance_id": recipe["instance_id"]}
    ge = _git_env(home)

    def run(argv, extra_env=None, tmo=1800, kind="step"):
        try:
            r = subprocess.run(argv, cwd=str(repo_dir), env={**env, **(extra_env or {})},
                               capture_output=True, timeout=tmo)
            warm["steps"].append({"kind": kind, "cmd": argv, "exit": r.returncode,
                                  "tail": (r.stdout[-1200:] + r.stderr[-1200:]).decode("utf-8", "replace")})
            return r
        except subprocess.TimeoutExpired as e:
            warm["steps"].append({"kind": kind, "cmd": argv, "exit": None, "timed_out": True,
                                  "tail": ((e.stdout or b"")[-900:] + (e.stderr or b"")[-900:]).decode("utf-8", "replace")})
            return None

    def _git(*args):
        return subprocess.run(["git", "-C", str(repo_dir), *args],
                              capture_output=True, text=True, env=ge)

    def boundary(label, **extra):
        diff = _git("diff", "HEAD").stdout.encode("utf-8", "replace")
        status = [ln for ln in _git("status", "--porcelain", "--untracked-files=no").stdout.splitlines()
                  if ln.strip()]
        return {"label": label, "protected": _protected_hashes(repo_dir, fam),
                "worktree_diff_sha256": hashlib.sha256(diff).hexdigest(),
                "worktree_diff_bytes": len(diff), "tracked_status": status, **extra}

    def apply_patch(name, blob):
        pf = home.parent / f"{name}.diff"
        pf.write_bytes(blob)
        r = _git("apply", str(pf))
        return {"name": name, "sha256": hashlib.sha256(blob).hexdigest(),
                "apply_exit": r.returncode, "apply_stderr": (r.stderr or "")[-400:]}

    seed_pol = xctl.policy_for_case(scen["case_id"])
    seed_extra = [seed_pol["arg"]] if seed_pol else []
    gradle_extra = xctl.gradle_offline_args() if fam == "jvm" else []
    gradle_extra_online = [a for a in gradle_extra if a != "--offline"]  # warm must fetch
    if seed_pol:
        warm["execution_control"] = seed_pol
    if fam == "jvm":
        warm["gradle_offline_policy"] = xctl.gradle_offline_policy()

    boundaries = [boundary("base")]

    # ---- (1) pre_install: publisher frozen construction on the PRISTINE tree ----
    for cmd in recipe.get("pre_install", []):
        run(["bash", "-c", cmd], tmo=300, kind="pre_install")
    boundaries.append(boundary("pre_install"))
    protected_pre_install = _protected_hashes(repo_dir, fam)

    # ---- (2) install / warm: populate the offline cache; rust compiles `--locked`
    #          against the FROZEN lockfile, BEFORE any patch mutates the manifest ----
    install_steps, locked_seen = [], False
    for cmd in recipe.get("install", []):
        wenv, wargv = pub.split_env(cmd)
        wargv_eff = [*wargv, *gradle_extra_online] if fam == "jvm" else wargv
        r = run(wargv_eff, extra_env=wenv, kind="install")
        locked_seen = locked_seen or ("--locked" in wargv)
        install_steps.append({"cmd": wargv, "effective_cmd": wargv_eff,
                              "locked": "--locked" in wargv,
                              "exit": (r.returncode if r is not None else None)})
    boundaries.append(boundary("install_warm"))
    protected_after_install = boundaries[-1]["protected"]

    # measured argv (offline) vs warm argv (online population, no --offline)
    test_env, test_argv_base = pub.split_env(recipe["test_cmd"][0])
    measured_argv = [*test_argv_base, *seed_extra, *gradle_extra]
    warm_test_argv = [*test_argv_base, *seed_extra, *gradle_extra_online]

    # ---- (3) gold/source patch, ::fixed only, AFTER the locked install ----
    applied_patches = []
    if scen["snapshot_variant"] == "fixed":
        if gold_blob:
            applied_patches.append(apply_patch("patch", gold_blob))
        boundaries.append(boundary("gold_patch", applied=bool(gold_blob),
                                   patch_sha256=hashlib.sha256(gold_blob).hexdigest() if gold_blob else None))

    # ---- (4) test_patch AFTER the gold patch ----
    if test_blob:
        applied_patches.append(apply_patch("test_patch", test_blob))
    boundaries.append(boundary("test_patch", applied=bool(test_blob),
                               patch_sha256=hashlib.sha256(test_blob).hexdigest() if test_blob else None))

    # ---- (5) jvm no-install: warm-prime (online) the NOW-PATCHED target test to compile
    #          + populate the cache; then sanitize the seed + strip project task history
    #          so each measured rep re-executes offline (item 5 / item 6) ----
    jvm_prime_proof = None
    target_class = _gradle_target_class(measured_argv) if fam == "jvm" else None
    if fam == "jvm":
        if not recipe.get("install"):
            run(warm_test_argv, extra_env=test_env, kind="warm_prime")
            prime = next((s for s in warm["steps"] if s.get("kind") == "warm_prime"), None)
            if prime and target_class:
                jvm_prime_proof = _gradle_test_proof(prime.get("tail", ""), target_class)
                warm["jvm_prime_proof"] = jvm_prime_proof
        removed = _sanitize_gradle_seed(gradle_seed)
        for rel in (".gradle", "build/test-results", "build/reports"):
            shutil.rmtree(repo_dir / rel, ignore_errors=True)
        warm["jvm_rerun_cleanup"] = [".gradle", "build/test-results", "build/reports"]
        warm["gradle_seed_sanitized_removed"] = removed
        warm["jvm_target_class"] = target_class

    # warm success = pre_install + dependency population + patch application succeeded.
    # A `warm_prime` RUNS the target test only to compile/populate caches; for ::buggy
    # that test legitimately exits non-zero, so its exit is informational -- but (item 6)
    # it must have actually EXECUTED the target test. A patch that fails to apply, an
    # install non-zero exit, or any timeout is a warm failure.
    warm["ok"] = (all(s.get("exit") == 0 for s in warm["steps"] if s.get("kind") not in ("warm_prime",))
                  and not any(s.get("timed_out") for s in warm["steps"])
                  and all(p.get("apply_exit") == 0 for p in applied_patches)
                  and (jvm_prime_proof is None or jvm_prime_proof["executed_ok"]))

    policy = canon.policy_for(fam, sub, jvm_build=("gradle" if fam == "jvm" else None),
                              case_id=scen["case_id"])
    resolved = {"raw_argv": measured_argv, "rtk_argv": ["rtk", *measured_argv],
                "jvm_proof_class": target_class}
    offline_env = {**offline_env, **test_env}  # publisher test env (e.g. RUSTFLAGS) on both arms

    # committed-input mutation guard, isolated to the WARM/install step: a COMMITTED
    # protected manifest that the install step changed between pre_install and
    # install_warm is a real mutation. The declared gold/test patches (applied AFTER
    # install_warm) legitimately change tracked inputs -- they ARE the scenario -- so
    # they are excluded from this guard.
    committed_mutated = sorted(k for k, h in protected_pre_install.items()
                               if h is not None and protected_after_install.get(k) != h)
    protected_after = _protected_hashes(repo_dir, fam)  # final frozen input (post-patches)
    rust_channel = (tc_spec.get("version", "") + ".0") if (fam == "rust_cargo"
                    and tc_spec.get("version", "").count(".") == 1) else tc_spec.get("version")
    acquisition_order = {
        "policy_id": ACQ_ORDER_POLICY_ID,
        "snapshot_variant": scen["snapshot_variant"],
        "canonical_sequence": _publisher_order_sequence(scen["snapshot_variant"]),
        "boundaries": boundaries,
        "install": {"ran": bool(recipe.get("install")), "locked": locked_seen, "steps": install_steps},
        "applied_patches": applied_patches,
        "gold_applied": bool(gold_blob) and scen["snapshot_variant"] == "fixed",
        "test_applied": bool(test_blob),
        "invariant": "publisher --locked install runs on the pristine manifest; the gold "
                     "patch is applied only afterwards, then the test_patch, then measured.",
    }
    env_identity = {
        "toolchain": _toolchain_identity(fam, repo_dir, rust_channel=rust_channel),
        "toolchain_pin": tc_spec,
        "platform": _platform_identity(fam),
        "acquisition_order": acquisition_order,
        "dependencies": {
            "protected_files": _PROTECTED_FILES.get(fam, []),
            "pristine_pre_install": protected_pre_install,
            "after_install_warm": protected_after_install,
            "after_acquisition": protected_after,
            "committed_mutated": committed_mutated,
            "mutation_guard_ok": committed_mutated == [],
        },
        "construction": {
            "publisher_recipe": spec_label,
            "pre_install": recipe.get("pre_install"),
            "baseline_tracked_status": _worktree_modified(repo_dir, home),
        },
        "publisher": {"recipe_spec": spec_label, "case_id": recipe["case_id"],
                      "test_cmd": recipe["test_cmd"], "install": recipe.get("install"),
                      "toolchain": tc_spec, "source": recipe["source"],
                      "registry_sha256": pub.registry_sha256()},
        "warm_commands": [{"kind": s.get("kind"), "cmd": s.get("cmd"), "exit": s.get("exit")}
                          for s in warm["steps"]],
    }
    return warm, policy, offline_env, resolved, env_identity


ADAPTERS = {"logs": acquire_loghub, "git": acquire_git, "files_search": acquire_git,
            "containers": acquire_docker, "rust_cargo": acquire_swebench, "go": acquire_swebench,
            "jvm": acquire_swebench, "js_ts": acquire_swebench, "python": acquire_bugsinpy}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("case_id")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    rtk_bin, qodec_bin = os.environ["RTK_BIN"], os.environ["QODEC_BIN"]
    out = Path(args.out)

    scen = next(s for s in c.load_record(SCEN)["scenarios"] if s["case_id"] == args.case_id)
    if args.case_id not in {m0["case_id"] for m0 in c.load_record(CANARY)["membership"]}:
        raise SystemExit(f"{args.case_id} not in frozen canary membership")
    fam, sub = scen["command_family"], scen["command_subfamily"]

    def emit(status, **kw):
        rec = c.envelope(record_type="n2e-canary-case", generated_by="tools/run_canary_case.py",
                         case_id=args.case_id, command_family=fam, command_subfamily=sub,
                         status=status, rtk_binary_sha256=c.sha256_file(rtk_bin), **kw)
        c.write_record(out, rec)
        return rec

    # rtk binary identity gate
    if c.sha256_file(rtk_bin) != RTK_BINARY_SHA256:
        emit("REJECTED_RTK_IDENTITY", reason="RTK_BIN sha256 != pinned")
        return 2
    # network isolation: required for all families EXCEPT containers (host-side
    # read-only docker observation, §6.9). Resolve the mechanism + positive probe.
    if fam == "containers":
        iso = {"method": "host_side_docker_observation", "host_side_observation": True,
               "denial_probe": {"denied": None, "note": "not applicable: host-side docker CLI read-only"}}
        wrapper = None
    else:
        resolved = resolve_isolation()
        if resolved is None:
            emit("REJECTED_NO_ISOLATION",
                 reason="no working network-denied mechanism (unshare -rn / unshare -n / sudo unshare -n)")
            return 2
        method, wrapper = resolved
        probe = denial_probe(wrapper)
        if not probe["denied"]:
            emit("REJECTED_ISOLATION_LEAK", isolation={"method": method, "denial_probe": probe})
            return 2
        iso = {"method": method, "denial_probe": probe}

    workroot = Path(tempfile.mkdtemp(prefix="n2e-case-"))
    try:
        acq = ADAPTERS[fam](scen, workroot)
        if not acq.get("identity_verified"):
            emit("REJECTED_ACQUISITION", acquisition=acq)
            return 2
        # Fail closed BEFORE measuring if offline dep-population failed: an offline
        # build/test over an unpopulated cache can never show the declared outcome,
        # so reject explicitly (with the warm diagnostic tail) instead of emitting a
        # confusing downstream oracle failure.
        warm = acq.get("warm")
        if warm is not None and not warm.get("ok", True):
            emit("REJECTED_WARM", acquisition=acq, isolation=iso,
                 rejection_reasons=["offline dependency preparation (warm) failed"])
            return 1
        # protected-file mutation guard (acquisition): a COMMITTED frozen dependency/
        # build input that warm CHANGED is a typed harness rejection even on success.
        # (Benign lockfile GENERATION of a previously-absent file is not a mutation --
        # it is recorded under dependencies.generated, never rejected here. The
        # declared SWE-bench patches are the scenario baseline, not a mutation.)
        env_id = acq.get("environment_identity") or {}
        deps = env_id.get("dependencies") or {}
        if deps and deps.get("mutation_guard_ok") is False:
            emit("REJECTED_MUTATION", acquisition=acq, isolation=iso,
                 rejection_reasons=[f"committed protected input(s) mutated during warm: "
                                    f"{deps.get('committed_mutated')}"])
            return 1
        policy = acq["policy"]
        frozen = workroot / acq.get("workdir", ".")
        raw_argv = acq.get("resolved_raw_argv") or scen["original_argv"]
        rtk_argv = acq.get("resolved_rtk_argv") or scen["explicit_rtk_argv"]
        env_extra = {"HOME": str(workroot / ".home")} if acq.get("home_local") else None
        if fam in ("rust_cargo", "go", "jvm", "js_ts", "python"):
            # the offline measurement runs under `env -i`; forward the toolchain
            # selectors resolved during warm plus the per-family offline/determinism
            # env so the FROZEN command runs network-denied and reproducibly. This
            # env is identical for the RAW and RTK arms (§ identical execution).
            tc = {"RUSTUP_TOOLCHAIN": os.environ.get("RUSTUP_TOOLCHAIN", "stable"),
                  "GOFLAGS": "-mod=mod",
                  "CARGO_HOME": str(workroot / ".home" / ".cargo"),
                  "GOPATH": str(workroot / ".home" / "go")}
            for k in ("JAVA_HOME", "RUSTUP_HOME"):
                if os.environ.get(k):
                    tc[k] = os.environ[k]
            tc.update(acq.get("offline_env") or {})
            env_extra = {**(env_extra or {}), **tc}
        if fam in ("git", "files_search"):
            # git needs a repository-local, fixed identity in the measurement env
            env_extra = {**(env_extra or {}),
                         "GIT_AUTHOR_NAME": "n2e", "GIT_AUTHOR_EMAIL": "n2e@local",
                         "GIT_COMMITTER_NAME": "n2e", "GIT_COMMITTER_EMAIL": "n2e@local",
                         "GIT_AUTHOR_DATE": "2026-07-17T00:00:00+0000",
                         "GIT_COMMITTER_DATE": "2026-07-17T00:00:00+0000",
                         "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
                         "GIT_PAGER": "cat", "PAGER": "cat"}
        # docker cases observe host state: not run inside a netns copy
        if fam == "containers":
            raw = _docker_arm(scen["original_argv"], policy, scen["timeout_seconds"])
            rtk_run = None
        else:
            raw = run_arm(raw_argv, frozen, policy, scen["timeout_seconds"], wrapper, env_extra,
                          jvm_proof_class=acq.get("jvm_proof_class"))
            rtk_run = None

        # ---- RAW acceptance gate ----
        raw_ok, raw_reasons, raw_oracle = _raw_accept(scen, raw, acq, iso)
        if not raw_ok:
            emit("RAW_REJECTED", acquisition=acq, isolation=iso,
                 raw_arm=_arm_public(raw), raw_semantic_oracle=raw_oracle,
                 raw_output_tail=raw.get("_output_tail"), raw_argv=raw_argv,
                 rejection_reasons=raw_reasons)
            return 1

        # ---- RTK arm (only after RAW passes) ----
        if rtk_argv is None:
            emit("RTK_REJECTED", acquisition=acq, isolation=iso, raw_arm=_arm_public(raw),
                 rejection_reasons=["no explicit RTK argv resolved"])
            return 1
        if fam == "containers":
            rtk_run = _docker_arm([rtk_bin] + rtk_argv[1:], policy, scen["timeout_seconds"])
        else:
            rtk_run = run_arm([rtk_bin] + rtk_argv[1:], frozen, policy, scen["timeout_seconds"],
                              wrapper, env_extra, is_rtk=True, jvm_proof_class=acq.get("jvm_proof_class"))

        rtk_ok, rtk_reasons, rtk_oracle = _rtk_accept(scen, raw, rtk_run, rtk_bin)
        # post-measurement mutation guard (the real correction #2 invariant): after
        # both arms have run against the constructed frozen input, no COMMITTED
        # protected file may have changed, and the tracked worktree may not have
        # drifted BEYOND the declared-patch baseline. A measured command that mutates
        # a frozen tracked input is a typed harness rejection even on a green oracle.
        if fam not in ("containers", "git", "files_search", "logs"):
            post = _post_measurement_state(frozen, workroot / ".home", fam, env_id)
            if not post["ok"]:
                emit("REJECTED_MUTATION", acquisition=acq, isolation=iso,
                     raw_arm=_arm_public(raw), rtk_arm=_arm_public(rtk_run),
                     post_measurement=post, rejection_reasons=post["reasons"])
                return 1
        raw_tokens = m.o200k_tokens(raw["_accepted_canonical"], qodec_bin)
        rtk_tokens = m.o200k_tokens(rtk_run["_accepted_canonical"], qodec_bin) if rtk_run.get("_accepted_canonical") is not None else None
        savings = round(100 * (raw_tokens - rtk_tokens) / raw_tokens, 2) if (rtk_tokens and raw_tokens) else None

        status = "PASS" if (raw_ok and rtk_ok) else "RTK_REJECTED"
        emit(status, acquisition=acq, isolation=iso,
             canonicalization_policy=policy,
             raw_arm={**_arm_public(raw), "o200k_tokens": raw_tokens},
             rtk_arm={**_arm_public(rtk_run), "o200k_tokens": rtk_tokens},
             raw_semantic_oracle=raw_oracle, rtk_semantic_oracle=rtk_oracle,
             rtk_savings_pct_reporting_only=savings, rejection_reasons=rtk_reasons or None,
             acceptance_note="RTK savings reporting-only; never a gate (§15/§19).")
        print(f"{args.case_id}: {status} raw={raw_tokens} rtk={rtk_tokens} savings={savings}")
        return 0 if status == "PASS" else 1
    except Exception as e:  # noqa: BLE001 -- fail closed WITH a record, never crash recordless
        import traceback
        emit("REJECTED_ERROR", isolation=iso,
             rejection_reasons=[f"unhandled measurement error: {type(e).__name__}: {e}"],
             error_traceback=traceback.format_exc()[-2000:])
        return 1
    finally:
        shutil.rmtree(workroot, ignore_errors=True)
        if fam == "containers":
            name = args.case_id.split("::")[1]
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def _docker_arm(argv, policy, timeout):
    """Docker read-only CLI observation (host-side). Not netns-isolated (§6.9)."""
    runs, canon_hashes, raw_hashes = [], [], []
    accepted = None
    for _ in range(REPS):
        p = subprocess.run(argv, env=m.measurement_env(), stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        cb = canon.canonicalize(p.stdout + p.stderr, policy)
        runs.append({"exit_code": p.returncode,
                     "raw_combined_sha256": hashlib.sha256(p.stdout + p.stderr).hexdigest(),
                     "canonical_sha256": hashlib.sha256(cb).hexdigest(), "canonical_bytes": len(cb)})
        canon_hashes.append(hashlib.sha256(cb).hexdigest())
        raw_hashes.append(hashlib.sha256(p.stdout + p.stderr).hexdigest())
        accepted = cb
    det = len(set(canon_hashes)) == 1
    return {"reps_completed": REPS, "exit_code": runs[0]["exit_code"],
            "exit_code_stable": len({x["exit_code"] for x in runs}) == 1,
            "canonical_deterministic": det, "canonicalization_policy": policy,
            "canonical_sha256": canon_hashes[0] if det else None,
            "raw_capture_hashes": raw_hashes, "runs": runs,
            "_accepted_canonical": accepted if det else None}


def _arm_public(arm):
    return {k: v for k, v in arm.items() if not k.startswith("_")}


def _raw_accept(scen, raw, acq, iso):
    reasons = []
    if raw["reps_completed"] != REPS:
        reasons.append("raw reps != 3")
    if raw.get("timed_out"):
        reasons.append("raw command timed out")
    if not raw["exit_code_stable"]:
        reasons.append("raw exit unstable")
    if not raw["canonical_deterministic"]:
        reasons.append("raw not canonically deterministic")
    if raw.get("target_execution_ok") is False:
        reasons.append("gradle target test task did not execute offline in every raw rep "
                       "(UP-TO-DATE / FROM-CACHE / NO-SOURCE / SKIPPED or infra failure)")
    if not acq.get("identity_verified"):
        reasons.append("acquisition identity unverified")
    if iso.get("host_side_observation"):
        pass  # containers: host-side read-only docker observation (§6.9), no netns
    elif not (iso.get("denial_probe") or {}).get("denied"):
        reasons.append("network denial probe failed")
    oracle = ora.raw_outcome(scen, raw["_accepted_canonical"] or b"", raw["exit_code"])
    if oracle.get("verdict") is not True:
        reasons.append(f"raw oracle failed: {oracle.get('oracle')}")
    return (len(reasons) == 0, reasons, oracle)


def _rtk_accept(scen, raw, rtk, rtk_bin):
    reasons = []
    if rtk["reps_completed"] != REPS:
        reasons.append("rtk reps != 3")
    if rtk.get("timed_out"):
        reasons.append("rtk command timed out")
    if not rtk["exit_code_stable"]:
        reasons.append("rtk exit unstable")
    if not rtk["canonical_deterministic"]:
        reasons.append("rtk not canonically deterministic")
    if rtk.get("target_execution_ok") is False:
        reasons.append("gradle target test task did not execute offline in every rtk rep "
                       "(UP-TO-DATE / FROM-CACHE / NO-SOURCE / SKIPPED or infra failure)")
    if c.sha256_file(rtk_bin) != RTK_BINARY_SHA256:
        reasons.append("rtk binary identity")
    oracle = ora.rtk_agrees(scen, raw["_accepted_canonical"] or b"", rtk.get("_accepted_canonical") or b"")
    if oracle.get("verdict") is not True:
        reasons.append(f"rtk oracle disagreement: {oracle.get('oracle')}")
    return (len(reasons) == 0, reasons, oracle)


if __name__ == "__main__":
    raise SystemExit(main())
