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

SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
CANARY = N2E_DIR / "n2e-canary-membership-v1.json"
PINS = N2E_DIR / "n2e-source-pins-v1.json"
RTK_BINARY_SHA256 = "41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf"
REPS = 3


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
_ISO_CANDIDATES = [
    ("unshare-rn", ["unshare", "-rn", "--"]),
    ("unshare-n-root", ["unshare", "-n", "--"] + _DROP),
    ("sudo-unshare-n", ["sudo", "-n", "unshare", "-n", "--"] + _DROP),
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


def run_arm(argv, frozen_dir: Path, policy_id: str, timeout: int, wrapper_prefix, env_extra=None) -> dict:
    """RAW or RTK arm: REPS runs in FRESH copies of the frozen env, network-denied.
    Canonicalize each combined stream under policy_id; the ACCEPTED stream is the
    canonical bytes (identical across reps when deterministic)."""
    runs, canon_hashes, raw_hashes = [], [], []
    accepted_canonical = None
    timed_out_any = False
    for _ in range(REPS):
        with tempfile.TemporaryDirectory(prefix="n2e-rep-") as td:
            work = Path(td) / "w"
            shutil.copytree(frozen_dir, work, symlinks=True)
            r = run_isolated(argv, str(work), timeout, wrapper_prefix, env_extra)
        timed_out_any = timed_out_any or r.get("timed_out", False)
        cb = canon.canonicalize(r["combined"], policy_id)
        runs.append({"exit_code": r["exit_code"],
                     "raw_combined_sha256": hashlib.sha256(r["combined"]).hexdigest(),
                     "canonical_sha256": hashlib.sha256(cb).hexdigest(),
                     "canonical_bytes": len(cb)})
        canon_hashes.append(hashlib.sha256(cb).hexdigest())
        raw_hashes.append(hashlib.sha256(r["combined"]).hexdigest())
        accepted_canonical = cb  # identical across reps iff deterministic
    exit_stable = len({x["exit_code"] for x in runs}) == 1
    deterministic = len(set(canon_hashes)) == 1
    return {
        "reps_completed": len(runs), "exit_code": runs[0]["exit_code"],
        "exit_code_stable": exit_stable, "canonical_deterministic": deterministic,
        "canonicalization_policy": policy_id, "timed_out": timed_out_any,
        "canonical_sha256": canon_hashes[0] if deterministic else None,
        "raw_capture_hashes": raw_hashes, "runs": runs,
        "_accepted_canonical": accepted_canonical if deterministic else None,
    }


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


def _git_fetch_checkout(repo_url, commit, dest, home):
    subprocess.run(["git", "init", "-q", str(dest)], check=True, env=_git_env(home))
    subprocess.run(["git", "-C", str(dest), "fetch", "-q", "--depth", "1", repo_url, commit],
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
    _git_fetch_checkout(f"https://github.com/{repo}.git", commit, repo_dir, home)
    sub = scen["command_subfamily"]
    applied = _construct_git_state(scen, repo_dir, home)
    return {"identity_verified": True, "repository": repo, "commit": commit,
            "git_state": applied, "workdir": "repo", "home_local": True,
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
    applied = []
    for name, key in (("test_patch", "test_patch"), ("patch", "patch")):
        if name == "patch" and scen["snapshot_variant"] != "fixed":
            continue
        blob = (row.get(key) or "").encode()
        if not blob:
            continue
        pf = workroot / f"{name}.diff"
        pf.write_bytes(blob)
        subprocess.run(["git", "-C", str(repo_dir), "apply", str(pf)], check=True, env=_git_env(home))
        applied.append({name: hashlib.sha256(blob).hexdigest()})
    warm, raw_argv, rtk_argv, policy = _warm_test_env(fam, sub, scen, repo_dir, home)
    return {"identity_verified": True, "repository": repo, "base_commit": base,
            "instance_id": instance_id, "applied_patches": applied, "warm": warm,
            "resolved_raw_argv": raw_argv, "resolved_rtk_argv": rtk_argv,
            "workdir": "repo", "home_local": True, "policy": policy}


def acquire_bugsinpy(scen, workroot):
    ident = scen["source_image_identity"]
    repo = ident["repository"]
    commit = ident.get("fixed_commit") if scen["snapshot_variant"] == "fixed" else ident.get("buggy_commit")
    gh = next((b["github_url"] for b in c.load_record(N2E_DIR / "n2e-bugsinpy-bugs-v1.json")["bugs"]
               if f"bugsinpy/{b['project']}" == repo), None)
    if not gh:
        raise SystemExit(f"github_url for {repo} not found")
    home = workroot / ".home"
    home.mkdir()
    repo_dir = workroot / "repo"
    _git_fetch_checkout(f"{gh}.git", commit, repo_dir, home)
    warm, raw_argv, rtk_argv, policy = _warm_test_env("python", scen["command_subfamily"], scen, repo_dir, home)
    return {"identity_verified": True, "repository": repo, "github_url": gh, "commit": commit,
            "warm": warm, "resolved_raw_argv": raw_argv, "resolved_rtk_argv": rtk_argv,
            "workdir": "repo", "home_local": True, "policy": policy}


def _warm_test_env(fam, sub, scen, repo_dir: Path, home: Path):
    """Install deps + prebuild during the network-enabled acquisition phase so
    the measurement runs offline. Returns (warm_evidence, raw_argv, rtk_argv, policy)."""
    env = m.measurement_env({"HOME": str(home), "CARGO_HOME": str(home / ".cargo"),
                             "GOFLAGS": "-mod=mod", "GOPATH": str(home / "go"),
                             "npm_config_cache": str(home / ".npm")})
    warm = {"steps": []}

    def step(cmd, tmo=1200):
        """Run a network-enabled warm step; ALWAYS record a diagnostic output tail
        and never crash (a timeout is recorded, not raised)."""
        try:
            r = subprocess.run(cmd, cwd=str(repo_dir), env=env, capture_output=True, timeout=tmo)
            tail = (r.stdout[-1200:] + r.stderr[-1200:]).decode("utf-8", "replace")
            warm["steps"].append({"cmd": cmd, "exit": r.returncode, "tail": tail})
            return r
        except subprocess.TimeoutExpired as e:
            tail = ((e.stdout or b"")[-1200:] + (e.stderr or b"")[-1200:]).decode("utf-8", "replace")
            warm["steps"].append({"cmd": cmd, "exit": None, "timed_out": True, "tail": tail})
            return None

    if fam == "rust_cargo":
        step(["cargo", "fetch"])
        raw = {"test": ["cargo", "test", "--offline"], "build": ["cargo", "build", "--offline"],
               "check": ["cargo", "check", "--offline"], "clippy": ["cargo", "clippy", "--offline"]}[sub]
        rtk = ["rtk"] + raw[:-1]  # rtk cargo <sub> (drop --offline for the wrapper; cargo still offline via CARGO_NET_OFFLINE)
        policy = canon.policy_for("rust_cargo", sub)
    elif fam == "go":
        step(["go", "mod", "download"])
        raw = {"test": ["go", "test", "./..."], "build": ["go", "build", "./..."],
               "vet": ["go", "vet", "./..."]}[sub]
        rtk = ["rtk", "go"] + raw[1:]
        policy = canon.policy_for("go", sub)
    elif fam == "js_ts":
        step(["npm", "install", "--no-audit", "--no-fund"], tmo=1800)
        runner = "vitest"
        pj = repo_dir / "package.json"
        if pj.exists():
            txt = pj.read_text(errors="replace")
            runner = "jest" if '"jest"' in txt and "vitest" not in txt else ("vitest" if "vitest" in txt else "jest")
        if sub == "test":
            raw, rtk = ["npx", runner, "run"], ["rtk", runner]
        elif sub == "tsc":
            raw, rtk = ["npx", "tsc", "--noEmit"], ["rtk", "tsc"]
        else:
            raw, rtk = ["npx", "eslint", "."], ["rtk", "lint", "."]
        policy = canon.policy_for("js_ts", sub)
        warm["js_test_runner"] = runner
    elif fam == "jvm":
        build_sys = "maven" if (repo_dir / "pom.xml").exists() else "gradle"
        if build_sys == "gradle":
            raw, rtk = ["./gradlew", "test", "--offline"], ["rtk", "gradlew", "test"]
        else:
            raw, rtk = ["mvn", "-o", "test"], ["rtk", "mvn", "test"]
        step(raw[:1] + (["dependencies"] if build_sys == "maven" else ["dependencies", "--refresh-dependencies"]), tmo=1800)
        policy = canon.policy_for("jvm", sub, jvm_build=build_sys)
        warm["jvm_build_system"] = build_sys
    elif fam == "python":
        step(["python3", "-m", "pip", "install", "-e", "."], tmo=1800)
        step(["python3", "-m", "pip", "install", "pytest", "ruff"])
        raw = {"pytest": ["python3", "-m", "pytest", "-q"], "ruff": ["ruff", "check", "."]}[sub]
        rtk = ["rtk", "pytest"] if sub == "pytest" else ["rtk", "ruff", "check", "."]
        policy = canon.policy_for("python", sub)
    else:
        raise SystemExit(f"no warm step for {fam}/{sub}")
    # Offline measurement is only meaningful if every dep-population step succeeded.
    warm["ok"] = all(s.get("exit") == 0 for s in warm["steps"])
    return warm, raw, rtk, policy


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
        policy = acq["policy"]
        frozen = workroot / acq.get("workdir", ".")
        raw_argv = acq.get("resolved_raw_argv") or scen["original_argv"]
        rtk_argv = acq.get("resolved_rtk_argv") or scen["explicit_rtk_argv"]
        env_extra = {"HOME": str(workroot / ".home")} if acq.get("home_local") else None
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
            raw = run_arm(raw_argv, frozen, policy, scen["timeout_seconds"], wrapper, env_extra)
            rtk_run = None

        # ---- RAW acceptance gate ----
        raw_ok, raw_reasons, raw_oracle = _raw_accept(scen, raw, acq, iso)
        if not raw_ok:
            emit("RAW_REJECTED", acquisition=acq, isolation=iso,
                 raw_arm=_arm_public(raw), raw_semantic_oracle=raw_oracle,
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
            rtk_run = run_arm([rtk_bin] + rtk_argv[1:], frozen, policy, scen["timeout_seconds"], wrapper, env_extra)

        rtk_ok, rtk_reasons, rtk_oracle = _rtk_accept(scen, raw, rtk_run, rtk_bin)
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
    if c.sha256_file(rtk_bin) != RTK_BINARY_SHA256:
        reasons.append("rtk binary identity")
    oracle = ora.rtk_agrees(scen, raw["_accepted_canonical"] or b"", rtk.get("_accepted_canonical") or b"")
    if oracle.get("verdict") is not True:
        reasons.append(f"rtk oracle disagreement: {oracle.get('oracle')}")
    return (len(reasons) == 0, reasons, oracle)


if __name__ == "__main__":
    raise SystemExit(main())
