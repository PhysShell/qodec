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
import re
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
import n2e_cargo_index_cache as cic  # noqa: E402
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
# env keys that are legitimately per-run path-specific (compared for presence, not value,
# and excluded from the RAW-vs-RTK semantic-equality comparison)
_ENV_PATH_KEYS = {"HOME", "CARGO_HOME", "RUSTUP_HOME", "PATH"}


def expected_argv(is_rtk: bool, rtk_bin: str | None) -> list:
    return [rtk_bin, *CONTRACT_RAW_ARGV] if is_rtk else list(CONTRACT_RAW_ARGV)


def argv_equals_contract(argv: list, is_rtk: bool, rtk_bin: str | None) -> bool:
    """RAW: argv == CONTRACT_RAW_ARGV. RTK: argv == [RTK_BIN, *CONTRACT_RAW_ARGV]. The full
    argv is compared (never argv[1:] vs CONTRACT[1:], which dropped the `cargo` element);
    a missing `cargo`, an injected `+1.81.0`, extra flags, or reordering all fail."""
    return list(argv) == expected_argv(is_rtk, rtk_bin)
_FIXED = Path(tempfile.gettempdir()) / "n2e-fixedwork"
# dependency-CONTENT roots: nothing under these is bookkeeping, even if lock-shaped (a crate
# fixture example.lock, testdata state.lock, a vendored .global-cache, etc.).
_DEP_CONTENT_ROOTS = frozenset({("registry", "src"), ("registry", "cache"),
                                ("git", "checkouts"), ("git", "db")})
# EXACT cargo bookkeeping paths (advisory locks + GC tracker), each a single file at a fixed
# CARGO_HOME location. Enumerated -- never a blanket suffix match.
_EPHEMERAL_ROOT_EXACT = frozenset({
    (".global-cache",),          # global GC tracker DB (last-use timestamps)
    (".package-cache",),         # package-cache advisory flock
    (".package-cache-mutate",),  # package-cache mutate advisory flock
    (".crates2.json.lock",),     # installed-binary registry (.crates2.json) advisory lock
    (".crates.toml.lock",),      # legacy installed-binary registry advisory lock
})


def _is_ephemeral_cargo_home_path(parts: tuple) -> bool:
    """True ONLY for enumerated cargo bookkeeping paths (advisory locks / GC tracker) with no
    dependency content. Everything else -- including any unknown lock-shaped path -- is RETAINED
    (fail-safe): a `.lock` under a dependency-content root or an unrecognized location is real
    content, never silently classified as bookkeeping."""
    parts = tuple(parts)
    if not parts:
        return False
    # never treat anything under a dependency-content root as bookkeeping
    if len(parts) >= 2 and (parts[0], parts[1]) in _DEP_CONTENT_ROOTS:
        return False
    if parts in _EPHEMERAL_ROOT_EXACT:
        return True
    # sparse-registry per-index config advisory lock, tightly bounded to its exact depth+shape:
    #   registry/index/<registry-id>/config.json.lock
    #   registry/index/<registry-id>/.cache/config.json.lock
    if (len(parts) == 4 and parts[0] == "registry" and parts[1] == "index"
            and parts[3] == "config.json.lock"):
        return True
    if (len(parts) == 5 and parts[0] == "registry" and parts[1] == "index"
            and parts[3] == ".cache" and parts[4] == "config.json.lock"):
        return True
    return False


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
    rustc_shim = shutil.which("rustc")
    rustup_exe = shutil.which("rustup")

    def _sz(p):
        return (Path(p).stat().st_size if p and Path(p).exists() else None)

    installed = {
        "resolved_channel_exact": CHANNEL, "host_target": host,
        # requested toolchain (RUSTUP_TOOLCHAIN) -> resolved executable (rustup which) ->
        # measured executable identity (on-disk sha256 + byte length). The three layers are
        # recorded DISTINCTLY and never conflated. Rust and Cargo identities are kept separate:
        # same toolchain != same artifact. Captured INDEPENDENTLY of the distribution-artifact hashes.
        "requested_toolchain": CHANNEL,
        # cargo: resolved (measured) executable = the exact binary the pinned toolchain selects
        "cargo_binary_path": which_cargo,
        "cargo_binary_sha256": (c.sha256_file(which_cargo) if Path(which_cargo).exists() else None),
        "cargo_binary_bytes": _sz(which_cargo),
        # cargo: invoked path (PATH proxy) + its resolved wrapper realpath (recorded because they differ)
        "cargo_shim_path": shim, "cargo_shim_realpath": (os.path.realpath(shim) if shim else None),
        # rustc: resolved (measured) executable
        "rustc_binary_path": which_rustc,
        "rustc_binary_sha256": (c.sha256_file(which_rustc) if Path(which_rustc).exists() else None),
        "rustc_binary_bytes": _sz(which_rustc),
        # rustc: invoked path (PATH proxy) + its resolved wrapper realpath (symmetric with cargo)
        "rustc_shim_path": rustc_shim, "rustc_shim_realpath": (os.path.realpath(rustc_shim) if rustc_shim else None),
        # the rustup wrapper the proxies resolve to (the invoked wrapper's own identity)
        "rustup_executable_path": rustup_exe,
        "rustup_executable_sha256": (c.sha256_file(rustup_exe) if rustup_exe and Path(rustup_exe).exists() else None),
        "rustup_executable_bytes": _sz(rustup_exe),
        "cargo_version_verbose": cargo_vv, "rustc_version_verbose": rustc_vv,
        "installed_components": _run(["rustup", "component", "list", "--installed", "--toolchain", CHANNEL],
                                     env=env)["stdout"].decode("utf-8", "replace").split(),
    }
    for k in ("cargo_binary_sha256", "rustc_binary_sha256", "cargo_binary_bytes", "rustc_binary_bytes"):
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
    """Normalized RAW content manifest of a directory tree: relpath -> sha256 for every file
    EXCEPT the explicitly-enumerated ephemeral files (lock/access-time markers) and .git.
    Used for the repo, rustup, frozen-env seed, and per-rep mutation guards. Cargo's
    sparse-index cache is compared SEMANTICALLY instead (see _cargo_cache_manifests)."""
    out = {}
    if not root.exists():
        return out
    for f in sorted(root.rglob("*")):
        if not f.is_file() or f.is_symlink():
            continue
        parts = f.relative_to(root).parts
        if ".git" in parts:
            continue
        if _is_ephemeral_cargo_home_path(parts):
            continue
        try:
            out[str(f.relative_to(root))] = c.sha256_file(str(f))
        except OSError:
            pass
    return out


def _cargo_cache_manifests(cargo_home: Path) -> dict:
    """Three relpath-keyed manifests of CARGO_HOME + an unparseable list (reqs 1/2/4):
      full      : relpath -> raw sha256 (every non-ephemeral file)
      semantic  : sparse-index cache entries -> pinned-parser SEMANTIC digest (validator
                  excluded); every other file -> raw sha256
      validator : sparse-index cache entries -> transport-VALIDATOR digest (etag) only
    Only the EXACT registry/index/<id>/.cache/** layout is treated as a cache entry; any such
    entry that fails the pinned Cargo-1.81 parse is collected in `unparseable` (fail-closed)."""
    full, semantic, validator, unparseable = {}, {}, {}, []
    payloads, revisions = {}, {}          # retained normalized semantic reps + validators (req 4/5)
    if not cargo_home.exists():
        return {"full": full, "semantic": semantic, "validator": validator, "unparseable": unparseable,
                "payloads": payloads, "revisions": revisions}
    for f in sorted(cargo_home.rglob("*")):
        if not f.is_file() or f.is_symlink():
            continue
        parts = f.relative_to(cargo_home).parts
        if ".git" in parts:
            continue
        if _is_ephemeral_cargo_home_path(parts):
            continue
        rel = str(f.relative_to(cargo_home))
        try:
            raw = f.read_bytes()
        except OSError:
            continue
        full[rel] = _sha(raw)
        if cic.is_sparse_index_cache_path(parts):
            try:
                entry = cic.parse_entry(raw)
                semantic[rel] = cic.semantic_digest(entry)
                validator[rel] = cic.validator_digest(entry)
                payloads[rel] = cic._semantic_payload(entry)
                revisions[rel] = entry["transport_revision"]
            except cic.CargoIndexCacheUnparseable as e:
                unparseable.append({"path": rel, "reason": str(e)})
        else:
            semantic[rel] = full[rel]
    return {"full": full, "semantic": semantic, "validator": validator, "unparseable": unparseable,
            "payloads": payloads, "revisions": revisions}


def _cargo_cache_full_diff_summary(am: dict, bm: dict) -> dict:
    """Always-emitted A/B cargo-cache diff at three levels (req 4). Acquisition parity may
    pass only when semantic_diff_count == 0; validator-only differences are transport noise."""
    def diff(a, b):
        return (sorted(set(a) - set(b)), sorted(set(b) - set(a)),
                sorted(p for p in (set(a) & set(b)) if a[p] != b[p]))
    f_oa, f_ob, f_ch = diff(am["full"], bm["full"])
    s_oa, s_ob, s_ch = diff(am["semantic"], bm["semantic"])
    v_oa, v_ob, v_ch = diff(am["validator"], bm["validator"])
    semantic_paths = sorted(set(s_oa) | set(s_ob) | set(s_ch))
    validator_only = sorted((set(v_oa) | set(v_ob) | set(v_ch)) - set(semantic_paths))
    return {
        "full_manifest_sha256_A": _manifest_hash(am["full"]), "full_manifest_sha256_B": _manifest_hash(bm["full"]),
        "semantic_manifest_sha256_A": _manifest_hash(am["semantic"]),
        "semantic_manifest_sha256_B": _manifest_hash(bm["semantic"]),
        "validator_manifest_sha256_A": _manifest_hash(am["validator"]),
        "validator_manifest_sha256_B": _manifest_hash(bm["validator"]),
        "full_diff_counts": {"only_in_A": len(f_oa), "only_in_B": len(f_ob), "changed": len(f_ch)},
        "semantic_diff_count": len(semantic_paths),
        "semantic_diff_paths": semantic_paths[:100],
        "validator_only_diff_count": len(validator_only),
        "validator_only_differing_paths": validator_only[:100],
    }


def _reachable_ids(roots: list, nodes: list) -> list:
    """package IDs reachable through the filtered resolve graph, BFS starting ONLY from the
    explicit resolve roots (follow-up item C -- no fall-back to all-nodes: a root that is not a
    node contributes nothing, and a node disconnected from every root is deliberately NOT
    reachable). This is the STRUCTURAL host package set, not len(metadata.packages)."""
    by_id = {n["id"]: n for n in nodes}
    seen, stack = set(), list(roots)
    while stack:
        nid = stack.pop()
        if nid in seen:
            continue
        seen.add(nid)
        for d in by_id.get(nid, {}).get("deps", []):
            pk = d.get("pkg")
            if pk:
                stack.append(pk)
    return sorted(i for i in seen if i in by_id)


def _normalize_resolve(meta: dict, tokens: list) -> dict:
    """HOST-ONLY resolve graph from `cargo metadata --filter-platform <host>`. The top-level
    `packages` array is deliberately NOT embedded (the full cross-platform package metadata is
    derived from the Cargo.lock instead). Only the resolve structure + the set of package IDs
    reachable through the filtered graph are kept. Path-normalized for A/B byte-equality.

    Resolve roots are EXPLICIT (item C): the complete set of normalized `metadata.workspace_members`
    -- every workspace member is a root of Cargo's resolve graph -- UNIONed with `resolve.root`
    when Cargo supplies a concrete primary root. `resolve.root` ALONE is insufficient for a
    workspace that has BOTH a root package and sibling members (e.g. uutils/coreutils: the
    `coreutils` aggregator is `resolve.root`, but the ~50 `src/uu/*` member crates and their
    exclusive transitive deps are workspace-member roots that the aggregator only reaches under
    non-default features, so they would be spuriously "disconnected"). Reachability BFS starts
    from all roots, which spans every node in the (workspace-scoped) resolve graph."""
    def norm(s):
        s = s or ""
        for a, b in tokens:
            s = s.replace(a, b)
        return s
    resolve = meta.get("resolve") or {}
    nodes = []
    for n in resolve.get("nodes", []):
        nodes.append({
            "id": norm(n.get("id", "")), "features": sorted(n.get("features") or []),
            "deps": sorted(
                ({"name": d.get("name"), "pkg": norm(d.get("pkg")),
                  "dep_kinds": sorted(
                      ({"kind": k.get("kind"), "target": k.get("target")} for k in (d.get("dep_kinds") or [])),
                      key=lambda k: (str(k.get("kind")), str(k.get("target"))))}
                 for d in (n.get("deps") or [])),
                key=lambda d: (norm(d.get("pkg")), str(d.get("name")))),
        })
    nodes.sort(key=lambda n: n["id"])
    roots = {norm(m) for m in (meta.get("workspace_members") or [])}   # every workspace member is a root
    raw_root = resolve.get("root")
    if raw_root:
        roots.add(norm(raw_root))                                      # + the concrete primary root, if any
    roots = sorted(roots)
    return {"resolve_roots": roots, "resolve_nodes": nodes,
            "reachable_package_ids": _reachable_ids(roots, nodes)}


def _normalize_lock_packages(lock_bytes: bytes) -> list:
    """The FULL cross-platform package resolution from the generated Cargo.lock: one
    normalized record per [[package]] (name, version, source, checksum), sorted. The lock is
    platform-INDEPENDENT, so this is every dependency for every target -- distinct from the
    host-filtered resolve graph. Path-independent, so byte-identical across A/B when the lock
    is identical."""
    import tomllib
    data = tomllib.loads(lock_bytes.decode("utf-8"))
    pkgs = [{"name": p.get("name"), "version": p.get("version"),
             "source": p.get("source"), "checksum": p.get("checksum")}
            for p in data.get("package", [])]
    pkgs.sort(key=lambda p: (p["name"] or "", p["version"] or "", p["source"] or ""))
    return pkgs


DEPENDENCY_FETCH_ARGV = ["cargo", "fetch", "--locked"]


def _dependency_fetch(repo_dir: Path, cargo_home: Path) -> dict:
    """Lock-preserving, fail-closed dependency fetch (correction items 1/2). Requires the
    generated Cargo.lock to exist, captures its pre-fetch identity, runs EXACTLY
    `cargo fetch --locked` (RUSTUP_TOOLCHAIN=1.81.0, CARGO_NET_OFFLINE=false), records the full
    command identity, and requires exit==0 & not timed_out. `--locked` forbids any lock update,
    so a lock that would need changing fails the fetch (COREUTILS_DEPENDENCY_FETCH_FAILURE)
    rather than silently mutating. The post-fetch lock is re-read and required byte-identical to
    the pre-fetch lock (COREUTILS_DEPENDENCY_FETCH_LOCK_MUTATION otherwise). Returns the public
    fetch record + pre/post identities + the private post-fetch raw bytes (the SOLE lock source
    for every downstream identity)."""
    lock = repo_dir / "Cargo.lock"
    if not lock.is_file():
        return {"status": "COREUTILS_DEPENDENCY_FETCH_FAILURE", "pre_fetch_lock_present": False,
                "reason": "no generated Cargo.lock before dependency fetch"}
    pre = lock.read_bytes()
    env = _cargo_env(cargo_home, {"CARGO_NET_OFFLINE": "false", "RUSTUP_TOOLCHAIN": CHANNEL})
    r = _run(DEPENDENCY_FETCH_ARGV, cwd=str(repo_dir), env=env, tmo=1800)
    fetch = {"argv": DEPENDENCY_FETCH_ARGV,
             "env": {"RUSTUP_TOOLCHAIN": CHANNEL, "CARGO_NET_OFFLINE": "false"},
             "exit": r["exit"], "timed_out": r["timed_out"],
             "stdout_sha256": _sha(r["stdout"]), "stderr_sha256": _sha(r["stderr"]),
             "stderr_tail": r["stderr"][-1500:].decode("utf-8", "replace")}
    out = {"dependency_fetch": fetch, "pre_fetch_lock_present": True,
           "pre_fetch_lock_sha256": _sha(pre), "pre_fetch_lock_bytes": len(pre)}
    if r["exit"] != 0 or r["timed_out"]:
        out["status"] = "COREUTILS_DEPENDENCY_FETCH_FAILURE"
        return out
    if not lock.is_file():
        out["status"] = "COREUTILS_DEPENDENCY_FETCH_FAILURE"; out["reason"] = "lock removed by fetch"
        return out
    post = lock.read_bytes()
    out["post_fetch_lock_sha256"] = _sha(post); out["post_fetch_lock_bytes"] = len(post)
    out["_post_fetch_lock_raw"] = post
    if _sha(pre) != _sha(post) or len(pre) != len(post):
        out["status"] = "COREUTILS_DEPENDENCY_FETCH_LOCK_MUTATION"
        return out
    out["status"] = "ok"
    return out


def _resolved_dependency_snapshot(repo_dir: Path, cargo_home: Path, post_fetch_lock: bytes | None) -> dict:
    """Resolved-dependency snapshot (req 3), derived EXCLUSIVELY from the POST-FETCH lock bytes.
    Two DISTINCT scopes with accurate terminology:
      * full_packages_metadata / cargo_lock_scope = "full cross-platform resolution": every
        dependency package record (name/version/source/checksum) from the (post-fetch) Cargo.lock,
        which is platform-independent.
      * host_resolve_graph (resolve_graph_scope = "host-filtered", resolve_graph_platform =
        x86_64-unknown-linux-gnu): the host resolve graph from `cargo metadata --offline
        --filter-platform <host>`, run AFTER the lock-pinned `cargo fetch --locked` populated
        the cache. A successful offline metadata never compensates for a failed fetch (the
        caller gates on dependency-fetch status first)."""
    env = _cargo_env(cargo_home, {"CARGO_NET_OFFLINE": "true", "RUSTUP_TOOLCHAIN": CHANNEL})
    r = _run(["cargo", "metadata", "--format-version", "1", "--offline",
              "--filter-platform", HOST], cwd=str(repo_dir), env=env, tmo=300)
    out = {"metadata_exit": r["exit"], "metadata_ok": r["exit"] == 0,
           "cargo_lock_present": post_fetch_lock is not None,
           "cargo_lock_sha256": (_sha(post_fetch_lock) if post_fetch_lock else None),
           "cargo_lock_bytes": (len(post_fetch_lock) if post_fetch_lock else 0),
           "cargo_lock_scope": "full cross-platform resolution"}
    if post_fetch_lock is not None:
        full_pkgs = _normalize_lock_packages(post_fetch_lock)
        out["full_packages_metadata"] = full_pkgs
        out["full_packages_metadata_sha256"] = _manifest_hash(full_pkgs)
        out["full_package_count"] = len(full_pkgs)
    if r["exit"] != 0:
        out["metadata_stderr_tail"] = r["stderr"][-800:].decode("utf-8", "replace")
        return out
    tokens = [(str(repo_dir), "<REPO>"), (str(cargo_home), "<CARGO_HOME>"),
              (str(Path(cargo_home).parent), "<ROOT>")]
    graph = _normalize_resolve(json.loads(r["stdout"]), tokens)
    graph["resolve_graph_platform"] = HOST
    graph["resolve_graph_scope"] = "host-filtered"
    out["host_resolve_graph"] = graph
    out["host_resolve_graph_sha256"] = _manifest_hash(graph)
    out["host_resolved_package_count"] = len(graph["reachable_package_ids"])
    return out


def _manifest_hash(man: dict) -> str:
    return _sha(json.dumps(man, sort_keys=True).encode())


# ---------------------- correction 9: external artifact manifest ----------------------
def _artifact_manifest(evidence: Path, record_path: Path) -> list:
    out = []
    for f in sorted(list(evidence.rglob("*")) + [record_path]):
        fa = f.resolve()  # rebase absolutely so a relative rglob path never trips relative_to
        if fa.is_file():
            out.append({"file": str(fa.relative_to(N2E_DIR)), "bytes": fa.stat().st_size,
                        "sha256": c.sha256_file(str(fa))})
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
    install_rec = {"argv": inst_argv, "env": inst_env, "exit": install["exit"], "timed_out": install["timed_out"],
                   "stdout_sha256": _sha(install["stdout"]), "stderr_sha256": _sha(install["stderr"]),
                   "stdout_bytes": len(install["stdout"]), "stderr_bytes": len(install["stderr"]),
                   "stderr_tail": install["stderr"][-1500:].decode("utf-8", "replace")}
    # lock-preserving fail-closed dependency fetch (items 1/2): `cargo fetch --locked` populates
    # the full lock-pinned cache online without mutating the lock.
    fetch = _dependency_fetch(repo_dir, cargo_home)
    fetch_pub = {k: v for k, v in fetch.items() if not k.startswith("_")}
    # required post-fetch state is a PASSIVE git/fs observation (executes NO cargo command); it is
    # captured before any metadata probing so it is safe to include even on a terminal fetch.
    post = capture_dependency_state_passive(repo_dir, ge)
    rec = {
        "label": label, "base_commit": base, "head_matches_base": head_ok, "fetch_exit": fe["exit"],
        "install": install_rec,
        "pristine_state": pristine, "post_install_state": post,
        "pre_install_metadata": pre_md,
        "dependency_fetch_result": fetch_pub,   # status + fetch record + pre/post lock identities
        "_root": str(root), "_repo_dir": str(repo_dir), "_cargo_home": str(cargo_home), "_ge": ge,
    }
    # follow-up item A: a TERMINAL dependency-fetch status STOPS the acquisition. After
    # _dependency_fetch() returns COREUTILS_DEPENDENCY_FETCH_FAILURE or
    # COREUTILS_DEPENDENCY_FETCH_LOCK_MUTATION, NONE of `cargo metadata`, post-install metadata
    # probing, cargo-cache semantic parsing, or measurement preparation runs -- the record carries
    # only the fetch primitives + required post-fetch state, and classification treats the terminal
    # status as taking precedence over any (never-computed) sparse-cache parse outcome.
    if fetch.get("status") in ("COREUTILS_DEPENDENCY_FETCH_FAILURE", "COREUTILS_DEPENDENCY_FETCH_LOCK_MUTATION"):
        rec["dependency_fetch_terminal"] = True
        return rec
    # fetch ok: the host graph is resolved OFFLINE from the (verified-unchanged) POST-FETCH lock
    # bytes, then the post-install metadata, cache manifest, and frozen lock bytes are captured --
    # all derived from the single post-fetch lock, never a pre/post mixture.
    post_fetch_lock = fetch.get("_post_fetch_lock_raw")
    resolved = _resolved_dependency_snapshot(repo_dir, cargo_home, post_fetch_lock)
    post_md = probe_cargo_metadata_disposable(repo_dir, cargo_home, offline=post["cargo_lock"]["present"])
    ccm = _cargo_cache_manifests(cargo_home)
    rec.update({
        "post_install_metadata": post_md,
        # SEMANTIC cargo-cache seed hash (validator excluded via the pinned Cargo-1.81 parser)
        "cargo_cache_semantic_manifest_hash": _manifest_hash(ccm["semantic"]),
        "cargo_cache_validator_manifest_hash": _manifest_hash(ccm["validator"]),
        "cargo_cache_full_manifest_hash": _manifest_hash(ccm["full"]),
        "cargo_index_cache_unparseable": ccm["unparseable"],
        "resolved_dependency_snapshot": resolved,
        "_cargo_cache_manifests": ccm,   # private full/semantic/validator, for the A/B diff summary
        "_cargo_lock_raw": post_fetch_lock,   # SOLE lock source: post-fetch bytes -> A/B-Cargo.lock
    })
    return rec


def _acq_public(a: dict) -> dict:
    return {k: v for k, v in a.items() if not k.startswith("_")}


def _write_cargo_cache_evidence(A: dict, B: dict, evidence: Path) -> dict:
    """Retain (req 4/5) the NORMALIZED SEMANTIC representation of every sparse-index cache
    entry + the offline resolved graph, per acquisition, so the independent verifier can
    re-parse, re-derive digests, and require zero semantic differences without re-measuring."""
    d = evidence / "cargo-cache"
    d.mkdir(parents=True, exist_ok=True)
    written = {}
    for label, acq in (("A", A), ("B", B)):
        ccm = acq.get("_cargo_cache_manifests") or {}
        entries = []
        for rel in sorted(ccm.get("payloads") or {}):
            payload = ccm["payloads"][rel]
            entries.append({
                "path": rel, "semantic_payload": payload,
                "transport_revision": (ccm.get("revisions") or {}).get(rel),
                "semantic_sha256": (ccm.get("semantic") or {}).get(rel),
                "validator_sha256": (ccm.get("validator") or {}).get(rel),
            })
        cache_path = d / f"{label}-cache-semantic.json"
        cache_path.write_text(json.dumps({"entries": entries, "entry_count": len(entries)},
                                         sort_keys=True, indent=1))
        rds = acq.get("resolved_dependency_snapshot") or {}
        graph_path = d / f"{label}-resolved-graph.json"
        graph_path.write_text(json.dumps({
            "host_resolve_graph": rds.get("host_resolve_graph"),
            "host_resolve_graph_sha256": rds.get("host_resolve_graph_sha256"),
            "host_resolved_package_count": rds.get("host_resolved_package_count"),
            "full_packages_metadata": rds.get("full_packages_metadata"),
            "full_packages_metadata_sha256": rds.get("full_packages_metadata_sha256"),
            "cargo_lock_scope": rds.get("cargo_lock_scope"),
            "cargo_lock_sha256": rds.get("cargo_lock_sha256"),
            "cargo_lock_bytes": rds.get("cargo_lock_bytes"),
        }, sort_keys=True, indent=1))
        # req 1: the exact post-install lock bytes of this acquisition's frozen state
        lock_written = None
        lock_raw = acq.get("_cargo_lock_raw")
        if lock_raw is not None:
            lock_path = d / f"{label}-Cargo.lock"
            lock_path.write_bytes(lock_raw)
            lock_written = str(lock_path.relative_to(evidence))
        written[label] = {"cache_semantic": str(cache_path.relative_to(evidence)),
                          "resolved_graph": str(graph_path.relative_to(evidence)),
                          "cargo_lock": lock_written,
                          "cache_entry_count": len(entries)}
    return written


# measurement model (req 3): Model B -- the publisher install generates an (untracked)
# Cargo.lock; the frozen measurement env carries A's generated lock (== B, proven), giving a
# deterministic offline substrate immune to crates.io sparse-index drift. Recorded distinct
# from pristine_dependency_state as publisher_install_resolved_dependency_snapshot.
MEASUREMENT_MODEL = "B_frozen_resolved_dependency_snapshot"


def _classify_acquisitions(A: dict, B: dict, tool_ident: dict) -> dict:
    if A["install"]["exit"] != 0 or B["install"]["exit"] != 0:
        return {"outcome": "COREUTILS_ACQUISITION_INSTALL_FAILURE",
                "a_exit": A["install"]["exit"], "b_exit": B["install"]["exit"]}
    # follow-up item A + items 1/2: the dependency-fetch terminal status TAKES PRECEDENCE over
    # sparse-cache parsing outcomes. A failed/lock-mutating `cargo fetch --locked` stops the
    # acquisition before the cache is ever parsed (so cargo_index_cache_unparseable is absent on a
    # terminal record); a successful offline metadata never compensates. Checked FIRST so a
    # malformed cache entry left behind by a failed fetch still classifies as the fetch failure.
    fa = A.get("dependency_fetch_result") or {}
    fb = B.get("dependency_fetch_result") or {}
    for st in ("COREUTILS_DEPENDENCY_FETCH_FAILURE", "COREUTILS_DEPENDENCY_FETCH_LOCK_MUTATION"):
        if fa.get("status") == st or fb.get("status") == st:
            return {"outcome": st, "a_dependency_fetch": fa, "b_dependency_fetch": fb,
                    "note": "lock-preserving dependency fetch gate failed before metadata/measurement"}
    # req 2: any sparse-index cache entry that fails the pinned Cargo-1.81 parse is terminal
    unparseable = (A.get("cargo_index_cache_unparseable") or []) + (B.get("cargo_index_cache_unparseable") or [])
    if unparseable:
        return {"outcome": "COREUTILS_CARGO_INDEX_CACHE_UNPARSEABLE",
                "unparseable_entries": unparseable[:50], "unparseable_count": len(unparseable),
                "note": "a sparse-index cache entry did not conform to the pinned Cargo-1.81 format"}
    pa, pb = A["post_install_state"], B["post_install_state"]
    # req 4: always compute the A/B cargo-cache diff at full/semantic/validator levels
    cache_diff = _cargo_cache_full_diff_summary(A["_cargo_cache_manifests"], B["_cargo_cache_manifests"])
    ra, rb = A.get("resolved_dependency_snapshot") or {}, B.get("resolved_dependency_snapshot") or {}
    resolved_ok = bool(ra.get("metadata_ok")) and bool(rb.get("metadata_ok"))
    # complete normalized post-install parity (correction 4 + reqs 2/3/4)
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
        # items 1/2: lock-preserving dependency fetch succeeded and did not mutate the lock (A&B)
        "dependency_fetch_ok": fa.get("status") == "ok" and fb.get("status") == "ok",
        "fetch_lock_unchanged": (fa.get("pre_fetch_lock_sha256") == fa.get("post_fetch_lock_sha256")
                                 and fb.get("pre_fetch_lock_sha256") == fb.get("post_fetch_lock_sha256")
                                 and fa.get("pre_fetch_lock_sha256") is not None
                                 and fb.get("pre_fetch_lock_sha256") is not None),
        # SEMANTIC sparse-index cache equality: validator-only differences do NOT count
        "cargo_cache_semantic_equal": cache_diff["semantic_diff_count"] == 0,
        # req 3: host-filtered resolve graph + full cross-platform package metadata +
        # generated lock, each byte-identical across A/B
        "resolved_metadata_ok": resolved_ok,
        "host_resolve_graph_equal": (resolved_ok and ra.get("host_resolve_graph_sha256")
                                     == rb.get("host_resolve_graph_sha256")),
        "full_packages_metadata_equal": (ra.get("full_packages_metadata_sha256")
                                         == rb.get("full_packages_metadata_sha256")),
        "generated_lock_equal": (ra.get("cargo_lock_sha256") == rb.get("cargo_lock_sha256")),
    }

    def tracked_nonlock_changed(a):
        changed = set(a["post_install_state"]["tracked_status"]) - set(a["pristine_state"]["tracked_status"])
        return sorted(x for x in changed if "Cargo.lock" not in x)
    a_nonlock, b_nonlock = tracked_nonlock_changed(A), tracked_nonlock_changed(B)
    cfg_or_tc_mutated = not (parity["cargo_config_equal"] and parity["rust_toolchain_equal"]) or bool(a_nonlock or b_nonlock)
    if cfg_or_tc_mutated:
        return {"outcome": "COREUTILS_ACQUISITION_UNAUTHORIZED_MUTATION", "parity": parity,
                "cargo_cache_full_diff_summary": cache_diff,
                "a_nonlock_tracked": a_nonlock, "b_nonlock_tracked": b_nonlock,
                "note": "only Cargo.lock create/modify is authorized during publisher install"}
    if not all(parity.values()):
        return {"outcome": "COREUTILS_ACQUISITION_NONDETERMINISTIC", "parity": parity,
                "cargo_cache_full_diff_summary": cache_diff,
                "host_resolve_graph_sha_A": ra.get("host_resolve_graph_sha256"),
                "host_resolve_graph_sha_B": rb.get("host_resolve_graph_sha256"),
                "full_packages_metadata_sha_A": ra.get("full_packages_metadata_sha256"),
                "full_packages_metadata_sha_B": rb.get("full_packages_metadata_sha256"),
                "generated_lock_sha_A": ra.get("cargo_lock_sha256"),
                "generated_lock_sha_B": rb.get("cargo_lock_sha256"),
                "resolved_metadata_ok_A": ra.get("metadata_ok"), "resolved_metadata_ok_B": rb.get("metadata_ok"),
                "metadata_stderr_tail_A": ra.get("metadata_stderr_tail"),
                "metadata_stderr_tail_B": rb.get("metadata_stderr_tail"),
                "note": "harness/acquisition investigation state, not a candidate disqualification"}
    # reproducible: Model B -- freeze the (A==B) generated resolved dependency snapshot
    lock_present = ra.get("cargo_lock_present") and rb.get("cargo_lock_present")
    if lock_present:
        return {"outcome": "publisher_install_resolved_dependency_snapshot",
                "measurement_model": MEASUREMENT_MODEL, "parity": parity,
                "cargo_cache_full_diff_summary": cache_diff,
                "frozen_lock_sha256": ra.get("cargo_lock_sha256"), "frozen_lock_bytes": ra.get("cargo_lock_bytes"),
                "cargo_lock_scope": "full cross-platform resolution",
                "host_resolve_graph_sha256": ra.get("host_resolve_graph_sha256"),
                "host_resolved_package_count": ra.get("host_resolved_package_count"),
                "full_packages_metadata_sha256": ra.get("full_packages_metadata_sha256"),
                "full_package_count": ra.get("full_package_count"),
                "byte_identical_across_A_B": True}
    # no generated lock at all (no dependencies) -> genuinely pristine
    return {"outcome": "pristine_dependency_state", "measurement_model": MEASUREMENT_MODEL,
            "parity": parity, "cargo_cache_full_diff_summary": cache_diff,
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
        "cargo_cache_semantic_equal": A["cargo_cache_semantic_manifest_hash"] == B["cargo_cache_semantic_manifest_hash"],
    }
    p["all_equal"] = all(p.values())
    return p


# ---------------------- corrections 6/7/8: measurement arm ----------------------
def _rustup_manifest(rustup_home: str) -> str:
    root = Path(rustup_home) / "toolchains" if rustup_home else None
    return _manifest_hash(_stable_manifest(root)) if root else ""


def _measure_arm(is_rtk: bool, frozen_env: Path, argv: list, rtk_bin: str | None, wrapper: list,
                 off_env: dict, target_ids: list, evidence: Path, rustup_home: str) -> dict:
    role = "rtk" if is_rtk else "raw"
    ge = _git_env(_FIXED / "home")
    runs, canon_hashes, per_rep, mut = [], [], [], []
    evidence.mkdir(parents=True, exist_ok=True)
    seed_cargo = _manifest_hash(_stable_manifest(frozen_env / "cargo-home"))
    seed_toolchain = _rustup_manifest(rustup_home)
    exp_argv = expected_argv(is_rtk, rtk_bin)
    contract_argv_ok = argv_equals_contract(argv, is_rtk, rtk_bin)
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
    semantic_env = {k: v for k, v in off_env.items() if k not in _ENV_PATH_KEYS}
    out = {"role": role, "reps": REPS, "actual_argv": argv, "expected_argv": exp_argv,
           "canonicalization_policy": CANON_POLICY,
           "actual_argv_equal_contract": contract_argv_ok,
           "semantic_env": semantic_env,
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

    return _rtk_chain(co, head, tree, evidence, ident)


# Rust symbol definition (fn / struct / enum / trait / const) with byte span.
_RUST_DEF = re.compile(
    rb"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:async[ \t]+)?(?:unsafe[ \t]+)?"
    rb"(fn|struct|enum|trait|const|static)[ \t]+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)


def _rust_defs(text: bytes) -> dict:
    """symbol -> (kind, byte_offset) for each Rust item definition in the file."""
    out = {}
    for m in _RUST_DEF.finditer(text):
        out.setdefault(m.group(2).decode(), (m.group(1).decode(), m.start()))
    return out


def _rtk_chain(co: Path, head: str, tree: str, evidence: Path, ident) -> dict:
    """Derive the CONNECTED source chain rtk `cargo test` dispatch -> cargo test filter ->
    native cargo result parser -> summary formatter. Each role is anchored by an exact
    content signal AND a Rust symbol; each edge is a MECHANICALLY-RESOLVED reference from
    a role's file to a symbol DEFINED in the next role's file. Keyword hits alone never set
    chain_complete=true."""
    rs = [f for f in co.rglob("*.rs") if f.is_file() and ".git" not in f.parts]
    files = {}
    for f in rs:
        try:
            txt = f.read_bytes()
        except OSError:
            continue
        files[str(f.relative_to(co))] = {"txt": txt, "defs": _rust_defs(txt), "path": f}

    def anchors(pred) -> list:
        return sorted(rel for rel, d in files.items() if pred(d["txt"].lower(), d["txt"]))

    role_files = {
        # dispatch: routes the cargo subcommand to test handling
        "cli_dispatch_cargo_test": anchors(lambda low, t: b"cargo" in low and b"test" in low
                                           and (b"subcommand" in low or b"=> " in t or b"match " in low)),
        # filter selection for `cargo test`
        "cargo_filter": anchors(lambda low, t: b"cargo" in low and b"filter" in low),
        # native cargo result parser: recognizes cargo's own "test result:" line
        "cargo_parser": anchors(lambda low, t: b"test result:" in low),
        # summary formatter: emits the aggregate "<n> passed[, <n> failed]" record
        "summary_formatter": anchors(lambda low, t: b"passed" in low and b"failed" in low
                                     and (b"write!" in t or b"format!" in t or b"println!" in t)),
    }
    order = ["cli_dispatch_cargo_test", "cargo_filter", "cargo_parser", "summary_formatter"]

    def resolve_edge(src_files: list, dst_files: list) -> dict | None:
        """A resolved edge: some symbol DEFINED in a dst file is REFERENCED in a src file."""
        for dst in dst_files:
            for sym, (kind, off) in files[dst]["defs"].items():
                if len(sym) < 4:
                    continue
                ref = re.compile(rb"\b" + re.escape(sym.encode()) + rb"\b")
                for src in src_files:
                    if src == dst:
                        continue
                    m = ref.search(files[src]["txt"])
                    if m:
                        return {"from_path": src, "to_path": dst, "target_symbol": sym,
                                "target_kind": kind, "reference_offset": m.start(),
                                "target_def_offset": off,
                                "from_blob": ident(files[src]["path"]),
                                "to_blob": ident(files[dst]["path"])}
        return None

    edges = {}
    for a, b in zip(order, order[1:]):
        edges[f"{a}->{b}"] = resolve_edge(role_files[a], role_files[b])
    all_roles_found = all(role_files[r] for r in order)
    all_edges_resolved = all(e is not None for e in edges.values())
    chain_complete = bool(all_roles_found and all_edges_resolved)

    # persist the exact source bytes for every file participating in a resolved edge
    part = set()
    for e in edges.values():
        if e:
            part.add(e["from_path"]); part.add(e["to_path"])
    ev_dir = evidence / "rtk-source-evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for rel in sorted(part):
        try:
            (ev_dir / rel.replace("/", "__")).write_bytes(files[rel]["txt"])
            copied.append(rel.replace("/", "__"))
        except OSError:
            pass
    return {"fetched": True, "commit": RTK_SOURCE_COMMIT, "head": head, "tree": tree,
            "head_proven": head == RTK_SOURCE_COMMIT,
            "role_files": role_files, "edges": edges,
            "all_roles_found": all_roles_found, "all_edges_resolved": all_edges_resolved,
            "chain_complete": chain_complete, "copied_evidence_files": sorted(copied),
            "chain": "rtk `cargo test` dispatch -> cargo test filter -> native cargo result "
                     "parser -> summary formatter"}


def _emit(out: Path, body: dict):
    c.write_record(out, c.envelope(record_type="n2e-coreutils-diagnostic",
                   generated_by="tools/probe_coreutils_diagnostic.py", **body))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(N2E_DIR / "coreutils-6731-diagnostic-v1.json"))
    ap.add_argument("--evidence", default=str(N2E_DIR / "out" / "evidence" / "coreutils-6731"))
    args = ap.parse_args()
    # resolve to absolute so evidence.rglob() yields absolute paths that relative_to(N2E_DIR)
    # can rebase to stable N2E-relative manifest strings regardless of the process cwd (the
    # workflow passes RELATIVE --out/--evidence with cwd=N2E; relative rglob paths vs an
    # absolute N2E_DIR previously raised ValueError inside _artifact_manifest).
    out = Path(args.out).resolve(); evidence = Path(args.evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=True)

    bundle = loader.load_case_bundle(CASE_ID, "resolved")
    recipe = bundle["publisher_recipe"]; scen = bundle["scenario"]
    base = scen["base_commit"]; target_ids = scen["target_test_ids"]
    pins = loader.validate_resolved_closure()["overlays"]["toolchain"]["resolved_rust_toolchain"]
    row = c.load_record(ROW)
    gold = (row.get("patch") or "").encode(); test = (row.get("test_patch") or "").encode()

    # producer-NEUTRAL fields (correction 2): the independent verifier -- not the producer --
    # derives normative_evidence_eligible from re-verified primitive evidence.
    body = {"case_id": CASE_ID, "instance_id": INSTANCE_ID, "base_commit": base,
            "record_kind": "focused_diagnostic",
            "acceptance_pass": False,
            "normative_evidence_eligibility": "UNDETERMINED",
            "resolved_bundle_source": bundle["source"],
            "effective_record_hash_map": bundle["effective_record_hash_map"],
            "canonicalization_policy_id": bundle["execution_contract"]["canonicalization_policy_id"],
            "contract_raw_argv": CONTRACT_RAW_ARGV, "contract_env": CONTRACT_ENV,
            "rtk_binary_path": os.environ.get("RTK_BIN"),
            "rtk_binary_sha256": (c.sha256_file(os.environ["RTK_BIN"]) if os.environ.get("RTK_BIN") else None),
            # built RTK executable byte length (alongside its sha256), for the P3 dialect identity chain
            "rtk_binary_bytes": (Path(os.environ["RTK_BIN"]).stat().st_size
                                 if os.environ.get("RTK_BIN") and Path(os.environ["RTK_BIN"]).exists() else None)}

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
        body["measurement_model"] = MEASUREMENT_MODEL
        body["cargo_cache_evidence"] = _write_cargo_cache_evidence(A, B, evidence)
        body["rtk_cargo_filter_source"] = _rtk_source_evidence(workroot, evidence)

        # Model B: only a reproducible resolved-dependency snapshot (or genuinely pristine) is
        # eligible to proceed to measurement.
        if cls["outcome"] not in ("publisher_install_resolved_dependency_snapshot", "pristine_dependency_state"):
            body["outcome"] = cls["outcome"]; body["acceptance_pass"] = False
            body["file_manifest"] = _artifact_manifest(evidence, out)
            _emit(out, body); print("coreutils-diagnostic:", body["outcome"]); return 0
        # Model B: record the frozen (A==B) generated resolved-dependency snapshot the
        # measurement substrate carries (the frozen-env copytree below uses A's repo+lock).
        _rdsA = A.get("resolved_dependency_snapshot") or {}
        body["frozen_resolved_dependency_snapshot"] = {
            "measurement_model": MEASUREMENT_MODEL,
            "cargo_lock_sha256": _rdsA.get("cargo_lock_sha256"),
            "cargo_lock_bytes": _rdsA.get("cargo_lock_bytes"),
            "cargo_lock_scope": "full cross-platform resolution",
            "full_packages_metadata_sha256": _rdsA.get("full_packages_metadata_sha256"),
            "host_resolve_graph_sha256": _rdsA.get("host_resolve_graph_sha256"),
            "host_resolved_package_count": _rdsA.get("host_resolved_package_count"),
            "byte_identical_across_A_B": True,
            "harness_owned": True,
        }

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
        meas_env = {**off, **_env}
        body["measurement_semantic_env"] = {k: v for k, v in meas_env.items() if k not in _ENV_PATH_KEYS}
        body["actual_environment_equal_contract"] = all(meas_env.get(k) == v for k, v in CONTRACT_ENV.items())
        rtk_bin = os.environ.get("RTK_BIN")
        raw = _measure_arm(False, frozen, list(CONTRACT_RAW_ARGV), rtk_bin, wrapper, meas_env,
                           target_ids, evidence, rustup_home)
        body["raw_arm"] = raw
        body["actual_raw_argv_equal_contract"] = raw["actual_argv_equal_contract"]
        if not raw["raw_qualified"]:
            body["outcome"] = "COREUTILS_RAW_NOT_QUALIFIED"
            body["file_manifest"] = _artifact_manifest(evidence, out)
            _emit(out, body); print("coreutils-diagnostic: RAW not qualified"); return 0

        rtk = _measure_arm(True, frozen, [rtk_bin, *CONTRACT_RAW_ARGV], rtk_bin, wrapper, meas_env,
                           target_ids, evidence, rustup_home)
        body["rtk_arm"] = rtk
        body["actual_rtk_argv_equal_contract"] = rtk["actual_argv_equal_contract"]
        # RAW and RTK receive identical semantic env (RTK differs only by the wrapper argv[0])
        body["raw_rtk_semantic_env_equal"] = raw["semantic_env"] == rtk["semantic_env"]
        body["outcome"] = "RTK_DIALECT_UNPROVEN"
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
