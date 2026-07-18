#!/usr/bin/env python3
"""Focused publisher-recipe consistency probe for tokio-rs__tokio-4384.

Gathers SYMMETRIC identity + failure evidence for the N2-E reconstruction (parts A/B/C)
and the pinned upstream SWE-bench harness SOURCE CHECKOUT (part D), so an independent
parity verifier can decide the classification boundary. Never chooses a lock. Part D
FAILS CLOSED (TOKIO_UPSTREAM_REPRODUCTION_DEFECT) rather than substituting local
commands. Network ENABLED (diagnostic, not a measurement).
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

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_publisher_registry as pub  # noqa: E402

INSTANCE = "tokio-rs__tokio-4384"
CASE_ID = "tokio-rs__tokio-4384::rust_cargo::test::fixed"
CHANNEL = "1.83.0"
HARNESS_COMMIT = "f7bbbb2ccdf479001d6467c9e34af59e44a840f9"
BUNDLE = N2E_DIR / "fixtures" / "swebench-source" / "swebench-f7bbbb2.bundle"
UPSTREAM_FIXTURE_PATH = "swebench/harness/constants/fixtures/tokio-rs__tokio-4384.Cargo.lock"
OUT = N2E_DIR / "tokio-4384-publisher-recipe-consistency-v1.json"
PINS = N2E_DIR / "n2e-source-pins-v1.json"
TOKIO_GIT = "https://github.com/tokio-rs/tokio.git"


def _run(argv, cwd=None, env=None, tmo=1800):
    try:
        p = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=tmo)
        return {"argv": list(argv), "exit": p.returncode, "timed_out": False,
                "stdout": p.stdout.decode("utf-8", "replace"), "stderr": p.stderr.decode("utf-8", "replace"),
                "stdout_bytes": len(p.stdout), "stderr_bytes": len(p.stderr),
                "stdout_sha256": hashlib.sha256(p.stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(p.stderr).hexdigest()}
    except subprocess.TimeoutExpired as e:
        return {"argv": list(argv), "exit": None, "timed_out": True,
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
         "CARGO_HOME": str(home / ".cargo"), "RUSTUP_TOOLCHAIN": CHANNEL, "RUSTFLAGS": "-Awarnings"}
    if os.environ.get("RUSTUP_HOME"):
        e["RUSTUP_HOME"] = os.environ["RUSTUP_HOME"]
    return e


def _cargo_binary_identity(env: dict) -> dict:
    which = _run(["bash", "-c", "command -v cargo"], env=env)["stdout"].strip()
    ident = {"command_v_cargo": which, "is_symlink": None, "symlink_target": None,
             "realpath": None, "realpath_sha256": None}
    if which:
        p = Path(which)
        ident["is_symlink"] = p.is_symlink()
        if p.is_symlink():
            ident["symlink_target"] = os.readlink(which)
        real = subprocess.run(["realpath", which], capture_output=True, text=True).stdout.strip()
        ident["realpath"] = real
        ident["realpath_sha256"] = _sha_file(Path(real)) if real else None
    rw = _run(["rustup", "which", "--toolchain", CHANNEL, "cargo"], env=env)["stdout"].strip()
    ident["rustup_which_cargo"] = rw
    ident["rustup_which_cargo_sha256"] = _sha_file(Path(rw)) if rw else None
    ident["real_cargo_binary_sha256"] = ident["rustup_which_cargo_sha256"] or ident["realpath_sha256"]
    return ident


def _fixture_evidence(repo: Path, checkout: Path) -> dict:
    up_path = checkout / UPSTREAM_FIXTURE_PATH
    up = up_path.read_bytes() if up_path.is_file() else b""
    blob = _git(checkout, "rev-parse", f"{HARNESS_COMMIT}:{UPSTREAM_FIXTURE_PATH}")["stdout"].strip()
    lock = repo / "Cargo.lock"
    mat = lock.read_bytes() if lock.is_file() else b""
    return {"upstream_fixture_path": UPSTREAM_FIXTURE_PATH, "upstream_fixture_git_blob": blob,
            "upstream_fixture_bytes": len(up), "upstream_fixture_sha256": hashlib.sha256(up).hexdigest(),
            "materialized_cargo_lock_bytes": len(mat),
            "materialized_cargo_lock_sha256": hashlib.sha256(mat).hexdigest(),
            "byte_length_delta": len(mat) - len(up), "byte_identical": mat == up,
            "diff_is_solely_trailing_newline": (mat == up + b"\n"),
            "materialized_extra_suffix": (mat[len(up):].decode("utf-8", "replace")
                                          if mat.startswith(up) else None)}


def _target_platform(env: dict) -> str | None:
    vv = _run(["cargo", f"+{CHANNEL}", "-Vv"], env=env)["stdout"]
    for ln in vv.splitlines():
        if ln.startswith("host:"):
            return ln.split(":", 1)[1].strip()
    return None


def _failure_class(text: str) -> dict:
    """Recognize the SPECIFIC locked-resolution refusal + requested lock mutation from
    the full Cargo output -- not merely 'exit == 101'."""
    t = text or ""
    refusal = ("needs to be updated" in t and "--locked" in t and "lock file" in t)
    return {"class": "cargo_locked_resolution_refusal" if refusal else ("cargo_other_error" if t.strip() else "none"),
            "locked_resolution_refusal": refusal,
            "requested_lock_mutation": "needs to be updated" in t,
            "updating_crates_io_index": "Updating crates.io index" in t}


def _identity(env: dict, repo: Path, checkout: Path, base: str, install: dict) -> dict:
    """SYMMETRIC identity schema emitted for BOTH the N2-E and upstream environments."""
    head = _git(repo, "rev-parse", "HEAD")["stdout"].strip()
    return {
        "base_commit": base, "head": head, "head_matches_base": head == base,
        "tracked_status_clean": _git(repo, "status", "--porcelain", "--untracked-files=no")["stdout"].strip() == "",
        "workspace_manifests": {str(p.relative_to(repo)): _sha_file(p) for p in sorted(repo.rglob("Cargo.toml"))},
        "cargo_config": {rel: _sha_file(repo / rel) for rel in (".cargo/config", ".cargo/config.toml")},
        "rust_toolchain": {rel: _sha_file(repo / rel) for rel in ("rust-toolchain", "rust-toolchain.toml")},
        "fixture_evidence": _fixture_evidence(repo, checkout),
        "cargo_binary_identity": _cargo_binary_identity(env),
        "cargo_version_verbose": _run(["cargo", f"+{CHANNEL}", "-Vv"], env=env)["stdout"],
        "target_platform": _target_platform(env),
        "cwd": str(repo), "effective_env": {k: env[k] for k in sorted(env)},
        "install": install, "failure_class": _failure_class(install.get("stderr", "")),
    }


def _materialize_and_install(repo: Path, pre_cmds, install_cmd, env, checkout):
    for cmd in pre_cmds:
        _run(["bash", "-c", cmd], cwd=str(repo), env={**env, "PYTHONPATH": str(checkout)}, tmo=300)
    ienv, argv = pub.split_env(install_cmd)                 # shared shell parser, not str.split
    run = _run(["cargo", f"+{CHANNEL}", *argv[1:]] if argv and argv[0] == "cargo" else argv,
               cwd=str(repo), env={**env, **ienv}, tmo=2400)
    run["command"] = install_cmd
    return run


def _fresh_tokio(workdir: Path, base: str, env) -> Path:
    subprocess.run(["git", "init", "-q", str(workdir)], check=True)
    _git(workdir, "fetch", "-q", "--depth", "1", TOKIO_GIT, base)
    _git(workdir, "checkout", "-q", "FETCH_HEAD")
    return workdir


def part_a_b(base, recipe, workroot, checkout):
    env = _cargo_env(workroot / ".home_n2e")
    (workroot / ".home_n2e").mkdir()
    repo = _fresh_tokio(workroot / "repo", base, env)
    install = _materialize_and_install(repo, recipe.get("pre_install", []), recipe["install"][0], env, checkout)
    meta = _run(["cargo", f"+{CHANNEL}", "metadata", "--locked", "--format-version", "1"],
                cwd=str(repo), env=env, tmo=900)
    return (_identity(env, repo, checkout, base, install),
            {"exit": meta["exit"], "stderr_tail": meta["stderr"][-2000:], "ok": meta["exit"] == 0},
            (repo / "Cargo.lock").read_bytes() if (repo / "Cargo.lock").is_file() else b"")


def _parse_lock_multiset(data: bytes) -> dict:
    if tomllib is None:
        return {"error": "tomllib unavailable"}
    doc = tomllib.loads(data.decode("utf-8", "replace"))
    tuples, by_name = {}, {}
    for p in doc.get("package", []):
        key = (p.get("name"), p.get("version"), p.get("source"), p.get("checksum"))
        tuples[key] = tuples.get(key, 0) + 1
        by_name.setdefault(p.get("name"), []).append(p.get("version"))
    return {"format_version": doc.get("version"), "tuples": tuples, "by_name": by_name,
            "package_count": len(doc.get("package", []))}


def _lock_diff(before: bytes, after: bytes) -> dict:
    a, b = _parse_lock_multiset(before), _parse_lock_multiset(after)
    if "error" in a or "error" in b:
        return {"error": "tomllib unavailable"}
    at, bt = a["tuples"], b["tuples"]
    added = [{"name": k[0], "version": k[1], "source": k[2], "checksum": k[3], "count": bt[k] - at.get(k, 0)}
             for k in bt if bt[k] > at.get(k, 0)]
    removed = [{"name": k[0], "version": k[1], "source": k[2], "checksum": k[3], "count": at[k] - bt.get(k, 0)}
               for k in at if at[k] > bt.get(k, 0)]
    return {"format_version_before": a["format_version"], "format_version_after": b["format_version"],
            "format_changed": a["format_version"] != b["format_version"],
            "package_count_before": a["package_count"], "package_count_after": b["package_count"],
            "tuples_added": sorted(added, key=lambda x: (x["name"] or "", x["version"] or "")),
            "tuples_removed": sorted(removed, key=lambda x: (x["name"] or "", x["version"] or "")),
            "added_count": len(added), "removed_count": len(removed),
            "duplicate_versions_before": {n: v for n, v in a["by_name"].items() if len(set(v)) > 1},
            "duplicate_versions_after": {n: v for n, v in b["by_name"].items() if len(set(v)) > 1},
            "before_sha256": hashlib.sha256(before).hexdigest(), "before_bytes": len(before),
            "after_sha256": hashlib.sha256(after).hexdigest(), "after_bytes": len(after),
            "keyed_by": "(name, version, source, checksum) multiset"}


def part_c(base, recipe, workroot, publisher_lock, checkout):
    env = _cargo_env(workroot / ".home_c")
    (workroot / ".home_c").mkdir()
    disp = _fresh_tokio(workroot / "disposable", base, env)
    for cmd in recipe.get("pre_install", []):
        _run(["bash", "-c", cmd], cwd=str(disp), env=env, tmo=300)
    ienv, argv = pub.split_env(recipe["install"][0])
    unlocked = _run(["cargo", f"+{CHANNEL}", *[a for a in argv[1:] if a != "--locked"]],
                    cwd=str(disp), env={**env, **ienv}, tmo=2400)
    return {"unlocked_install_exit": unlocked["exit"], "unlocked_install_stderr_tail": unlocked["stderr"][-2000:],
            "structured_lock_diff": _lock_diff(publisher_lock, (disp / "Cargo.lock").read_bytes()),
            "note": "regenerated lock is DIAGNOSTIC ONLY -- never used for qualification"}


def part_d(base, workroot, checkout, registry_pre_install):
    """Reproduce via the pinned harness SOURCE CHECKOUT. FAILS CLOSED on any gate."""
    reasons = []
    bundle_head = _git(checkout, "rev-parse", "HEAD")["stdout"].strip()
    if bundle_head != HARNESS_COMMIT:
        reasons.append(f"bundle HEAD {bundle_head} != pinned harness {HARNESS_COMMIT}")
    penv = {**os.environ, "PYTHONPATH": str(checkout)}
    probe = (
        "import json,swebench.harness.constants.rust as R\n"
        "from pathlib import Path\n"
        "specs=R.MAP_REPO_VERSION_TO_SPECS_RUST.get('tokio-rs/tokio',{})\n"
        "fx=Path(R.__file__).parent/'fixtures'/'tokio-rs__tokio-4384.Cargo.lock'\n"
        "pre=R._write_cargo_lock_script('tokio-rs__tokio-4384.Cargo.lock')\n"
        "print(json.dumps({'rust_py_file':R.__file__,'has_4384':'4384' in specs,'spec':specs.get('4384'),"
        "'fixture':str(fx),'fixture_exists':fx.is_file(),'pre_install':pre}))\n")
    ex = _run([sys.executable, "-c", probe], env=penv, tmo=180)
    if ex["exit"] != 0:
        reasons.append(f"upstream spec/pre-install generation failed: {ex['stderr'][-400:]}")
        return {"status": "TOKIO_UPSTREAM_REPRODUCTION_DEFECT", "reasons": reasons,
                "bundle_head": bundle_head, "spec_probe": ex["stdout"][-400:] or ex["stderr"][-400:]}
    info = json.loads(ex["stdout"])
    if str(checkout) not in info.get("rust_py_file", ""):
        reasons.append(f"rust.py not loaded from checkout: {info.get('rust_py_file')}")
    if not info.get("fixture_exists"):
        reasons.append("fixture does not resolve inside the checkout")
    if not info.get("has_4384") or not info.get("spec"):
        reasons.append("TOKIO_SPECS['4384'] absent from the pinned source")
    gen_pre = info.get("pre_install") or []
    if gen_pre != registry_pre_install:
        reasons.append("generated pre-install differs from the mechanically-extracted pinned source")
    if reasons:
        return {"status": "TOKIO_UPSTREAM_REPRODUCTION_DEFECT", "reasons": reasons,
                "bundle_head": bundle_head, "generated_pre_install_matches_registry": gen_pre == registry_pre_install}
    spec = info["spec"]
    env = _cargo_env(workroot / ".home_d")
    (workroot / ".home_d").mkdir()
    up = _fresh_tokio(workroot / "upstream_repo", base, env)
    up_head = _git(up, "rev-parse", "HEAD")["stdout"].strip()
    if up_head != base:
        reasons.append(f"fresh tokio HEAD {up_head} != dataset base {base}")
        return {"status": "TOKIO_UPSTREAM_REPRODUCTION_DEFECT", "reasons": reasons, "bundle_head": bundle_head}
    install = _materialize_and_install(up, gen_pre, spec["install"][0], env, checkout)
    return {"status": "upstream_install_ran", "bundle_head": bundle_head,
            "rust_py_loaded_from_checkout": True, "fixture_resolves_inside_checkout": True,
            "generated_pre_install_matches_registry": True,
            "identity": _identity(env, up, checkout, base, install)}


def _provenance_evidence(checkout: Path, revision: str) -> dict:
    """Immutable evidence connecting harness f7bbbb2 <-> dataset revision (item 6). Both
    merely containing instance '4384' is INSUFFICIENT. Search publisher-controlled files
    in the pinned harness for an explicit dataset reference/revision."""
    hits = []
    for rel in ("swebench/harness/constants/__init__.py", "swebench/harness/constants/rust.py",
                "swebench/harness/run_evaluation.py", "README.md", "pyproject.toml",
                "swebench/collect/build_dataset_ft.py"):
        p = checkout / rel
        if p.is_file():
            txt = p.read_text(errors="replace")
            if "Multilingual" in txt or revision in txt or "SWE-bench_Multilingual" in txt:
                hits.append({"path": rel, "mentions_revision": revision in txt,
                             "mentions_multilingual": "Multilingual" in txt})
    return {"dataset_revision": revision, "harness_commit": HARNESS_COMMIT,
            "publisher_pair_evidence": hits,
            "compatible_pair_proven": any(h["mentions_revision"] for h in hits),
            "note": "shared presence of instance '4384' is NOT a pair proof; a published "
                    "manifest/workflow/dataset reference tying the revision to the harness is required"}


def _unbundle_checkout(workroot: Path) -> Path:
    checkout = workroot / "harness"
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    _git(checkout, "bundle", "unbundle", str(BUNDLE))
    _git(checkout, "checkout", "-q", HARNESS_COMMIT)
    return checkout


def build() -> dict:
    revision = next(h["revision"] for h in c.load_record(PINS)["hf_datasets"]
                    if h["source_id"] == "swe-bench-multilingual")
    recipe = pub.recipe_for_case(CASE_ID)
    row = _hf_row(INSTANCE, revision)
    row_hash = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
    base = row["base_commit"]
    workroot = Path(tempfile.mkdtemp(prefix="tokio-probe-"))
    try:
        checkout = _unbundle_checkout(workroot)
        n2e_identity, meta, publisher_lock = part_a_b(base, recipe, workroot, checkout)
        c_res = part_c(base, recipe, workroot, publisher_lock, checkout)
        d_res = part_d(base, workroot, checkout, recipe.get("pre_install", []))
        prov = _provenance_evidence(checkout, revision)
    finally:
        shutil.rmtree(workroot, ignore_errors=True)

    classification_input = {
        "n2e_locked_exit": n2e_identity["install"]["exit"],
        "n2e_failure_class": n2e_identity["failure_class"]["class"],
        "upstream_status": d_res.get("status"),
        "upstream_failure_class": (d_res.get("identity", {}).get("failure_class", {}) or {}).get("class"),
        "compatible_pair_proven": prov["compatible_pair_proven"],
        "boundary": {
            "upstream_source_checkout_reproduction_succeeds": "HARNESS_DEFECT (diff + fix N2-E)",
            "upstream_fails_identically_all_identities_match_via_parity_verifier":
                "DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE",
            "no_compatible_pair_proof": "SOURCE_PROVENANCE_DEFECT (before unreproducibility)",
            "upstream_reproduction_defect": "TOKIO_UPSTREAM_REPRODUCTION_DEFECT (fix the probe, re-run)",
        },
        "classification": None,  # decided by verify_n2e_tokio_parity + reviewer
    }
    return c.envelope(
        record_type="tokio-4384-publisher-recipe-consistency",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/probe_tokio_recipe_consistency.py",
        purpose="Symmetric N2-E vs upstream-source-checkout identity + failure evidence for the "
                "pinned tokio-4384 substrate; classification deferred to the parity verifier.",
        instance_id=INSTANCE, case_id=CASE_ID, dataset_revision=revision, instance_row_sha256=row_hash,
        base_commit=base, rust_channel=CHANNEL, harness_commit=HARNESS_COMMIT,
        publisher_recipe=recipe["source"], registry_sha256=pub.registry_sha256(),
        n2e_identity=n2e_identity, part_b_cargo_metadata=meta, part_c_disposable_lock_diff=c_res,
        part_d_upstream=d_res, harness_dataset_provenance=prov,
        classification_input=classification_input)


def main() -> int:
    rec = build()
    c.write_record(OUT, rec)
    fe = rec["n2e_identity"]["fixture_evidence"]
    print(f"wrote {OUT.name}: n2e_exit={rec['n2e_identity']['install']['exit']} "
          f"n2e_failure={rec['n2e_identity']['failure_class']['class']} "
          f"upstream={rec['part_d_upstream'].get('status')} "
          f"pair_proven={rec['harness_dataset_provenance']['compatible_pair_proven']}")
    print(f"  fixture byte_identical={fe['byte_identical']} trailing_newline_only={fe['diff_is_solely_trailing_newline']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
