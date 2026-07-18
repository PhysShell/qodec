#!/usr/bin/env python3
"""Focused publisher-recipe consistency probe for tokio-rs__tokio-4384.

The publisher-provided Cargo.lock is rejected by the publisher's own `--locked` install
("the lock file needs to be updated"). This probe gathers terminal evidence WITHOUT
choosing a lock, and it REPRODUCES through the pinned upstream harness SOURCE CHECKOUT
(never a pip-installed wheel, whose fixtures may be absent):

  A. exact pre-install state (identities of every input to the locked command);
  B. the exact `--locked` install failure (+ `cargo metadata --locked`);
  C. DISPOSABLE-copy structured Cargo.lock diff via tomllib, multiset-keyed by
     (name, version, source, checksum) -- diagnostic only, never used for qualification;
  D. reproduction through the pinned SWE-bench harness at commit f7bbbb2, loaded from an
     unbundled SOURCE CHECKOUT (its own fixture bytes), running the exact publisher
     pre-install + install on a fresh tokio base checkout with no gold/test patch.

Classification is deferred to the evidence (`classification_input.boundary`). Network is
ENABLED (diagnostic, not a measurement).
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
    import tomllib  # py3.11+
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


def _run(argv, cwd=None, env=None, tmo=1800):
    try:
        p = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=tmo)
        return {"argv": list(argv), "exit": p.returncode,
                "stdout": p.stdout.decode("utf-8", "replace"), "stderr": p.stderr.decode("utf-8", "replace"),
                "stdout_sha256": hashlib.sha256(p.stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(p.stderr).hexdigest(),
                "stdout_bytes": len(p.stdout), "stderr_bytes": len(p.stderr)}
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
    """Correction 5: never a null shim identity. Record the cargo on PATH (symlink or
    file), its resolved target, the rustup-which real binary, and the real binary hash."""
    which = _run(["bash", "-c", "command -v cargo"], env=env)["stdout"].strip()
    ident = {"command_v_cargo": which}
    if which:
        p = Path(which)
        ident["is_symlink"] = p.is_symlink()
        if p.is_symlink():
            ident["symlink_target"] = os.readlink(which)
        ident["path_entry_sha256"] = _sha_file(p) if p.is_file() else None
        real = subprocess.run(["realpath", which], capture_output=True, text=True).stdout.strip()
        ident["realpath"] = real
        ident["realpath_sha256"] = _sha_file(Path(real)) if real else None
    rw = _run(["rustup", "which", "--toolchain", CHANNEL, "cargo"], env=env)["stdout"].strip()
    ident["rustup_which_cargo"] = rw
    ident["rustup_which_cargo_sha256"] = _sha_file(Path(rw)) if rw else None
    ident["real_cargo_binary_sha256"] = ident["rustup_which_cargo_sha256"] or ident.get("realpath_sha256")
    return ident


def _member_manifests(repo: Path) -> dict:
    return {str(p.relative_to(repo)): _sha_file(p) for p in sorted(repo.rglob("Cargo.toml"))}


def _fixture_evidence(repo: Path, checkout: Path) -> dict:
    """Correction 5: real fixture identity + exact byte diff vs the materialized lock."""
    ev = {}
    # upstream fixture from the pinned harness SOURCE CHECKOUT
    up_path = checkout / UPSTREAM_FIXTURE_PATH
    up = up_path.read_bytes() if up_path.is_file() else b""
    blob = _git(checkout, "rev-parse", f"{HARNESS_COMMIT}:{UPSTREAM_FIXTURE_PATH}")["stdout"].strip()
    ev["upstream_fixture_path"] = UPSTREAM_FIXTURE_PATH
    ev["upstream_fixture_git_blob"] = blob
    ev["upstream_fixture_bytes"] = len(up)
    ev["upstream_fixture_sha256"] = hashlib.sha256(up).hexdigest()
    # materialized lock in the repo (written by the publisher pre-install heredoc)
    lock = repo / "Cargo.lock"
    mat = lock.read_bytes() if lock.is_file() else b""
    ev["materialized_cargo_lock_bytes"] = len(mat)
    ev["materialized_cargo_lock_sha256"] = hashlib.sha256(mat).hexdigest()
    ev["byte_length_delta"] = len(mat) - len(up)
    ev["byte_identical"] = mat == up
    # is the ONLY difference a single trailing newline the heredoc appends?
    ev["diff_is_solely_trailing_newline"] = (mat == up + b"\n")
    ev["materialized_extra_suffix"] = mat[len(up):].decode("utf-8", "replace") if mat.startswith(up) else None
    return ev


def part_a_b(base, recipe, workroot, checkout):
    repo = workroot / "repo"
    home = workroot / ".home"
    home.mkdir()
    env = _cargo_env(home)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    _git(repo, "fetch", "-q", "--depth", "1", "https://github.com/tokio-rs/tokio.git", base)
    _git(repo, "checkout", "-q", "FETCH_HEAD")
    head = _git(repo, "rev-parse", "HEAD")["stdout"].strip()
    manifests_pristine = _member_manifests(repo)
    for cmd in recipe.get("pre_install", []):
        _run(["bash", "-c", cmd], cwd=str(repo), env=env, tmo=300)
    fixture_ev = _fixture_evidence(repo, checkout)
    cargo_id = _cargo_binary_identity(env)
    pre = {
        "base_commit": base, "head": head, "head_matches_base": head == base,
        "tracked_status_clean": _git(repo, "status", "--porcelain", "--untracked-files=no")["stdout"].strip() == "",
        "workspace_member_manifests_pristine": manifests_pristine,
        "cargo_config": {rel: _sha_file(repo / rel) for rel in (".cargo/config", ".cargo/config.toml")},
        "rust_toolchain": {rel: _sha_file(repo / rel) for rel in ("rust-toolchain", "rust-toolchain.toml")},
        "fixture_evidence": fixture_ev,
        "no_gold_or_test_patch_applied": True, "cwd": str(repo), "PATH": env["PATH"],
        "cargo_binary_identity": cargo_id,
        "cargo_version_verbose": _run(["cargo", f"+{CHANNEL}", "-Vv"], env=env)["stdout"],
    }
    env2, argv = pub.split_env(recipe["install"][0])
    locked = _run(["cargo", f"+{CHANNEL}", *argv[1:]], cwd=str(repo), env={**env, **env2}, tmo=2400)
    meta = _run(["cargo", f"+{CHANNEL}", "metadata", "--locked", "--format-version", "1"],
                cwd=str(repo), env=env, tmo=900)
    return ({"pre_install_state": pre, "locked_install": {"command": recipe["install"][0], **locked},
             "cargo_metadata_locked": {"exit": meta["exit"], "stderr_tail": meta["stderr"][-2000:],
                                       "ok": meta["exit"] == 0}},
            (repo / "Cargo.lock").read_bytes() if (repo / "Cargo.lock").is_file() else b"")


def _parse_lock_multiset(data: bytes) -> dict:
    """Correction 6: tomllib parse; packages as a MULTISET keyed by (name,version,source,
    checksum). Returns {format_version, tuples: Counter-like list, by_name: {name:[...]}}"""
    if tomllib is None:
        return {"error": "tomllib unavailable"}
    doc = tomllib.loads(data.decode("utf-8", "replace"))
    tuples = {}
    by_name = {}
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
    # duplicate versions (same name, >1 distinct version) reported independently
    dup_before = {n: v for n, v in a["by_name"].items() if len(set(v)) > 1}
    dup_after = {n: v for n, v in b["by_name"].items() if len(set(v)) > 1}
    return {
        "format_version_before": a["format_version"], "format_version_after": b["format_version"],
        "format_changed": a["format_version"] != b["format_version"],
        "package_count_before": a["package_count"], "package_count_after": b["package_count"],
        "tuples_added": sorted(added, key=lambda x: (x["name"] or "", x["version"] or "")),
        "tuples_removed": sorted(removed, key=lambda x: (x["name"] or "", x["version"] or "")),
        "added_count": len(added), "removed_count": len(removed),
        "duplicate_versions_before": dup_before, "duplicate_versions_after": dup_after,
        "before_sha256": hashlib.sha256(before).hexdigest(), "before_bytes": len(before),
        "after_sha256": hashlib.sha256(after).hexdigest(), "after_bytes": len(after),
        "keyed_by": "(name, version, source, checksum) multiset",
    }


def part_c(base, recipe, workroot, publisher_lock):
    disp = workroot / "disposable"
    env = _cargo_env(workroot / ".home")
    subprocess.run(["git", "init", "-q", str(disp)], check=True)
    _git(disp, "fetch", "-q", "--depth", "1", "https://github.com/tokio-rs/tokio.git", base)
    _git(disp, "checkout", "-q", "FETCH_HEAD")
    for cmd in recipe.get("pre_install", []):
        _run(["bash", "-c", cmd], cwd=str(disp), env=env, tmo=300)
    env2, argv = pub.split_env(recipe["install"][0])
    unlocked = _run(["cargo", f"+{CHANNEL}", *[a for a in argv[1:] if a != "--locked"]],
                    cwd=str(disp), env={**env, **env2}, tmo=2400)
    regenerated = (disp / "Cargo.lock").read_bytes()
    return {"unlocked_install_exit": unlocked["exit"], "unlocked_install_stderr_tail": unlocked["stderr"][-2000:],
            "structured_lock_diff": _lock_diff(publisher_lock, regenerated),
            "note": "regenerated lock is DIAGNOSTIC ONLY -- never used for qualification"}


def part_d(base, workroot, checkout):
    """Reproduce via the pinned harness SOURCE CHECKOUT (PYTHONPATH), not a pip wheel."""
    env = _cargo_env(workroot / ".home_d")
    (workroot / ".home_d").mkdir(exist_ok=True)
    penv = {**os.environ, "PYTHONPATH": str(checkout)}
    # prove rust.py + fixtures resolve INSIDE the checkout, and extract TOKIO_SPECS[4384]
    probe = (
        "import json,swebench.harness.constants.rust as R\n"
        "specs=R.MAP_REPO_VERSION_TO_SPECS_RUST.get('tokio-rs/tokio',{})\n"
        "s=specs.get('4384')\n"
        "from pathlib import Path\n"
        "fx=Path(R.__file__).parent/'fixtures'/'tokio-rs__tokio-4384.Cargo.lock'\n"
        "print(json.dumps({'rust_py_file':R.__file__,'has_4384':'4384' in specs,'spec':s,"
        "'fixture_resolves_inside':str(fx),'fixture_exists':fx.is_file()}))\n")
    ex = _run([sys.executable, "-c", probe], env=penv, tmo=180)
    attempt = {"harness_commit": HARNESS_COMMIT, "source": "unbundled checkout (PYTHONPATH)",
               "checkout_head": _git(checkout, "rev-parse", "HEAD")["stdout"].strip(),
               "spec_probe_exit": ex["exit"], "spec_probe": ex["stdout"].strip() or ex["stderr"][-1500:]}
    if ex["exit"] != 0:
        attempt["status"] = "harness_spec_unreadable"
        return attempt
    spec = json.loads(ex["stdout"]).get("spec") or {}
    attempt["rust_py_loaded_from_checkout"] = str(checkout) in json.loads(ex["stdout"]).get("rust_py_file", "")
    attempt["fixture_resolves_inside_checkout"] = json.loads(ex["stdout"]).get("fixture_exists")
    # fresh tokio base checkout, NO gold/test patch, run publisher pre-install + install
    up = workroot / "upstream_repo"
    subprocess.run(["git", "init", "-q", str(up)], check=True)
    _git(up, "fetch", "-q", "--depth", "1", "https://github.com/tokio-rs/tokio.git", base)
    _git(up, "checkout", "-q", "FETCH_HEAD")
    # materialize the upstream fixture via the harness's OWN pre_install (reads its fixture)
    gen = _run([sys.executable, "-c",
                "import json,swebench.harness.constants.rust as R;"
                "print(json.dumps(R._write_cargo_lock_script('tokio-rs__tokio-4384.Cargo.lock')))"],
               env=penv, tmo=120)
    pre_cmds = json.loads(gen["stdout"]) if gen["exit"] == 0 else recipe_preinstall_fallback()
    for cmd in pre_cmds:
        _run(["bash", "-c", cmd], cwd=str(up), env={**env, "PYTHONPATH": str(checkout)}, tmo=300)
    install_cmd = spec.get("install", [None])[0]
    attempt["generated_pre_install"] = pre_cmds
    attempt["upstream_install_command"] = install_cmd
    if install_cmd:
        # split leading VAR=val, run under the pinned toolchain
        parts = install_cmd.split()
        env3 = {}
        i = 0
        while i < len(parts) and "=" in parts[i] and parts[i].split("=")[0].isupper():
            k, v = parts[i].split("=", 1)
            env3[k] = v
            i += 1
        argv = parts[i:]
        run = _run(["cargo", f"+{CHANNEL}", *argv[1:]] if argv and argv[0] == "cargo" else argv,
                   cwd=str(up), env={**env, **env3}, tmo=2400)
        attempt["upstream_locked_install"] = {"command": install_cmd, "exit": run["exit"],
                                              "stderr_tail": run["stderr"][-2500:], "cwd": str(up),
                                              "stdout_sha256": run.get("stdout_sha256"),
                                              "stderr_sha256": run.get("stderr_sha256")}
        attempt["status"] = "upstream_install_ran"
    else:
        attempt["status"] = "no_upstream_install_command"
    return attempt


def recipe_preinstall_fallback():
    return pub.recipe_for_case(CASE_ID).get("pre_install", [])


def _unbundle_checkout(workroot: Path) -> Path:
    checkout = workroot / "harness"
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    _git(checkout, "bundle", "unbundle", str(BUNDLE))
    head = _git(checkout, "checkout", "-q", HARNESS_COMMIT)
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
        bundle_head = _git(checkout, "rev-parse", "HEAD")["stdout"].strip()
        ab, publisher_lock = part_a_b(base, recipe, workroot, checkout)
        c_res = part_c(base, recipe, workroot, publisher_lock)
        d_res = part_d(base, workroot, checkout)
    finally:
        shutil.rmtree(workroot, ignore_errors=True)

    n2e_exit = ab["locked_install"]["exit"]
    up_install = (d_res.get("upstream_locked_install") or {})
    classification_input = {
        "n2e_locked_install_failed": n2e_exit not in (0, None), "n2e_locked_exit": n2e_exit,
        "upstream_status": d_res.get("status"), "upstream_locked_exit": up_install.get("exit"),
        "harness_bundle_head_matches_pin": bundle_head == HARNESS_COMMIT,
        "fixture_byte_identical": ab["pre_install_state"]["fixture_evidence"]["byte_identical"],
        "fixture_diff_is_trailing_newline_only":
            ab["pre_install_state"]["fixture_evidence"]["diff_is_solely_trailing_newline"],
        "boundary": {
            "upstream_source_checkout_reproduction_succeeds": "HARNESS_DEFECT (diff + fix N2-E)",
            "upstream_fails_identically_all_identities_match": "DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE",
            "harness_dataset_pair_incompatible": "SOURCE_PROVENANCE_DEFECT (pin matching pair)",
        },
        "classification": None,  # decided by reviewer from this evidence
        "note": "TOKIO_RECIPE_PROBE result; classification only after a REAL Part D that ran "
                "the publisher install from the pinned harness source checkout.",
    }
    return c.envelope(
        record_type="tokio-4384-publisher-recipe-consistency",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/probe_tokio_recipe_consistency.py",
        purpose="Distinguish HARNESS_DEFECT / DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE / "
                "SOURCE_PROVENANCE_DEFECT for the pinned tokio-4384 substrate; classification deferred.",
        instance_id=INSTANCE, case_id=CASE_ID, dataset_revision=revision, instance_row_sha256=row_hash,
        base_commit=base, rust_channel=CHANNEL, harness_commit=HARNESS_COMMIT,
        harness_bundle_head=bundle_head, publisher_recipe=recipe["source"],
        registry_sha256=pub.registry_sha256(),
        part_a_pre_install_state=ab["pre_install_state"], part_b_locked_failure=ab["locked_install"],
        part_b_cargo_metadata=ab["cargo_metadata_locked"], part_c_disposable_lock_diff=c_res,
        part_d_upstream_source_checkout=d_res, classification_input=classification_input)


def main() -> int:
    rec = build()
    c.write_record(OUT, rec)
    fe = rec["part_a_pre_install_state"]["fixture_evidence"]
    d = rec["part_c_disposable_lock_diff"].get("structured_lock_diff", {})
    print(f"wrote {OUT.name}: n2e_locked_exit={rec['part_b_locked_failure']['exit']} "
          f"upstream_status={rec['part_d_upstream_source_checkout'].get('status')} "
          f"upstream_exit={(rec['part_d_upstream_source_checkout'].get('upstream_locked_install') or {}).get('exit')}")
    print(f"  fixture: byte_identical={fe['byte_identical']} "
          f"trailing_newline_only={fe['diff_is_solely_trailing_newline']} delta={fe['byte_length_delta']}")
    print(f"  lock diff (tomllib multiset): +{d.get('added_count')} -{d.get('removed_count')} "
          f"format_changed={d.get('format_changed')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
