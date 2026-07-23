#!/usr/bin/env python3
"""Build tokio-4384-instance-recipe-applicability-v1 (ruling step 1).

Proves -- OFFLINE, from already-pinned bytes, WITHOUT another Tokio execution -- that
the pinned SWE-bench harness's OWN recipe-selection mechanism deterministically maps the
pinned instance (repo, version) to exactly the recipe V4 executed. This is the
instance-level applicability bar that REPLACES the withdrawn global harness<->dataset
revision-pair cross-pin gate (VERIFIER_DEFECT_PROVENANCE_GATE_PRECEDENCE).

Inputs (all pinned/committed):
  * fixtures/swebench-source/swebench-f7bbbb2.bundle  -- the harness at commit f7bbbb2;
  * n2e-swebench-instances-v1.json                    -- pinned instance row (dataset rev);
  * n2e-publisher-env-registry-v1.json                -- mechanical registry extraction;
  * tokio-4384-publisher-recipe-consistency-v1.json   -- preserved V4 evidence.

It materializes the harness tree from the bundle, verifies rust.py's blob identity,
imports it, and resolves R.MAP_REPO_VERSION_TO_SPECS_RUST[row.repo][row.version] to the
per-instance spec, then requires BYTE-FOR-BYTE equality between that spec (pre_install
Cargo.lock heredoc, install, test_cmd, docker rust_version, fixture blob/sha256/bytes)
and the registry extraction, plus agreement with V4's executed install command and the
pinned instance identity (instance_id/repo/version/base_commit).
"""
from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

BUNDLE = N2E_DIR / "fixtures" / "swebench-source" / "swebench-f7bbbb2.bundle"
INSTANCES = N2E_DIR / "n2e-swebench-instances-v1.json"
REGISTRY = N2E_DIR / "n2e-publisher-env-registry-v1.json"
V4 = N2E_DIR / "tokio-4384-publisher-recipe-consistency-v1.json"
OUT = N2E_DIR / "tokio-4384-instance-recipe-applicability-v1.json"

INSTANCE_ID = "tokio-rs__tokio-4384"
CASE_ID = "tokio-rs__tokio-4384::rust_cargo::test::fixed"
HARNESS_COMMIT = "f7bbbb2ccdf479001d6467c9e34af59e44a840f9"
RUST_PY_REL = "swebench/harness/constants/rust.py"
RUST_PY_BLOB_SHA1 = "068c7c2414edbcc14d42cca3bae96d27bdfb39f4"
RUST_PY_SHA256 = "1ad97f35f1202ef2a69c066b29d2edc5f552fd62db2230f38d2f7dd91a4a3da2"
POLICY_ID = "n2e-tokio-instance-recipe-applicability-v1"


def _run(cmd, cwd=None, **kw):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True, **kw)


def _materialize_harness(dst: Path) -> Path:
    """Extract the pinned harness tree at f7bbbb2 from the committed bundle.

    The bundle records f7bbbb2 as a full snapshot but lists an ancestor as a
    prerequisite, so a connectivity-checking `git fetch`/`clone` refuses it. We index
    the bundle's packfile directly (bypassing the parent-traversal check) and read the
    tree -- the snapshot's objects (tree + blobs) are all present, which is exactly what
    a per-instance recipe resolution needs.
    """
    raw = BUNDLE.read_bytes()
    off = raw.find(b"PACK")
    if off < 0:
        raise SystemExit("bundle: no PACK signature")
    pack = dst / "only.pack"
    pack.write_bytes(raw[off:])
    repo = dst / "repo"
    repo.mkdir()
    _run(["git", "init", "-q"], cwd=repo)
    with open(pack, "rb") as fh:
        subprocess.run(["git", "index-pack", "--stdin", "--fix-thin"],
                       cwd=repo, check=True, stdin=fh, capture_output=True)
    _run(["git", "read-tree", HARNESS_COMMIT], cwd=repo)
    tree = repo / "tree"
    _run(["git", "checkout-index", "-a", "-f", f"--prefix={tree}/"], cwd=repo)
    # blob identity of rust.py as recorded by the pinned harness commit
    blob = _run(["git", "ls-tree", HARNESS_COMMIT, RUST_PY_REL], cwd=repo).stdout.split()[2]
    if blob != RUST_PY_BLOB_SHA1:
        raise SystemExit(f"rust.py blob {blob} != pinned {RUST_PY_BLOB_SHA1}")
    return tree


def _load_rust(tree: Path):
    rp = tree / RUST_PY_REL
    got = hashlib.sha256(rp.read_bytes()).hexdigest()
    if got != RUST_PY_SHA256:
        raise SystemExit(f"rust.py sha256 {got} != pinned {RUST_PY_SHA256}")
    spec = importlib.util.spec_from_file_location("pinned_rust_applic", rp)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, got


def build() -> dict:
    instances = c.load_record(INSTANCES)
    row = next(r for r in instances["instances"] if r["instance_id"] == INSTANCE_ID)
    reg = c.load_record(REGISTRY)
    recipe = next(r for r in reg["recipes"] if r["case_id"] == CASE_ID)
    v4 = c.load_record(V4)
    v4n = v4["n2e_identity"]

    with tempfile.TemporaryDirectory(prefix="n2e-applic-") as td:
        tree = _materialize_harness(Path(td))
        R, rust_sha256 = _load_rust(tree)
        # THE harness's own recipe-selection mechanism -- purely (repo, version):
        spec_dict = R.MAP_REPO_VERSION_TO_SPECS_RUST[row["repo"]]
        spec = spec_dict[row["version"]]
        # fixture the resolved spec's pre_install materializes:
        fx = tree / "swebench" / "harness" / "constants" / "fixtures" / f"{INSTANCE_ID}.Cargo.lock"
        fx_bytes = fx.read_bytes()
        fx_sha256 = hashlib.sha256(fx_bytes).hexdigest()
        # git blob sha1 computed directly (blob <len>\0 + content) -- no path ambiguity
        fx_blob = hashlib.sha1(b"blob " + str(len(fx_bytes)).encode() + b"\x00" + fx_bytes).hexdigest()
        resolved = {
            "docker_rust_version": spec["docker_specs"]["rust_version"],
            "pre_install": spec["pre_install"],
            "install": spec["install"],
            "test_cmd": spec["test_cmd"],
            "spec_dict_name": "TOKIO_SPECS", "spec_key": row["version"],
        }

    src = recipe["source"]
    reg_fx = reg["source_bundle"][f"fixtures/{INSTANCE_ID}.Cargo.lock"]
    v4fx = v4n["fixture_evidence"]

    # ---- equalities (byte-for-byte against the mechanical registry extraction) -------
    eq = {
        "instance_id_matches": row["instance_id"] == INSTANCE_ID == recipe["instance_id"]
        == v4["instance_id"],
        "repo_matches": row["repo"] == recipe["repository"] == "tokio-rs/tokio",
        "version_matches": row["version"] == recipe["source"]["spec_key"] == "4384"
        == resolved["spec_key"],
        "base_commit_matches": row["base_commit"] == v4["base_commit"]
        == v4n["base_commit"] == "553cc3b194df875cac8736473e1f01cf3e40a660",
        "harness_commit_matches": reg["harness"]["commit"] == HARNESS_COMMIT
        == v4["harness_commit"],
        # rust.py source blob resolves the recipe registry pinned + V4 pinned
        "recipe_source_blob_matches": src["git_blob_sha1"] == RUST_PY_BLOB_SHA1
        == v4["publisher_recipe"]["git_blob_sha1"],
        "recipe_source_sha256_matches": src["sha256"] == rust_sha256 == RUST_PY_SHA256
        == v4["publisher_recipe"]["sha256"],
        "spec_dict_matches": src["spec_dict"] == "TOKIO_SPECS"
        == v4["publisher_recipe"]["spec_dict"],
        # recipe body byte-for-byte
        "pre_install_byte_equal": resolved["pre_install"] == recipe["pre_install"],
        "install_byte_equal": resolved["install"] == recipe["install"],
        "test_cmd_byte_equal": resolved["test_cmd"] == recipe["test_cmd"],
        "docker_rust_version_equal": resolved["docker_rust_version"]
        == recipe["toolchain"]["docker_specs"]["rust_version"] == "1.83",
        # resolved install == the command V4 actually executed
        "install_matches_v4_executed": resolved["install"][0] == v4n["install"]["command"],
        # fixture identity: resolved-spec fixture == registry source_bundle == V4 upstream
        "fixture_blob_equal": fx_blob == reg_fx["git_blob_sha1"]
        == v4fx["upstream_fixture_git_blob"] == "903110c1640b9c408631c89d642157b286bce642",
        "fixture_sha256_equal": fx_sha256 == reg_fx["sha256"]
        == v4fx["upstream_fixture_sha256"],
        "fixture_bytes_equal": len(fx_bytes) == reg_fx["bytes"]
        == v4fx["upstream_fixture_bytes"] == 43465,
    }
    applicable = all(eq.values())

    return c.envelope(
        record_type="n2e-tokio-instance-recipe-applicability",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/"
                     "build_n2e_tokio_instance_recipe_applicability.py",
        purpose="Offline proof that the pinned SWE-bench harness maps the pinned instance "
                "(repo, version) to exactly the recipe V4 executed -- the instance-level "
                "applicability bar that replaces the withdrawn global cross-pin gate.",
        policy_id=POLICY_ID,
        case_id=CASE_ID, instance_id=INSTANCE_ID,
        dataset={"id": instances["dataset_id"], "revision": instances["pinned_revision"]},
        harness_commit=HARNESS_COMMIT,
        harness_bundle={
            "path": "fixtures/swebench-source/swebench-f7bbbb2.bundle",
            "sha256": "sha256:" + hashlib.sha256(BUNDLE.read_bytes()).hexdigest(),
        },
        recipe_selection_mechanism="MAP_REPO_VERSION_TO_SPECS_RUST[repo][version] -> "
                                   "TOKIO_SPECS[version] (pinned harness rust.py; no global "
                                   "dataset-revision cross-pin is consulted)",
        pinned_instance_row=row,
        pinned_instance_row_sha256="sha256:" + hashlib.sha256(
            c.compact_canonical_bytes(row)).hexdigest(),
        complete_instance_row_sha256_from_v4=v4["instance_row_sha256"],
        resolved_recipe=resolved,
        registry_recipe_source=src,
        fixture_identity={"path": v4fx["upstream_fixture_path"], "git_blob_sha1": fx_blob,
                          "sha256": fx_sha256, "bytes": len(fx_bytes)},
        v4_executed_install_command=v4n["install"]["command"],
        equalities=eq,
        instance_recipe_applicable=applicable,
        registry_sha256=c.sha256_json_file(REGISTRY),
        swebench_instances_sha256=c.sha256_json_file(INSTANCES),
        v4_consistency_record_sha256=c.sha256_json_file(V4),
        v4_consistency_record_internal_sha256=v4["record_sha256"],
    )


def main() -> int:
    body = build()
    c.write_record(OUT, body)
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name}: instance_recipe_applicable={rec['instance_recipe_applicable']}")
    for k, v in rec["equalities"].items():
        if not v:
            print(f"  UNMET: {k}")
    return 0 if rec["instance_recipe_applicable"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
