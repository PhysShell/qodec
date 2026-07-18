#!/usr/bin/env python3
"""Build coreutils-6731-instance-recipe-applicability-v1 (contract step 4).

Proves offline, from the pinned dataset row + pinned harness bundle, that the harness maps
(uutils/coreutils, 6731) to COREUTILS_SPECS["6731"] -- exactly the recipe carried by the
resolved publisher-env overlay -- and records the full instance identity (complete-row,
base commit, gold/test patch, FAIL_TO_PASS/PASS_TO_PASS hashes, harness commit + bundle,
rust.py path/blob/sha256, spec dict/key, docker/toolchain, install/test command bytes).
Requires BYTE-FOR-BYTE agreement with the resolved publisher overlay recipe.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import build_n2e_tokio_instance_recipe_applicability as tokio_applic  # noqa: E402

INSTANCES = N2E_DIR / "n2e-swebench-instances-v1.json"
ROW = N2E_DIR / "evidence" / "coreutils-6731" / "uutils__coreutils-6731.row.json"
OVERLAY = N2E_DIR / "n2e-resolved-publisher-env-overlay-v1.json"
OUT = N2E_DIR / "coreutils-6731-instance-recipe-applicability-v1.json"

INSTANCE_ID = "uutils__coreutils-6731"
CASE_ID = "uutils__coreutils-6731::rust_cargo::test::fixed"
HARNESS_COMMIT = tokio_applic.HARNESS_COMMIT
RUST_PY_REL = tokio_applic.RUST_PY_REL
RUST_PY_BLOB_SHA1 = tokio_applic.RUST_PY_BLOB_SHA1
RUST_PY_SHA256 = tokio_applic.RUST_PY_SHA256
POLICY_ID = "n2e-coreutils-instance-recipe-applicability-v1"


def _h(x) -> str:
    b = (json.dumps(x, separators=(",", ":"), ensure_ascii=True).encode() if isinstance(x, list)
         else x.encode())
    return "sha256:" + hashlib.sha256(b).hexdigest()


def build() -> dict:
    reduced = next(r for r in c.load_record(INSTANCES)["instances"] if r["instance_id"] == INSTANCE_ID)
    row = c.load_record(ROW)
    overlay = c.load_record(OVERLAY)
    recipe = next(r for r in overlay["overlay_recipes"] if r["case_id"] == CASE_ID)

    import tempfile
    with tempfile.TemporaryDirectory(prefix="n2e-cu-applic-") as td:
        tree = tokio_applic._materialize_harness(Path(td))
        R, rust_sha256 = tokio_applic._load_rust(tree)
        spec = R.MAP_REPO_VERSION_TO_SPECS_RUST[reduced["repo"]][str(reduced["version"])]
        resolved = {
            "docker_rust_version": spec["docker_specs"]["rust_version"],
            "pre_install": spec.get("pre_install", []),
            "install": spec["install"], "test_cmd": spec["test_cmd"],
            "spec_dict_name": "COREUTILS_SPECS", "spec_key": str(reduced["version"]),
        }

    # anchor the fetched complete row to the pinned reduced record (pinned to dataset rev)
    anchor = {
        "base_commit_matches": row["base_commit"] == reduced["base_commit"],
        "repo_matches": row["repo"] == reduced["repo"] == "uutils/coreutils",
        "version_matches": str(row["version"]) == str(reduced["version"]) == "6731",
        "fail_to_pass_matches": row["FAIL_TO_PASS"] == reduced["fail_to_pass"],
        "pass_to_pass_count_matches": len(row["PASS_TO_PASS"]) == reduced["pass_to_pass_count"],
    }

    eq = {
        "instance_id_matches": reduced["instance_id"] == INSTANCE_ID == recipe["instance_id"],
        "repo_matches": reduced["repo"] == recipe["repository"] == "uutils/coreutils",
        "version_matches": str(reduced["version"]) == recipe["source"]["spec_key"] == "6731"
        == resolved["spec_key"],
        "recipe_source_blob_matches": recipe["source"]["git_blob_sha1"] == RUST_PY_BLOB_SHA1,
        "recipe_source_sha256_matches": recipe["source"]["sha256"] == rust_sha256 == RUST_PY_SHA256,
        "spec_dict_matches": recipe["source"]["spec_dict"] == "COREUTILS_SPECS",
        # byte-for-byte agreement with the resolved publisher overlay recipe
        "pre_install_byte_equal": resolved["pre_install"] == recipe["pre_install"],
        "install_byte_equal": resolved["install"] == recipe["install"],
        "test_cmd_byte_equal": resolved["test_cmd"] == recipe["test_cmd"],
        "docker_rust_version_equal": resolved["docker_rust_version"]
        == recipe["toolchain"]["docker_specs"]["rust_version"] == "1.81",
        "anchor_all_true": all(anchor.values()),
    }
    applicable = all(eq.values())

    return c.envelope(
        record_type="n2e-coreutils-instance-recipe-applicability",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/"
                     "build_n2e_coreutils_instance_recipe_applicability.py",
        purpose="Offline proof that the pinned harness maps (uutils/coreutils, 6731) to exactly "
                "the recipe in the resolved publisher-env overlay; full instance identity recorded.",
        policy_id=POLICY_ID, case_id=CASE_ID, instance_id=INSTANCE_ID,
        dataset={"id": c.load_record(INSTANCES)["dataset_id"],
                 "revision": c.load_record(INSTANCES)["pinned_revision"]},
        harness_commit=HARNESS_COMMIT,
        harness_bundle={"path": "fixtures/swebench-source/swebench-f7bbbb2.bundle",
                        "sha256": "sha256:" + hashlib.sha256(
                            tokio_applic.BUNDLE.read_bytes()).hexdigest()},
        recipe_selection_mechanism="MAP_REPO_VERSION_TO_SPECS_RUST[repo][version] -> "
                                   "COREUTILS_SPECS[version] (pinned harness rust.py)",
        base_commit=row["base_commit"],
        complete_instance_row_path="evidence/coreutils-6731/uutils__coreutils-6731.row.json",
        complete_instance_row_sha256=c.sha256_json_file(ROW),
        pinned_reduced_instance_row=reduced,
        gold_patch_sha256=_h(row["patch"]), gold_patch_bytes=len(row["patch"]),
        test_patch_sha256=_h(row["test_patch"]), test_patch_bytes=len(row["test_patch"]),
        fail_to_pass=row["FAIL_TO_PASS"], fail_to_pass_sha256=_h(row["FAIL_TO_PASS"]),
        pass_to_pass_sha256=_h(row["PASS_TO_PASS"]), pass_to_pass_count=len(row["PASS_TO_PASS"]),
        rust_py={"path": RUST_PY_REL, "git_blob_sha1": RUST_PY_BLOB_SHA1, "sha256": RUST_PY_SHA256},
        resolved_spec_dict="COREUTILS_SPECS", resolved_spec_key="6731",
        docker_toolchain=recipe["toolchain"],
        install_command_bytes=recipe["install"], test_command_bytes=recipe["test_cmd"],
        resolved_publisher_overlay_sha256=c.sha256_json_file(OVERLAY),
        swebench_instances_sha256=c.sha256_json_file(INSTANCES),
        anchor_to_pinned_reduced_row=anchor,
        equalities=eq,
        instance_recipe_applicable=applicable,
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
