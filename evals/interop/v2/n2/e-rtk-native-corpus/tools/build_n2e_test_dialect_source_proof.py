#!/usr/bin/env python3
"""Test-dialect SOURCE-IDENTITY + CASE-SCOPE proof (reusable across the four P5.2A test dialects).

Freezes, for a proven test dialect, the exact pinned RTK source identity it was grounded in (commit +
source file + content sha256 + git blob sha + bytes), the semantics-module identity (so the parser
implementation is pinned), the single pinned corpus RTK binary identity, and the CASE-SCOPE binding
to the manifest -- a dialect is proven for LISTED cases only, never family-level (`rtk-files-read-
oracle-v1` will list preact AND lombok as two independent bindings; a test dialect lists its one
case). This is the "source identity + scope proof" that must exist BEFORE a case's acceptance vertical
binds real streams. Sets no promotion flag.

Caddy is the first: rtk-go-test-summary-v1 already exists in the frozen corpus, so this PROVES its
source identity + scope rather than authoring a new policy.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402

MANIFEST = N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"
SRC_DIR = N2E_DIR / "evidence" / "rtk-source"

# policy id -> (semantics module basename, manifest case ids it is proven for -- case-scoped)
DIALECT_PROOFS = {
    "rtk-go-test-summary-v1": ("n2e_rtk_go_test_dialect.py", ["caddyserver__caddy-5870::go::test::buggy"]),
    "rtk-jvm-test-summary-v1": ("n2e_rtk_jvm_test_dialect.py", ["apache__lucene-13704::jvm::test::buggy"]),
    "rtk-js-vitest-summary-v1": ("n2e_rtk_js_vitest_dialect.py", ["vuejs__core-11589::js_ts::test::buggy"]),
    "rtk-python-pytest-summary-v1": ("n2e_rtk_python_pytest_dialect.py", ["bugsinpy::scrapy-9::python::pytest::fixed"]),
}


def _git_blob_sha1(data: bytes) -> str:
    h = hashlib.sha1()
    h.update(b"blob %d\0" % len(data))
    h.update(data)
    return h.hexdigest()


def build_proof(policy_id: str) -> dict:
    module_name, cases = DIALECT_PROOFS[policy_id]
    mod_path = HERE / module_name
    module_bytes = mod_path.read_bytes()
    # import the module to read its self-declared source identity (must match the frozen source file)
    import importlib
    mod = importlib.import_module(module_name[:-3])
    src_path = SRC_DIR / Path(mod.RTK_SOURCE_FILE).name
    if not src_path.is_file():
        raise SystemExit(f"pinned RTK source not committed: {src_path} (freeze it under evidence/rtk-source/)")
    src_bytes = src_path.read_bytes()

    man = c.load_record(MANIFEST)
    # every listed case must be in the manifest, classified rtk_test_dialect, bound to THIS policy
    by_case = {x["case_id"]: x for x in man["cases"]}
    for cid in cases:
        e = by_case.get(cid)
        if e is None:
            raise SystemExit(f"case {cid} not in manifest")
        if e["qualification_kind"] != "rtk_test_dialect" or e["rtk_test_dialect_policy_id"] != policy_id:
            raise SystemExit(f"case {cid} not classified rtk_test_dialect/{policy_id}")

    return c.envelope(
        record_type="n2e-test-dialect-source-proof",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_test_dialect_source_proof.py",
        record_version="v1",
        purpose=f"Source-identity + case-scope proof for {policy_id}. Pins the exact pinned RTK "
                f"source it was grounded in, the semantics-module identity, the pinned corpus RTK "
                f"binary, and the case-scoped manifest binding. Sets no promotion flag.",
        dialect_policy_id=policy_id,
        dialect_scope="case_scoped",
        proven_case_ids=list(cases),
        rtk_source_identity={
            "commit": mod.RTK_SOURCE_COMMIT, "source_file": mod.RTK_SOURCE_FILE,
            "content_sha256": c.sha256_bytes(src_bytes), "git_blob_sha1": _git_blob_sha1(src_bytes),
            "bytes": len(src_bytes)},
        semantics_module={
            "path": f"tools/{module_name}", "sha256": c.sha256_bytes(module_bytes),
            "bytes": len(module_bytes), "declared_dialect_id": mod.DIALECT_ID},
        pinned_rtk_binary_identity={"sha256": L.DIALECT_RTK_SHA, "bytes": L.DIALECT_RTK_BYTES},
        manifest_binding={"manifest_generation": man["manifest_generation"],
                          "manifest_sha256": c.sha256_json_file(MANIFEST)},
        no_family_level=("this dialect is proven for the listed case ids ONLY; one case does not "
                         "establish family-level test-dialect scope"),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", default="rtk-go-test-summary-v1", choices=sorted(DIALECT_PROOFS))
    args = ap.parse_args()
    out = N2E_DIR / f"n2e-test-dialect-source-proof-{args.policy}.json"
    c.write_record(out, build_proof(args.policy))
    print(f"wrote {out.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
