#!/usr/bin/env python3
"""Verifier for a test-dialect source-identity + case-scope proof. Fail-closed: the pinned RTK source
committed under evidence/rtk-source/ must re-hash to the recorded content sha + git blob sha; the
semantics module on disk must re-hash to the recorded module sha and self-declare the same dialect id
+ source commit/file; the pinned RTK binary identity must equal the corpus RTK; every proven case id
must be in the manifest, classified rtk_test_dialect, and bound to THIS policy (case-scoped, never
family-level); and the manifest binding must match the current frozen manifest.
"""
from __future__ import annotations

import hashlib
import importlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402
import build_n2e_test_dialect_source_proof as B  # noqa: E402

MANIFEST = N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"
SRC_DIR = N2E_DIR / "evidence" / "rtk-source"


class SourceProofError(Exception):
    pass


def _git_blob_sha1(data: bytes) -> str:
    h = hashlib.sha1(); h.update(b"blob %d\0" % len(data)); h.update(data)
    return h.hexdigest()


def verify_proof(rec: dict) -> dict:
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        raise SourceProofError(f"self-hash: {msg}")
    if rec.get("record_type") != "n2e-test-dialect-source-proof":
        raise SourceProofError("wrong record_type")
    policy = rec.get("dialect_policy_id")
    if policy not in B.DIALECT_PROOFS:
        raise SourceProofError(f"unknown dialect policy {policy!r}")
    if rec.get("dialect_scope") != "case_scoped":
        raise SourceProofError("dialect_scope != case_scoped")

    module_name, expected_cases = B.DIALECT_PROOFS[policy]

    # ---- pinned RTK source identity ----
    si = rec.get("rtk_source_identity") or {}
    src_path = SRC_DIR / Path(si.get("source_file", "")).name
    if not src_path.is_file():
        raise SourceProofError(f"pinned RTK source not committed: {src_path}")
    sb = src_path.read_bytes()
    if c.sha256_bytes(sb) != si.get("content_sha256") or len(sb) != si.get("bytes"):
        raise SourceProofError("frozen RTK source content sha/bytes != recorded")
    if _git_blob_sha1(sb) != si.get("git_blob_sha1"):
        raise SourceProofError("frozen RTK source git blob sha != recorded")

    # ---- semantics module identity + self-declared grounding ----
    mod = importlib.import_module(module_name[:-3])
    mb = (HERE / module_name).read_bytes()
    sm = rec.get("semantics_module") or {}
    if c.sha256_bytes(mb) != sm.get("sha256") or len(mb) != sm.get("bytes"):
        raise SourceProofError("semantics module sha/bytes != recorded")
    if mod.DIALECT_ID != policy or sm.get("declared_dialect_id") != policy:
        raise SourceProofError("semantics module does not declare this dialect id")
    if mod.RTK_SOURCE_COMMIT != si.get("commit") or mod.RTK_SOURCE_FILE != si.get("source_file"):
        raise SourceProofError("semantics module source commit/file != recorded")

    # ---- pinned corpus RTK binary ----
    rb = rec.get("pinned_rtk_binary_identity") or {}
    if rb.get("sha256") != L.DIALECT_RTK_SHA or rb.get("bytes") != L.DIALECT_RTK_BYTES:
        raise SourceProofError("pinned RTK binary identity != corpus RTK")

    # ---- case-scope binding against the frozen manifest (case-scoped, never family-level) ----
    cases = rec.get("proven_case_ids") or []
    if cases != expected_cases:
        raise SourceProofError(f"proven_case_ids {cases} != expected {expected_cases}")
    man = c.load_record(MANIFEST)
    by_case = {x["case_id"]: x for x in man["cases"]}
    for cid in cases:
        e = by_case.get(cid)
        if e is None:
            raise SourceProofError(f"proven case {cid} not in manifest")
        if e["qualification_kind"] != "rtk_test_dialect" or e["rtk_test_dialect_policy_id"] != policy:
            raise SourceProofError(f"proven case {cid} not classified rtk_test_dialect/{policy}")
    mbind = rec.get("manifest_binding") or {}
    if (mbind.get("manifest_generation") != man["manifest_generation"]
            or mbind.get("manifest_sha256") != c.sha256_json_file(MANIFEST)):
        raise SourceProofError("manifest binding != current frozen manifest")

    return {"policy": policy, "cases": cases}


def main() -> int:
    policy = sys.argv[1] if len(sys.argv) > 1 else "rtk-go-test-summary-v1"
    path = N2E_DIR / f"n2e-test-dialect-source-proof-{policy}.json"
    try:
        f = verify_proof(c.load_record(path))
    except SourceProofError as e:
        print(f"test-dialect-source-proof: FAIL {e}")
        return 1
    print(f"test-dialect-source-proof: OK {f['policy']} case-scoped to {f['cases']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
