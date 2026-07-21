#!/usr/bin/env python3
"""Verifier for a command-oracle source-identity + case-scope proof. Fail-closed: pinned RTK source
re-hashes to the recorded content + git blob sha; the semantics module re-hashes to the recorded sha
and self-declares the same oracle id + source commit/file/function; the pinned RTK binary matches;
every proven case is in the manifest, classified rtk_command_oracle, bound to THIS oracle
(case-scoped, never family-level); and the manifest binding matches the current frozen manifest.
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
import build_n2e_command_oracle_source_proof as B  # noqa: E402

MANIFEST = N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"
SRC_DIR = N2E_DIR / "evidence" / "rtk-source"


class OracleProofError(Exception):
    pass


def _git_blob_sha1(data: bytes) -> str:
    h = hashlib.sha1(); h.update(b"blob %d\0" % len(data)); h.update(data)
    return h.hexdigest()


def verify_proof(rec: dict) -> dict:
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        raise OracleProofError(f"self-hash: {msg}")
    if rec.get("record_type") != "n2e-command-oracle-source-proof":
        raise OracleProofError("wrong record_type")
    policy = rec.get("oracle_policy_id")
    if policy not in B.ORACLE_PROOFS:
        raise OracleProofError(f"unknown oracle policy {policy!r}")
    if rec.get("oracle_scope") != "case_scoped":
        raise OracleProofError("oracle_scope != case_scoped")
    module_name, expected_cases = B.ORACLE_PROOFS[policy]

    si = rec.get("rtk_source_identity") or {}
    src_path = SRC_DIR / Path(si.get("source_file", "")).name
    if not src_path.is_file():
        raise OracleProofError(f"pinned RTK source not committed: {src_path}")
    sb = src_path.read_bytes()
    if c.sha256_bytes(sb) != si.get("content_sha256") or len(sb) != si.get("bytes"):
        raise OracleProofError("frozen RTK source content sha/bytes != recorded")
    if _git_blob_sha1(sb) != si.get("git_blob_sha1"):
        raise OracleProofError("frozen RTK source git blob sha != recorded")

    mod = importlib.import_module(module_name[:-3])
    mb = (HERE / module_name).read_bytes()
    sm = rec.get("semantics_module") or {}
    if c.sha256_bytes(mb) != sm.get("sha256") or len(mb) != sm.get("bytes"):
        raise OracleProofError("semantics module sha/bytes != recorded")
    if mod.ORACLE_ID != policy or sm.get("declared_oracle_id") != policy:
        raise OracleProofError("semantics module does not declare this oracle id")
    if (mod.RTK_SOURCE_COMMIT != si.get("commit") or mod.RTK_SOURCE_FILE != si.get("source_file")
            or mod.RTK_SOURCE_FUNCTION != si.get("source_function")):
        raise OracleProofError("semantics module source commit/file/function != recorded")

    # additional pinned source refs (multi-file grounding): each must re-hash to the recorded
    # content + git blob sha, and the set must equal the module's declared RTK_SOURCE_REFS.
    refs = rec.get("additional_source_identities") or []
    declared = getattr(mod, "RTK_SOURCE_REFS", [])
    if {(r["source_file"], r["source_function"]) for r in refs} != {
            (d["source_file"], d["source_function"]) for d in declared}:
        raise OracleProofError("additional_source_identities != module RTK_SOURCE_REFS")
    for r in refs:
        rp = SRC_DIR / Path(r["source_file"]).name
        if not rp.is_file():
            raise OracleProofError(f"pinned RTK source ref not committed: {rp}")
        rb2 = rp.read_bytes()
        if (c.sha256_bytes(rb2) != r.get("content_sha256") or len(rb2) != r.get("bytes")
                or _git_blob_sha1(rb2) != r.get("git_blob_sha1")):
            raise OracleProofError(f"frozen source ref {r['source_file']} sha/blob/bytes != recorded")

    rb = rec.get("pinned_rtk_binary_identity") or {}
    if rb.get("sha256") != L.DIALECT_RTK_SHA or rb.get("bytes") != L.DIALECT_RTK_BYTES:
        raise OracleProofError("pinned RTK binary identity != corpus RTK")

    cases = rec.get("proven_case_ids") or []
    if cases != expected_cases:
        raise OracleProofError(f"proven_case_ids {cases} != expected {expected_cases}")
    man = c.load_record(MANIFEST)
    by_case = {x["case_id"]: x for x in man["cases"]}
    for cid in cases:
        e = by_case.get(cid)
        if e is None:
            raise OracleProofError(f"proven case {cid} not in manifest")
        if e["qualification_kind"] != "rtk_command_oracle" or e["command_semantic_oracle_policy_id"] != policy:
            raise OracleProofError(f"proven case {cid} not classified rtk_command_oracle/{policy}")
    mbind = rec.get("manifest_binding") or {}
    if (mbind.get("manifest_generation") != man["manifest_generation"]
            or mbind.get("manifest_sha256") != c.sha256_json_file(MANIFEST)):
        raise OracleProofError("manifest binding != current frozen manifest")
    return {"policy": policy, "cases": cases}


def main() -> int:
    policy = sys.argv[1] if len(sys.argv) > 1 else "rtk-go-vet-oracle-v1"
    path = N2E_DIR / f"n2e-command-oracle-source-proof-{policy}.json"
    try:
        f = verify_proof(c.load_record(path))
    except OracleProofError as e:
        print(f"command-oracle-source-proof: FAIL {e}")
        return 1
    print(f"command-oracle-source-proof: OK {f['policy']} case-scoped to {f['cases']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
