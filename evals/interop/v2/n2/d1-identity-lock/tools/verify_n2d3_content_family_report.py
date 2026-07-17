#!/usr/bin/env python3
"""Independently, fail-closedly verifies
n2d3-token-results-by-content-family-v1.json.

Never trusts: the report's own cached group aggregates, its rendered
Markdown/CSV, or PR body totals. Verifies the taxonomy's own self-hash,
pins the exact canonical N2-D3 record sha256, verifies the exact 18-case
set, verifies each case is classified exactly once, verifies enum
membership, verifies each case's canonical input sha256 against the real
committed benchmark, then rebuilds the ENTIRE report via
build_n2d3_content_family_report.build_record() (group memberships, token
totals, weighted/macro/median/min/max savings, RAW token share, dominance
flags, bootstrap CIs, sensitivity analysis, equal-family exploratory
summary) and requires exact equality (record_sha256, then full dict) with
the committed record.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
IDENTITY_LOCK_DIR = TOOLS_DIR.parent
sys.path.insert(0, str(TOOLS_DIR))

RECORD_PATH = IDENTITY_LOCK_DIR / "n2d3-token-results-by-content-family-v1.json"
CANONICAL_N2D3_SHA256 = "sha256:c00d2ff8f4883c964fbd05d46840763826806ea73357511e6f38a882aaf0e1cd"


def verify(record_path: Path = RECORD_PATH) -> tuple[bool, str]:
    if not record_path.is_file():
        return False, f"{record_path} does not exist"
    record = json.loads(record_path.read_text())

    import build_n2d3_content_family_report as builder
    import build_n2d3_content_taxonomy as taxonomy_builder
    import verify_n2d3_content_taxonomy as taxonomy_verifier

    # 1. self-hash of the report itself
    recomputed = builder.compute_record_sha256(record)
    if recomputed != record.get("record_sha256"):
        return False, f"self-hash mismatch: recorded={record.get('record_sha256')} recomputed={recomputed}"

    if record.get("record_type") != "n2d3-token-results-by-content-family-v1":
        return False, f"unexpected record_type: {record.get('record_type')!r}"
    if record.get("post_hoc_exploratory") is not True:
        return False, "post_hoc_exploratory must be true"

    # 2. exact canonical N2-D3 record sha
    link = record.get("canonical_benchmark_link", {})
    if link.get("record_sha256") != CANONICAL_N2D3_SHA256:
        return False, f"canonical_benchmark_link.record_sha256 != pinned {CANONICAL_N2D3_SHA256!r}"

    # 1 (taxonomy). taxonomy self-hash + its own full independent verification
    taxonomy_link = record.get("taxonomy_link", {})
    taxonomy_ok, taxonomy_msg = taxonomy_verifier.verify()
    if not taxonomy_ok:
        return False, f"n2d3-content-taxonomy-v1.json failed independent re-verification: {taxonomy_msg}"
    taxonomy_record = json.loads(taxonomy_builder.OUT_PATH.read_text())
    if taxonomy_link.get("record_sha256") != taxonomy_record.get("record_sha256"):
        return False, "taxonomy_link.record_sha256 does not match the real committed taxonomy record"
    if taxonomy_record["canonical_benchmark_link"]["record_sha256"] != CANONICAL_N2D3_SHA256:
        return False, "committed taxonomy is not linked to the pinned canonical N2-D3 record"

    # real committed canonical benchmark, re-verified fresh (never trust n2d3 rows cached elsewhere)
    n2d3_path = IDENTITY_LOCK_DIR / "n2d3-primary-token-benchmark-v1.json"
    if not n2d3_path.is_file():
        return False, f"{n2d3_path} does not exist"
    n2d3_record = json.loads(n2d3_path.read_text())
    if n2d3_record.get("record_sha256") != CANONICAL_N2D3_SHA256:
        return False, "the real committed n2d3-primary-token-benchmark-v1.json no longer matches the pinned canonical sha256"
    import build_n2d3_primary_benchmark as bench_builder
    if bench_builder.compute_record_sha256(n2d3_record) != n2d3_record["record_sha256"]:
        return False, "n2d3-primary-token-benchmark-v1.json self-hash does not verify"

    # 3. exact 18-case set
    n2d3_cases = n2d3_record["cases"]
    taxonomy_cases = taxonomy_record["cases"]
    if sorted(n2d3_cases.keys()) != sorted(taxonomy_cases.keys()):
        return False, "canonical N2-D3 case set != taxonomy case set"
    if len(n2d3_cases) != 18:
        return False, f"expected exactly 18 cases, got {len(n2d3_cases)}"

    # 4. each case classified exactly once (per axis, every case appears in exactly one group)
    axis_enums = {
        "content_family": taxonomy_builder.CONTENT_FAMILIES,
        "origin_kind": taxonomy_builder.ORIGIN_KINDS,
        "producer_family": taxonomy_builder.PRODUCER_FAMILIES,
        "payload_kind": taxonomy_builder.PAYLOAD_KINDS,
    }
    for axis in builder.AXES:
        seen = set()
        view = record.get("views", {}).get(axis, {})
        for group_id, g in view.items():
            if group_id not in axis_enums[axis]:
                return False, f"views.{axis}: group id {group_id!r} is not an authorized {axis} value"
            for cid in g["case_ids"]:
                if cid in seen:
                    return False, f"views.{axis}: case {cid!r} appears in more than one group"
                seen.add(cid)
        if seen != set(n2d3_cases.keys()):
            return False, f"views.{axis}: group memberships do not cover exactly the 18-case set"

    # 5. enum membership (re-verified directly, not just trusted from taxonomy)
    for case_id, entry in taxonomy_cases.items():
        if entry["content_family"] not in taxonomy_builder.CONTENT_FAMILIES:
            return False, f"{case_id}: content_family not authorized"
        if entry["origin_kind"] not in taxonomy_builder.ORIGIN_KINDS:
            return False, f"{case_id}: origin_kind not authorized"
        if entry["producer_family"] not in taxonomy_builder.PRODUCER_FAMILIES:
            return False, f"{case_id}: producer_family not authorized"
        if entry["payload_kind"] not in taxonomy_builder.PAYLOAD_KINDS:
            return False, f"{case_id}: payload_kind not authorized"

    # 6. canonical input sha256 per case, re-checked against the real committed benchmark
    for case_id, row in n2d3_cases.items():
        taxonomy_sha = taxonomy_cases[case_id]["classification_evidence"]["canonical_benchmark_input_sha256"]
        if taxonomy_sha != row["input_sha256"]:
            return False, f"{case_id}: taxonomy canonical input sha256 != real committed N2-D3 row's input_sha256"

    # bootstrap seed/resample policy pins
    policy = record.get("bootstrap_policy", {})
    if policy.get("seed") != builder.BOOTSTRAP_SEED:
        return False, f"bootstrap_policy.seed != {builder.BOOTSTRAP_SEED!r}"
    if policy.get("resamples") != builder.BOOTSTRAP_RESAMPLES:
        return False, f"bootstrap_policy.resamples != {builder.BOOTSTRAP_RESAMPLES!r}"
    if policy.get("min_measured_case_count") != builder.MIN_BOOTSTRAP_MEASURED_CASES:
        return False, "bootstrap_policy.min_measured_case_count != required minimum"
    if policy.get("resampling_unit") != "case_id":
        return False, "bootstrap_policy.resampling_unit must be 'case_id'"

    # no bootstrap CI on any group below the minimum measured case count (7-16: recomputed
    # exhaustively below via full rebuild, but checked directly here too for a specific message)
    for axis in builder.AXES:
        for group_id, g in record["views"][axis].items():
            if g["measured_case_count"] < builder.MIN_BOOTSTRAP_MEASURED_CASES:
                for arm_key in builder.ARM_TOKEN_FIELDS:
                    if g[arm_key]["bootstrap_ci95"] is not None:
                        return False, f"views.{axis}.{group_id}: bootstrap CI present despite measured_case_count < {builder.MIN_BOOTSTRAP_MEASURED_CASES}"

    # 7-14, 16: full ground-truth rebuild -- group memberships, token totals,
    # weighted/macro/median/min/max savings, RAW token share, dominance flags,
    # bootstrap CIs, sensitivity analysis, equal-family exploratory summary,
    # and the report's own self-hash, all recomputed from scratch.
    try:
        rebuilt = builder.build_record()
    except Exception as exc:  # noqa: BLE001
        return False, f"rebuilding the content-family report raised: {exc}"

    # 15. exact equality with committed report
    if rebuilt.get("record_sha256") != record.get("record_sha256"):
        return False, (
            f"rebuilt report record_sha256 {rebuilt.get('record_sha256')!r} != "
            f"committed {record.get('record_sha256')!r}"
        )
    if rebuilt != record:
        return False, "rebuilt content-family report differs from the committed record despite matching record_sha256"

    return True, "OK"


def main() -> int:
    ok, message = verify()
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
