#!/usr/bin/env python3
"""Independently, fail-closedly verifies n2d3-content-taxonomy-v1.json.

Never trusts the taxonomy record's own cached evidence fields: rebuilds the
whole record via build_n2d3_content_taxonomy.build_record() (which itself
re-derives everything from the real committed bundle manifest, Stage 2
record, durable manifest, RTK applicability map, source-freeze manifests,
and N2-A source manifest) and requires exact equality (record_sha256, then
full dict) with the committed record. Also independently re-checks the
enum membership and per-case classification/canonical-input-SHA/exactly-
once-classified invariants directly, so a tampered committed record fails
for a specific, readable reason rather than only "differs from rebuild".
"""
from __future__ import annotations

import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
IDENTITY_LOCK_DIR = TOOLS_DIR.parent
sys.path.insert(0, str(TOOLS_DIR))

import json  # noqa: E402

RECORD_PATH = IDENTITY_LOCK_DIR / "n2d3-content-taxonomy-v1.json"
CANONICAL_N2D3_SHA256 = "sha256:c00d2ff8f4883c964fbd05d46840763826806ea73357511e6f38a882aaf0e1cd"


def verify(record_path: Path = RECORD_PATH) -> tuple[bool, str]:
    if not record_path.is_file():
        return False, f"{record_path} does not exist"
    record = json.loads(record_path.read_text())

    import build_n2d3_content_taxonomy as builder

    recomputed = builder.compute_record_sha256(record)
    if recomputed != record.get("record_sha256"):
        return False, f"self-hash mismatch: recorded={record.get('record_sha256')} recomputed={recomputed}"

    if record.get("record_type") != "n2d3-content-taxonomy-v1":
        return False, f"unexpected record_type: {record.get('record_type')!r}"
    if record.get("post_hoc_exploratory") is not True:
        return False, "post_hoc_exploratory must be true"

    link = record.get("canonical_benchmark_link", {})
    if link.get("record_sha256") != CANONICAL_N2D3_SHA256:
        return False, f"canonical_benchmark_link.record_sha256 != pinned {CANONICAL_N2D3_SHA256!r}"

    cases = record.get("cases", {})
    if sorted(cases.keys()) != sorted(builder.EXPECTED_CASE_IDS):
        return False, "cases key set != the required exact 18-case set (missing or duplicate/extra case)"
    if len(cases) != 18:
        return False, f"expected exactly 18 classified cases, got {len(cases)}"

    for case_id, entry in cases.items():
        if entry.get("case_id") != case_id:
            return False, f"cases[{case_id!r}].case_id does not match its own key"
        if entry.get("content_family") not in builder.CONTENT_FAMILIES:
            return False, f"cases[{case_id!r}].content_family is not an authorized value"
        if entry.get("origin_kind") not in builder.ORIGIN_KINDS:
            return False, f"cases[{case_id!r}].origin_kind is not an authorized value"
        if entry.get("producer_family") not in builder.PRODUCER_FAMILIES:
            return False, f"cases[{case_id!r}].producer_family is not an authorized value"
        if entry.get("payload_kind") not in builder.PAYLOAD_KINDS:
            return False, f"cases[{case_id!r}].payload_kind is not an authorized value"
        ev = entry.get("classification_evidence", {})
        if not isinstance(ev.get("canonical_benchmark_input_sha256"), str) or len(ev["canonical_benchmark_input_sha256"]) != 64:
            return False, f"cases[{case_id!r}].classification_evidence.canonical_benchmark_input_sha256 is malformed"
        if not isinstance(ev.get("utf8_valid"), bool):
            return False, f"cases[{case_id!r}].classification_evidence.utf8_valid must be a boolean"
        expected_payload_kind = "utf8-text" if ev["utf8_valid"] else "binary-container"
        if entry["payload_kind"] != expected_payload_kind:
            return False, f"cases[{case_id!r}].payload_kind does not match its own utf8_valid evidence"

    # --- independent cross-check against the real committed canonical benchmark
    n2d3_path = IDENTITY_LOCK_DIR / "n2d3-primary-token-benchmark-v1.json"
    if not n2d3_path.is_file():
        return False, f"{n2d3_path} does not exist"
    n2d3_record = json.loads(n2d3_path.read_text())
    if n2d3_record.get("record_sha256") != CANONICAL_N2D3_SHA256:
        return False, "the real committed n2d3-primary-token-benchmark-v1.json no longer matches the pinned canonical sha256"
    for case_id, n2d3_row in n2d3_record["cases"].items():
        if case_id not in cases:
            return False, f"canonical N2-D3 case {case_id!r} is missing from the taxonomy"
        taxonomy_sha = cases[case_id]["classification_evidence"]["canonical_benchmark_input_sha256"]
        if taxonomy_sha != n2d3_row["input_sha256"]:
            return False, f"cases[{case_id!r}] canonical input sha256 does not match the real committed N2-D3 row"
        is_refusal = n2d3_row["measurement_status"] == "UNMEASURABLE_NON_UTF8"
        if is_refusal and cases[case_id]["payload_kind"] != "binary-container":
            return False, f"cases[{case_id!r}] is a real UNMEASURABLE_NON_UTF8 refusal but payload_kind != 'binary-container'"
        if not is_refusal and cases[case_id]["payload_kind"] != "utf8-text":
            return False, f"cases[{case_id!r}] is a real MEASURED case but payload_kind != 'utf8-text'"

    # --- full ground-truth recompute: rebuild the ENTIRE record from live
    # evidence (bundle manifest, stage2 record, durable manifest, rtk map,
    # source-freeze manifests, n2a source manifest) and require exact equality.
    try:
        rebuilt = builder.build_record()
    except Exception as exc:  # noqa: BLE001
        return False, f"rebuilding the taxonomy from live evidence raised: {exc}"

    if rebuilt.get("record_sha256") != record.get("record_sha256"):
        return False, (
            f"rebuilt taxonomy record_sha256 {rebuilt.get('record_sha256')!r} != "
            f"committed {record.get('record_sha256')!r}"
        )
    if rebuilt != record:
        return False, "rebuilt taxonomy differs from the committed record despite matching record_sha256"

    return True, "OK"


def main() -> int:
    ok, message = verify()
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
