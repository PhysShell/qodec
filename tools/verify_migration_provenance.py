#!/usr/bin/env python3
"""Independently verifies MIGRATION_PROVENANCE.json's self-hash.

Recomputes the record's SHA-256 from its own committed content (not from the
builder script) and fails closed on any mismatch -- run this to check that
the provenance record has not been tampered with or drifted from what it
claims about itself.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

PROVENANCE_PATH = Path(__file__).resolve().parents[1] / "MIGRATION_PROVENANCE.json"


def _compact_canonical_bytes(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify(path: Path) -> tuple[bool, str]:
    if not path.is_file():
        return False, f"{path} does not exist"

    record = json.loads(path.read_text())

    recorded = record.get("record_sha256")
    if not isinstance(recorded, str) or not recorded.startswith("sha256:"):
        return False, "record_sha256 is missing or not in 'sha256:<hex>' form"

    without_hash = dict(record)
    without_hash["record_sha256"] = None
    recomputed = f"sha256:{hashlib.sha256(_compact_canonical_bytes(without_hash)).hexdigest()}"

    if recomputed != recorded:
        return False, f"self-hash mismatch: recorded={recorded} recomputed={recomputed}"

    required_fields = (
        "schema_version", "record_type", "source_repository", "source_mode",
        "source_pull_request_chain", "authoritative_source_pr",
        "authoritative_source_head_sha", "target_repository",
        "history_transform", "migration_content_commit_sha",
    )
    missing = [f for f in required_fields if f not in record]
    if missing:
        return False, f"missing required fields: {missing}"

    if record["source_mode"] != "stacked_unmerged_pr_tip":
        return False, f"unexpected source_mode: {record['source_mode']!r}"

    if "source_merge_commit_sha" in record:
        return False, "source_merge_commit_sha must not be present (source is an unmerged stacked PR tip, not a merge commit)"

    return True, "OK"


def main() -> int:
    ok, message = verify(PROVENANCE_PATH)
    if not ok:
        print(f"::error::migration provenance verification FAILED: {message}", file=sys.stderr)
        return 1
    print(f"migration provenance verification passed: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
