#!/usr/bin/env python3
"""Builds the self-hash-locked N2-D3 leg-evidence record: all 36 real
per-case-leg measurement rows downloaded from the canonical CI run
(29575975971), preserving leg a and leg b independently for every one of
the 18 primary cases.

This is the raw evidence build_n2d3_primary_benchmark.py's own
combine_case_legs()/build_benchmark() consume; committing it here lets
verify_n2d_run_evidence.py re-derive the entire committed
n2d3-primary-token-benchmark-v1.json from scratch and require exact
equality, rather than trusting the aggregate alone.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

IDENTITY_LOCK_DIR = Path(__file__).resolve().parents[1]
OUT_PATH = IDENTITY_LOCK_DIR / "n2d3-run-29575975971-leg-evidence-v1.json"

RUN_ID = 29575975971
HEAD_BRANCH = "n2d/ci-trigger-full-run"
HEAD_SHA = "46a7986967c1837797f5edc32e79122d839c3de3"

EXPECTED_CASE_IDS = [
    "bot-dependabot-black-5206", "bot-syzbot-do-mkdirat", "ci-log-jansson",
    "ci-log-nlog", "ci-log-spdlog", "dataset-loghub-v8", "dataset-rtn-traffic-ids",
    "n2a-miner-canary", "repo-docker-java-parser", "repo-dockerfile-parser-rs",
    "repo-helm-values", "repo-hyperfine", "repo-kubeops-generator", "repo-moshi",
    "repo-pyflakes", "repo-requests", "repo-rustlings", "research-corpus-loghub2",
]


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def build_record(leg_rows_dir: Path) -> dict:
    rows: dict[str, dict[str, dict]] = {}
    for f in sorted(leg_rows_dir.glob("*.json")):
        row = json.loads(f.read_text())
        case_id, leg = row["case_id"], row["leg"]
        rows.setdefault(case_id, {})[leg] = row

    missing = set(EXPECTED_CASE_IDS) - set(rows.keys())
    extra = set(rows.keys()) - set(EXPECTED_CASE_IDS)
    if missing:
        raise RuntimeError(f"missing case(s) in leg-rows dir: {sorted(missing)}")
    if extra:
        raise RuntimeError(f"unexpected case(s) in leg-rows dir: {sorted(extra)}")
    for case_id, legs in rows.items():
        if set(legs.keys()) != {"a", "b"}:
            raise RuntimeError(f"{case_id}: expected legs {{'a','b'}}, got {sorted(legs.keys())}")

    cases = {case_id: {"a": rows[case_id]["a"], "b": rows[case_id]["b"]} for case_id in sorted(rows)}

    body = {
        "record_type": "n2d3-run-leg-evidence-v1",
        "record_version": 1,
        "schema_version": 1,
        "run_id": RUN_ID,
        "head_branch": HEAD_BRANCH,
        "head_sha": HEAD_SHA,
        "case_count": len(cases),
        "cases": cases,
    }
    body["record_sha256"] = compute_record_sha256(body)
    return body


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--leg-rows-dir", required=True, type=Path)
    args = parser.parse_args()

    record = build_record(args.leg_rows_dir)
    OUT_PATH.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT_PATH} (record_sha256={record['record_sha256']}, case_count={record['case_count']})")


if __name__ == "__main__":
    main()
