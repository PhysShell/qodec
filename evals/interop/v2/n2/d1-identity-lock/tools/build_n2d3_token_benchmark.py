#!/usr/bin/env python3
"""N2-D3: model-free primary token benchmark.

Gated strictly on N2-D2: this tool refuses to produce a benchmark table
unless n2d2-determinism-canary-report-v1.json shows
all_cases_deterministic=true. The token counts themselves are NOT
recomputed here -- they are read directly from the canary report's own
already-verified-deterministic per-case counts (each one independently
confirmed byte-identical and count-identical across >=20 real repetitions
in N2-D2). Recomputing them a third time here would not make them more
real; it would just be a fourth, unnecessary invocation.

No model or agent evaluation of any kind is performed. No leaderboard is
constructed -- this produces exactly one thing: the raw/QODEC/RTK/hybrid
o200k token counts for the 18 accepted N2-D primary cases, self-hash-
locked, plus a plain-text table for human reading.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

IDENTITY_LOCK_DIR = Path(__file__).resolve().parents[1]
CANARY_REPORT_PATH = IDENTITY_LOCK_DIR / "n2d2-determinism-canary-report-v1.json"
OUT_JSON_PATH = IDENTITY_LOCK_DIR / "n2d3-primary-token-benchmark-v1.json"
OUT_TABLE_PATH = IDENTITY_LOCK_DIR / "n2d3-primary-token-benchmark-v1.md"


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def build_benchmark(canary_report: dict) -> dict:
    if not canary_report.get("all_cases_deterministic"):
        raise RuntimeError(
            "N2-D2 gate not satisfied: n2d2-determinism-canary-report-v1.json shows "
            "all_cases_deterministic=false -- N2-D3 must not proceed"
        )

    rows = {}
    for case_id, case in sorted(canary_report["cases"].items()):
        if not case.get("deterministic"):
            raise RuntimeError(f"case {case_id!r} is not deterministic -- N2-D3 must not proceed")
        raw = case["raw_tokens"]
        qodec = case["qodec_tokens"]
        rtk = case["rtk_tokens"]
        hybrid = case["hybrid_tokens"]
        rows[case_id] = {
            "raw_tokens": raw,
            "qodec_tokens": qodec,
            "rtk_tokens": rtk,
            "hybrid_tokens": hybrid,
            "qodec_reduction_pct": round(100.0 * (raw - qodec) / raw, 2) if raw else None,
            "rtk_reduction_pct": round(100.0 * (raw - rtk) / raw, 2) if raw and rtk is not None else None,
            "hybrid_reduction_pct": round(100.0 * (raw - hybrid) / raw, 2) if raw and hybrid is not None else None,
        }

    body = {
        "record_type": "n2d3-primary-token-benchmark-v1",
        "record_version": 1,
        "schema_version": 1,
        "n2d2_gate_status": "passed",
        "n2d2_canary_report_sha256": canary_report["record_sha256"],
        "n2d2_repetitions_per_case": canary_report["repetitions_per_case"],
        "model_based_quality_evaluation_performed": False,
        "leaderboard_constructed": False,
        "case_count": len(rows),
        "cases": rows,
    }
    body["record_sha256"] = compute_record_sha256(body)
    return body


def render_table(benchmark: dict) -> str:
    lines = [
        "# N2-D3 Primary Token Benchmark (model-free)",
        "",
        f"18 primary N2-D cases; token counts via qodec's own o200k meter; "
        f"gated on N2-D2 ({benchmark['n2d2_repetitions_per_case']} repetitions/case, all byte-identical).",
        "",
        "| case_id | raw | qodec | qodec_red% | rtk | rtk_red% | hybrid | hybrid_red% |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for case_id, row in sorted(benchmark["cases"].items()):
        lines.append(
            f"| {case_id} | {row['raw_tokens']} | {row['qodec_tokens']} | "
            f"{row['qodec_reduction_pct']} | {row['rtk_tokens']} | {row['rtk_reduction_pct']} | "
            f"{row['hybrid_tokens']} | {row['hybrid_reduction_pct']} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    canary_report = json.loads(CANARY_REPORT_PATH.read_text())
    benchmark = build_benchmark(canary_report)
    OUT_JSON_PATH.write_text(json.dumps(benchmark, indent=2, sort_keys=True) + "\n")
    OUT_TABLE_PATH.write_text(render_table(benchmark))
    print(f"wrote {OUT_JSON_PATH} and {OUT_TABLE_PATH} (record_sha256={benchmark['record_sha256']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
