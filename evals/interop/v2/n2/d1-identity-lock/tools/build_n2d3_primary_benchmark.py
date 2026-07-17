#!/usr/bin/env python3
"""N2-D3: aggregate the 18-case x 2-leg measurement matrix into the primary
model-free token benchmark.

Combines each case's two independent leg measurements (n2d3_measure_case.py
output), requires exact agreement between them, then reports:

  - 18 total corpus cases
  - 16 token-measurable cases (MEASURED) -> token aggregates (RAW/QODEC/RTK/
    RTK+QODEC totals, weighted savings, macro savings, medians, bootstrap
    confidence intervals), explicitly labeled "measured text-domain subset,
    n=16"
  - 2 typed non-UTF-8 measurement-domain refusals (dataset-loghub-v8,
    research-corpus-loghub2) -- valid corpus members, excluded from token
    aggregates, never imputed

No model or agent evaluation of any kind is performed. No leaderboard is
constructed.
"""
from __future__ import annotations

import hashlib
import json
import random
import statistics
from pathlib import Path

IDENTITY_LOCK_DIR = Path(__file__).resolve().parents[1]
OUT_JSON_PATH = IDENTITY_LOCK_DIR / "n2d3-primary-token-benchmark-v1.json"
OUT_TABLE_PATH = IDENTITY_LOCK_DIR / "n2d3-primary-token-benchmark-v1.md"

EXPECTED_CASE_COUNT = 18
AUTHORIZED_NON_UTF8_CASE_IDS = frozenset({"dataset-loghub-v8", "research-corpus-loghub2"})

BOOTSTRAP_SEED = 20260716
BOOTSTRAP_RESAMPLES = 10000

MEASURED_COMPARE_FIELDS = (
    "raw_tokens", "qodec_tokens", "rtk_tokens", "rtk_plus_qodec_tokens",
    "qodec_encode_stdout_sha256", "qodec_encoded",
    "raw_roundtrip_ok", "rtk_exit_code", "rtk_stdout_sha256",
    "hybrid_encode_stdout_sha256", "hybrid_encoded", "hybrid_roundtrip_ok",
)
REFUSAL_COMPARE_FIELDS = (
    "input_sha256", "qodec_exit_code", "qodec_stderr_sha256", "qodec_failure_classification",
)


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def combine_case_legs(leg_a: dict, leg_b: dict) -> dict:
    if leg_a.get("leg") != "a" or leg_b.get("leg") != "b":
        raise ValueError("combine_case_legs requires exactly one leg 'a' row and one leg 'b' row")
    if leg_a.get("case_id") != leg_b.get("case_id"):
        raise ValueError(f"case_id mismatch between legs: {leg_a.get('case_id')!r} != {leg_b.get('case_id')!r}")
    case_id = leg_a["case_id"]

    status_a = leg_a.get("measurement_status")
    status_b = leg_b.get("measurement_status")
    if status_a != status_b:
        raise RuntimeError(
            f"{case_id}: leg disagreement on measurement_status: a={status_a!r} b={status_b!r}"
        )

    if status_a == "MEASURED":
        compare_fields = MEASURED_COMPARE_FIELDS
    elif status_a == "UNMEASURABLE_NON_UTF8":
        if case_id not in AUTHORIZED_NON_UTF8_CASE_IDS:
            raise RuntimeError(f"{case_id}: UNMEASURABLE_NON_UTF8 status on an unauthorized case_id")
        compare_fields = REFUSAL_COMPARE_FIELDS
    else:
        raise RuntimeError(f"{case_id}: unrecognized measurement_status {status_a!r}")

    if leg_a.get("input_sha256") != leg_b.get("input_sha256"):
        raise RuntimeError(f"{case_id}: leg disagreement on input_sha256")

    disagreements = [f for f in compare_fields if leg_a.get(f) != leg_b.get(f)]
    leg_agreement = not disagreements

    combined = {
        "case_id": case_id,
        "measurement_status": status_a,
        "leg_agreement": leg_agreement,
        "disagreements": disagreements,
        "input_sha256": leg_a["input_sha256"],
        "input_bytes": leg_a["input_bytes"],
    }
    for f in compare_fields:
        combined[f] = leg_a.get(f)
    if status_a == "MEASURED":
        combined["excluded_from_token_aggregates"] = False
    else:
        combined["excluded_from_token_aggregates"] = True
        combined["utf8_valid"] = False
    return combined


def _bootstrap_ci(values: list[float], seed: int, resamples: int) -> dict:
    rng = random.Random(seed)
    n = len(values)
    means = []
    for _ in range(resamples):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        means.append(statistics.fmean(sample))
    means.sort()
    lo_idx = int(0.025 * resamples)
    hi_idx = min(int(0.975 * resamples), resamples - 1)
    return {
        "seed": seed,
        "resamples": resamples,
        "point_estimate": statistics.fmean(values),
        "ci_low_2_5pct": means[lo_idx],
        "ci_high_97_5pct": means[hi_idx],
    }


def _arm_stats(measured_rows: list[dict], token_field: str) -> dict:
    raw_total = sum(r["raw_tokens"] for r in measured_rows)
    out_total = sum(r[token_field] for r in measured_rows)
    per_case_savings = [
        1.0 - (r[token_field] / r["raw_tokens"]) if r["raw_tokens"] else 0.0
        for r in measured_rows
    ]
    return {
        "total_tokens": out_total,
        "weighted_savings_pct": round(100.0 * (1.0 - out_total / raw_total), 4) if raw_total else None,
        "macro_savings_pct": round(100.0 * statistics.fmean(per_case_savings), 4),
        "median_savings_pct": round(100.0 * statistics.median(per_case_savings), 4),
        "bootstrap_macro_savings_pct_ci95": {
            k: (round(100.0 * v, 4) if isinstance(v, float) else v)
            for k, v in _bootstrap_ci(per_case_savings, BOOTSTRAP_SEED, BOOTSTRAP_RESAMPLES).items()
        },
    }


def build_benchmark(case_leg_pairs: dict) -> dict:
    """case_leg_pairs: {case_id: (leg_a_row, leg_b_row)} for all 18 cases."""
    if len(case_leg_pairs) != EXPECTED_CASE_COUNT:
        raise RuntimeError(f"expected exactly {EXPECTED_CASE_COUNT} cases, got {len(case_leg_pairs)}")

    combined = {}
    for case_id, (leg_a, leg_b) in sorted(case_leg_pairs.items()):
        row = combine_case_legs(leg_a, leg_b)
        if not row["leg_agreement"]:
            raise RuntimeError(f"{case_id}: leg a/b disagreement on fields {row['disagreements']}")
        combined[case_id] = row

    measured = [r for cid, r in sorted(combined.items()) if r["measurement_status"] == "MEASURED"]
    refused = [r for cid, r in sorted(combined.items()) if r["measurement_status"] == "UNMEASURABLE_NON_UTF8"]

    refused_ids = {r["case_id"] for r in refused}
    if refused_ids != set(AUTHORIZED_NON_UTF8_CASE_IDS):
        raise RuntimeError(f"non-UTF-8 refusal set mismatch: got {refused_ids}, expected {set(AUTHORIZED_NON_UTF8_CASE_IDS)}")
    if len(measured) != EXPECTED_CASE_COUNT - len(AUTHORIZED_NON_UTF8_CASE_IDS):
        raise RuntimeError(f"expected {EXPECTED_CASE_COUNT - len(AUTHORIZED_NON_UTF8_CASE_IDS)} measured cases, got {len(measured)}")

    passthrough_count = sum(1 for r in measured if r["qodec_encoded"] is False)
    exact_roundtrip_count = sum(1 for r in measured if r["raw_roundtrip_ok"] and r["hybrid_roundtrip_ok"])

    body = {
        "record_type": "n2d3-primary-token-benchmark-v1",
        "record_version": 2,
        "schema_version": 2,
        "model_based_quality_evaluation_performed": False,
        "leaderboard_constructed": False,
        "corpus": {
            "total_corpus_cases": EXPECTED_CASE_COUNT,
            "token_measurable_cases": len(measured),
            "non_utf8_measurement_refusals": len(refused),
            "runtime_failure_count": 0,
            "passthrough_count_where_observable": passthrough_count,
            "exact_roundtrip_count_where_measurable": exact_roundtrip_count,
        },
        "token_aggregates_measured_text_domain_subset_n16": {
            "n": len(measured),
            "note": "measured text-domain subset, n=16 -- excludes the 2 typed non-UTF-8 refusals",
            "raw_total_tokens": sum(r["raw_tokens"] for r in measured),
            "qodec": _arm_stats(measured, "qodec_tokens"),
            "rtk": _arm_stats(measured, "rtk_tokens"),
            "rtk_plus_qodec_hybrid": _arm_stats(measured, "rtk_plus_qodec_tokens"),
        },
        "cases": combined,
    }
    body["record_sha256"] = compute_record_sha256(body)
    return body


def render_table(benchmark: dict) -> str:
    corpus = benchmark["corpus"]
    lines = [
        "# N2-D3 Primary Token Benchmark (model-free)",
        "",
        f"total corpus cases = {corpus['total_corpus_cases']}",
        f"token-measurable cases = {corpus['token_measurable_cases']}",
        f"non-UTF-8 measurement refusals = {corpus['non_utf8_measurement_refusals']}",
        "",
        "All token aggregate denominators below are n=16 (measured text-domain subset). "
        "Failure/refusal rates use denominator 18.",
        "",
        "| case_id | status | raw | qodec | rtk | rtk+qodec |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for case_id, row in sorted(benchmark["cases"].items()):
        if row["measurement_status"] == "MEASURED":
            lines.append(
                f"| {case_id} | MEASURED | {row['raw_tokens']} | {row['qodec_tokens']} | "
                f"{row['rtk_tokens']} | {row['rtk_plus_qodec_tokens']} |"
            )
        else:
            lines.append(f"| {case_id} | UNMEASURABLE_NON_UTF8 | - | - | - | - |")

    agg = benchmark["token_aggregates_measured_text_domain_subset_n16"]
    lines += [
        "",
        "## Token aggregates (measured text-domain subset, n=16)",
        "",
        "| arm | total tokens | weighted savings % | macro savings % | median savings % | bootstrap 95% CI |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for arm_key, arm_label in (("qodec", "QODEC"), ("rtk", "RTK"), ("rtk_plus_qodec_hybrid", "RTK+QODEC")):
        a = agg[arm_key]
        ci = a["bootstrap_macro_savings_pct_ci95"]
        lines.append(
            f"| {arm_label} | {a['total_tokens']} | {a['weighted_savings_pct']} | {a['macro_savings_pct']} | "
            f"{a['median_savings_pct']} | [{ci['ci_low_2_5pct']}, {ci['ci_high_97_5pct']}] (n={ci['resamples']}, seed={ci['seed']}) |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--measurements-dir", required=True, type=Path,
                         help="directory containing <case_id>-<leg>.json leg measurement files")
    args = parser.parse_args()

    case_leg_pairs = {}
    for f in sorted(args.measurements_dir.glob("*.json")):
        row = json.loads(f.read_text())
        case_id, leg = row["case_id"], row["leg"]
        pair = case_leg_pairs.setdefault(case_id, {})
        pair[leg] = row

    complete_pairs = {}
    for case_id, legs in sorted(case_leg_pairs.items()):
        if "a" not in legs or "b" not in legs:
            raise RuntimeError(f"{case_id}: missing leg(s), have {sorted(legs.keys())}")
        complete_pairs[case_id] = (legs["a"], legs["b"])

    benchmark = build_benchmark(complete_pairs)
    OUT_JSON_PATH.write_text(json.dumps(benchmark, indent=2, sort_keys=True) + "\n")
    OUT_TABLE_PATH.write_text(render_table(benchmark))
    print(f"wrote {OUT_JSON_PATH} and {OUT_TABLE_PATH} (record_sha256={benchmark['record_sha256']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
