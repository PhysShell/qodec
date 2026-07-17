#!/usr/bin/env python3
"""Builds the weighted-total bootstrap confidence-interval supplement.

This is a separately-derived REPORTING SUPPLEMENT, not part of the
canonical N2-D3 record. The canonical n2d3-primary-token-benchmark-v1.json
bootstrap resamples per-case savings ratios and averages them across the
resample ("macro savings" bootstrap) -- that bootstrap's seed (20260716)
was already committed in implementation SHA 0abdde6723574e908415835612e8f520d85c33e7
before the canonical CI run, so it is accepted as a predeclared deviation
from the originally-requested seed 20260717 and is NOT changed here or
anywhere else post-run.

This supplement instead computes a pooled/weighted-ratio bootstrap: each
resample draws n=16 measured cases with replacement and computes
1 - sum(resampled arm_tokens) / sum(resampled raw_tokens) -- i.e. it
resamples cases jointly (raw + arm tokens together) and pools by token
mass, rather than resampling per-case ratios and averaging them unweighted.
This is the correct way to put a confidence interval around the already-
reported *weighted* savings percentages (as opposed to the canonical
record's macro savings percentages). It uses the originally-requested seed
20260717, since this fresh computation is not constrained by the "already
committed before the canonical run" argument that justified keeping
20260716 in the canonical record.

This tool reads ONLY the already-committed, already-accepted
n2d3-primary-token-benchmark-v1.json (re-verifying its self-hash first);
it does not read raw leg data, does not invoke qodec/rtk, and does not
write to or alter the canonical record in any way.
"""
from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path

IDENTITY_LOCK_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
OUT_PATH = IDENTITY_LOCK_DIR / "n2d3-weighted-total-bootstrap-supplement-v1.json"
N2D3_BENCHMARK_PATH = IDENTITY_LOCK_DIR / "n2d3-primary-token-benchmark-v1.json"

SEED = 20260717
CANONICAL_SEED = 20260716
RESAMPLES = 10000
ARM_TOKEN_FIELDS = {
    "qodec": "qodec_tokens",
    "rtk": "rtk_tokens",
    "rtk_plus_qodec_hybrid": "rtk_plus_qodec_tokens",
}


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _measured_rows(benchmark: dict) -> list[dict]:
    rows = [
        r for _, r in sorted(benchmark["cases"].items())
        if r["measurement_status"] == "MEASURED"
    ]
    if len(rows) != 16:
        raise RuntimeError(f"expected exactly 16 measured rows, got {len(rows)}")
    return rows


def _weighted_bootstrap_ci(rows: list[dict], token_field: str, seed: int, resamples: int) -> dict:
    rng = random.Random(seed)
    n = len(rows)
    raw = [r["raw_tokens"] for r in rows]
    out = [r[token_field] for r in rows]

    point_raw_total = sum(raw)
    point_out_total = sum(out)
    point_estimate = 1.0 - point_out_total / point_raw_total if point_raw_total else 0.0

    ratios = []
    for _ in range(resamples):
        idxs = [rng.randrange(n) for _ in range(n)]
        resampled_raw_total = sum(raw[i] for i in idxs)
        resampled_out_total = sum(out[i] for i in idxs)
        ratios.append(1.0 - resampled_out_total / resampled_raw_total if resampled_raw_total else 0.0)
    ratios.sort()
    lo_idx = int(0.025 * resamples)
    hi_idx = min(int(0.975 * resamples), resamples - 1)

    return {
        "seed": seed,
        "resamples": resamples,
        "point_estimate_weighted_savings_pct": round(100.0 * point_estimate, 4),
        "ci_low_2_5pct": round(100.0 * ratios[lo_idx], 4),
        "ci_high_97_5pct": round(100.0 * ratios[hi_idx], 4),
    }


def build_record(benchmark: dict) -> dict:
    import build_n2d3_primary_benchmark as bench_builder

    if bench_builder.compute_record_sha256(benchmark) != benchmark.get("record_sha256"):
        raise RuntimeError("source n2d3-primary-token-benchmark-v1.json self-hash mismatch -- refusing to build on unverified input")

    rows = _measured_rows(benchmark)

    ci_by_arm = {
        arm_key: _weighted_bootstrap_ci(rows, token_field, SEED, RESAMPLES)
        for arm_key, token_field in ARM_TOKEN_FIELDS.items()
    }

    # Sanity cross-check: the point estimate this supplement recomputes must
    # equal the canonical record's own already-reported weighted_savings_pct
    # for every arm (same pooled ratio, just also given a bootstrap CI here).
    for arm_key in ARM_TOKEN_FIELDS:
        canonical_weighted = benchmark["token_aggregates_measured_text_domain_subset_n16"][arm_key]["weighted_savings_pct"]
        recomputed_point = ci_by_arm[arm_key]["point_estimate_weighted_savings_pct"]
        if round(canonical_weighted, 4) != round(recomputed_point, 4):
            raise RuntimeError(
                f"{arm_key}: recomputed weighted point estimate {recomputed_point} != canonical record's "
                f"own weighted_savings_pct {canonical_weighted} -- source data or arithmetic mismatch"
            )

    body = {
        "record_type": "n2d3-weighted-total-bootstrap-supplement-v1",
        "record_version": 1,
        "schema_version": 1,
        "canonical": False,
        "supplement_only": True,
        "note": (
            "This is a separately-derived reporting supplement. It is NOT part of the canonical "
            "CI-produced n2d3-primary-token-benchmark-v1.json record and does not alter it. It puts "
            "a bootstrap confidence interval around the already-reported WEIGHTED savings percentages "
            "(pooled by token mass) as opposed to the canonical record's MACRO savings bootstrap "
            "(averaging per-case ratios, unweighted by size)."
        ),
        "seed_provenance": (
            f"uses seed {SEED}, the originally-requested seed. The canonical record's own bootstrap "
            f"uses seed {CANONICAL_SEED}, which was already committed in implementation SHA "
            "0abdde6723574e908415835612e8f520d85c33e7 before the canonical CI run and is accepted as a "
            f"predeclared deviation from the originally-requested seed {SEED}; that seed is NOT changed "
            "here or anywhere else post-run. This supplement is a fresh, independent computation "
            "unconstrained by that deviation, so it uses the originally-requested seed."
        ),
        "methodology": (
            "pooled/weighted-ratio bootstrap: each of the resamples draws n=16 measured cases with "
            "replacement and computes 1 - sum(resampled arm_tokens) / sum(resampled raw_tokens) -- "
            "cases are resampled jointly (raw and arm token counts together, per case), and the ratio "
            "is computed once per resample over the pooled resampled totals. This differs from the "
            "canonical record's bootstrap, which resamples per-case ratios independently and averages "
            "them (unweighted by case size) each resample."
        ),
        "source_benchmark_record_path": "evals/interop/v2/n2/d1-identity-lock/n2d3-primary-token-benchmark-v1.json",
        "source_benchmark_record_sha256": benchmark["record_sha256"],
        "n": len(rows),
        "weighted_total_bootstrap_ci95": ci_by_arm,
    }
    body["record_sha256"] = compute_record_sha256(body)
    return body


def main() -> None:
    benchmark = json.loads(N2D3_BENCHMARK_PATH.read_text())
    record = build_record(benchmark)
    OUT_PATH.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT_PATH} (record_sha256={record['record_sha256']})")


if __name__ == "__main__":
    main()
