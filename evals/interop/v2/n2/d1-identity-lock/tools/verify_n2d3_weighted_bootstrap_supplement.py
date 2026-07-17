#!/usr/bin/env python3
"""Independently, fail-closedly verifies
n2d3-weighted-total-bootstrap-supplement-v1.json.

Re-derives the whole supplement from the real, already-committed
n2d3-primary-token-benchmark-v1.json (re-verifying that record's own
self-hash first) via the real, unmodified
build_n2d3_weighted_bootstrap_supplement.build_record(), and requires
byte-exact equality (record_sha256, then full dict) with the committed
supplement. Also pins that this supplement's seed is the originally-
requested 20260717 (not the canonical record's predeclared-deviation seed
20260716), and that it never mutates the canonical record.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
IDENTITY_LOCK_DIR = TOOLS_DIR.parent
sys.path.insert(0, str(TOOLS_DIR))

SUPPLEMENT_PATH = IDENTITY_LOCK_DIR / "n2d3-weighted-total-bootstrap-supplement-v1.json"
N2D3_BENCHMARK_PATH = IDENTITY_LOCK_DIR / "n2d3-primary-token-benchmark-v1.json"


def verify(supplement_path: Path = SUPPLEMENT_PATH, benchmark_path: Path = N2D3_BENCHMARK_PATH) -> tuple[bool, str]:
    if not supplement_path.is_file():
        return False, f"{supplement_path} does not exist"
    if not benchmark_path.is_file():
        return False, f"{benchmark_path} does not exist"

    import build_n2d3_primary_benchmark as bench_builder
    import build_n2d3_weighted_bootstrap_supplement as supplement_builder

    supplement = json.loads(supplement_path.read_text())
    benchmark = json.loads(benchmark_path.read_text())

    if supplement_builder.compute_record_sha256(supplement) != supplement.get("record_sha256"):
        return False, "supplement self-hash mismatch"
    if bench_builder.compute_record_sha256(benchmark) != benchmark.get("record_sha256"):
        return False, "n2d3-primary-token-benchmark-v1.json self-hash mismatch"

    if supplement.get("record_type") != "n2d3-weighted-total-bootstrap-supplement-v1":
        return False, f"unexpected record_type: {supplement.get('record_type')!r}"
    if supplement.get("canonical") is not False:
        return False, "supplement.canonical must be false"
    if supplement.get("supplement_only") is not True:
        return False, "supplement.supplement_only must be true"
    if supplement.get("source_benchmark_record_sha256") != benchmark.get("record_sha256"):
        return False, "supplement.source_benchmark_record_sha256 does not match the real committed benchmark"

    for arm_key, ci in supplement.get("weighted_total_bootstrap_ci95", {}).items():
        if ci.get("seed") != supplement_builder.SEED:
            return False, f"{arm_key}: supplement bootstrap seed != originally-requested {supplement_builder.SEED!r}"
    if supplement_builder.SEED == supplement_builder.CANONICAL_SEED:
        return False, "supplement seed must differ from the canonical record's predeclared-deviation seed"

    try:
        recomputed = supplement_builder.build_record(benchmark)
    except Exception as exc:  # noqa: BLE001
        return False, f"recomputing the supplement from the committed benchmark raised: {exc}"

    if recomputed.get("record_sha256") != supplement.get("record_sha256"):
        return False, (
            f"recomputed supplement record_sha256 {recomputed.get('record_sha256')!r} != "
            f"committed {supplement.get('record_sha256')!r}"
        )
    if recomputed != supplement:
        return False, "recomputed supplement differs from the committed record despite matching record_sha256"

    return True, "OK"


def main() -> int:
    ok, message = verify()
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
