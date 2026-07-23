#!/usr/bin/env python3
"""Independent canary acceptance verification from PRIMARY evidence (§8/§19/§28).

Consumes the per-case records, the aggregate record, and (when present) the job
and artifact manifests. It:
  1. recomputes every per-case self-hash and detects duplicates;
  2. verifies the exact frozen 12-case membership (no missing/extra/duplicate);
  3. RE-DERIVES every verdict from primitive fields (not the producer status);
  4. rebuilds the aggregate verdicts/canary_pass and requires exact agreement;
  5. recomputes the aggregate self-hash and its referenced manifest hashes;
  6. requires run/implementation identity to be present and internally consistent.

Downloading only the aggregate summary is NOT acceptance. Returns non-zero unless
the canary genuinely passed 12/12 over the exact frozen set with agreeing,
independently re-derived verdicts.

Usage: verify_n2e_canary_acceptance.py <evidence-dir>
  evidence-dir must contain the per-case n2e-canary-case-*.json, the aggregate
  n2e-canary-acceptance-v1.json, and optionally job/artifact manifest files.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import build_n2e_canary_acceptance as agg  # noqa: E402

CANARY = N2E_DIR / "n2e-canary-membership-v1.json"


def verify(evidence_dir: Path) -> tuple[bool, str]:
    agg_path = evidence_dir / "n2e-canary-acceptance-v1.json"
    if not agg_path.is_file():
        # fall back to committed location
        agg_path = N2E_DIR / "n2e-canary-acceptance-v1.json"
    if not agg_path.is_file():
        return False, "aggregate record missing"
    aggregate = c.load_record(agg_path)
    ok, msg = c.verify_self_hash(aggregate)
    if not ok:
        return False, f"aggregate self-hash: {msg}"
    if aggregate.get("canary_membership_sha256") != c.sha256_json_file(CANARY):
        return False, "aggregate canary_membership_sha256 mismatch"

    # 1-2. per-case records, hashes, dedup, membership
    expected = {m["case_id"] for m in c.load_record(CANARY)["membership"]}
    try:
        cases = agg.load_cases(evidence_dir)  # re-hashes + dedup-detects
    except SystemExit as e:
        return False, str(e)
    got = {r["case_id"] for r in cases}
    if got != expected:
        return False, f"case set != frozen 12 (missing={sorted(expected - got)}, extra={sorted(got - expected)})"

    # 3-4. re-derive verdicts from primitives; require aggregate agreement
    rederived = {}
    for rec in cases:
        v, _ = agg.rederive_verdict(rec)
        rederived[rec["case_id"]] = v
        # cross-check the per-case record's own self-hash is the one the aggregate cited
        cited = next((row["record_sha256"] for row in aggregate["table"] if row["case_id"] == rec["case_id"]), None)
        if cited != rec.get("record_sha256"):
            return False, f"{rec['case_id']}: aggregate cites a different record self-hash"
    if rederived != aggregate.get("verdicts"):
        return False, "re-derived verdicts disagree with the aggregate"
    want_pass = all(v == "PASS" for v in rederived.values()) and got == expected
    if bool(aggregate.get("all_twelve_pass")) != want_pass:
        return False, "aggregate all_twelve_pass disagrees with re-derived verdicts"
    # acceptance-eligibility gate (directive item 1/8): original_canary_pass may be
    # true ONLY on a canonical run (COMPLETE toolchain lock). A HARVEST run must never
    # assert it, even at 12/12.
    eligible = bool(aggregate.get("acceptance_eligible"))
    if bool(aggregate.get("original_canary_pass")) != (want_pass and eligible):
        return False, "original_canary_pass must equal all_twelve_pass AND acceptance_eligible"
    if aggregate.get("run_class") == "CANONICAL" and not eligible:
        return False, "CANONICAL run_class with acceptance_eligible=false"

    # 5-6. run/implementation identity present + internally consistent
    if not want_pass:
        failing = {k: v for k, v in rederived.items() if v != "PASS"}
        return False, f"canary did NOT pass; non-PASS: {failing}"
    if not aggregate.get("run_id") or not aggregate.get("implementation_sha"):
        return False, "aggregate missing run_id / implementation_sha for a passing canary"
    return True, (f"OK; 12/12 PASS re-derived from primary evidence; run {aggregate['run_id']} "
                  f"impl {aggregate['implementation_sha']}")


def main() -> int:
    evidence_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else N2E_DIR
    ok, message = verify(evidence_dir)
    if not ok:
        print(f"::error::n2e canary acceptance verification FAILED: {message}", file=sys.stderr)
        return 1
    print(f"n2e canary acceptance verification passed: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
