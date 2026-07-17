#!/usr/bin/env python3
"""Independently verify n2e-canary-acceptance-v1.json (§19/§22/§28).

Recomputes the acceptance self-hash, re-derives per-case verdicts from the table,
requires the exact frozen 12-case set with no missing/extra/duplicate, and
requires canary_pass to be the AND of all per-case PASS verdicts. Does not treat
positive savings as a gate; a zero/negative saving does not fail a case. Returns
non-zero unless the canary genuinely passed over the exact 12 frozen cases.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

REC = N2E_DIR / "n2e-canary-acceptance-v1.json"
CANARY = N2E_DIR / "n2e-canary-membership-v1.json"


def verify() -> tuple[bool, str]:
    if not REC.is_file():
        return False, "acceptance record missing"
    rec = c.load_record(REC)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        return False, msg
    if rec.get("canary_membership_sha256") != c.sha256_json_file(CANARY):
        return False, "canary_membership_sha256 mismatch"

    expected = {m["case_id"] for m in c.load_record(CANARY)["membership"]}
    table_ids = [r["case_id"] for r in rec["table"]]
    if len(table_ids) != len(set(table_ids)):
        return False, "duplicate case in acceptance table"
    if set(table_ids) != expected:
        return False, f"acceptance set != frozen 12 (missing={sorted(expected - set(table_ids))}, extra={sorted(set(table_ids) - expected)})"
    if rec.get("missing_cases") or rec.get("extra_cases"):
        return False, "record reports missing/extra cases"

    # canary_pass must equal AND of per-case PASS (savings never a gate)
    all_pass = all(rec["verdicts"].get(cid) == "PASS" for cid in expected)
    if bool(rec.get("canary_pass")) != all_pass:
        return False, "canary_pass does not match per-case verdicts"

    if not rec.get("canary_pass"):
        failing = {cid: v for cid, v in rec["verdicts"].items() if v != "PASS"}
        return False, f"canary did NOT pass; non-PASS cases: {failing}"
    return True, "OK; 12/12 cases PASS over the exact frozen set"


def main() -> int:
    ok, message = verify()
    if not ok:
        print(f"::error::n2e canary acceptance verification FAILED: {message}", file=sys.stderr)
        return 1
    print(f"n2e canary acceptance verification passed: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
