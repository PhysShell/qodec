#!/usr/bin/env python3
"""Independent verifier for n2e-canary-resolved-membership-v1.json (correction 5).

Rebuilds the resolved membership from ONLY the frozen inputs -- original membership,
the terminal rejection ledger, the frozen per-slot reserve ordering, and the frozen
resolution-order rule -- and requires byte-for-byte agreement with the committed
record's resolution decisions + resolved membership. Also re-verifies the self-hash,
the linked input SHA-256s, and that every global constraint recheck holds.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import build_n2e_canary_resolved_membership as R  # noqa: E402

OUT = N2E_DIR / "n2e-canary-resolved-membership-v1.json"

_COMPARE_FIELDS = ["disqualified_case_ids", "resolution_order", "resolutions",
                   "resolved_membership", "resolved_case_count", "reserves_exhausted",
                   "slot_quotas_preserved", "global_constraints_recheck", "constraints_ok",
                   "corpus_feasibility_blocker"]
_LINK_FIELDS = {
    "original_membership_sha256": R.MEMBERSHIP, "selection_result_sha256": R.SELECTION,
    "reserve_list_sha256": R.RESERVES, "selection_policy_sha256": R.POLICY,
    "candidate_inventory_sha256": R.INVENTORY, "resolution_order_rule_sha256": R.RULE,
    "rejection_ledger_sha256": R.LEDGER,
}


def verify(path: Path = OUT) -> tuple[bool, list]:
    reasons = []
    if not path.is_file():
        return False, [f"resolved-membership record not found: {path.name}"]
    rec = c.load_record(path)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        reasons.append(f"self-hash: {msg}")
    # linked input hashes must match the current frozen inputs
    for field, p in _LINK_FIELDS.items():
        if p.exists() and rec.get(field) != c.sha256_json_file(p):
            reasons.append(f"{field} != current {p.name}")
    # byte-for-byte rebuild from frozen inputs
    rebuilt = R.build(None)
    for f in _COMPARE_FIELDS:
        if json.dumps(rec.get(f), sort_keys=True) != json.dumps(rebuilt.get(f), sort_keys=True):
            reasons.append(f"field {f!r} does not match an independent rebuild")
    if rec.get("constraints_ok") is not True:
        reasons.append("constraints_ok is not True")
    if rec.get("corpus_feasibility_blocker"):
        reasons.append("corpus_feasibility_blocker set (reserves exhausted)")
    return (len(reasons) == 0, reasons)


def main() -> int:
    ok, reasons = verify()
    print(f"resolved-membership: {'OK' if ok else 'FAIL'}")
    for r in reasons:
        print(f"  - {r}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
