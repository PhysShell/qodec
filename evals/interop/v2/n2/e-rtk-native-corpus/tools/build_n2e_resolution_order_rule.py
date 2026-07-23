#!/usr/bin/env python3
"""Freeze the multi-rejection RESOLUTION-ORDER rule (correction 6).

When more than one canary slot is terminally disqualified, the order in which their
replacements are resolved must be deterministic and derived ONLY from frozen
PRE-MEASUREMENT data -- never from outcome type, run order, savings/ease, or when a
failure was discovered. The rule sorts disqualified cases by:

    1. original membership order   (position in n2e-canary-membership-v1.json)
    2. then frozen slot order      (position of the case's selection slot in the frozen
                                    reserve-list slot ordering)
    3. then original selection pos (position in n2e-selection-result-v1.json)

Original membership order alone is already a total order over the frozen twelve; the
slot and selection tiebreakers are recorded for completeness and to bind the rule to
the frozen inputs. For the present single Caddy rejection the choice is unaffected, but
the rule is frozen here BEFORE the 70-case campaign can produce interacting
disqualifications. Self-hash-locked; links every frozen input by SHA-256.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

MEMBERSHIP = N2E_DIR / "n2e-canary-membership-v1.json"
SELECTION = N2E_DIR / "n2e-selection-result-v1.json"
RESERVES = N2E_DIR / "n2e-reserve-list-v1.json"
POLICY = N2E_DIR / "n2e-selection-policy-v1.json"
OUT = N2E_DIR / "n2e-resolution-order-rule-v1.json"

RULE_ID = "n2e-resolution-order-rule-v1"


def build() -> dict:
    reserves = c.load_record(RESERVES)["reserves"]
    slot_order = [r["slot"] for r in reserves]  # frozen order slots appear in the reserve list
    return c.envelope(
        record_type="n2e-resolution-order-rule",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_resolution_order_rule.py",
        rule_id=RULE_ID,
        purpose="Deterministic order for resolving multiple terminally-disqualified canary "
                "slots, derived only from frozen pre-measurement data.",
        ordering_keys=["original_membership_index", "frozen_slot_order_index",
                       "original_selection_position"],
        independent_of=["outcome_type", "run_order", "savings_or_ease", "discovery_time"],
        frozen_slot_order=slot_order,
        original_membership_sha256=c.sha256_json_file(MEMBERSHIP),
        selection_result_sha256=c.sha256_json_file(SELECTION),
        reserve_list_sha256=c.sha256_json_file(RESERVES),
        selection_policy_sha256=c.sha256_json_file(POLICY),
    )


def main() -> int:
    c.write_record(OUT, build())
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name}: rule_id={rec['rule_id']} keys={rec['ordering_keys']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
