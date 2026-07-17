#!/usr/bin/env python3
"""Independently verify n2e-command-scenarios-v1.json (§12/§22) and the canary
membership (§19). Re-derives both from committed inputs and checks structure.
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import build_n2e_canary_membership as cm  # noqa: E402

SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
SEL = N2E_DIR / "n2e-selection-result-v1.json"
INV = N2E_DIR / "n2e-candidate-inventory-v1.json"
CLAIM = N2E_DIR / "n2e-rtk-claim-surface-v1.json"
CANARY = N2E_DIR / "n2e-canary-membership-v1.json"
RTK_BINARY_SHA256 = "41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf"
CLASSES = {"RTK_NATIVE_SPECIALIZED", "RTK_GENERIC_TEST_WRAPPER", "RTK_PASSTHROUGH_CONTROL"}


def verify_scenarios() -> tuple[bool, str]:
    if not SCEN.is_file():
        return False, "scenarios record missing"
    rec = c.load_record(SCEN)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        return False, msg
    if rec.get("selection_sha256") != c.sha256_json_file(SEL):
        return False, "selection_sha256 mismatch"
    if rec.get("inventory_sha256") != c.sha256_json_file(INV):
        return False, "inventory_sha256 mismatch"
    if rec.get("claim_surface_sha256") != c.sha256_json_file(CLAIM):
        return False, "claim_surface_sha256 mismatch"
    if rec.get("rtk_binary_sha256") != RTK_BINARY_SHA256:
        return False, "rtk_binary_sha256 drift"

    sel_ids = {s["case_id"] for s in c.load_record(SEL)["selection"]}
    scen = rec["scenarios"]
    if len(scen) != 70 or {s["case_id"] for s in scen} != sel_ids:
        return False, "scenarios do not cover exactly the 70 selected cases"
    for s in scen:
        if not isinstance(s["original_argv"], list) or not s["original_argv"]:
            return False, f"{s['case_id']}: original_argv must be a non-empty array (no shell strings)"
        if not s.get("semantic_oracle_type") or not s.get("semantic_oracle_parameters"):
            return False, f"{s['case_id']}: missing semantic oracle"
        if s.get("rtk_support_classification") not in CLASSES:
            return False, f"{s['case_id']}: bad RTK classification"
        env = s.get("environment", {})
        if env.get("TZ") != "UTC" or env.get("LANG") != "C.UTF-8" or env.get("NO_COLOR") != "1":
            return False, f"{s['case_id']}: altered measurement environment"
        # test cases must carry failing-test identities for the oracle
        if s["command_subfamily"] in ("test", "pytest") and s.get("snapshot_variant") in ("buggy", "fail"):
            if not s.get("target_test_ids"):
                return False, f"{s['case_id']}: failing test case lacks target_test_ids"
        # explicit_rtk_argv is an array unless deferred to acquisition resolution
        if s["explicit_rtk_argv"] is not None and not isinstance(s["explicit_rtk_argv"], list):
            return False, f"{s['case_id']}: explicit_rtk_argv must be an array"
        if s["explicit_rtk_argv"] is None and not s.get("rtk_argv_resolution"):
            return False, f"{s['case_id']}: null RTK argv without a resolution note"
    return True, f"OK; {len(scen)} scenario contracts"


def verify_canary() -> tuple[bool, str]:
    if not CANARY.is_file():
        return False, "canary membership missing"
    rec = c.load_record(CANARY)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        return False, msg
    # re-derive deterministically
    rebuilt = cm.build()
    got = sorted(m["case_id"] for m in rec["membership"])
    want = sorted(m["case_id"] for m in rebuilt["membership"])
    if got != want:
        return False, "canary membership does not reproduce from selection+seed"
    if rec["canary_case_count"] != 12:
        return False, f"canary must be 12 cases, got {rec['canary_case_count']}"
    sel_ids = {s["case_id"] for s in c.load_record(SEL)["selection"]}
    if not set(got) <= sel_ids:
        return False, "canary case not in the frozen selection"
    fam = Counter(m["command_family"] for m in rec["membership"])
    # §19 composition sanity: >=5 test ecosystems represented, log + docker present
    if "logs" not in fam or "containers" not in fam:
        return False, "canary missing log or docker case"
    test_ecos = {m["command_family"] for m in rec["membership"]
                 if m["command_subfamily"] in ("test", "pytest")}
    if len(test_ecos) < 5:
        return False, f"canary spans <5 test ecosystems ({sorted(test_ecos)})"
    return True, "OK; 12 cases, >=5 test ecosystems"


def main() -> int:
    ok1, m1 = verify_scenarios()
    ok2, m2 = verify_canary()
    if not (ok1 and ok2):
        print(f"::error::scenarios={m1} | canary={m2}", file=sys.stderr)
        return 1
    print(f"n2e scenario+canary verification passed: {m1}; canary: {m2}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
