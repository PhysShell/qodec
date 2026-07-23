#!/usr/bin/env python3
"""Independently verify the §10 selection (§10/§11/§22).

Recomputes the deterministic selection from the committed inventory + policy +
seed and REQUIRES it to match the committed selection exactly. This single check
catches wrong seed, any reordering (e.g. by observed savings), manual
replacement, and a selected count != 70. Also checks the §11 diversity
constraints and that the reserve list covers every slot.
"""
from __future__ import annotations

import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import build_n2e_selection as b  # noqa: E402

SEL = N2E_DIR / "n2e-selection-result-v1.json"
RES = N2E_DIR / "n2e-reserve-list-v1.json"
REJ = N2E_DIR / "n2e-rejection-ledger-v1.json"
POLICY = N2E_DIR / "n2e-selection-policy-v1.json"
INVENTORY = N2E_DIR / "n2e-candidate-inventory-v1.json"


def verify() -> tuple[bool, str]:
    for p in (SEL, RES, REJ, POLICY, INVENTORY):
        if not p.is_file():
            return False, f"{p.name} missing"
    sel = c.load_record(SEL)
    res = c.load_record(RES)
    pol = c.load_record(POLICY)
    for rec, name in ((sel, "selection"), (res, "reserve"), (c.load_record(REJ), "rejection"), (pol, "policy")):
        ok, msg = c.verify_self_hash(rec)
        if not ok:
            return False, f"{name}: {msg}"

    # cross-hashes
    if sel.get("inventory_sha256") != c.sha256_json_file(INVENTORY):
        return False, "selection.inventory_sha256 mismatch"
    if sel.get("policy_sha256") != c.sha256_json_file(POLICY):
        return False, "selection.policy_sha256 mismatch"

    # exact count
    if sel["selected_count"] != pol["target_case_count"] or len(sel["selection"]) != 70:
        return False, f"selected_count != 70 ({sel['selected_count']})"

    # re-derive deterministically and require identical selection + reserves
    rebuilt_sel, rebuilt_res, _ = b.build()
    got = sorted(s["case_id"] for s in sel["selection"])
    want = sorted(s["case_id"] for s in rebuilt_sel["selection"])
    if got != want:
        return False, "selection does not reproduce from inventory+policy+seed (tampering/reorder/wrong seed)"
    # reserve ordering must match exactly (frozen fallback order)
    got_res = {r["slot"]: r["reserve_case_ids"] for r in res["reserves"]}
    want_res = {r["slot"]: r["reserve_case_ids"] for r in rebuilt_res["reserves"]}
    if got_res != want_res:
        return False, "reserve ordering does not reproduce (fallback order tampered)"

    # family quota match
    fam = Counter(s["command_family"] for s in sel["selection"])
    want_fam = Counter()
    for slot in pol["slots"]:
        want_fam[slot["family"]] += slot["count"]
    if fam != want_fam:
        return False, f"family quotas off: {dict(fam)} != {dict(want_fam)}"

    # §11 diversity
    dc = pol["diversity_constraints"]
    if sel["distinct_source_systems"] < dc["min_distinct_source_systems"]:
        return False, "too few source systems"
    if sel["distinct_repositories"] < dc["min_distinct_repositories"]:
        return False, "too few repositories"
    cpr = defaultdict(set)
    cases = Counter()
    for s in sel["selection"]:
        cpr[s["repository"]].add(s["cluster_id"])
        cases[s["repository"]] += 1
    if any(len(v) > dc["max_source_units_per_repository"] for v in cpr.values()):
        return False, "a repository contributes >2 source units"
    cap = int(pol["target_case_count"] * dc["max_pct_cases_per_repository"])
    if any(v > cap for v in cases.values()):
        return False, f"a repository exceeds the {cap}-case cap"
    lang_repos = defaultdict(set)
    for s in sel["selection"]:
        if s["command_family"] in dc["min_repos_per_language"]:
            lang_repos[s["command_family"]].add(s["repository"])
    for fam_key, need in dc["min_repos_per_language"].items():
        if len(lang_repos[fam_key]) < need:
            return False, f"{fam_key}: {len(lang_repos[fam_key])} repos < {need}"

    # reserve list covers every slot
    slot_ids = {s["id"] for s in pol["slots"]}
    if {r["slot"] for r in res["reserves"]} != slot_ids:
        return False, "reserve list does not cover every slot"

    return True, f"OK; 70 cases, {sel['distinct_repositories']} repos, {sel['distinct_source_systems']} systems"


def main() -> int:
    ok, message = verify()
    if not ok:
        print(f"::error::n2e selection verification FAILED: {message}", file=sys.stderr)
        return 1
    print(f"n2e selection verification passed: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
