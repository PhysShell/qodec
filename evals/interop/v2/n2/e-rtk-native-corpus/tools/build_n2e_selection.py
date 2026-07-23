#!/usr/bin/env python3
"""Build the §10 deterministic selection — OFFLINE, seed-frozen, outcome-blind.

Reads the committed candidate inventory + selection policy and produces:
  - n2e-selection-result-v1.json  (exactly 70 selected case ids per slot)
  - n2e-reserve-list-v1.json      (ordered fallback candidates per slot)
  - n2e-rejection-ledger-v1.json  (typed reasons for hard-filter rejections)

Ordering is seed-frozen: within each slot, eligible candidates are stable-sorted
by candidate_id then ordered by sha256(f"{seed}:{candidate_id}"). Greedy fill
respects the §11 global caps (<=2 source-units/repo, <=10% cases/repo). Selection
observes NO RTK/QODEC output — only committed metadata.
"""
from __future__ import annotations

import hashlib
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

INVENTORY = N2E_DIR / "n2e-candidate-inventory-v1.json"
POLICY = N2E_DIR / "n2e-selection-policy-v1.json"
SEL = N2E_DIR / "n2e-selection-result-v1.json"
RES = N2E_DIR / "n2e-reserve-list-v1.json"
REJ = N2E_DIR / "n2e-rejection-ledger-v1.json"


def _order_key(seed: int, cid: str) -> str:
    return hashlib.sha256(f"{seed}:{cid}".encode()).hexdigest()


def eligible(cand: dict, slot: dict) -> bool:
    if cand["command_family"] != slot["family"]:
        return False
    if slot.get("subfamilies") and cand["command_subfamily"] not in slot["subfamilies"]:
        return False
    if slot.get("variant") and cand.get("snapshot_variant") != slot["variant"]:
        return False
    if slot.get("min_target_tests"):
        if cand.get("target_test_count", 0) < slot["min_target_tests"]:
            return False
    return True


def hard_filter(cand: dict) -> str | None:
    """§9 metadata-knowable hard filters. Returns a typed rejection reason or None."""
    if not cand.get("outcome_blind", False):
        return "REJECTED_NOT_OUTCOME_BLIND"
    if not isinstance(cand.get("raw_command_argv"), list) or not cand["raw_command_argv"]:
        return "REJECTED_NO_COMMAND"
    if not cand.get("source_id") or not cand.get("repository") or not cand.get("cluster_id"):
        return "REJECTED_MISSING_IDENTITY"
    if cand["command_subfamily"] == "test" and not cand.get("target_test_ids"):
        return "REJECTED_NO_FAILING_TEST_IDENTITY"
    return None


def build() -> tuple[dict, dict, dict]:
    inv = c.load_record(INVENTORY)
    pol = c.load_record(POLICY)
    seed = pol["seed"]
    max_units_per_repo = pol["diversity_constraints"]["max_source_units_per_repository"]
    max_cases_per_repo = int(pol["target_case_count"] * pol["diversity_constraints"]["max_pct_cases_per_repository"])

    # hard filter first (rejection ledger)
    rejections = []
    pool = []
    for cand in inv["candidates"]:
        reason = hard_filter(cand)
        if reason:
            rejections.append({"candidate_id": cand["candidate_id"], "reason": reason})
        else:
            pool.append(cand)

    # global caps state
    clusters_per_repo = defaultdict(set)
    cases_per_repo = defaultdict(int)
    selected_ids = set()

    selection = []
    reserves = []

    for slot in pol["slots"]:
        elig = [x for x in pool if eligible(x, slot) and x["candidate_id"] not in selected_ids]
        elig.sort(key=lambda x: x["candidate_id"])
        elig.sort(key=lambda x: _order_key(seed, x["candidate_id"]))
        picked = []
        reserve_ids = []
        for cand in elig:
            repo = cand["repository"]
            cluster = cand["cluster_id"]
            if len(picked) < slot["count"]:
                # caps: <=2 source units per repo (a new cluster counts), <=10% cases/repo
                new_cluster = cluster not in clusters_per_repo[repo]
                if new_cluster and len(clusters_per_repo[repo]) >= max_units_per_repo:
                    reserve_ids.append(cand["candidate_id"])
                    continue
                if cases_per_repo[repo] >= max_cases_per_repo:
                    reserve_ids.append(cand["candidate_id"])
                    continue
                picked.append(cand)
                selected_ids.add(cand["candidate_id"])
                clusters_per_repo[repo].add(cluster)
                cases_per_repo[repo] += 1
            else:
                reserve_ids.append(cand["candidate_id"])
        for cand in picked:
            selection.append({
                "case_id": cand["candidate_id"], "slot": slot["id"],
                "cluster_id": cand["cluster_id"], "source_id": cand["source_id"],
                "repository": cand["repository"], "language": cand.get("language"),
                "command_family": cand["command_family"], "command_subfamily": cand["command_subfamily"],
                "snapshot_variant": cand.get("snapshot_variant"),
            })
        reserves.append({"slot": slot["id"], "reserve_case_ids": reserve_ids})
        if len(picked) < slot["count"]:
            rejections.append({"slot": slot["id"],
                               "reason": "SLOT_UNDERFILLED",
                               "got": len(picked), "want": slot["count"]})

    sel_body = c.envelope(
        record_type="n2e-selection-result",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_selection.py",
        purpose="Deterministic seed-frozen selection of exactly 70 outcome-blind cases (§10).",
        seed=seed,
        inventory_sha256=c.sha256_json_file(INVENTORY),
        policy_sha256=c.sha256_json_file(POLICY),
        selected_count=len(selection),
        distinct_clusters=len({s["cluster_id"] for s in selection}),
        distinct_repositories=len({s["repository"] for s in selection}),
        distinct_source_systems=len({s["source_id"] for s in selection}),
        selection=sorted(selection, key=lambda s: s["case_id"]),
    )
    res_body = c.envelope(
        record_type="n2e-reserve-list",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_selection.py",
        purpose="Frozen per-slot fallback ordering for typed qualification failures (§10/§18).",
        seed=seed, selection_policy_sha256=c.sha256_json_file(POLICY),
        reserves=reserves,
    )
    rej_body = c.envelope(
        record_type="n2e-rejection-ledger",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_selection.py",
        purpose="Typed hard-filter rejections and slot underfills (§9).",
        rejection_count=len(rejections),
        rejections=sorted(rejections, key=lambda r: (r.get("candidate_id") or r.get("slot") or "")),
    )
    return sel_body, res_body, rej_body


def main() -> int:
    sel, res, rej = build()
    c.write_record(SEL, sel)
    c.write_record(RES, res)
    c.write_record(REJ, rej)
    s = c.load_record(SEL)
    print(f"selection: {s['selected_count']} cases, {s['distinct_repositories']} repos, "
          f"{s['distinct_source_systems']} systems, {s['distinct_clusters']} clusters")
    print(f"reserves: {SEL.name}={s['record_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
