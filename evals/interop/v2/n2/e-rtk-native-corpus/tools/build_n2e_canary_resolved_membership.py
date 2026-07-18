#!/usr/bin/env python3
"""Mechanically resolve the terminally-disqualified canary slots via the FROZEN
per-slot reserve ordering (Option D fallback), re-checking ALL global constraints.

STRICT rules (frozen intent):
  * a slot is resolved ONLY from cases in that slot's frozen reserve ordering, IN
    ORDER -- the winner is the FIRST reserve that satisfies every global constraint;
  * SAVINGS / EASE ARE NEVER INSPECTED -- selection is outcome-blind, structural only;
  * the replacement must be a like-for-like workload (same selection slot signature);
  * global constraints re-checked against the surviving members + already-chosen
    replacements: no repository over its cap, distinct source cluster, not already a
    member, eligible source unit;
  * if a slot's reserves are exhausted without a satisfying candidate -> a terminal
    corpus-feasibility blocker (recorded, never silently dropped).

The disqualified slots are taken from the committed rejection ledger's terminal
entries (never re-judged here). Output is self-hash-locked and links every input by
SHA-256.
"""
from __future__ import annotations

import argparse
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
LEDGER = N2E_DIR / "n2e-canary-rejection-ledger-qualification-v1.json"
OUT = N2E_DIR / "n2e-canary-resolved-membership-v1.json"


def _instance(case_id: str) -> str:
    return case_id.split("::")[0]


def _repository(case_id: str) -> str:
    inst = _instance(case_id)
    return inst.replace("__", "/", 1).rsplit("-", 1)[0] if "__" in inst else inst


def _cluster(case_id: str) -> str:
    return f"swebench:{_instance(case_id)}"


def _slot_of(case_id: str, selection: list) -> str | None:
    for e in selection:
        if e["case_id"] == case_id:
            return e["slot"]
    return None


def _reserve_pool(slot: str, reserves: list) -> list:
    for r in reserves:
        if r["slot"] == slot:
            return r["reserve_case_ids"]
    return []


def resolve_slot(disq_case: str, survivors: list, chosen: list, selection: list,
                 reserves: list, repo_cap: int) -> tuple[dict, list]:
    """Return (resolution, constraint_trace). resolution['resolved_case_id'] is the
    first frozen reserve satisfying all constraints, or None if reserves exhausted."""
    slot = _slot_of(disq_case, selection)
    pool = _reserve_pool(slot, reserves)
    present = {m["case_id"] for m in survivors} | {x["resolved_case_id"] for x in chosen
                                                   if x.get("resolved_case_id")}
    repo_counts: dict = {}
    for m in survivors:
        repo_counts[_repository(m["case_id"])] = repo_counts.get(_repository(m["case_id"]), 0) + 1
    for x in chosen:
        if x.get("resolved_case_id"):
            rc = _repository(x["resolved_case_id"])
            repo_counts[rc] = repo_counts.get(rc, 0) + 1
    clusters = {_cluster(m["case_id"]) for m in survivors} | {
        _cluster(x["resolved_case_id"]) for x in chosen if x.get("resolved_case_id")}

    trace = []
    for cand in pool:
        reasons = []
        if cand in present:
            reasons.append("already a member/replacement")
        if _cluster(cand) in clusters:
            reasons.append("duplicate source cluster")
        if repo_counts.get(_repository(cand), 0) + 1 > repo_cap:
            reasons.append(f"repository over cap ({repo_cap})")
        # like-for-like workload signature (family::sub::variant), never savings/ease
        if cand.split("::")[1:] != disq_case.split("::")[1:]:
            reasons.append("workload signature mismatch")
        trace.append({"candidate": cand, "accepted": not reasons, "reasons": reasons})
        if not reasons:
            return ({"disqualified_case_id": disq_case, "slot": slot,
                     "resolved_case_id": cand, "repository": _repository(cand),
                     "cluster": _cluster(cand), "reserve_rank": pool.index(cand)}, trace)
    return ({"disqualified_case_id": disq_case, "slot": slot, "resolved_case_id": None,
             "reserves_exhausted": True}, trace)


def build(args) -> dict:
    membership = c.load_record(MEMBERSHIP)["membership"]
    selection = c.load_record(SELECTION)["selection"]
    reserves = c.load_record(RESERVES)["reserves"]
    policy = c.load_record(POLICY)
    repo_cap = policy["diversity_constraints"]["max_source_units_per_repository"]

    ledger = c.load_record(LEDGER)
    disq = [e["case_id"] for e in ledger.get("terminal_rejections", [])]
    disq_set = set(disq)

    survivors = [m for m in membership if m["case_id"] not in disq_set]
    chosen, traces = [], {}
    for dcase in sorted(disq):
        res, trace = resolve_slot(dcase, survivors, chosen, selection, reserves, repo_cap)
        chosen.append(res)
        traces[dcase] = trace

    exhausted = [x for x in chosen if x.get("resolved_case_id") is None]
    resolved_membership = list(survivors)
    for x in chosen:
        if x.get("resolved_case_id"):
            # preserve the disqualified case's canary_slot label for the replacement
            orig = next(m for m in membership if m["case_id"] == x["disqualified_case_id"])
            resolved_membership.append({
                "case_id": x["resolved_case_id"], "canary_slot": orig.get("canary_slot"),
                "command_family": x["resolved_case_id"].split("::")[1],
                "command_subfamily": x["resolved_case_id"].split("::")[2]
                if len(x["resolved_case_id"].split("::")) > 2 else None,
                "replaces": x["disqualified_case_id"], "reserve_rank": x["reserve_rank"]})

    # global-constraint re-check on the RESOLVED set
    repo_hist: dict = {}
    for m in resolved_membership:
        repo_hist[_repository(m["case_id"])] = repo_hist.get(_repository(m["case_id"]), 0) + 1
    over_cap = sorted(r for r, n in repo_hist.items() if n > repo_cap)
    clusters = [_cluster(m["case_id"]) for m in resolved_membership]
    dup_clusters = sorted({x for x in clusters if clusters.count(x) > 1})
    constraints_ok = not over_cap and not dup_clusters and not exhausted \
        and len(resolved_membership) == len(membership)

    return c.envelope(
        record_type="n2e-canary-resolved-membership",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_canary_resolved_membership.py",
        purpose="Deterministic Option-D resolution of terminally-disqualified canary "
                "slots via frozen per-slot reserve ordering; outcome-blind, savings never inspected.",
        original_membership_sha256=c.sha256_json_file(MEMBERSHIP),
        selection_result_sha256=c.sha256_json_file(SELECTION),
        reserve_list_sha256=c.sha256_json_file(RESERVES),
        selection_policy_sha256=c.sha256_json_file(POLICY),
        rejection_ledger_sha256=c.sha256_json_file(LEDGER),
        repository_cap=repo_cap,
        disqualified_case_ids=sorted(disq),
        resolutions=chosen, resolution_traces=traces,
        reserves_exhausted=[x["disqualified_case_id"] for x in exhausted],
        resolved_membership=sorted(resolved_membership, key=lambda m: m["case_id"]),
        resolved_case_count=len(resolved_membership),
        global_constraints_recheck={"repository_over_cap": over_cap,
                                    "duplicate_clusters": dup_clusters,
                                    "count_matches_original": len(resolved_membership) == len(membership)},
        constraints_ok=constraints_ok,
        corpus_feasibility_blocker=bool(exhausted),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.parse_args()
    body = build(None)
    c.write_record(OUT, body)
    print(f"wrote {OUT.name}: resolved {body['resolved_case_count']} cases; "
          f"constraints_ok={body['constraints_ok']} blocker={body['corpus_feasibility_blocker']}")
    for r in body["resolutions"]:
        print(f"  {r['disqualified_case_id']} -> {r.get('resolved_case_id')} "
              f"(slot={r.get('slot')}, rank={r.get('reserve_rank')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
