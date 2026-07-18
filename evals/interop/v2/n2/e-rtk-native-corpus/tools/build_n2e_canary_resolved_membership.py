#!/usr/bin/env python3
"""Mechanically resolve terminally-disqualified canary slots via the FROZEN per-slot
reserve ordering (Option D fallback), re-checking ALL global constraints (correction 5)
and honouring the frozen multi-rejection resolution-order rule (correction 6).

STRICT rules (frozen intent):
  * candidate metadata (family/subfamily/variant/repo/cluster/source/language) is derived
    from the frozen CANDIDATE INVENTORY + selection records -- never by parsing case_id;
  * a slot is resolved ONLY from that slot's frozen reserve ordering, IN ORDER; the
    winner is the FIRST reserve satisfying every constraint;
  * SAVINGS / EASE ARE NEVER INSPECTED -- selection is outcome-blind, structural only;
  * multiple disqualified slots are resolved in the frozen resolution-order-rule order
    (original membership index -> frozen slot order -> selection position);
  * every proposed resolved membership independently rechecks: exact original case count,
    slot quotas, family/subfamily/variant compatibility, no duplicate case, no duplicate
    cluster, per-repository source-unit cap, max case pct per repository, and no reduction
    in distinct repositories / distinct source systems / repos-per-language vs the
    original; candidate eligibility, scenario constructibility, and publisher-recipe
    availability where required;
  * reserves exhausted without a satisfying candidate -> terminal corpus-feasibility
    blocker (recorded, never silently dropped).

Self-hash-locked; links every frozen input + the rejection ledger by SHA-256.
"""
from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_publisher_registry as pub  # noqa: E402

MEMBERSHIP = N2E_DIR / "n2e-canary-membership-v1.json"
SELECTION = N2E_DIR / "n2e-selection-result-v1.json"
RESERVES = N2E_DIR / "n2e-reserve-list-v1.json"
POLICY = N2E_DIR / "n2e-selection-policy-v1.json"
INVENTORY = N2E_DIR / "n2e-candidate-inventory-v1.json"
SCENARIOS = N2E_DIR / "n2e-command-scenarios-v1.json"
RULE = N2E_DIR / "n2e-resolution-order-rule-v1.json"
LEDGER = N2E_DIR / "n2e-canary-rejection-ledger-qualification-v1.json"
OUT = N2E_DIR / "n2e-canary-resolved-membership-v1.json"

# families whose faithful measurement REQUIRES a publisher recipe (SWE-bench test cases)
_RECIPE_REQUIRED = {("go", "test"), ("rust_cargo", "test"), ("jvm", "test"), ("js_ts", "test")}


class Ctx:
    def __init__(self):
        self.membership = c.load_record(MEMBERSHIP)["membership"]
        self.selection = c.load_record(SELECTION)["selection"]
        self.reserves = c.load_record(RESERVES)["reserves"]
        self.policy = c.load_record(POLICY)
        self.inv = {x["candidate_id"]: x for x in c.load_record(INVENTORY)["candidates"]}
        self.scen_ids = {s["case_id"] for s in c.load_record(SCENARIOS)["scenarios"]}
        self.sel_slot = {e["case_id"]: e["slot"] for e in self.selection}
        self.sel_pos = {e["case_id"]: i for i, e in enumerate(self.selection)}
        self.mem_pos = {m["case_id"]: i for i, m in enumerate(self.membership)}
        self.dv = self.policy["diversity_constraints"]
        rr = c.load_record(RULE)
        self.slot_order = {s: i for i, s in enumerate(rr["frozen_slot_order"])}

    def meta(self, case_id: str) -> dict | None:
        """All candidate metadata from the frozen inventory (never case_id parsing)."""
        return self.inv.get(case_id)

    def reserve_pool(self, slot: str) -> list:
        for r in self.reserves:
            if r["slot"] == slot:
                return r["reserve_case_ids"]
        return []


def _eligible(ctx: Ctx, case_id: str) -> tuple[bool, str]:
    m = ctx.meta(case_id)
    if not m:
        return False, "not in candidate inventory"
    if not m.get("outcome_blind", False):
        return False, "not outcome-blind"
    if (m.get("command_family"), m.get("command_subfamily")) in _RECIPE_REQUIRED \
            and not m.get("target_test_ids"):
        return False, "no target_test_ids for a test case"
    # scenario constructibility: either a frozen scenario exists, or the inventory entry
    # carries the fields needed to construct one (raw argv + base + image recipe).
    constructible = case_id in ctx.scen_ids or all(
        m.get(k) for k in ("raw_command_argv", "base_commit", "image_recipe"))
    if not constructible:
        return False, "scenario not available/constructible"
    # publisher-recipe availability where required
    if (m.get("command_family"), m.get("command_subfamily")) in _RECIPE_REQUIRED \
            and pub.recipe_for_case(case_id) is None:
        return False, "publisher recipe not yet available in registry"
    return True, "eligible"


def resolve_slot(ctx: Ctx, disq_case: str, survivors: list, chosen: list) -> tuple[dict, list]:
    slot = ctx.sel_slot.get(disq_case)
    pool = ctx.reserve_pool(slot)
    dq = ctx.meta(disq_case) or {}
    present = {m["case_id"] for m in survivors} | {x["resolved_case_id"] for x in chosen
                                                   if x.get("resolved_case_id")}
    chosen_ids = [x["resolved_case_id"] for x in chosen if x.get("resolved_case_id")]

    def repo_of(cid):
        return (ctx.meta(cid) or {}).get("repository")

    def cluster_of(cid):
        return (ctx.meta(cid) or {}).get("cluster_id")
    repo_counts: dict = {}
    for cid in [m["case_id"] for m in survivors] + chosen_ids:
        repo_counts[repo_of(cid)] = repo_counts.get(repo_of(cid), 0) + 1
    clusters = {cluster_of(m["case_id"]) for m in survivors} | {cluster_of(x) for x in chosen_ids}
    cap = ctx.dv["max_source_units_per_repository"]

    trace = []
    for cand in pool:
        m = ctx.meta(cand)
        reasons = []
        if cand in present:
            reasons.append("already a member/replacement")
        if not m:
            reasons.append("not in candidate inventory")
        else:
            if m.get("cluster_id") in clusters:
                reasons.append("duplicate source cluster")
            if repo_counts.get(m.get("repository"), 0) + 1 > cap:
                reasons.append(f"repository over source-unit cap ({cap})")
            # like-for-like workload signature from inventory metadata (not case_id)
            sig_c = (m.get("command_family"), m.get("command_subfamily"), m.get("snapshot_variant"))
            sig_d = (dq.get("command_family"), dq.get("command_subfamily"), dq.get("snapshot_variant"))
            if sig_c != sig_d:
                reasons.append(f"workload signature {sig_c} != disqualified {sig_d}")
        el_ok, el_msg = _eligible(ctx, cand)
        if not el_ok:
            reasons.append(f"ineligible: {el_msg}")
        trace.append({"candidate": cand, "accepted": not reasons, "reasons": reasons})
        if not reasons:
            return ({"disqualified_case_id": disq_case, "slot": slot, "resolved_case_id": cand,
                     "repository": m.get("repository"), "cluster": m.get("cluster_id"),
                     "reserve_rank": pool.index(cand)}, trace)
    return ({"disqualified_case_id": disq_case, "slot": slot, "resolved_case_id": None,
             "reserves_exhausted": True}, trace)


def _global_recheck(ctx: Ctx, original: list, resolved: list) -> dict:
    def repos(ms):
        return [(ctx.meta(m["case_id"]) or {}).get("repository") for m in ms]

    def systems(ms):
        return {(ctx.meta(m["case_id"]) or {}).get("source_id") for m in ms}

    def clusters(ms):
        return [(ctx.meta(m["case_id"]) or {}).get("cluster_id") for m in ms]

    def lang_repos(ms, lang):
        return {(ctx.meta(m["case_id"]) or {}).get("repository") for m in ms
                if (ctx.meta(m["case_id"]) or {}).get("language") == lang}
    cap = ctx.dv["max_source_units_per_repository"]
    max_pct = ctx.dv["max_pct_cases_per_repository"]
    n = len(resolved)
    rhist: dict = {}
    for r in repos(resolved):
        rhist[r] = rhist.get(r, 0) + 1
    over_cap = sorted(k for k, v in rhist.items() if v > cap)
    pct_cap = max(1, math.floor(max_pct * n))
    over_pct = sorted(k for k, v in rhist.items() if v > pct_cap)
    cl = clusters(resolved)
    dup_clusters = sorted({x for x in cl if cl.count(x) > 1})
    langs = {(ctx.meta(m["case_id"]) or {}).get("language") for m in original}
    lang_ok = {lang: len(lang_repos(resolved, lang)) >= len(lang_repos(original, lang))
               for lang in langs if lang}
    return {
        "count_matches_original": n == len(original),
        "repository_over_source_unit_cap": over_cap,
        "repository_over_pct_cap": over_pct, "pct_cap_cases": pct_cap,
        "duplicate_clusters": dup_clusters,
        "distinct_repositories": len(set(repos(resolved))),
        "distinct_repositories_not_reduced": len(set(repos(resolved))) >= len(set(repos(original))),
        "distinct_source_systems": len(systems(resolved)),
        "distinct_source_systems_not_reduced": len(systems(resolved)) >= len(systems(original)),
        "repos_per_language_not_reduced": all(lang_ok.values()),
        "repos_per_language": lang_ok,
    }


def _slot_quotas_ok(ctx: Ctx, original: list, resolved: list) -> bool:
    def hist(ms):
        h: dict = {}
        for m in ms:
            h[m.get("canary_slot")] = h.get(m.get("canary_slot"), 0) + 1
        return h
    return hist(original) == hist(resolved)


def build(args) -> dict:
    ctx = Ctx()
    ledger = c.load_record(LEDGER) if LEDGER.exists() else {"terminal_rejections": []}
    disq = [e["case_id"] for e in ledger.get("terminal_rejections", [])]
    disq_set = set(disq)
    # correction 6: resolve in the frozen resolution-order-rule order
    disq_sorted = sorted(disq, key=lambda cid: (ctx.mem_pos.get(cid, 1 << 30),
                                                ctx.slot_order.get(ctx.sel_slot.get(cid), 1 << 30),
                                                ctx.sel_pos.get(cid, 1 << 30)))
    survivors = [m for m in ctx.membership if m["case_id"] not in disq_set]
    chosen, traces = [], {}
    for dcase in disq_sorted:
        res, trace = resolve_slot(ctx, dcase, survivors, chosen)
        chosen.append(res)
        traces[dcase] = trace

    exhausted = [x for x in chosen if x.get("resolved_case_id") is None]
    resolved_membership = list(survivors)
    for x in chosen:
        if x.get("resolved_case_id"):
            orig = next(m for m in ctx.membership if m["case_id"] == x["disqualified_case_id"])
            m = ctx.meta(x["resolved_case_id"]) or {}
            resolved_membership.append({
                "case_id": x["resolved_case_id"], "canary_slot": orig.get("canary_slot"),
                "command_family": m.get("command_family"),
                "command_subfamily": m.get("command_subfamily"),
                "snapshot_variant": m.get("snapshot_variant"),
                "replaces": x["disqualified_case_id"], "reserve_rank": x["reserve_rank"]})
    resolved_membership = sorted(resolved_membership, key=lambda m: m["case_id"])

    recheck = _global_recheck(ctx, ctx.membership, resolved_membership)
    slot_ok = _slot_quotas_ok(ctx, ctx.membership, resolved_membership)
    constraints_ok = (not exhausted and slot_ok and recheck["count_matches_original"]
                      and not recheck["repository_over_source_unit_cap"]
                      and not recheck["repository_over_pct_cap"]
                      and not recheck["duplicate_clusters"]
                      and recheck["distinct_repositories_not_reduced"]
                      and recheck["distinct_source_systems_not_reduced"]
                      and recheck["repos_per_language_not_reduced"])

    return c.envelope(
        record_type="n2e-canary-resolved-membership",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_canary_resolved_membership.py",
        purpose="Deterministic Option-D resolution of terminally-disqualified canary slots "
                "via frozen per-slot reserve ordering; outcome-blind, savings never inspected.",
        original_membership_sha256=c.sha256_json_file(MEMBERSHIP),
        selection_result_sha256=c.sha256_json_file(SELECTION),
        reserve_list_sha256=c.sha256_json_file(RESERVES),
        selection_policy_sha256=c.sha256_json_file(POLICY),
        candidate_inventory_sha256=c.sha256_json_file(INVENTORY),
        resolution_order_rule_sha256=c.sha256_json_file(RULE),
        rejection_ledger_sha256=(c.sha256_json_file(LEDGER) if LEDGER.exists() else None),
        disqualified_case_ids=sorted(disq),
        resolution_order=disq_sorted,
        resolutions=chosen, resolution_traces=traces,
        reserves_exhausted=[x["disqualified_case_id"] for x in exhausted],
        resolved_membership=resolved_membership, resolved_case_count=len(resolved_membership),
        slot_quotas_preserved=slot_ok, global_constraints_recheck=recheck,
        constraints_ok=constraints_ok, corpus_feasibility_blocker=bool(exhausted),
    )


def main() -> int:
    argparse.ArgumentParser().parse_args()
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
