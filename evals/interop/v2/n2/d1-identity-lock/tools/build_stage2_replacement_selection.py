#!/usr/bin/env python3
"""N2-D1b Stage 2: builds the deterministic replacement-selection evidence
record for the ninth (jvm-gradle repository-miner) case.

repo-spotless (Stage 1's original jvm-gradle repository-miner primary) was
permanently rejected -- see repo-spotless-rejection-record.json -- and its
own rejection record explicitly names the mechanism its successor must be
chosen by: "the pre-existing deterministic candidate-selection policy (N2-B's
eligibility.py/scorer.py/quota_planner.py, applied to candidate-registry.json's
jvm-gradle-ecosystem candidates)... never a hand-picked or QODEC/RTK/token-
count/output-size re-ranked substitute."

This script does not reimplement that policy -- it imports and RUNS the real,
frozen source-freeze/tools/{registry,eligibility,selection,scoring}.py code
(which itself loads and runs the frozen miner/tools/{eligibility,scorer,
quota_planner}.py modules unmodified via n2b_bridge.py), against the live
committed candidate-registry.json, and records every step's real output.

The candidate-selection-policy.json actually consulted by scoring.rank_all()
(via scoring.load_policy()) is source-freeze/candidate-selection-policy.json
-- NOT miner/candidate-selection-policy.json (a separate, differently-scoped
file that exists but is not read by this code path). Both are left untouched;
only source-freeze's is hashed here as the operative policy identity.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BASE_DIR.parents[4]
SOURCE_FREEZE_DIR = REPO_ROOT / "evals" / "interop" / "v2" / "n2" / "source-freeze"
SOURCE_FREEZE_TOOLS = SOURCE_FREEZE_DIR / "tools"
MINER_TOOLS = REPO_ROOT / "evals" / "interop" / "v2" / "n2" / "miner" / "tools"
OUT_PATH = BASE_DIR / "stage2-replacement-selection-v1.json"

BASE_MAIN_SHA = "e7e6759298e7f5526a751bddac0cdafc3b6c28c3"
REJECTED_CASE_ID = "repo-spotless"
REJECTION_RECORD_PATH = BASE_DIR / "repo-spotless-rejection-record.json"
CANDIDATE_REGISTRY_PATH = SOURCE_FREEZE_DIR / "candidate-registry.json"
CANDIDATE_SELECTION_POLICY_PATH = SOURCE_FREEZE_DIR / "candidate-selection-policy.json"
ELIGIBILITY_TOOL_PATH = MINER_TOOLS / "eligibility.py"
SCORER_TOOL_PATH = MINER_TOOLS / "scorer.py"
QUOTA_PLANNER_TOOL_PATH = MINER_TOOLS / "quota_planner.py"

# Already-consumed jvm-gradle repository-miner cases -- never eligible again
# as "the replacement": repo-spotless (rejected) occupies its own frozen
# primary manifest slot, and repo-moshi already fills Stage 1's jvm-gradle
# pilot slot and remains in Stage 2's fixed five.
ALREADY_USED_CASE_IDS = {"repo-spotless", "repo-moshi"}

# Real durable acquisition asset for the derived replacement, independently
# downloaded from the n2d0-durable-evidence-v1 release and hash-verified
# (zip SHA-256, plus every contained file's SHA-256) against
# evals/interop/v2/n2/d0-durable-evidence/durable-input-manifest.json's
# n2c_entries before this script ever ran -- see the task's evidence trail.
REPLACEMENT_DURABLE_ASSET_NAME = "n2c-acquisition-repo-helm-values.zip"
REPLACEMENT_DURABLE_ASSET_SHA256 = "005dd900fba6d10becac8e470e0510d1a6a8502cac0427a052cba0dda02465ec"
REPLACEMENT_SOURCE_MANIFEST = "evals/interop/v2/n2/source-freeze/source-manifests/alternate/repo-helm-values.json"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def run_real_selection() -> dict:
    """Imports and executes the actual frozen selection pipeline -- never a
    reimplementation -- and returns every intermediate artifact needed for
    a full, independently-checkable evidence record."""
    sys.path.insert(0, str(SOURCE_FREEZE_TOOLS))
    import registry  # noqa: E402
    import eligibility  # noqa: E402
    import selection  # noqa: E402
    import scoring  # noqa: E402

    reg = registry.load_registry(CANDIDATE_REGISTRY_PATH)
    eligibility_reports = eligibility.evaluate_registry(reg)
    eligible_ids = sorted(r["candidate_id"] for r in eligibility_reports if r["eligible"])
    eligible_candidates = [c for c in reg["candidates"] if c["candidate_id"] in eligible_ids]

    ranking = sorted(
        scoring.rank_all(eligible_candidates),
        key=lambda r: (r["quota_group"], r["rank_within_group"]),
    )

    result = selection.run_selection(eligible_candidates)

    return {
        "eligibility_reports": sorted(eligibility_reports, key=lambda r: r["candidate_id"]),
        "eligible_candidate_ids": eligible_ids,
        "ranking": ranking,
        "quota_trace": result,
        "candidates_by_id": {c["candidate_id"]: c for c in reg["candidates"]},
    }


def derive_replacement(pipeline_output: dict) -> dict:
    """Applies section 3.1's exact filter (frozen alternates, jvm-gradle,
    repository-miner) to the real selection output's alternate_case_ids
    (already in the frozen deterministic rank order), and returns the
    single top-ranked eligible candidate not already used."""
    alternate_case_ids = pipeline_output["quota_trace"]["alternate_case_ids"]
    by_id = pipeline_output["candidates_by_id"]

    filtered = [
        cid for cid in alternate_case_ids
        if by_id[cid].get("ecosystem") == "jvm-gradle"
        and by_id[cid].get("origin_kind") == "repository-miner"
        and cid not in ALREADY_USED_CASE_IDS
    ]

    if len(filtered) == 0:
        raise SystemExit("selection procedure produced zero eligible jvm-gradle repository-miner replacements")

    replacement_case_id = filtered[0]
    # "More than one final replacement" means the procedure failed to
    # resolve to a single top choice -- it does NOT mean more than one
    # candidate satisfies the raw ecosystem/origin_kind filter (multiple
    # alternates may exist; the frozen rank order's first entry is always
    # the unique final replacement, by construction of a total order).
    return {
        "replacement_case_id": replacement_case_id,
        "candidates_considered": filtered,
        "fallback_rank_position": alternate_case_ids.index(replacement_case_id) + 1,
    }


def build_record() -> dict:
    pipeline = run_real_selection()
    derivation = derive_replacement(pipeline)
    replacement_case_id = derivation["replacement_case_id"]

    if replacement_case_id != "repo-helm-values":
        raise SystemExit(
            f"derived replacement {replacement_case_id!r} does not match the "
            "independently pre-verified durable-asset identity hardcoded in "
            "this builder (repo-helm-values) -- stop for review, do not guess"
        )

    body = {
        "schema_version": 1,
        "record_type": "n2d1b-stage2-replacement-selection-v1",
        "repository": "PhysShell/qodec",
        "base_main_sha": BASE_MAIN_SHA,
        "rejected_case_id": REJECTED_CASE_ID,
        "rejection_record_path": "evals/interop/v2/n2/d1-identity-lock/repo-spotless-rejection-record.json",
        "rejection_record_sha256": f"sha256:{_sha256_file(REJECTION_RECORD_PATH)}",
        "selection_scope": "frozen eligible jvm-gradle repository-miner alternates",
        "candidate_registry_path": "evals/interop/v2/n2/source-freeze/candidate-registry.json",
        "candidate_registry_sha256": f"sha256:{_sha256_file(CANDIDATE_REGISTRY_PATH)}",
        "candidate_selection_policy_path": "evals/interop/v2/n2/source-freeze/candidate-selection-policy.json",
        "candidate_selection_policy_sha256": f"sha256:{_sha256_file(CANDIDATE_SELECTION_POLICY_PATH)}",
        "eligibility_tool_path": "evals/interop/v2/n2/miner/tools/eligibility.py",
        "eligibility_tool_sha256": f"sha256:{_sha256_file(ELIGIBILITY_TOOL_PATH)}",
        "scorer_tool_path": "evals/interop/v2/n2/miner/tools/scorer.py",
        "scorer_tool_sha256": f"sha256:{_sha256_file(SCORER_TOOL_PATH)}",
        "quota_planner_tool_path": "evals/interop/v2/n2/miner/tools/quota_planner.py",
        "quota_planner_tool_sha256": f"sha256:{_sha256_file(QUOTA_PLANNER_TOOL_PATH)}",
        "already_used_jvm_gradle_case_ids": sorted(ALREADY_USED_CASE_IDS),
        "eligible_candidate_ids": pipeline["eligible_candidate_ids"],
        "ranking": pipeline["ranking"],
        "quota_trace": pipeline["quota_trace"],
        "jvm_gradle_alternates_considered_in_rank_order": derivation["candidates_considered"],
        "replacement_case_id": replacement_case_id,
        "replacement_fallback_rank_position": derivation["fallback_rank_position"],
        "replacement_source_manifest": REPLACEMENT_SOURCE_MANIFEST,
        "replacement_source_commit_sha": pipeline["candidates_by_id"][replacement_case_id]["source_identity"]["commit_sha"],
        "replacement_durable_asset_name": REPLACEMENT_DURABLE_ASSET_NAME,
        "replacement_durable_asset_sha256": f"sha256:{REPLACEMENT_DURABLE_ASSET_SHA256}",
        "forbidden_benchmark_signals_used": False,
        "selection_is_deterministic": True,
        "record_sha256": None,
    }
    body["record_sha256"] = compute_record_sha256(body)
    return body


def main() -> int:
    body = build_record()
    recomputed = compute_record_sha256(body)
    assert recomputed == body["record_sha256"], "self-hash did not verify stable"
    OUT_PATH.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT_PATH} (record_sha256={body['record_sha256']}, replacement={body['replacement_case_id']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
