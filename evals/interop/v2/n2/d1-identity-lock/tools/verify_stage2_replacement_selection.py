#!/usr/bin/env python3
"""Independently, fail-closedly verifies stage2-replacement-selection-v1.json.

Recomputes the record's self-hash from its own committed content, then
INDEPENDENTLY RE-RUNS the real frozen selection pipeline (registry.load_registry
-> eligibility.evaluate_registry -> scoring.rank_all -> selection.run_selection,
exactly as the builder does, never merely re-reading the builder's own output)
against the actual committed candidate-registry.json, and requires the record's
claimed eligible_candidate_ids / ranking / quota_trace / replacement_case_id to
match this re-run's real result byte-for-byte. Also independently re-hashes
every referenced tool/policy/registry file rather than trusting the record's
copied hash values, and cross-checks the durable-asset identity against the
committed durable-input-manifest.json (no network access, no re-download).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
BASE_DIR = TOOLS_DIR.parent
REPO_ROOT = BASE_DIR.parents[4]
SOURCE_FREEZE_DIR = REPO_ROOT / "evals" / "interop" / "v2" / "n2" / "source-freeze"
SOURCE_FREEZE_TOOLS = SOURCE_FREEZE_DIR / "tools"
MINER_TOOLS = REPO_ROOT / "evals" / "interop" / "v2" / "n2" / "miner" / "tools"
DURABLE_MANIFEST_PATH = REPO_ROOT / "evals" / "interop" / "v2" / "n2" / "d0-durable-evidence" / "durable-input-manifest.json"
RECORD_PATH = BASE_DIR / "stage2-replacement-selection-v1.json"
REJECTION_RECORD_PATH = BASE_DIR / "repo-spotless-rejection-record.json"
CANDIDATE_REGISTRY_PATH = SOURCE_FREEZE_DIR / "candidate-registry.json"
CANDIDATE_SELECTION_POLICY_PATH = SOURCE_FREEZE_DIR / "candidate-selection-policy.json"
ELIGIBILITY_TOOL_PATH = MINER_TOOLS / "eligibility.py"
SCORER_TOOL_PATH = MINER_TOOLS / "scorer.py"
QUOTA_PLANNER_TOOL_PATH = MINER_TOOLS / "quota_planner.py"

REQUIRED_BASE_MAIN_SHA = "e7e6759298e7f5526a751bddac0cdafc3b6c28c3"
REQUIRED_REJECTED_CASE_ID = "repo-spotless"
REQUIRED_REPLACEMENT_CASE_ID = "repo-helm-values"
ALREADY_USED_CASE_IDS = {"repo-spotless", "repo-moshi"}


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def run_real_selection() -> dict:
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


def verify(record_path: Path = RECORD_PATH) -> tuple[bool, str]:
    if not record_path.is_file():
        return False, f"{record_path} does not exist"

    record = json.loads(record_path.read_text())

    recorded = record.get("record_sha256")
    if not isinstance(recorded, str) or not recorded.startswith("sha256:"):
        return False, "record_sha256 is missing or not in 'sha256:<hex>' form"
    recomputed = compute_record_sha256(record)
    if recomputed != recorded:
        return False, f"self-hash mismatch: recorded={recorded} recomputed={recomputed}"

    if record.get("schema_version") != 1:
        return False, f"unexpected schema_version: {record.get('schema_version')!r}"
    if record.get("record_type") != "n2d1b-stage2-replacement-selection-v1":
        return False, f"unexpected record_type: {record.get('record_type')!r}"
    if record.get("repository") != "PhysShell/qodec":
        return False, f"unexpected repository: {record.get('repository')!r}"
    if record.get("base_main_sha") != REQUIRED_BASE_MAIN_SHA:
        return False, f"base_main_sha {record.get('base_main_sha')!r} != required {REQUIRED_BASE_MAIN_SHA!r}"
    if record.get("rejected_case_id") != REQUIRED_REJECTED_CASE_ID:
        return False, f"rejected_case_id {record.get('rejected_case_id')!r} != required {REQUIRED_REJECTED_CASE_ID!r}"
    if record.get("forbidden_benchmark_signals_used") is not False:
        return False, "forbidden_benchmark_signals_used must be false"
    if record.get("selection_is_deterministic") is not True:
        return False, "selection_is_deterministic must be true"

    # --- independent file-hash re-verification (never trust copied hashes) ---
    file_checks = (
        (REJECTION_RECORD_PATH, "rejection_record_sha256"),
        (CANDIDATE_REGISTRY_PATH, "candidate_registry_sha256"),
        (CANDIDATE_SELECTION_POLICY_PATH, "candidate_selection_policy_sha256"),
        (ELIGIBILITY_TOOL_PATH, "eligibility_tool_sha256"),
        (SCORER_TOOL_PATH, "scorer_tool_sha256"),
        (QUOTA_PLANNER_TOOL_PATH, "quota_planner_tool_sha256"),
    )
    for path, field in file_checks:
        if not path.is_file():
            return False, f"{path} does not exist"
        actual = f"sha256:{_sha256_file(path)}"
        recorded_hash = record.get(field)
        if actual != recorded_hash:
            return False, f"{field} mismatch: file={actual} record={recorded_hash!r}"

    # --- independent re-run of the real selection pipeline -------------------
    pipeline = run_real_selection()

    if record.get("eligible_candidate_ids") != pipeline["eligible_candidate_ids"]:
        return False, "eligible_candidate_ids does not match independently re-run pipeline output"

    if record.get("ranking") != pipeline["ranking"]:
        return False, "ranking does not match independently re-run pipeline output"

    if record.get("quota_trace") != pipeline["quota_trace"]:
        return False, "quota_trace does not match independently re-run pipeline output"

    alternate_case_ids = pipeline["quota_trace"]["alternate_case_ids"]
    by_id = pipeline["candidates_by_id"]
    filtered = [
        cid for cid in alternate_case_ids
        if by_id[cid].get("ecosystem") == "jvm-gradle"
        and by_id[cid].get("origin_kind") == "repository-miner"
        and cid not in ALREADY_USED_CASE_IDS
    ]
    if not filtered:
        return False, "independent re-run produced zero eligible jvm-gradle repository-miner replacements"
    independent_replacement = filtered[0]

    if independent_replacement != REQUIRED_REPLACEMENT_CASE_ID:
        return False, (
            f"independently re-derived replacement {independent_replacement!r} "
            f"!= required {REQUIRED_REPLACEMENT_CASE_ID!r}"
        )
    if record.get("replacement_case_id") != REQUIRED_REPLACEMENT_CASE_ID:
        return False, f"record replacement_case_id {record.get('replacement_case_id')!r} != required {REQUIRED_REPLACEMENT_CASE_ID!r}"
    if record.get("jvm_gradle_alternates_considered_in_rank_order") != filtered:
        return False, "jvm_gradle_alternates_considered_in_rank_order does not match independent re-run"

    # --- durable asset identity cross-check (local file only, no network) ---
    if not DURABLE_MANIFEST_PATH.is_file():
        return False, f"{DURABLE_MANIFEST_PATH} does not exist"
    durable_manifest = json.loads(DURABLE_MANIFEST_PATH.read_text())
    entry = next(
        (e for e in durable_manifest.get("n2c_entries", []) if e.get("logical_id") == REQUIRED_REPLACEMENT_CASE_ID),
        None,
    )
    if entry is None:
        return False, f"no durable-input-manifest.json n2c_entries entry for {REQUIRED_REPLACEMENT_CASE_ID!r}"

    recorded_asset_name = record.get("replacement_durable_asset_name")
    recorded_asset_sha256 = record.get("replacement_durable_asset_sha256", "")
    if recorded_asset_name != entry.get("durable_release_asset_name"):
        return False, (
            f"replacement_durable_asset_name {recorded_asset_name!r} != durable manifest's "
            f"{entry.get('durable_release_asset_name')!r}"
        )
    if not recorded_asset_sha256.startswith("sha256:"):
        return False, "replacement_durable_asset_sha256 must be in 'sha256:<hex>' form"
    if recorded_asset_sha256[len("sha256:"):] != entry.get("durable_release_asset_sha256"):
        return False, (
            f"replacement_durable_asset_sha256 {recorded_asset_sha256!r} != durable manifest's "
            f"sha256:{entry.get('durable_release_asset_sha256')!r}"
        )

    return True, "OK"


def main() -> int:
    ok, message = verify()
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
