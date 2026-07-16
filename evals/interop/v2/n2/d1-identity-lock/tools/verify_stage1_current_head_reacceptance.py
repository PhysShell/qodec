#!/usr/bin/env python3
"""Independently verifies stage1-current-head-reacceptance-v2.json.

Recomputes the record's self-hash from its own committed content (never
from the builder script or the recorded field itself), and cross-checks its
claims against the other artifacts this repository actually carries:
gradle_canonicalizer_v2.py, gradle-capture-canonicalization-policy-v2.json,
and evidence/stage1-v2-trigger.patch. Fails closed on any mismatch.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
RECORD_PATH = BASE_DIR / "stage1-current-head-reacceptance-v2.json"
POLICY_PATH = BASE_DIR / "gradle-capture-canonicalization-policy-v2.json"
TRIGGER_PATCH_PATH = BASE_DIR / "evidence" / "stage1-v2-trigger.patch"

REQUIRED_CASE_IDS = {
    "repo-hyperfine",
    "repo-docker-java-parser",
    "repo-kubeops-generator",
    "repo-pyflakes",
    "repo-moshi",
}


def _canonicalize_and_hash(body: dict) -> str:
    text = json.dumps(body, indent=2, sort_keys=True) + "\n"
    return hashlib.sha256(text.encode()).hexdigest()


def verify(path: Path) -> tuple[bool, str]:
    if not path.is_file():
        return False, f"{path} does not exist"

    record = json.loads(path.read_text())

    recorded = record.get("record_sha256")
    if not isinstance(recorded, str):
        return False, "record_sha256 is missing"
    without_hash = {k: v for k, v in record.items() if k != "record_sha256"}
    recomputed = _canonicalize_and_hash(without_hash)
    if recomputed != recorded:
        return False, f"self-hash mismatch: recorded={recorded} recomputed={recomputed}"

    if record.get("status") != "STAGE_1_REACCEPTED_COMPLETE":
        return False, f"unexpected status: {record.get('status')!r}"

    if set(record.get("accepted_pilot_case_ids", [])) != REQUIRED_CASE_IDS:
        return False, (
            f"accepted_pilot_case_ids mismatch: "
            f"{record.get('accepted_pilot_case_ids')!r} != {sorted(REQUIRED_CASE_IDS)!r}"
        )

    if record.get("job_count") != 10 or len(record.get("jobs", [])) != 10:
        return False, "expected exactly 10 pilot capture jobs"
    if not record.get("all_job_conclusions_success"):
        return False, "not all pilot job conclusions were success"

    if record.get("pair_verify_job_count") != 5 or len(record.get("pair_verify_jobs", [])) != 5:
        return False, "expected exactly 5 pair-verify jobs"
    if not record.get("all_pair_verify_job_conclusions_success"):
        return False, "not all pair-verify job conclusions were success"

    if record.get("artifact_count") != 10 or len(record.get("artifacts", [])) != 10:
        return False, "expected exactly 10 capture artifacts"
    if record.get("pair_report_artifact_count") != 5 or len(record.get("pair_report_artifacts", [])) != 5:
        return False, "expected exactly 5 pair-report artifacts"

    workflow = record.get("workflow", {})
    if workflow.get("event") != "push" or workflow.get("conclusion") != "success":
        return False, f"unexpected workflow identity: {workflow!r}"
    if workflow.get("head_sha") != record.get("execution_trigger_sha"):
        return False, "workflow.head_sha does not match execution_trigger_sha"

    implementation_sha = record.get("implementation_sha")
    execution_trigger_sha = record.get("execution_trigger_sha")
    if not implementation_sha or not execution_trigger_sha:
        return False, "implementation_sha or execution_trigger_sha missing"
    if implementation_sha == execution_trigger_sha:
        return False, (
            "implementation_sha must differ from execution_trigger_sha -- "
            "the trigger commit adds a workflow-only diff on top of the "
            "implementation commit, it is never the same commit"
        )
    if record.get("execution_trigger_changed_paths") != [
        ".github/workflows/qodec-n2d1b-miner-pilot.yml"
    ]:
        return False, "execution_trigger_changed_paths must be exactly the one workflow file"
    if record.get("trigger_commit_included_in_pull_request") is not False:
        return False, "trigger_commit_included_in_pull_request must be false"
    if record.get("non_workflow_tree_equivalent_to_implementation") is not True:
        return False, "non_workflow_tree_equivalent_to_implementation must be true"

    gradle_v2 = record.get("gradle_canonicalization_v2", {})
    if gradle_v2.get("applicable_case_ids") != ["repo-moshi"]:
        return False, "gradle_canonicalization_v2.applicable_case_ids must be exactly ['repo-moshi']"
    if gradle_v2.get("canonicalizer_module") != "gradle_canonicalizer_v2.py":
        return False, "gradle_canonicalization_v2.canonicalizer_module mismatch"

    if POLICY_PATH.is_file():
        policy = json.loads(POLICY_PATH.read_text())
        if policy.get("policy_sha256") != gradle_v2.get("policy_sha256"):
            return False, (
                "gradle_canonicalization_v2.policy_sha256 does not match the "
                "committed policy file's own policy_sha256"
            )
    else:
        return False, f"{POLICY_PATH} does not exist"

    trigger_patch_sha256 = record.get("execution_trigger_patch_sha256", "")
    if not trigger_patch_sha256.startswith("sha256:"):
        return False, "execution_trigger_patch_sha256 must be in 'sha256:<hex>' form"
    if TRIGGER_PATCH_PATH.is_file():
        actual = hashlib.sha256(TRIGGER_PATCH_PATH.read_bytes()).hexdigest()
        if f"sha256:{actual}" != trigger_patch_sha256:
            return False, (
                f"evidence/stage1-v2-trigger.patch sha256 mismatch: "
                f"file={actual} record={trigger_patch_sha256}"
            )
    else:
        return False, f"{TRIGGER_PATCH_PATH} does not exist"

    return True, "OK"


def main() -> int:
    ok, message = verify(RECORD_PATH)
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
