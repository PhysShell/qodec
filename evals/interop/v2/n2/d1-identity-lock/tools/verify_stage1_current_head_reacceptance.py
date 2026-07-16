#!/usr/bin/env python3
"""Independently, fail-closedly verifies stage1-current-head-reacceptance-v2.json.

Recomputes the record's self-hash from its own committed content using the
documented compact-canonical protocol (never from the builder script or the
recorded field itself), then cross-checks its claims against: real git
history (base/implementation ancestry, implementation vs. execution-trigger
identity), the actual v2 and v1 canonicalization policy files (via each
module's own load_and_verify_policy, never a value merely copied into the
record), job/artifact ID and name uniqueness plus digest shape, every
acceptance-gate boolean, every independent_rederivation_verification entry,
and the trigger patch's literal diff content (not just its hash). Fails
closed on any mismatch.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
BASE_DIR = TOOLS_DIR.parent
RECORD_PATH = BASE_DIR / "stage1-current-head-reacceptance-v2.json"
POLICY_PATH = BASE_DIR / "gradle-capture-canonicalization-policy-v2.json"
V1_POLICY_PATH = BASE_DIR / "gradle-capture-canonicalization-policy.json"
TRIGGER_PATCH_PATH = BASE_DIR / "evidence" / "stage1-v2-trigger.patch"

REQUIRED_CASE_IDS = {
    "repo-hyperfine",
    "repo-docker-java-parser",
    "repo-kubeops-generator",
    "repo-pyflakes",
    "repo-moshi",
}
REQUIRED_WORKFLOW_FILE = ".github/workflows/qodec-n2d1b-miner-pilot.yml"
REQUIRED_V1_POLICY_SHA256 = "c968245e3837e2155873a8c8a3623bad9b2522ef163ee79cfbf2461eb8ef3b7c"
REQUIRED_TRIGGER_BRANCH = "ci-trigger/n2d1b-stage1-eaafc178"


def compute_record_sha256(body: dict) -> str:
    """Independent re-implementation of the documented self-hash protocol
    (same protocol as the builder's compute_record_sha256, deliberately
    re-typed here rather than imported, so a bug in one cannot silently
    survive a matching bug in the other)."""
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _git(repo_root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        text=True,
    )


def _repo_root() -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=TOOLS_DIR,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"could not resolve repo root from {TOOLS_DIR}: {result.stderr}")
    return Path(result.stdout.strip())


def _check_job_group(jobs: list, group_name: str, seen_ids: set, seen_names: set) -> str | None:
    for job in jobs:
        job_id = job.get("job_id")
        name = job.get("name")
        if job_id in seen_ids:
            return f"{group_name}: duplicate job_id {job_id!r}"
        if name in seen_names:
            return f"{group_name}: duplicate job name {name!r}"
        seen_ids.add(job_id)
        seen_names.add(name)
        if job.get("conclusion") != "success":
            return f"{group_name}: job {name!r} conclusion is not 'success' ({job.get('conclusion')!r})"
    return None


def _check_artifact_group(artifacts: list, group_name: str, seen_ids: set, seen_names: set) -> str | None:
    for art in artifacts:
        art_id = art.get("artifact_id")
        name = art.get("name")
        digest = art.get("digest_sha256", "")
        if art_id in seen_ids:
            return f"{group_name}: duplicate artifact_id {art_id!r}"
        if name in seen_names:
            return f"{group_name}: duplicate artifact name {name!r}"
        seen_ids.add(art_id)
        seen_names.add(name)
        if len(digest) != 64 or digest != digest.lower() or any(c not in "0123456789abcdef" for c in digest):
            return f"{group_name}: artifact {name!r} digest_sha256 is not 64 lowercase hex chars: {digest!r}"
    return None


def _check_trigger_patch_content(patch_text: str) -> str | None:
    lines = patch_text.splitlines()
    changed_files = set()
    for line in lines:
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                changed_files.add(parts[2][2:])
                changed_files.add(parts[3][2:])
    if changed_files != {REQUIRED_WORKFLOW_FILE}:
        return f"trigger patch changes {sorted(changed_files)}, expected only {{{REQUIRED_WORKFLOW_FILE!r}}}"

    added_lines = [l[1:] for l in lines if l.startswith("+") and not l.startswith("+++")]
    removed_lines = [l[1:] for l in lines if l.startswith("-") and not l.startswith("---")]
    if removed_lines:
        return f"trigger patch removes lines, expected an additive-only diff: {removed_lines!r}"

    expected_added = [
        "  push:",
        "    branches:",
        f"      - {REQUIRED_TRIGGER_BRANCH}",
    ]
    if added_lines != expected_added:
        return f"trigger patch adds {added_lines!r}, expected exactly {expected_added!r}"

    forbidden_keywords = (
        "permissions:", "jobs:", "steps:", "matrix:", "env:", "run:",
        "uses:", "with:",
    )
    for line in added_lines + removed_lines:
        stripped = line.strip()
        for kw in forbidden_keywords:
            if stripped.startswith(kw):
                return f"trigger patch touches a forbidden section: {stripped!r}"

    if REQUIRED_TRIGGER_BRANCH not in patch_text:
        return f"trigger patch does not contain the required branch name {REQUIRED_TRIGGER_BRANCH!r}"

    return None


def verify(
    record_path: Path = RECORD_PATH,
    policy_path: Path = POLICY_PATH,
    v1_policy_path: Path = V1_POLICY_PATH,
    trigger_patch_path: Path = TRIGGER_PATCH_PATH,
    repo_root: Path | None = None,
) -> tuple[bool, str]:
    if not record_path.is_file():
        return False, f"{record_path} does not exist"

    record = json.loads(record_path.read_text())

    # --- self-hash -----------------------------------------------------
    recorded = record.get("record_sha256")
    if not isinstance(recorded, str) or not recorded.startswith("sha256:"):
        return False, "record_sha256 is missing or not in 'sha256:<hex>' form"
    recomputed = compute_record_sha256(record)
    if recomputed != recorded:
        return False, f"self-hash mismatch: recorded={recorded} recomputed={recomputed}"

    # --- record identity -------------------------------------------------
    if record.get("schema_version") != 1:
        return False, f"unexpected schema_version: {record.get('schema_version')!r}"
    if record.get("record_type") != "n2d1b-stage1-current-head-reacceptance-v2":
        return False, f"unexpected record_type: {record.get('record_type')!r}"
    if record.get("repository") != "PhysShell/qodec":
        return False, f"unexpected repository: {record.get('repository')!r}"
    if record.get("status") != "STAGE_1_REACCEPTED_COMPLETE":
        return False, f"unexpected status: {record.get('status')!r}"
    if set(record.get("accepted_pilot_case_ids", [])) != REQUIRED_CASE_IDS:
        return False, (
            f"accepted_pilot_case_ids mismatch: "
            f"{record.get('accepted_pilot_case_ids')!r} != {sorted(REQUIRED_CASE_IDS)!r}"
        )

    base_main_sha = record.get("base_main_sha")
    tested_implementation_sha = record.get("tested_implementation_sha")
    implementation_sha = record.get("implementation_sha")
    execution_trigger_sha = record.get("execution_trigger_sha")
    if not base_main_sha or not tested_implementation_sha or not implementation_sha or not execution_trigger_sha:
        return False, "base_main_sha, tested_implementation_sha, implementation_sha, or execution_trigger_sha missing"
    if tested_implementation_sha != implementation_sha:
        return False, "tested_implementation_sha must equal implementation_sha"
    if implementation_sha == execution_trigger_sha:
        return False, (
            "implementation_sha must differ from execution_trigger_sha -- "
            "the trigger commit adds a workflow-only diff on top of the "
            "implementation commit, it is never the same commit"
        )

    workflow = record.get("workflow", {})
    if record.get("workflow_file") != REQUIRED_WORKFLOW_FILE:
        return False, f"unexpected workflow_file: {record.get('workflow_file')!r}"
    if record.get("workflow_run_id") != workflow.get("run_id"):
        return False, "workflow_run_id does not match workflow.run_id"
    if workflow.get("event") != "push" or workflow.get("conclusion") != "success":
        return False, f"unexpected workflow identity: {workflow!r}"
    if workflow.get("head_sha") != execution_trigger_sha:
        return False, "workflow.head_sha does not match execution_trigger_sha"

    if record.get("execution_trigger_changed_paths") != [REQUIRED_WORKFLOW_FILE]:
        return False, "execution_trigger_changed_paths must be exactly the one workflow file"
    if record.get("trigger_commit_included_in_pull_request") is not False:
        return False, "trigger_commit_included_in_pull_request must be false"
    if record.get("non_workflow_tree_equivalent_to_implementation") is not True:
        return False, "non_workflow_tree_equivalent_to_implementation must be true"

    # --- git identity ------------------------------------------------------
    root = repo_root if repo_root is not None else _repo_root()
    for sha, label in ((base_main_sha, "base_main_sha"), (implementation_sha, "implementation_sha")):
        result = _git(root, "cat-file", "-e", f"{sha}^{{commit}}")
        if result.returncode != 0:
            return False, f"{label} {sha!r} is not a valid commit in this repository"

    result = _git(root, "merge-base", "--is-ancestor", base_main_sha, implementation_sha)
    if result.returncode != 0:
        return False, f"base_main_sha {base_main_sha!r} is not an ancestor of implementation_sha {implementation_sha!r}"

    result = _git(root, "merge-base", "--is-ancestor", implementation_sha, "HEAD")
    if result.returncode != 0:
        return False, f"implementation_sha {implementation_sha!r} is not an ancestor of the verifier's current HEAD"

    # --- job/artifact counts and required matrix ----------------------------
    jobs = record.get("jobs", [])
    pair_verify_jobs = record.get("pair_verify_jobs", [])
    other_jobs = record.get("other_jobs_not_part_of_required_matrix", [])
    if record.get("job_count") != 10 or record.get("capture_job_count") != 10 or len(jobs) != 10:
        return False, "expected exactly 10 pilot capture jobs"
    if record.get("pair_verify_job_count") != 5 or len(pair_verify_jobs) != 5:
        return False, "expected exactly 5 pair-verify jobs"
    if len(other_jobs) != 1:
        return False, "expected exactly 1 other (non-required-matrix) job"

    seen_job_ids: set = set()
    seen_job_names: set = set()
    for group, name in ((jobs, "jobs"), (pair_verify_jobs, "pair_verify_jobs"), (other_jobs, "other_jobs")):
        err = _check_job_group(group, name, seen_job_ids, seen_job_names)
        if err:
            return False, err

    artifacts = record.get("artifacts", [])
    pair_report_artifacts = record.get("pair_report_artifacts", [])
    other_artifacts = record.get("other_artifacts_not_part_of_required_matrix", [])
    if record.get("artifact_count") != 10 or len(artifacts) != 10:
        return False, "expected exactly 10 capture artifacts"
    if record.get("pair_report_artifact_count") != 5 or len(pair_report_artifacts) != 5:
        return False, "expected exactly 5 pair-report artifacts"
    if len(other_artifacts) != 1:
        return False, "expected exactly 1 other (non-required-matrix) artifact"

    seen_art_ids: set = set()
    seen_art_names: set = set()
    for group, name in (
        (artifacts, "artifacts"), (pair_report_artifacts, "pair_report_artifacts"), (other_artifacts, "other_artifacts")
    ):
        err = _check_artifact_group(group, name, seen_art_ids, seen_art_names)
        if err:
            return False, err

    if not record.get("all_job_conclusions_success") or not record.get("all_capture_jobs_success"):
        return False, "all_job_conclusions_success / all_capture_jobs_success must be true"
    if not record.get("all_pair_verify_job_conclusions_success") or not record.get("all_pair_verify_jobs_success"):
        return False, "all_pair_verify_job_conclusions_success / all_pair_verify_jobs_success must be true"

    # --- policy identities ---------------------------------------------------
    sys.path.insert(0, str(TOOLS_DIR))
    import gradle_canonicalizer_v2  # noqa: E402
    import gradle_canonicalizer as gradle_canonicalizer_v1  # noqa: E402
    from maven_canonicalizer import PolicyIntegrityError  # noqa: E402

    gradle_v2_record = record.get("gradle_canonicalization_v2", {})
    if gradle_v2_record.get("canonicalizer_module") != "gradle_canonicalizer_v2.py":
        return False, "gradle_canonicalization_v2.canonicalizer_module mismatch"
    if gradle_v2_record.get("applicable_case_ids") != ["repo-moshi"]:
        return False, "gradle_canonicalization_v2.applicable_case_ids must be exactly ['repo-moshi']"

    try:
        v2_policy_body = gradle_canonicalizer_v2.load_and_verify_policy(policy_path)
    except PolicyIntegrityError as exc:
        return False, f"v2 policy failed its own integrity check: {exc}"
    if v2_policy_body["policy_sha256"] != gradle_v2_record.get("policy_sha256"):
        return False, (
            "gradle_canonicalization_v2.policy_sha256 does not match the "
            "independently recomputed hash of the actual v2 policy file"
        )

    try:
        v1_policy_body = gradle_canonicalizer_v1.load_and_verify_policy(v1_policy_path)
    except PolicyIntegrityError as exc:
        return False, f"v1 policy failed its own integrity check: {exc}"
    if v1_policy_body["policy_sha256"] != REQUIRED_V1_POLICY_SHA256:
        return False, (
            f"v1 policy's independently recomputed self-hash "
            f"{v1_policy_body['policy_sha256']!r} does not match the required "
            f"historical value {REQUIRED_V1_POLICY_SHA256!r} -- the untouched "
            "v1 policy file appears to have drifted"
        )

    # --- acceptance assertions -----------------------------------------------
    for flag in (
        "all_artifacts_content_inspected",
        "all_cases_content_accepted",
        "all_pairs_canonically_equal",
        "stage2_authorized_next",
    ):
        if record.get(flag) is not True:
            return False, f"{flag} must be true"
    for flag in ("token_counts_computed", "stage2_executed"):
        if record.get(flag) is not False:
            return False, f"{flag} must be false"
    if record.get("unexplained_raw_differences") != []:
        return False, "unexplained_raw_differences must be an empty list"

    rederivation = record.get("independent_rederivation_verification", {})
    for case_id, entry in rederivation.items():
        if case_id == "method":
            continue
        for key, value in entry.items():
            if key.endswith("_rederived_equals_committed") or key == "capture_a_and_b_canonicalize_to_identical_bytes":
                if value is not True:
                    return False, f"independent_rederivation_verification[{case_id!r}][{key!r}] must be true"
            if key == "receipt_canonicalization_policy_sha256_matches_locally_built_policy" and value is not True:
                return False, f"independent_rederivation_verification[{case_id!r}][{key!r}] must be true"

    # --- trigger patch evidence ------------------------------------------
    trigger_patch_sha256 = record.get("execution_trigger_patch_sha256", "")
    if not trigger_patch_sha256.startswith("sha256:"):
        return False, "execution_trigger_patch_sha256 must be in 'sha256:<hex>' form"
    if not trigger_patch_path.is_file():
        return False, f"{trigger_patch_path} does not exist"
    patch_bytes = trigger_patch_path.read_bytes()
    actual = hashlib.sha256(patch_bytes).hexdigest()
    if f"sha256:{actual}" != trigger_patch_sha256:
        return False, (
            f"evidence/stage1-v2-trigger.patch sha256 mismatch: "
            f"file={actual} record={trigger_patch_sha256}"
        )

    content_err = _check_trigger_patch_content(patch_bytes.decode("utf-8"))
    if content_err:
        return False, content_err

    return True, "OK"


def main() -> int:
    ok, message = verify()
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
