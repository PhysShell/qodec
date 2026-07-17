#!/usr/bin/env python3
"""Independently, fail-closedly verifies stage2-full-matrix-acceptance.json.

Recomputes the record's self-hash from its own committed content using the
documented compact-canonical protocol (never from the builder script or the
recorded field itself), then cross-checks its claims against: real git
history (base/implementation ancestry, implementation vs. execution-trigger
identity), the actual six canonicalization policy files (via each module's
own load_and_verify_policy, never a value merely copied into the record),
job/artifact ID and name uniqueness plus digest shape, every acceptance-gate
boolean, every independent_rederivation_verification entry, and the trigger
patch's literal diff content (not just its hash). Fails closed on any
mismatch. Mirrors verify_stage1_current_head_reacceptance.py's structure and
discipline, independently re-implemented (not imported) for this record.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
BASE_DIR = TOOLS_DIR.parent
RECORD_PATH = BASE_DIR / "stage2-full-matrix-acceptance.json"
TRIGGER_PATCH_PATH = BASE_DIR / "evidence" / "stage2-full-matrix-trigger.patch"

MAVEN_POLICY_PATH = BASE_DIR / "capture-canonicalization-policy.json"
VSTEST_POLICY_PATH = BASE_DIR / "vstest-capture-canonicalization-policy.json"
GRADLE_V2_POLICY_PATH = BASE_DIR / "gradle-capture-canonicalization-policy-v2.json"
GRADLE_HELM_VALUES_V1_POLICY_PATH = BASE_DIR / "gradle-capture-canonicalization-policy-helm-values-v1.json"
CARGO_TEST_POLICY_PATH = BASE_DIR / "cargo-test-capture-canonicalization-policy.json"
PYTEST_REQUESTS_DURATION_V1_POLICY_PATH = BASE_DIR / "pytest-requests-duration-capture-canonicalization-policy-v1.json"
REPLACEMENT_SELECTION_RECORD_PATH = BASE_DIR / "stage2-replacement-selection-v1.json"

REQUIRED_CASE_IDS = {
    "repo-docker-java-parser", "repo-dockerfile-parser-rs", "repo-helm-values",
    "repo-hyperfine", "repo-kubeops-generator", "repo-moshi", "repo-pyflakes",
    "repo-requests", "repo-rustlings",
}
REQUIRED_WORKFLOW_FILE = ".github/workflows/qodec-n2d1b-miner-pilot.yml"

# Exact identity constants -- the record's own fields must match these
# LITERALLY, not merely agree with each other or with real git ancestry.
# Internal consistency alone would pass a record that is self-consistent
# but simply wrong (e.g. describing a different, unauthorized run).
REQUIRED_BASE_MAIN_SHA = "e7e6759298e7f5526a751bddac0cdafc3b6c28c3"
REQUIRED_IMPLEMENTATION_SHA = "478d70b87d76fb57bdc6e118fde7c4521eb177be"
REQUIRED_EXECUTION_TRIGGER_SHA = "c430812a604ec25fa68d40e55a5df156f6029707"
REQUIRED_TRIGGER_BRANCH = "ci-trigger/n2d1b-stage2-478d70b"
REQUIRED_WORKFLOW_RUN_ID = 29550102525
REQUIRED_WORKFLOW_NAME = "qodec-n2d1b-miner-pilot"
REQUIRED_PULL_REQUEST_NUMBER = 3
REQUIRED_REDERIVATION_KEYS = {"method"} | REQUIRED_CASE_IDS

REQUIRED_MAVEN_POLICY_SHA256 = "d633497d6b2e5575bdaeb183ad10b140e2900df98d8299caa57772fd4d8b495c"
REQUIRED_VSTEST_POLICY_SHA256 = "c6728ad1447dc9ab328bee526f60fb33b29d3346f0db8d3b617ef4352db7df59"
REQUIRED_GRADLE_V2_POLICY_SHA256 = "ba7f088d56aca7255c274b1b9a17f07fd64d65d77fd24577700f90b82c53e248"
REQUIRED_GRADLE_HELM_VALUES_V1_POLICY_SHA256 = "27038e648e4b476dc62c60e1cf4107f4f1dce38dcdbccae4a01da334218ebe09"
REQUIRED_CARGO_TEST_POLICY_SHA256 = "adba425839a3cab23874eada88e63d471958f0611e3833d06125605bf696e5d6"
REQUIRED_PYTEST_REQUESTS_DURATION_V1_POLICY_SHA256 = "21543de45468f51c103d078f78acd3079bfd1d9e1b8927722913add6e16f3597"

REQUIRED_REPLACEMENT_CASE_ID = "repo-helm-values"
REQUIRED_REJECTED_CASE_ID = "repo-spotless"


def compute_record_sha256(body: dict) -> str:
    """Independent re-implementation of the documented self-hash protocol
    (deliberately re-typed here rather than imported, so a bug in one
    cannot silently survive a matching bug in the other)."""
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _git(repo_root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo_root), *args], capture_output=True, text=True)


def _repo_root() -> Path:
    result = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=TOOLS_DIR, capture_output=True, text=True)
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

    added_lines = [line[1:] for line in lines if line.startswith("+") and not line.startswith("+++")]
    removed_lines = [line[1:] for line in lines if line.startswith("-") and not line.startswith("---")]
    if removed_lines:
        return f"trigger patch removes lines, expected an additive-only diff: {removed_lines!r}"

    expected_added = [
        "  push:",
        "    branches: [ci-trigger/n2d1b-stage2-478d70b]",
    ]
    if added_lines != expected_added:
        return f"trigger patch adds {added_lines!r}, expected exactly {expected_added!r}"

    forbidden_keywords = ("permissions:", "jobs:", "steps:", "matrix:", "env:", "run:", "uses:", "with:")
    for line in added_lines + removed_lines:
        stripped = line.strip()
        for kw in forbidden_keywords:
            if stripped.startswith(kw):
                return f"trigger patch touches a forbidden section: {stripped!r}"

    if REQUIRED_TRIGGER_BRANCH not in patch_text:
        return f"trigger patch does not contain the required branch name {REQUIRED_TRIGGER_BRANCH!r}"

    return None


def verify(record_path: Path = RECORD_PATH, trigger_patch_path: Path = TRIGGER_PATCH_PATH,
           repo_root: Path | None = None) -> tuple[bool, str]:
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
    if record.get("schema_version") != 2:
        return False, f"unexpected schema_version: {record.get('schema_version')!r}"
    if record.get("record_version") != 2:
        return False, f"unexpected record_version: {record.get('record_version')!r}"
    if record.get("record_type") != "n2d1b-stage2-full-matrix-acceptance-v1":
        return False, f"unexpected record_type: {record.get('record_type')!r}"
    if record.get("repository") != "PhysShell/qodec":
        return False, f"unexpected repository: {record.get('repository')!r}"
    if record.get("status") != "STAGE_2_FULL_MATRIX_ACCEPTED_COMPLETE":
        return False, f"unexpected status: {record.get('status')!r}"
    if set(record.get("accepted_case_ids", [])) != REQUIRED_CASE_IDS:
        return False, (
            f"accepted_case_ids mismatch: {record.get('accepted_case_ids')!r} != {sorted(REQUIRED_CASE_IDS)!r}"
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
            "implementation_sha must differ from execution_trigger_sha -- the trigger "
            "commit adds a workflow-only diff on top of the implementation commit"
        )

    # --- git identity --------------------------------------------------
    root = repo_root if repo_root is not None else _repo_root()
    for sha, label in (
        (base_main_sha, "base_main_sha"), (implementation_sha, "implementation_sha"),
        (execution_trigger_sha, "execution_trigger_sha"),
    ):
        result = _git(root, "cat-file", "-e", f"{sha}^{{commit}}")
        if result.returncode != 0:
            return False, f"{label} {sha!r} is not a valid commit in this repository"

    result = _git(root, "merge-base", "--is-ancestor", base_main_sha, implementation_sha)
    if result.returncode != 0:
        return False, f"base_main_sha {base_main_sha!r} is not an ancestor of implementation_sha {implementation_sha!r}"

    result = _git(root, "merge-base", "--is-ancestor", implementation_sha, "HEAD")
    if result.returncode != 0:
        return False, f"implementation_sha {implementation_sha!r} is not an ancestor of the verifier's current HEAD"

    result = _git(root, "merge-base", "--is-ancestor", execution_trigger_sha, "HEAD")
    if result.returncode == 0:
        return False, (
            f"execution_trigger_sha {execution_trigger_sha!r} IS an ancestor of the verifier's "
            "current HEAD -- the disposable trigger commit must never be merged into "
            "the implementation branch's history"
        )

    if base_main_sha != REQUIRED_BASE_MAIN_SHA:
        return False, f"base_main_sha {base_main_sha!r} != required {REQUIRED_BASE_MAIN_SHA!r}"
    if implementation_sha != REQUIRED_IMPLEMENTATION_SHA:
        return False, f"implementation_sha {implementation_sha!r} != required {REQUIRED_IMPLEMENTATION_SHA!r}"
    if execution_trigger_sha != REQUIRED_EXECUTION_TRIGGER_SHA:
        return False, f"execution_trigger_sha {execution_trigger_sha!r} != required {REQUIRED_EXECUTION_TRIGGER_SHA!r}"
    if record.get("execution_trigger_branch") != REQUIRED_TRIGGER_BRANCH:
        return False, (
            f"execution_trigger_branch {record.get('execution_trigger_branch')!r} != "
            f"required {REQUIRED_TRIGGER_BRANCH!r}"
        )

    workflow = record.get("workflow", {})
    if record.get("workflow_file") != REQUIRED_WORKFLOW_FILE:
        return False, f"unexpected workflow_file: {record.get('workflow_file')!r}"
    if record.get("workflow_run_id") != REQUIRED_WORKFLOW_RUN_ID:
        return False, f"workflow_run_id {record.get('workflow_run_id')!r} != required {REQUIRED_WORKFLOW_RUN_ID!r}"
    if workflow.get("run_id") != REQUIRED_WORKFLOW_RUN_ID:
        return False, f"workflow.run_id {workflow.get('run_id')!r} != required {REQUIRED_WORKFLOW_RUN_ID!r}"
    if workflow.get("name") != REQUIRED_WORKFLOW_NAME:
        return False, f"workflow.name {workflow.get('name')!r} != required {REQUIRED_WORKFLOW_NAME!r}"
    if workflow.get("event") != "push" or workflow.get("conclusion") != "success":
        return False, f"unexpected workflow identity: {workflow!r}"
    if workflow.get("head_sha") != REQUIRED_EXECUTION_TRIGGER_SHA:
        return False, f"workflow.head_sha {workflow.get('head_sha')!r} != required {REQUIRED_EXECUTION_TRIGGER_SHA!r}"
    if workflow.get("head_branch") != REQUIRED_TRIGGER_BRANCH:
        return False, f"workflow.head_branch {workflow.get('head_branch')!r} != required {REQUIRED_TRIGGER_BRANCH!r}"

    if record.get("execution_trigger_changed_paths") != [REQUIRED_WORKFLOW_FILE]:
        return False, "execution_trigger_changed_paths must be exactly the one workflow file"
    if record.get("trigger_commit_included_in_pull_request") is not False:
        return False, "trigger_commit_included_in_pull_request must be false"
    if record.get("non_workflow_tree_equivalent_to_implementation") is not True:
        return False, "non_workflow_tree_equivalent_to_implementation must be true"

    pull_request = record.get("pull_request", {})
    if pull_request.get("number") != REQUIRED_PULL_REQUEST_NUMBER:
        return False, f"pull_request.number {pull_request.get('number')!r} != required {REQUIRED_PULL_REQUEST_NUMBER!r}"

    # --- job/artifact counts and required matrix ----------------------------
    jobs = record.get("jobs", [])
    pair_verify_jobs = record.get("pair_verify_jobs", [])
    other_jobs = record.get("other_jobs_not_part_of_required_matrix", [])
    if record.get("job_count") != 18 or record.get("capture_job_count") != 18 or len(jobs) != 18:
        return False, "expected exactly 18 capture jobs"
    if record.get("pair_verify_job_count") != 9 or len(pair_verify_jobs) != 9:
        return False, "expected exactly 9 pair-verify jobs"
    if len(other_jobs) != 1:
        return False, "expected exactly 1 other (non-required-matrix) job"

    seen_job_ids: set = set()
    seen_job_names: set = set()
    for group, name in ((jobs, "jobs"), (pair_verify_jobs, "pair_verify_jobs"), (other_jobs, "other_jobs")):
        err = _check_job_group(group, name, seen_job_ids, seen_job_names)
        if err:
            return False, err

    expected_capture_job_names = {f"pilot-{case}-capture-{leg}" for case in REQUIRED_CASE_IDS for leg in ("a", "b")}
    actual_capture_job_names = {j.get("name") for j in jobs}
    if actual_capture_job_names != expected_capture_job_names:
        return False, (
            f"capture job names {sorted(actual_capture_job_names)} != required {sorted(expected_capture_job_names)}"
        )

    expected_pair_verify_names = {f"pair-verify-{case}" for case in REQUIRED_CASE_IDS}
    actual_pair_verify_names = {j.get("name") for j in pair_verify_jobs}
    if actual_pair_verify_names != expected_pair_verify_names:
        return False, (
            f"pair-verify job names {sorted(actual_pair_verify_names)} != required {sorted(expected_pair_verify_names)}"
        )

    expected_other_job_names = {"dockerfile-parser-rs-lockfile"}
    actual_other_job_names = {j.get("name") for j in other_jobs}
    if actual_other_job_names != expected_other_job_names:
        return False, f"other job names {sorted(actual_other_job_names)} != required {sorted(expected_other_job_names)}"

    artifacts = record.get("artifacts", [])
    pair_report_artifacts = record.get("pair_report_artifacts", [])
    other_artifacts = record.get("other_artifacts_not_part_of_required_matrix", [])
    if record.get("artifact_count") != 18 or len(artifacts) != 18:
        return False, "expected exactly 18 capture artifacts"
    if record.get("pair_report_artifact_count") != 9 or len(pair_report_artifacts) != 9:
        return False, "expected exactly 9 pair-report artifacts"
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

    expected_capture_artifact_names = {
        f"n2d1b-pilot-{case}-capture-{leg}" for case in REQUIRED_CASE_IDS for leg in ("a", "b")
    }
    actual_capture_artifact_names = {a.get("name") for a in artifacts}
    if actual_capture_artifact_names != expected_capture_artifact_names:
        return False, (
            f"capture artifact names {sorted(actual_capture_artifact_names)} != "
            f"required {sorted(expected_capture_artifact_names)}"
        )

    expected_pair_report_artifact_names = {f"n2d1b-pair-reproducibility-{case}" for case in REQUIRED_CASE_IDS}
    actual_pair_report_artifact_names = {a.get("name") for a in pair_report_artifacts}
    if actual_pair_report_artifact_names != expected_pair_report_artifact_names:
        return False, (
            f"pair-report artifact names {sorted(actual_pair_report_artifact_names)} != "
            f"required {sorted(expected_pair_report_artifact_names)}"
        )

    expected_other_artifact_names = {"n2d1b-dockerfile-parser-rs-lockfile"}
    actual_other_artifact_names = {a.get("name") for a in other_artifacts}
    if actual_other_artifact_names != expected_other_artifact_names:
        return False, (
            f"other artifact names {sorted(actual_other_artifact_names)} != "
            f"required {sorted(expected_other_artifact_names)}"
        )

    if not record.get("all_job_conclusions_success") or not record.get("all_capture_jobs_success"):
        return False, "all_job_conclusions_success / all_capture_jobs_success must be true"
    if not record.get("all_pair_verify_job_conclusions_success") or not record.get("all_pair_verify_jobs_success"):
        return False, "all_pair_verify_job_conclusions_success / all_pair_verify_jobs_success must be true"

    # --- policy identities ---------------------------------------------------
    sys.path.insert(0, str(TOOLS_DIR))
    import cargo_test_canonicalizer  # noqa: E402
    import gradle_canonicalizer_helm_values_v1  # noqa: E402
    import gradle_canonicalizer_v2  # noqa: E402
    import maven_canonicalizer  # noqa: E402
    import pytest_requests_duration_canonicalizer_v1  # noqa: E402
    import vstest_canonicalizer  # noqa: E402
    from maven_canonicalizer import PolicyIntegrityError  # noqa: E402

    policies = record.get("canonicalization_policies", {})
    policy_checks = [
        ("maven", maven_canonicalizer, MAVEN_POLICY_PATH, REQUIRED_MAVEN_POLICY_SHA256),
        ("vstest", vstest_canonicalizer, VSTEST_POLICY_PATH, REQUIRED_VSTEST_POLICY_SHA256),
        ("gradle_v2", gradle_canonicalizer_v2, GRADLE_V2_POLICY_PATH, REQUIRED_GRADLE_V2_POLICY_SHA256),
        ("gradle_helm_values_v1", gradle_canonicalizer_helm_values_v1,
         GRADLE_HELM_VALUES_V1_POLICY_PATH, REQUIRED_GRADLE_HELM_VALUES_V1_POLICY_SHA256),
        ("cargo_test", cargo_test_canonicalizer, CARGO_TEST_POLICY_PATH, REQUIRED_CARGO_TEST_POLICY_SHA256),
        ("pytest_requests_duration_v1", pytest_requests_duration_canonicalizer_v1,
         PYTEST_REQUESTS_DURATION_V1_POLICY_PATH, REQUIRED_PYTEST_REQUESTS_DURATION_V1_POLICY_SHA256),
    ]
    if set(policies.keys()) != {key for key, *_ in policy_checks}:
        return False, f"canonicalization_policies keys {sorted(policies.keys())} != required {sorted(k for k, *_ in policy_checks)}"

    for key, module, policy_path, required_sha256 in policy_checks:
        record_entry = policies.get(key, {})
        try:
            policy_body = module.load_and_verify_policy(policy_path)
        except PolicyIntegrityError as exc:
            return False, f"{key} policy failed its own integrity check: {exc}"
        if policy_body["policy_sha256"] != required_sha256:
            return False, (
                f"{key} policy's independently recomputed self-hash "
                f"{policy_body['policy_sha256']!r} does not match the required historical "
                f"value {required_sha256!r} -- the policy file appears to have drifted"
            )
        if record_entry.get("policy_sha256") != policy_body["policy_sha256"]:
            return False, f"canonicalization_policies[{key!r}].policy_sha256 does not match the actual policy file"

    # --- acceptance assertions -----------------------------------------------
    for flag in (
        "all_artifacts_content_inspected", "all_cases_content_accepted", "all_pairs_canonically_equal",
        "rtk_nix_identity_closure_authorized_next",
    ):
        if record.get(flag) is not True:
            return False, f"{flag} must be true"
    for flag in (
        "token_counts_computed", "rtk_or_qodec_benchmark_arms_executed", "nix_identity_builds_performed",
        "n2d2_executed", "n2d3_executed", "leaderboard_constructed",
        "model_based_quality_evaluation_performed", "physshell_007_modified",
    ):
        if record.get(flag) is not False:
            return False, f"{flag} must be false"
    if record.get("unexplained_raw_differences") != []:
        return False, "unexplained_raw_differences must be an empty list"

    rederivation = record.get("independent_rederivation_verification", {})
    if set(rederivation.keys()) != REQUIRED_REDERIVATION_KEYS:
        return False, (
            f"independent_rederivation_verification keys {sorted(rederivation.keys())} != "
            f"required {sorted(REQUIRED_REDERIVATION_KEYS)}"
        )
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
        return False, f"evidence/stage2-full-matrix-trigger.patch sha256 mismatch: file={actual} record={trigger_patch_sha256}"

    content_err = _check_trigger_patch_content(patch_bytes.decode("utf-8"))
    if content_err:
        return False, content_err

    # --- per-case canonical benchmark input map -------------------------------
    cases = record.get("cases", {})
    if set(cases.keys()) != REQUIRED_CASE_IDS:
        return False, f"cases keys {sorted(cases.keys())} != required {sorted(REQUIRED_CASE_IDS)}"

    sha256_by_case = record.get("canonical_benchmark_input_sha256_by_case_id", {})
    if set(sha256_by_case.keys()) != REQUIRED_CASE_IDS:
        return False, (
            f"canonical_benchmark_input_sha256_by_case_id keys {sorted(sha256_by_case.keys())} != "
            f"required {sorted(REQUIRED_CASE_IDS)}"
        )

    for case_id in REQUIRED_CASE_IDS:
        case = cases[case_id]
        if case.get("canonical_bytes_equal") is not True:
            return False, f"cases[{case_id!r}].canonical_bytes_equal must be true"
        if case.get("canonical_capture") != "capture_a":
            return False, f"cases[{case_id!r}].canonical_capture must be 'capture_a'"
        final_sha = case.get("canonical_benchmark_input_sha256_final", "")
        if len(final_sha) != 64 or final_sha != final_sha.lower():
            return False, f"cases[{case_id!r}].canonical_benchmark_input_sha256_final is not 64 lowercase hex chars"
        per_capture = case.get("canonical_benchmark_input_sha256", {})
        if per_capture.get("capture_a") != final_sha or per_capture.get("capture_b") != final_sha:
            return False, (
                f"cases[{case_id!r}]: capture_a/capture_b canonical sha256 must both equal "
                f"canonical_benchmark_input_sha256_final"
            )
        if sha256_by_case.get(case_id) != final_sha:
            return False, (
                f"canonical_benchmark_input_sha256_by_case_id[{case_id!r}] "
                f"{sha256_by_case.get(case_id)!r} != cases[{case_id!r}].canonical_benchmark_input_sha256_final "
                f"{final_sha!r}"
            )
        capture_ids = case.get("capture_artifact_ids", {})
        if not isinstance(capture_ids.get("capture_a"), int) or not isinstance(capture_ids.get("capture_b"), int):
            return False, f"cases[{case_id!r}].capture_artifact_ids must have integer capture_a/capture_b artifact IDs"

    # --- repo-requests detailed content-acceptance / canonicalization binding -
    rr = record.get("repo_requests_detailed_acceptance", {})
    if rr.get("case_id") != "repo-requests":
        return False, "repo_requests_detailed_acceptance.case_id must be 'repo-requests'"
    for flag in (
        "exit_code_zero_both_captures", "zero_failed_zero_errors_both_captures",
        "content_accepted_both_captures", "timeout_sink_verified_both_captures",
        "loopback_bind_connect_confirmed_allowed_both_captures",
        "other_external_connectivity_confirmed_blocked_both_captures",
        "network_enforcement_distinct_from_test_network_fixture",
        "canonical_bytes_equal", "raw_ab_diff_is_exactly_the_pytest_duration_token",
    ):
        if rr.get(flag) is not True:
            return False, f"repo_requests_detailed_acceptance.{flag} must be true"
    if rr.get("toolchain_classification_both_captures") != "exact-match":
        return False, "repo_requests_detailed_acceptance.toolchain_classification_both_captures must be 'exact-match'"
    if rr.get("content_classification_both_captures") != "genuine-workload-output":
        return False, (
            "repo_requests_detailed_acceptance.content_classification_both_captures "
            "must be 'genuine-workload-output'"
        )
    if rr.get("canonicalization_replacement_count") != 1:
        return False, "repo_requests_detailed_acceptance.canonicalization_replacement_count must be exactly 1"
    if rr.get("raw_ab_diff_line_count") != 1:
        return False, "repo_requests_detailed_acceptance.raw_ab_diff_line_count must be exactly 1"
    if rr.get("canonical_capture") != "capture_a":
        return False, "repo_requests_detailed_acceptance.canonical_capture must be 'capture_a'"
    if rr.get("canonicalization_policy_identity") != "pytest_requests_duration_v1":
        return False, (
            "repo_requests_detailed_acceptance.canonicalization_policy_identity must be 'pytest_requests_duration_v1'"
        )
    if rr.get("canonical_benchmark_input_sha256") != cases["repo-requests"]["canonical_benchmark_input_sha256_final"]:
        return False, "repo_requests_detailed_acceptance.canonical_benchmark_input_sha256 does not match cases map"
    if rr.get("timeout_sink_target") != "10.255.255.1":
        return False, "repo_requests_detailed_acceptance.timeout_sink_target must be '10.255.255.1'"
    expected_probe_argv = [
        "python3",
        "evals/interop/v2/n2/d1-identity-lock/tools/timeout_sink_target_probe.py",
        "10.255.255.1",
    ]
    if rr.get("timeout_sink_probe_argv") != expected_probe_argv:
        return False, f"repo_requests_detailed_acceptance.timeout_sink_probe_argv != required {expected_probe_argv!r}"
    if rr.get("network_enforcement_mode") != "outer-netns-loopback-only":
        return False, "repo_requests_detailed_acceptance.network_enforcement_mode must be 'outer-netns-loopback-only'"
    if not rr.get("test_network_fixture") or not rr.get("test_network_fixture_approval_identity"):
        return False, "repo_requests_detailed_acceptance test_network_fixture / its approval identity must be set"
    if not rr.get("network_enforcement_approval_identity"):
        return False, "repo_requests_detailed_acceptance.network_enforcement_approval_identity must be set"
    if rr.get("test_network_fixture_approval_identity") == rr.get("network_enforcement_approval_identity"):
        return False, (
            "repo_requests_detailed_acceptance: test_network_fixture_approval_identity must NOT be silently "
            "merged with network_enforcement_approval_identity -- these are distinct authorizations"
        )
    if rr.get("source_mtime_materialization_fixed_timestamp_epoch_seconds") != 946684800:
        return False, "repo_requests_detailed_acceptance source_mtime epoch must be 946684800 (2000-01-01T00:00:00Z)"
    if rr.get("source_mtime_materialization_fixed_timestamp_iso8601_utc") != "2000-01-01T00:00:00Z":
        return False, "repo_requests_detailed_acceptance source_mtime iso8601 must be '2000-01-01T00:00:00Z'"
    if not isinstance(rr.get("source_mtime_materialization_affected_file_count_both_captures"), int) or (
        rr.get("source_mtime_materialization_affected_file_count_both_captures") <= 0
    ):
        return False, "repo_requests_detailed_acceptance source_mtime affected file count must be a positive int"

    # --- timeout-sink / network-enforcement / mtime authorization maps --------
    if record.get("timeout_sink_authorized_cases", {}).get("repo-requests") != "10.255.255.1":
        return False, "timeout_sink_authorized_cases['repo-requests'] must be '10.255.255.1'"
    if "repo-requests" not in record.get("network_enforcement_authorized_cases", {}):
        return False, "network_enforcement_authorized_cases must include 'repo-requests'"
    if record.get("source_mtime_materialization_authorized_cases", {}).get("repo-requests") != "2000-01-01T00:00:00Z":
        return False, "source_mtime_materialization_authorized_cases['repo-requests'] must be '2000-01-01T00:00:00Z'"
    net_approvals = record.get("network_enforcement_approval_identities", {})
    sink_approvals = record.get("timeout_sink_approval_identities", {})
    fixture_names = record.get("timeout_sink_test_network_fixture_names", {})
    if net_approvals.get("repo-requests") != rr.get("network_enforcement_approval_identity"):
        return False, "network_enforcement_approval_identities['repo-requests'] does not match repo_requests_detailed_acceptance"
    if sink_approvals.get("repo-requests") != rr.get("test_network_fixture_approval_identity"):
        return False, "timeout_sink_approval_identities['repo-requests'] does not match repo_requests_detailed_acceptance"
    if fixture_names.get("repo-requests") != rr.get("test_network_fixture"):
        return False, "timeout_sink_test_network_fixture_names['repo-requests'] does not match repo_requests_detailed_acceptance"

    # --- replacement-selection link: re-verify the linked record itself, ------
    # independently of the builder's own build-time check.
    linked = record.get("replacement_selection", {})
    if linked.get("replacement_case_id") != REQUIRED_REPLACEMENT_CASE_ID:
        return False, f"replacement_selection.replacement_case_id != required {REQUIRED_REPLACEMENT_CASE_ID!r}"
    if linked.get("rejected_case_id") != REQUIRED_REJECTED_CASE_ID:
        return False, f"replacement_selection.rejected_case_id != required {REQUIRED_REJECTED_CASE_ID!r}"
    if linked.get("verified_by_its_own_verifier_at_build_time") is not True:
        return False, "replacement_selection.verified_by_its_own_verifier_at_build_time must be true"
    linked_path = linked.get("record_path", "")
    if linked_path != "evals/interop/v2/n2/d1-identity-lock/stage2-replacement-selection-v1.json":
        return False, f"replacement_selection.record_path unexpected: {linked_path!r}"
    if not REPLACEMENT_SELECTION_RECORD_PATH.is_file():
        return False, f"{REPLACEMENT_SELECTION_RECORD_PATH} does not exist"
    replacement_record = json.loads(REPLACEMENT_SELECTION_RECORD_PATH.read_text())
    if replacement_record.get("record_sha256") != linked.get("record_sha256"):
        return False, (
            "replacement_selection.record_sha256 does not match the actual committed "
            "stage2-replacement-selection-v1.json file's own record_sha256"
        )
    sys.path.insert(0, str(TOOLS_DIR))
    import verify_stage2_replacement_selection  # noqa: E402
    repl_ok, repl_message = verify_stage2_replacement_selection.verify(REPLACEMENT_SELECTION_RECORD_PATH)
    if not repl_ok:
        return False, f"replacement-selection record failed independent re-verification: {repl_message}"

    return True, "OK"


def main() -> int:
    ok, message = verify()
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
