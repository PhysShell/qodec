#!/usr/bin/env python3
"""N2-D1b: builds the Stage-1 five-ecosystem-pilot re-acceptance evidence
record for the current PhysShell/qodec main-descended head, under the new
Gradle duration canonicalization policy v2.

Every field here is real data retrieved from the GitHub API for the accepted
run (workflow run 29510992023, executed at TRIGGER_SHA
0c6884d35df537dc4226afa709c3148423cec9e2 on the disposable branch
ci-trigger/n2d1b-stage1-eaafc178) plus this session's own local test-suite
run and independent artifact-content rederivation at IMPLEMENTATION_SHA
(eaafc1780a01117029833585c5c58b2ac8962b93, the tip of
n2d1b/gradle-duration-v2-stage1-reacceptance) -- nothing here is synthesized
or estimated.

Direct workflow_dispatch was unavailable to this session (GitHub integration
returned 403 on every attempt); the repository owner authorized a disposable
trigger branch whose only diff from IMPLEMENTATION_SHA is the workflow's
`on:` event stanza (adding a push trigger scoped to that one branch name).
This record distinguishes the benchmark implementation identity
(implementation_sha) from the execution-wrapper identity
(execution_trigger_sha) that the real CI run actually executed at -- see
the execution_trigger_* fields below and evidence/stage1-v2-trigger.patch.

Supersedes evals/interop/v2/n2/d1-identity-lock/stage1-pilot-evidence.json
(frozen on PhysShell/007 pre-migration, gradle_canonicalizer.py v1). That
prior record is NOT overwritten or modified by this script.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

OUT_PATH = Path(__file__).resolve().parents[1] / "stage1-current-head-reacceptance-v2.json"

IMPLEMENTATION_SHA = "eaafc1780a01117029833585c5c58b2ac8962b93"
EXECUTION_TRIGGER_SHA = "0c6884d35df537dc4226afa709c3148423cec9e2"
EXECUTION_TRIGGER_BRANCH = "ci-trigger/n2d1b-stage1-eaafc178"
EXECUTION_TRIGGER_PATCH_SHA256 = "01060a7c4ec688c0f531a472f8f0c8d1eadd30f083464e46461905346127efa0"

PRIOR_RECORD_SHA256 = "ad71afd35e1af0668277e494c6594040fef21f44b55dc11564450437c72c345e"
PRIOR_RECORD_TESTED_HEAD_SHA = "c51eacca7edd9b73f58c740f5de31998304cf85c"
PRIOR_RECORD_WORKFLOW_RUN_ID = 29474805883


def canonicalize_and_hash(body: dict) -> tuple[str, str]:
    text = json.dumps(body, indent=2, sort_keys=True) + "\n"
    return text, hashlib.sha256(text.encode()).hexdigest()


PILOT_JOBS = [
    {"name": "pilot-repo-hyperfine-capture-a", "job_id": 87664158327, "conclusion": "success"},
    {"name": "pilot-repo-hyperfine-capture-b", "job_id": 87664158404, "conclusion": "success"},
    {"name": "pilot-repo-docker-java-parser-capture-a", "job_id": 87664158292, "conclusion": "success"},
    {"name": "pilot-repo-docker-java-parser-capture-b", "job_id": 87664158386, "conclusion": "success"},
    {"name": "pilot-repo-kubeops-generator-capture-a", "job_id": 87664158303, "conclusion": "success"},
    {"name": "pilot-repo-kubeops-generator-capture-b", "job_id": 87664158352, "conclusion": "success"},
    {"name": "pilot-repo-pyflakes-capture-a", "job_id": 87664158336, "conclusion": "success"},
    {"name": "pilot-repo-pyflakes-capture-b", "job_id": 87664158342, "conclusion": "success"},
    {"name": "pilot-repo-moshi-capture-a", "job_id": 87664158353, "conclusion": "success"},
    {"name": "pilot-repo-moshi-capture-b", "job_id": 87664158334, "conclusion": "success"},
]

PAIR_VERIFY_JOBS = [
    {"name": "pair-verify-repo-hyperfine", "job_id": 87665666071, "conclusion": "success"},
    {"name": "pair-verify-repo-docker-java-parser", "job_id": 87665666108, "conclusion": "success"},
    {"name": "pair-verify-repo-kubeops-generator", "job_id": 87665665985, "conclusion": "success"},
    {"name": "pair-verify-repo-pyflakes", "job_id": 87665666053, "conclusion": "success"},
    {"name": "pair-verify-repo-moshi", "job_id": 87665666044, "conclusion": "success"},
]

OTHER_JOBS_NOT_PART_OF_REQUIRED_MATRIX = [
    {
        "name": "dockerfile-parser-rs-lockfile",
        "job_id": 87664085728,
        "conclusion": "success",
        "note": (
            "Pre-existing Stage-2 lockfile-generation dependency job that the "
            "workflow's `pilot` job needs: unconditionally. Not one of the "
            "5 frozen Stage-1 pilot cases; not counted in job_count/pilot "
            "job_count below."
        ),
    },
]

ARTIFACTS = [
    {"name": "n2d1b-pilot-repo-hyperfine-capture-a", "artifact_id": 8380625484,
     "digest_sha256": "8204675e1bebdd74e60c32d37b4c0bbe4f40fbb0dacfd5d77e0ba521b18ad5ff"},
    {"name": "n2d1b-pilot-repo-hyperfine-capture-b", "artifact_id": 8380625761,
     "digest_sha256": "446de2b95238a07883980402d3984b8c99a05163df70179c01c061f51e22d170"},
    {"name": "n2d1b-pilot-repo-docker-java-parser-capture-a", "artifact_id": 8380693847,
     "digest_sha256": "015fafac240832358a926fc0eade6a2231a46e7dcd79ae33cb680b943da576c3"},
    {"name": "n2d1b-pilot-repo-docker-java-parser-capture-b", "artifact_id": 8380675111,
     "digest_sha256": "b658ce7d3e0dbba8141a6bb2405f8166b829b1146f0a47c34fed30592d8c2e1b"},
    {"name": "n2d1b-pilot-repo-kubeops-generator-capture-a", "artifact_id": 8380630994,
     "digest_sha256": "f26745212a0783650185ac72a65eaf7560d14cdd023fecc60410f2394d42f74d"},
    {"name": "n2d1b-pilot-repo-kubeops-generator-capture-b", "artifact_id": 8380632816,
     "digest_sha256": "b7a328595a0ef2d98fd38255e801003f8ad2624b8991f0bb8bc83972987f719e"},
    {"name": "n2d1b-pilot-repo-pyflakes-capture-a", "artifact_id": 8380623834,
     "digest_sha256": "43b353a9aa2548a9dd207674038b7c813a73d906c9eb75585340bbc34a248832"},
    {"name": "n2d1b-pilot-repo-pyflakes-capture-b", "artifact_id": 8380625119,
     "digest_sha256": "ad54e6e1c452856d0df71a8edf491df446022c4fa11e02afc0892e4fee1d09f1"},
    {"name": "n2d1b-pilot-repo-moshi-capture-a", "artifact_id": 8380777918,
     "digest_sha256": "257f8f7d90a29e6164c0eaac9bc0da3158d1e28172ae4ad707ab0349ddf44250"},
    {"name": "n2d1b-pilot-repo-moshi-capture-b", "artifact_id": 8380768012,
     "digest_sha256": "bfab20e0a5a1787e99eb17ced3a870700bb2360ae83f2f5168cb13ec202ecbab"},
]

PAIR_REPORT_ARTIFACTS = [
    {"name": "n2d1b-pair-reproducibility-repo-hyperfine", "artifact_id": 8380783431,
     "digest_sha256": "c5ba119a19291b3d02e4bd95851eab5f13d25601e34b37061ab49810782e7ccd"},
    {"name": "n2d1b-pair-reproducibility-repo-docker-java-parser", "artifact_id": 8380784240,
     "digest_sha256": "b353791968bd9f52e1662d6b2c0937c8db662d80c4cb8626f94c173eb5bd2ff2"},
    {"name": "n2d1b-pair-reproducibility-repo-kubeops-generator", "artifact_id": 8380783453,
     "digest_sha256": "2d7765a7d2ba3f282740988e3a16867a4ddcacefeeca62363adbeabb4c2b8363"},
    {"name": "n2d1b-pair-reproducibility-repo-pyflakes", "artifact_id": 8380785262,
     "digest_sha256": "710d5e892f7927107e51e8a1780cd44439290ebcfc6ec588a5ae60be62c03dbb"},
    {"name": "n2d1b-pair-reproducibility-repo-moshi", "artifact_id": 8380784544,
     "digest_sha256": "9a163b3e14ba7f128b8a24eb26781a3c1ce49b437358b84f46d5f3be98400a28"},
]

OTHER_ARTIFACTS_NOT_PART_OF_REQUIRED_MATRIX = [
    {
        "name": "n2d1b-dockerfile-parser-rs-lockfile",
        "artifact_id": 8380601803,
        "digest_sha256": "73197866c97b993b9a7ec5f9a20cf4d6d3543a2e6bcdb8bb864d7cbc3637ce22",
    },
]

GRADLE_CANONICALIZATION_V2 = {
    "policy_file": "gradle-capture-canonicalization-policy-v2.json",
    "policy_sha256": "ba7f088d56aca7255c274b1b9a17f07fd64d65d77fd24577700f90b82c53e248",
    "canonicalizer_module": "gradle_canonicalizer_v2.py",
    "policy_version": 2,
    "applicable_case_ids": ["repo-moshi"],
    "rules": ["gradle_build_duration_v2"],
    "grammar_derivation": (
        "Independently re-derived from Gradle's real source "
        "(TimeFormatting.formatDurationTerse, tag v9.5.1, commit "
        "fd78213f09782e62ca4957f9cfd3d90c6c3f1767): hours/minutes/seconds/"
        "milliseconds are each independently omitted when zero, which "
        "produces reachable forms v1's mandatory-trailing-seconds grammar "
        "rejected (e.g. a bare 'Nh Ns' with zero minutes, or a bare 'Nm' "
        "with zero seconds -- the real-world 'BUILD SUCCESSFUL in 2m' line "
        "that originally motivated this policy)."
    ),
    "superseded_policy": {
        "policy_file": "gradle-capture-canonicalization-policy.json",
        "policy_sha256": "c968245e3837e2155873a8c8a3623bad9b2522ef163ee79cfbf2461eb8ef3b7c",
        "canonicalizer_module": "gradle_canonicalizer.py",
        "policy_version": 1,
        "status": "left byte-for-byte untouched on disk; no longer imported by the active capture/pair-verify dispatch",
    },
    "real_run_note": (
        "This specific run's two real captured durations ('BUILD SUCCESSFUL "
        "in 1m 50s' / '1m 48s') both happen to be forms v1's grammar would "
        "also have accepted -- Gradle's actual build duration on this "
        "runner did not land on the previously-unsupported form in this "
        "particular run. v2's necessity and correctness on the previously-"
        "unsupported forms is proven by the grammar test suite (32/32, "
        "including the exact '2m' case) and by v2 remaining a strict "
        "behavioral superset of v1 on every input v1 already accepted -- "
        "not by this run happening to exercise the edge case. This run "
        "proves v2 works correctly end-to-end in real production, on "
        "whatever Gradle actually emits, wired through the real capture "
        "and pair-verification pipeline."
    ),
}

INDEPENDENT_REDERIVATION_VERIFICATION = {
    "method": (
        "For each of the 5 cases, downloaded every real CI artifact, "
        "verified each zip's SHA-256 against the digest GitHub itself "
        "reported for that artifact, then re-ran the actual canonicalizer "
        "module (not the receipt's recorded hash, not the builder) against "
        "the downloaded raw bytes and confirmed the result is byte-"
        "identical to the committed canonical-raw-input.bin."
    ),
    "repo-moshi": {
        "canonicalizer_module": "gradle_canonicalizer_v2.py",
        "capture_a_rederived_equals_committed": True,
        "capture_b_rederived_equals_committed": True,
        "capture_a_and_b_canonicalize_to_identical_bytes": True,
        "receipt_canonicalization_policy_sha256_matches_locally_built_policy": True,
    },
    "repo-docker-java-parser": {
        "canonicalizer_module": "maven_canonicalizer.py (v1, unrelated to this task)",
        "capture_a_rederived_equals_committed": True,
        "capture_b_rederived_equals_committed": True,
    },
    "repo-kubeops-generator": {
        "canonicalizer_module": "vstest_canonicalizer.py (v1, unrelated to this task)",
        "capture_a_rederived_equals_committed": True,
        "capture_b_rederived_equals_committed": True,
    },
    "repo-hyperfine": {
        "canonicalizer_module": None,
        "note": "no rule applicable; canonical-raw-input.bin verified byte-identical to raw.stdout",
        "capture_a_rederived_equals_committed": True,
        "capture_b_rederived_equals_committed": True,
    },
    "repo-pyflakes": {
        "canonicalizer_module": None,
        "note": (
            "no rule applicable; canonical-raw-input.bin verified byte-"
            "identical to raw.stdout; content_classification is the "
            "pre-documented 'successful-empty-domain-result', not a bug"
        ),
        "capture_a_rederived_equals_committed": True,
        "capture_b_rederived_equals_committed": True,
    },
}


def build_record() -> dict:
    body = {
        "record_type": "n2d1b-stage1-current-head-reacceptance-v2",
        "record_version": 1,
        "status": "STAGE_1_REACCEPTED_COMPLETE",
        "repository": "PhysShell/qodec",
        "implementation_sha": IMPLEMENTATION_SHA,
        "tested_head_sha": IMPLEMENTATION_SHA,
        "execution_event": "push",
        "execution_trigger_branch": EXECUTION_TRIGGER_BRANCH,
        "execution_trigger_sha": EXECUTION_TRIGGER_SHA,
        "execution_trigger_patch_sha256": f"sha256:{EXECUTION_TRIGGER_PATCH_SHA256}",
        "execution_trigger_changed_paths": [
            ".github/workflows/qodec-n2d1b-miner-pilot.yml",
        ],
        "execution_trigger_scope": "workflow event stanza only",
        "execution_trigger_patch_file": "evidence/stage1-v2-trigger.patch",
        "non_workflow_tree_equivalent_to_implementation": True,
        "trigger_commit_included_in_pull_request": False,
        "direct_workflow_dispatch_availability": (
            "unavailable to this session -- the GitHub integration returned "
            "403 Resource not accessible by integration on every "
            "workflow_dispatch attempt (both filename and numeric workflow-id "
            "forms); confirmed via list_workflow_runs that no workflow_dispatch "
            "event had ever fired on this repository. The repository owner "
            "explicitly authorized the disposable-trigger-branch procedure "
            "below as the substitute execution path, with the canonical "
            "implementation branch and Commit A left untouched throughout."
        ),
        "workflow": {
            "name": "qodec-n2d1b-miner-pilot",
            "run_id": 29510992023,
            "run_number": 1,
            "run_html_url": "https://github.com/PhysShell/qodec/actions/runs/29510992023",
            "event": "push",
            "conclusion": "success",
            "head_branch": EXECUTION_TRIGGER_BRANCH,
            "head_sha": EXECUTION_TRIGGER_SHA,
        },
        "accepted_pilot_case_ids": [
            "repo-hyperfine", "repo-docker-java-parser", "repo-kubeops-generator",
            "repo-pyflakes", "repo-moshi",
        ],
        "job_count": len(PILOT_JOBS),
        "jobs": sorted(PILOT_JOBS, key=lambda j: j["name"]),
        "all_job_conclusions_success": all(j["conclusion"] == "success" for j in PILOT_JOBS),
        "pair_verify_job_count": len(PAIR_VERIFY_JOBS),
        "pair_verify_jobs": sorted(PAIR_VERIFY_JOBS, key=lambda j: j["name"]),
        "all_pair_verify_job_conclusions_success": all(j["conclusion"] == "success" for j in PAIR_VERIFY_JOBS),
        "other_jobs_not_part_of_required_matrix": OTHER_JOBS_NOT_PART_OF_REQUIRED_MATRIX,
        "artifact_count": len(ARTIFACTS),
        "artifacts": sorted(ARTIFACTS, key=lambda a: a["name"]),
        "pair_report_artifact_count": len(PAIR_REPORT_ARTIFACTS),
        "pair_report_artifacts": sorted(PAIR_REPORT_ARTIFACTS, key=lambda a: a["name"]),
        "other_artifacts_not_part_of_required_matrix": OTHER_ARTIFACTS_NOT_PART_OF_REQUIRED_MATRIX,
        "gradle_canonicalization_v2": GRADLE_CANONICALIZATION_V2,
        "independent_rederivation_verification": INDEPENDENT_REDERIVATION_VERIFICATION,
        "local_test_suite_at_implementation_sha": {
            "command": 'python3 -m unittest discover -s tests -p "test_*.py" -v',
            "working_directory": "qodec/evals/interop/v2/n2/d1-identity-lock",
            "test_count": 347,
            "result": "OK (skipped=2)",
        },
        "pull_request": {
            "repo": "PhysShell/qodec",
            "number": None,
            "state_at_acceptance": (
                "not yet opened -- per the two-commit protocol, this evidence "
                "record is finalized in Commit B before the pull request is "
                "opened; the PR will contain Commit A and Commit B only, not "
                "the trigger commit"
            ),
        },
        "superseded_record": {
            "file": "stage1-pilot-evidence.json",
            "record_sha256": PRIOR_RECORD_SHA256,
            "tested_head_sha": PRIOR_RECORD_TESTED_HEAD_SHA,
            "workflow_run_id": PRIOR_RECORD_WORKFLOW_RUN_ID,
            "reason": (
                "Frozen on PhysShell/007 prior to the QODEC migration to a "
                "standalone PhysShell/qodec repository, and built against "
                "gradle_canonicalizer.py v1. This new record re-establishes "
                "Stage-1 acceptance on the migrated repository's current "
                "main-descended head under the newly authorized Gradle "
                "duration canonicalization policy v2. The prior record and "
                "file are NOT modified or deleted by this one."
            ),
        },
        "not_yet_authorized": [
            "token counting of any kind",
            "Stage 2 execution",
            "RTK comparison",
            "leaderboard construction",
            "Claude or Codex reader-quality evaluation",
            "modifications to PhysShell/007",
        ],
    }
    _, digest = canonicalize_and_hash(body)
    body["record_sha256"] = digest
    return body


def main() -> int:
    body = build_record()
    without_hash = {k: v for k, v in body.items() if k != "record_sha256"}
    _, recomputed = canonicalize_and_hash(without_hash)
    assert recomputed == body["record_sha256"], "self-hash did not verify stable"
    OUT_PATH.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT_PATH} (record_sha256={body['record_sha256']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
