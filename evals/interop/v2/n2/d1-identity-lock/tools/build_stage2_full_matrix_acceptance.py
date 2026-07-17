#!/usr/bin/env python3
"""N2-D1b Stage 2: builds the immutable, self-hash-locked full nine-case
repository-miner raw-input acceptance evidence record.

Every field here is real data retrieved from the GitHub API for the accepted
run (workflow run 29544801640, executed at EXECUTION_TRIGGER_SHA
ad628f716c50b042867eac972bb95e1c7f24229c on the disposable branch
ci-trigger/n2d1b-stage2-1a4c363) plus this session's own local test-suite
run and independent artifact-content rederivation at IMPLEMENTATION_SHA
(1a4c3635abeaedfc585874c2e375326566d07c78, the tip of
n2d1b/stage2-full-matrix-reacceptance) -- nothing here is synthesized or
estimated. This is the FIFTH real 28-job CI attempt at this exact matrix;
the first four each surfaced genuinely new bugs (see the workflow file's own
running commentary and this branch's commit history) -- this record exists
only because run #5 was independently verified fully green across all 28
artifacts, not because it was merely "green" in the GitHub UI.

Direct workflow_dispatch was unavailable to this session (GitHub integration
returned 403 on every attempt, same as Stage 1); the repository owner
authorized the identical disposable-trigger-branch procedure documented in
build_stage1_current_head_reacceptance_v2.py. This record distinguishes the
benchmark implementation identity (implementation_sha) from the
execution-wrapper identity (execution_trigger_sha) that the real CI run
actually executed at -- see evidence/stage2-full-matrix-trigger.patch.

This is the first Stage-2 full-matrix acceptance record; there is no prior
Stage-2 record to supersede (stage1-pilot-evidence.json and
stage1-current-head-reacceptance-v2.json are both Stage-1-scoped and are
untouched by this script).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

OUT_PATH = Path(__file__).resolve().parents[1] / "stage2-full-matrix-acceptance.json"

BASE_MAIN_SHA = "e7e6759298e7f5526a751bddac0cdafc3b6c28c3"
IMPLEMENTATION_SHA = "1a4c3635abeaedfc585874c2e375326566d07c78"
EXECUTION_TRIGGER_SHA = "ad628f716c50b042867eac972bb95e1c7f24229c"
EXECUTION_TRIGGER_BRANCH = "ci-trigger/n2d1b-stage2-1a4c363"
EXECUTION_TRIGGER_PATCH_SHA256 = "d9f779aa7fe33a2b688b39f854230538931b273a86f28aac81709f345dc4514d"
WORKFLOW_FILE = ".github/workflows/qodec-n2d1b-miner-pilot.yml"
WORKFLOW_RUN_ID = 29544801640
WORKFLOW_NAME = "qodec-n2d1b-miner-pilot"
PULL_REQUEST_NUMBER = 3
PULL_REQUEST_STATE_AT_ACCEPTANCE = (
    "PR #3 is opened after Commit B, reporting this exact accepted evidence. "
    "The disposable trigger commit is not an ancestor of the PR head."
)

REQUIRED_CASE_IDS = [
    "repo-docker-java-parser", "repo-dockerfile-parser-rs", "repo-helm-values",
    "repo-hyperfine", "repo-kubeops-generator", "repo-moshi", "repo-pyflakes",
    "repo-requests", "repo-rustlings",
]


def compute_record_sha256(body: dict) -> str:
    """Documented, fail-closed self-hash protocol shared with the verifier
    (same protocol as build_stage1_current_head_reacceptance_v2.py): the
    hash input is the COMPACT canonical form (sort_keys, no indentation, no
    separator whitespace, no trailing newline) with record_sha256 present
    and explicitly set to None -- never removed from the dict entirely. The
    human-readable committed file may still be pretty-printed; only the
    hash INPUT must be this compact form."""
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


PILOT_JOBS = [
    {"name": "pilot-repo-docker-java-parser-capture-a", "job_id": 87774640724, "conclusion": "success"},
    {"name": "pilot-repo-docker-java-parser-capture-b", "job_id": 87774640747, "conclusion": "success"},
    {"name": "pilot-repo-dockerfile-parser-rs-capture-a", "job_id": 87774640739, "conclusion": "success"},
    {"name": "pilot-repo-dockerfile-parser-rs-capture-b", "job_id": 87774640719, "conclusion": "success"},
    {"name": "pilot-repo-helm-values-capture-a", "job_id": 87774640750, "conclusion": "success"},
    {"name": "pilot-repo-helm-values-capture-b", "job_id": 87774640741, "conclusion": "success"},
    {"name": "pilot-repo-hyperfine-capture-a", "job_id": 87774640692, "conclusion": "success"},
    {"name": "pilot-repo-hyperfine-capture-b", "job_id": 87774640730, "conclusion": "success"},
    {"name": "pilot-repo-kubeops-generator-capture-a", "job_id": 87774640715, "conclusion": "success"},
    {"name": "pilot-repo-kubeops-generator-capture-b", "job_id": 87774640712, "conclusion": "success"},
    {"name": "pilot-repo-moshi-capture-a", "job_id": 87774640717, "conclusion": "success"},
    {"name": "pilot-repo-moshi-capture-b", "job_id": 87774640729, "conclusion": "success"},
    {"name": "pilot-repo-pyflakes-capture-a", "job_id": 87774640731, "conclusion": "success"},
    {"name": "pilot-repo-pyflakes-capture-b", "job_id": 87774640714, "conclusion": "success"},
    {"name": "pilot-repo-requests-capture-a", "job_id": 87774640752, "conclusion": "success"},
    {"name": "pilot-repo-requests-capture-b", "job_id": 87774640726, "conclusion": "success"},
    {"name": "pilot-repo-rustlings-capture-a", "job_id": 87774640707, "conclusion": "success"},
    {"name": "pilot-repo-rustlings-capture-b", "job_id": 87774640725, "conclusion": "success"},
]

PAIR_VERIFY_JOBS = [
    {"name": "pair-verify-repo-docker-java-parser", "job_id": 87775458181, "conclusion": "success"},
    {"name": "pair-verify-repo-dockerfile-parser-rs", "job_id": 87775458157, "conclusion": "success"},
    {"name": "pair-verify-repo-helm-values", "job_id": 87775458159, "conclusion": "success"},
    {"name": "pair-verify-repo-hyperfine", "job_id": 87775458110, "conclusion": "success"},
    {"name": "pair-verify-repo-kubeops-generator", "job_id": 87775458100, "conclusion": "success"},
    {"name": "pair-verify-repo-moshi", "job_id": 87775458106, "conclusion": "success"},
    {"name": "pair-verify-repo-pyflakes", "job_id": 87775458113, "conclusion": "success"},
    {"name": "pair-verify-repo-requests", "job_id": 87775458165, "conclusion": "success"},
    {"name": "pair-verify-repo-rustlings", "job_id": 87775458162, "conclusion": "success"},
]

OTHER_JOBS_NOT_PART_OF_REQUIRED_MATRIX = [
    {
        "name": "dockerfile-parser-rs-lockfile", "job_id": 87774602305, "conclusion": "success",
        "note": (
            "Dedicated lockfile-generation dependency job (repo-dockerfile-parser-rs' "
            "frozen acquisition has no committed Cargo.lock) that both its capture-a "
            "and capture-b jobs consume via `cargo fetch --locked`, run exactly ONCE "
            "per workflow run, never regenerated per-capture. Not one of the 9 frozen "
            "Stage-2 case IDs; not counted in job_count/capture_job_count below."
        ),
    },
]

ARTIFACTS = [
    {"name": "n2d1b-pilot-repo-docker-java-parser-capture-a", "artifact_id": 8393576192,
     "digest_sha256": "7aacd9c70d3089780c1ff736d2f85904c5338b2e23e6bb3c5704b2a6d9da4c54"},
    {"name": "n2d1b-pilot-repo-docker-java-parser-capture-b", "artifact_id": 8393584241,
     "digest_sha256": "5939402c80cf0749969f15bc41ae022b06f4b15531666cf7d1fde12eca734966"},
    {"name": "n2d1b-pilot-repo-dockerfile-parser-rs-capture-a", "artifact_id": 8393541796,
     "digest_sha256": "92f47cf3df8b52e70b71f4630de75eaf248a6e134031aa299e1a43852442474f"},
    {"name": "n2d1b-pilot-repo-dockerfile-parser-rs-capture-b", "artifact_id": 8393540792,
     "digest_sha256": "321ddbc4cea2ced69b7904e4de3764d3d5e8ffecb5ec7aead43e253ad39a998c"},
    {"name": "n2d1b-pilot-repo-helm-values-capture-a", "artifact_id": 8393579542,
     "digest_sha256": "670cc1a227b2ab610ab204162fbfa1462eb80374aa845f0386e8e2e81a05b781"},
    {"name": "n2d1b-pilot-repo-helm-values-capture-b", "artifact_id": 8393581709,
     "digest_sha256": "b3a4ce9da1cc40f9f43d0ae45e6a320d24c7f2c78282c5afa838e5d1f6eb8714"},
    {"name": "n2d1b-pilot-repo-hyperfine-capture-a", "artifact_id": 8393540239,
     "digest_sha256": "45669991a29b71b0789a1cecc9c07a55f10c39f3cef0de0381f58bba54b9f514"},
    {"name": "n2d1b-pilot-repo-hyperfine-capture-b", "artifact_id": 8393541237,
     "digest_sha256": "5bcbf8433cd1aad183662ec8c58f41684d028311f0f6dcd6fffe1e4d0e352513"},
    {"name": "n2d1b-pilot-repo-kubeops-generator-capture-a", "artifact_id": 8393544909,
     "digest_sha256": "8c84d0245f344ad815f9103cfd0fd885f88ca593cf40624f8d5e5b33e0e62bdd"},
    {"name": "n2d1b-pilot-repo-kubeops-generator-capture-b", "artifact_id": 8393543983,
     "digest_sha256": "28e5c33c78c10d1847e787459c6f844206f9acbfabd4d1efac2cfed9e57b10e5"},
    {"name": "n2d1b-pilot-repo-moshi-capture-a", "artifact_id": 8393620070,
     "digest_sha256": "2a3fa442eac53e521b7cc5d72d2391921714761d3d56d97446cf198651c9896c"},
    {"name": "n2d1b-pilot-repo-moshi-capture-b", "artifact_id": 8393622883,
     "digest_sha256": "af2ba6055c6454a76f304761eef24c9b845f272c3378a218d604b95404ea152f"},
    {"name": "n2d1b-pilot-repo-pyflakes-capture-a", "artifact_id": 8393540495,
     "digest_sha256": "9ed27f61b0ce45e8fccbd29e611672b09cc4f400ad0453fd3e77288800fb75fe"},
    {"name": "n2d1b-pilot-repo-pyflakes-capture-b", "artifact_id": 8393540285,
     "digest_sha256": "641faf38eac50cf1b5f64581635385b7ad2dd3f657f6fb9eea2641644c19bd5d"},
    {"name": "n2d1b-pilot-repo-requests-capture-a", "artifact_id": 8393544251,
     "digest_sha256": "dd28d45bf1f4f808ee1320f061590809212b68ccd057e5f0ef6b6d78d4e65dc7"},
    {"name": "n2d1b-pilot-repo-requests-capture-b", "artifact_id": 8393543976,
     "digest_sha256": "ff3bd191b2f1b6ad67b1a6f2647a47572f150edd0a06dc053af3f03b5c03564b"},
    {"name": "n2d1b-pilot-repo-rustlings-capture-a", "artifact_id": 8393541615,
     "digest_sha256": "b75c68205605bf4985c67fa91302e8b67c2267eb7c4315f57eb7001af3391d30"},
    {"name": "n2d1b-pilot-repo-rustlings-capture-b", "artifact_id": 8393541391,
     "digest_sha256": "eb4b0cb3c138ee98c685cbc1441de3762f5eda07a93a0a7c401547be6186341a"},
]

PAIR_REPORT_ARTIFACTS = [
    {"name": "n2d1b-pair-reproducibility-repo-docker-java-parser", "artifact_id": 8393626039,
     "digest_sha256": "f9b8989c1e60c665b3bb2b8e53f49945b946ff1b17da4c01e67dda88d3c5b699"},
    {"name": "n2d1b-pair-reproducibility-repo-dockerfile-parser-rs", "artifact_id": 8393625133,
     "digest_sha256": "91f83bb38ec0075a180f4868aa9cf2e1e85f591397a55f4d8b9b3393b497612a"},
    {"name": "n2d1b-pair-reproducibility-repo-helm-values", "artifact_id": 8393625404,
     "digest_sha256": "94b19ef6ee2e2b98443d277df3973ece5fdb9c761ea741ef3c5554dc4116bd8e"},
    {"name": "n2d1b-pair-reproducibility-repo-hyperfine", "artifact_id": 8393625103,
     "digest_sha256": "1d896de0582dfd4229dae408ba629da566a390124d7b29389a92f28550c79ebd"},
    {"name": "n2d1b-pair-reproducibility-repo-kubeops-generator", "artifact_id": 8393625143,
     "digest_sha256": "dbd6488d16dc4e9050c663d3bfa2311e7cc7540459b65f75b8a63ac87067269b"},
    {"name": "n2d1b-pair-reproducibility-repo-moshi", "artifact_id": 8393624992,
     "digest_sha256": "a284b079e45cafe303c0916c9c4f095ff1bdee2e41d9bb050ab70ddb42ddc735"},
    {"name": "n2d1b-pair-reproducibility-repo-pyflakes", "artifact_id": 8393625075,
     "digest_sha256": "588ff0a5a1df484777d02b7edbea4cf6b11ca2f891b4de7e71611a55c1c2851d"},
    {"name": "n2d1b-pair-reproducibility-repo-requests", "artifact_id": 8393631517,
     "digest_sha256": "b929e627845a1a08375234786cca2f42623ecee37fe3c0dd455cb0cd876ad426"},
    {"name": "n2d1b-pair-reproducibility-repo-rustlings", "artifact_id": 8393625291,
     "digest_sha256": "3dd8261707ba1f4d56eaaf0dd8039fd14abafaf8036f6bbd8e38d7c403fbd773"},
]

OTHER_ARTIFACTS_NOT_PART_OF_REQUIRED_MATRIX = [
    {"name": "n2d1b-dockerfile-parser-rs-lockfile", "artifact_id": 8393527960,
     "digest_sha256": "a90f5e2bfc10da2f4b79aadbcd68f049f4798ce4be3456fbb2f7a1a4dfb76026"},
]

CANONICALIZATION_POLICIES = {
    "maven": {
        "file": "capture-canonicalization-policy.json",
        "policy_sha256": "d633497d6b2e5575bdaeb183ad10b140e2900df98d8299caa57772fd4d8b495c",
        "policy_version": 1,
        "applicable_case_ids": ["repo-docker-java-parser"],
        "canonicalizer_module": "maven_canonicalizer.py",
    },
    "vstest": {
        "file": "vstest-capture-canonicalization-policy.json",
        "policy_sha256": "c6728ad1447dc9ab328bee526f60fb33b29d3346f0db8d3b617ef4352db7df59",
        "policy_version": 2,
        "applicable_case_ids": ["repo-kubeops-generator"],
        "canonicalizer_module": "vstest_canonicalizer.py",
    },
    "gradle_v2": {
        "file": "gradle-capture-canonicalization-policy-v2.json",
        "policy_sha256": "ba7f088d56aca7255c274b1b9a17f07fd64d65d77fd24577700f90b82c53e248",
        "policy_version": 2,
        "applicable_case_ids": ["repo-moshi"],
        "canonicalizer_module": "gradle_canonicalizer_v2.py",
    },
    "gradle_helm_values_v1": {
        "file": "gradle-capture-canonicalization-policy-helm-values-v1.json",
        "policy_sha256": "27038e648e4b476dc62c60e1cf4107f4f1dce38dcdbccae4a01da334218ebe09",
        "policy_version": 1,
        "applicable_case_ids": ["repo-helm-values"],
        "canonicalizer_module": "gradle_canonicalizer_helm_values_v1.py",
        "note": (
            "repo-helm-values runs Gradle 9.5.0, confirmed byte-for-byte identical "
            "in its TimeFormatting.java to repo-moshi's authorized Gradle 9.5.1 -- "
            "per this task's explicit requirement, this is its OWN, wholly separate "
            "policy/module/approval identity, never a broadening of gradle_v2 above, "
            "even though the underlying grammar is the same."
        ),
    },
    "cargo_test": {
        "file": "cargo-test-capture-canonicalization-policy.json",
        "policy_sha256": "adba425839a3cab23874eada88e63d471958f0611e3833d06125605bf696e5d6",
        "policy_version": 1,
        "applicable_case_ids": ["repo-dockerfile-parser-rs", "repo-rustlings"],
        "canonicalizer_module": "cargo_test_canonicalizer.py",
        "note": (
            "Single shared identity for both cases -- both invoke the identical "
            "frozen ['cargo', 'test'] argv against the identical rustup 'stable' "
            "toolchain, unlike the Gradle 9.5.0/9.5.1 replacement scenario above."
        ),
    },
    "pytest_requests": {
        "file": "pytest-requests-capture-canonicalization-policy.json",
        "policy_sha256": "8670190615b541db18e4ae2e13379f9477f38fa023ae342d30d85bbd1d78f16f",
        "policy_version": 1,
        "applicable_case_ids": ["repo-requests"],
        "canonicalizer_module": "pytest_requests_canonicalizer.py",
        "note": (
            "Three independently-derived rules: CPython's default object-repr "
            "memory address, pytest's own session-summary trailing duration (tag "
            "v9.1.1), and threading.Thread's own repr's native thread ident (used "
            "by pytest-httpbin's background Server/TLSServer threads)."
        ),
    },
}

NETWORK_ENFORCEMENT_AUTHORIZED_CASES = {
    "repo-kubeops-generator": "outer-netns-loopback-only",
    "repo-moshi": "outer-netns-loopback-only",
    "repo-helm-values": "outer-netns-loopback-only",
}

# Real values read directly from the committed receipts at this same commit --
# never hand-copied from memory. repo-moshi and repo-helm-values happen to
# share byte-identical scheduling-profile TEXT (hence the same hash), but
# each case's authorization to use it is independent (D1b, 2026-07-16/17).
GRADLE_DETERMINISTIC_SCHEDULING_PROFILE_SHA256_BY_CASE_ID = {
    "repo-moshi": "68c4b4cccc5bb7c7d8862cf09195538a1d9d62e9b0e6229cad2e8b69d8d81aa2",
    "repo-helm-values": "68c4b4cccc5bb7c7d8862cf09195538a1d9d62e9b0e6229cad2e8b69d8d81aa2",
}

RUST_DETERMINISTIC_TEST_THREADS_AUTHORIZED_CASE_IDS = [
    "repo-dockerfile-parser-rs", "repo-rustlings",
]

INDEPENDENT_REDERIVATION_VERIFICATION = {
    "method": (
        "For each of the 9 cases, downloaded every real CI artifact, verified "
        "each zip's SHA-256 against the digest GitHub itself reported for that "
        "artifact, then re-ran the actual canonicalizer module (not the "
        "receipt's recorded hash, not the builder) against the downloaded raw "
        "bytes and confirmed the result is byte-identical to the committed "
        "canonical-raw-input.bin, for cases with an applicable canonicalization "
        "policy; for cases with none, confirmed canonical-raw-input.bin is "
        "byte-identical to the raw, capped, selected stream."
    ),
    "repo-docker-java-parser": {
        "canonicalizer_module": "maven_canonicalizer.py",
        "capture_a_rederived_equals_committed": True,
        "capture_b_rederived_equals_committed": True,
    },
    "repo-dockerfile-parser-rs": {
        "canonicalizer_module": "cargo_test_canonicalizer.py",
        "capture_a_rederived_equals_committed": True,
        "capture_b_rederived_equals_committed": True,
        "capture_a_and_b_canonicalize_to_identical_bytes": True,
        "receipt_canonicalization_policy_sha256_matches_locally_built_policy": True,
    },
    "repo-helm-values": {
        "canonicalizer_module": "gradle_canonicalizer_helm_values_v1.py",
        "capture_a_rederived_equals_committed": True,
        "capture_b_rederived_equals_committed": True,
        "capture_a_and_b_canonicalize_to_identical_bytes": True,
        "receipt_canonicalization_policy_sha256_matches_locally_built_policy": True,
    },
    "repo-hyperfine": {
        "canonicalizer_module": None,
        "note": "no rule applicable; canonical-raw-input.bin verified byte-identical to raw.stdout",
        "capture_a_rederived_equals_committed": True,
        "capture_b_rederived_equals_committed": True,
    },
    "repo-kubeops-generator": {
        "canonicalizer_module": "vstest_canonicalizer.py",
        "capture_a_rederived_equals_committed": True,
        "capture_b_rederived_equals_committed": True,
    },
    "repo-moshi": {
        "canonicalizer_module": "gradle_canonicalizer_v2.py",
        "capture_a_rederived_equals_committed": True,
        "capture_b_rederived_equals_committed": True,
        "capture_a_and_b_canonicalize_to_identical_bytes": True,
        "receipt_canonicalization_policy_sha256_matches_locally_built_policy": True,
    },
    "repo-pyflakes": {
        "canonicalizer_module": None,
        "note": (
            "no rule applicable; canonical-raw-input.bin verified byte-identical "
            "to raw.stdout; content_classification is the pre-documented "
            "'successful-empty-domain-result', not a bug"
        ),
        "capture_a_rederived_equals_committed": True,
        "capture_b_rederived_equals_committed": True,
    },
    "repo-requests": {
        "canonicalizer_module": "pytest_requests_canonicalizer.py",
        "capture_a_rederived_equals_committed": True,
        "capture_b_rederived_equals_committed": True,
        "capture_a_and_b_canonicalize_to_identical_bytes": True,
        "receipt_canonicalization_policy_sha256_matches_locally_built_policy": True,
        "note": (
            "205 pytest-httpbin ERRORs in both captures are genuine, "
            "deterministic, identical local-WSGI-server-bind failures under "
            "this sandbox's permanent network denial (repo-requests is not in "
            "NETWORK_ENFORCEMENT_AUTHORIZED_CASES) -- not a bug, not loosened."
        ),
    },
    "repo-rustlings": {
        "canonicalizer_module": "cargo_test_canonicalizer.py",
        "capture_a_rederived_equals_committed": True,
        "capture_b_rederived_equals_committed": True,
        "capture_a_and_b_canonicalize_to_identical_bytes": True,
        "receipt_canonicalization_policy_sha256_matches_locally_built_policy": True,
    },
}


def build_record() -> dict:
    body = {
        "record_type": "n2d1b-stage2-full-matrix-acceptance-v1",
        "record_version": 1,
        "schema_version": 1,
        "status": "STAGE_2_FULL_MATRIX_ACCEPTED_COMPLETE",
        "repository": "PhysShell/qodec",
        "base_main_sha": BASE_MAIN_SHA,
        "implementation_sha": IMPLEMENTATION_SHA,
        "tested_implementation_sha": IMPLEMENTATION_SHA,
        "tested_head_sha": IMPLEMENTATION_SHA,
        "workflow_file": WORKFLOW_FILE,
        "workflow_run_id": WORKFLOW_RUN_ID,
        "execution_event": "push",
        "execution_trigger_branch": EXECUTION_TRIGGER_BRANCH,
        "execution_trigger_sha": EXECUTION_TRIGGER_SHA,
        "execution_trigger_patch_sha256": f"sha256:{EXECUTION_TRIGGER_PATCH_SHA256}",
        "execution_trigger_changed_paths": [WORKFLOW_FILE],
        "execution_trigger_scope": "workflow event stanza only",
        "execution_trigger_patch_file": "evidence/stage2-full-matrix-trigger.patch",
        "non_workflow_tree_equivalent_to_implementation": True,
        "trigger_commit_included_in_pull_request": False,
        "direct_workflow_dispatch_availability": (
            "unavailable to this session -- the GitHub integration returned "
            "403 Resource not accessible by integration on every "
            "workflow_dispatch attempt, identical to the Stage 1 restriction; "
            "the repository owner authorized the same disposable-trigger-branch "
            "procedure as the substitute execution path, with the canonical "
            "implementation branch and its own Commit A history left untouched "
            "throughout (re-confirmed additive-only via git diff after every "
            "trigger-branch push)."
        ),
        "attempt_history": (
            "This is the fifth real 28-job CI attempt at the exact nine-case "
            "matrix below. Runs 1-4 each surfaced genuinely new, previously "
            "undiscovered root-cause bugs (Gradle subproject build-dir "
            "writability, python argv0 resolution, rustlings state-file "
            "writability, cargo-test ordering nondeterminism, a second Gradle "
            "root-dir writability gap, pytest TMPDIR/tmp-fs-rw exposure, a "
            "python editable-install source-dir exposure gap, and finally "
            "three independently-derived pytest_requests_canonicalizer.py "
            "rules) -- each fixed via a fresh, never-amended Commit A and a "
            "brand-new disposable trigger branch, per the required re-run "
            "discipline. No artifact from any of runs 1-4 is reused as "
            "evidence anywhere in this record; every job_id, artifact_id, and "
            "digest below was independently re-verified from run 29544801640 "
            "alone."
        ),
        "workflow": {
            "name": WORKFLOW_NAME,
            "run_id": WORKFLOW_RUN_ID,
            "run_number": 6,
            "run_html_url": f"https://github.com/PhysShell/qodec/actions/runs/{WORKFLOW_RUN_ID}",
            "event": "push",
            "conclusion": "success",
            "head_branch": EXECUTION_TRIGGER_BRANCH,
            "head_sha": EXECUTION_TRIGGER_SHA,
        },
        "accepted_case_ids": REQUIRED_CASE_IDS,
        "job_count": len(PILOT_JOBS),
        "capture_job_count": len(PILOT_JOBS),
        "jobs": sorted(PILOT_JOBS, key=lambda j: j["name"]),
        "all_job_conclusions_success": all(j["conclusion"] == "success" for j in PILOT_JOBS),
        "all_capture_jobs_success": all(j["conclusion"] == "success" for j in PILOT_JOBS),
        "pair_verify_job_count": len(PAIR_VERIFY_JOBS),
        "pair_verify_jobs": sorted(PAIR_VERIFY_JOBS, key=lambda j: j["name"]),
        "all_pair_verify_job_conclusions_success": all(j["conclusion"] == "success" for j in PAIR_VERIFY_JOBS),
        "all_pair_verify_jobs_success": all(j["conclusion"] == "success" for j in PAIR_VERIFY_JOBS),
        "other_jobs_not_part_of_required_matrix": OTHER_JOBS_NOT_PART_OF_REQUIRED_MATRIX,
        "artifact_count": len(ARTIFACTS),
        "artifacts": sorted(ARTIFACTS, key=lambda a: a["name"]),
        "pair_report_artifact_count": len(PAIR_REPORT_ARTIFACTS),
        "pair_report_artifacts": sorted(PAIR_REPORT_ARTIFACTS, key=lambda a: a["name"]),
        "other_artifacts_not_part_of_required_matrix": OTHER_ARTIFACTS_NOT_PART_OF_REQUIRED_MATRIX,
        "canonicalization_policies": CANONICALIZATION_POLICIES,
        "network_enforcement_authorized_cases": NETWORK_ENFORCEMENT_AUTHORIZED_CASES,
        "gradle_deterministic_scheduling_profile_sha256_by_case_id": GRADLE_DETERMINISTIC_SCHEDULING_PROFILE_SHA256_BY_CASE_ID,
        "rust_deterministic_test_threads_authorized_case_ids": RUST_DETERMINISTIC_TEST_THREADS_AUTHORIZED_CASE_IDS,
        "independent_rederivation_verification": INDEPENDENT_REDERIVATION_VERIFICATION,
        "all_artifacts_content_inspected": True,
        "all_cases_content_accepted": True,
        "all_pairs_canonically_equal": True,
        "unexplained_raw_differences": [],
        "token_counts_computed": False,
        "rtk_or_qodec_benchmark_arms_executed": False,
        "nix_identity_builds_performed": False,
        "n2d2_executed": False,
        "n2d3_executed": False,
        "leaderboard_constructed": False,
        "model_based_quality_evaluation_performed": False,
        "physshell_007_modified": False,
        "rtk_nix_identity_closure_authorized_next": True,
        "local_test_suite_at_implementation_sha": {
            "command": 'python3 -m unittest discover -s tests -p "test_*.py"',
            "working_directory": "qodec/evals/interop/v2/n2/d1-identity-lock",
            "test_count": 507,
            "result": "OK (skipped=2)",
        },
        "pull_request": {
            "repo": "PhysShell/qodec",
            "number": PULL_REQUEST_NUMBER,
            "state_at_acceptance": PULL_REQUEST_STATE_AT_ACCEPTANCE,
        },
        "not_yet_authorized": [
            "token counting of any kind",
            "QODEC or RTK benchmark-arm execution",
            "canonical QODEC or RTK Nix identity builds",
            "N2-D2 determinism canaries",
            "N2-D3",
            "leaderboard construction",
            "model-based quality evaluation",
            "modifications to PhysShell/007",
            "merging the reporting PR without explicit owner authorization",
            "beginning RTK/Nix identity closure in this same branch/PR",
        ],
    }
    body["record_sha256"] = compute_record_sha256(body)
    return body


def main() -> int:
    body = build_record()
    recomputed = compute_record_sha256(body)
    assert recomputed == body["record_sha256"], "self-hash did not verify stable"
    OUT_PATH.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT_PATH} (record_sha256={body['record_sha256']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
