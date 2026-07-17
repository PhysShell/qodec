#!/usr/bin/env python3
"""N2-D1b Stage 2: builds the immutable, self-hash-locked full nine-case
repository-miner raw-input acceptance evidence record.

Every field here is real data retrieved from the GitHub API for the accepted
run (workflow run 29550102525, executed at EXECUTION_TRIGGER_SHA
c430812a604ec25fa68d40e55a5df156f6029707 on the disposable branch
ci-trigger/n2d1b-stage2-478d70b) plus this session's own local test-suite run
and independent artifact-content rederivation at IMPLEMENTATION_SHA
(478d70b87d76fb57bdc6e118fde7c4521eb177be, the tip of
n2d1b/stage2-full-matrix-reacceptance) -- nothing here is synthesized or
estimated.

This record SUPERSEDES the prior stage2-full-matrix-acceptance.json, which
was built from workflow run 29544801640 -- since REVOKED (see
"remediation history" below): repo-requests' capture in that run genuinely
FAILED (30 failed, 205 errors) and was wrongly accepted as
"genuine-workload-output" by the content-acceptance gate active at the
time. A second real run (29547420247, after round-1 remediation) also
rejected repo-requests -- correctly this time -- surfacing two further,
genuine execution-environment incompatibilities (a network-namespace
timeout-sink gap; a source-mtime/zipfile-1980-floor gap). Both are fixed as
of this record. Two further disposable, repo-requests-only diagnostic
probes (runs 29548972173, rejected due to a probe-only argv/env wiring bug;
29549403465, genuinely successful) preceded this full-matrix re-run and are
NOT themselves reused as evidence anywhere in this record.

Direct workflow_dispatch was unavailable to this session (GitHub integration
returned 403 on every attempt, same as Stage 1 and every prior Stage 2
attempt); the repository owner authorized the identical disposable-
trigger-branch procedure documented in build_stage1_current_head_reacceptance_v2.py.
This record distinguishes the benchmark implementation identity
(implementation_sha) from the execution-wrapper identity
(execution_trigger_sha) that the real CI run actually executed at -- see
evidence/stage2-full-matrix-trigger.patch.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

OUT_PATH = Path(__file__).resolve().parents[1] / "stage2-full-matrix-acceptance.json"
REPLACEMENT_SELECTION_RECORD_PATH = Path(__file__).resolve().parents[1] / "stage2-replacement-selection-v1.json"

BASE_MAIN_SHA = "e7e6759298e7f5526a751bddac0cdafc3b6c28c3"
IMPLEMENTATION_SHA = "478d70b87d76fb57bdc6e118fde7c4521eb177be"
EXECUTION_TRIGGER_SHA = "c430812a604ec25fa68d40e55a5df156f6029707"
EXECUTION_TRIGGER_BRANCH = "ci-trigger/n2d1b-stage2-478d70b"
EXECUTION_TRIGGER_PATCH_SHA256 = "a9eece536f34785cf5febe34976e5591c72072cdcb8c655c4c004956d89c9db5"
WORKFLOW_FILE = ".github/workflows/qodec-n2d1b-miner-pilot.yml"
WORKFLOW_RUN_ID = 29550102525
WORKFLOW_NAME = "qodec-n2d1b-miner-pilot"
PULL_REQUEST_NUMBER = 3
PULL_REQUEST_STATE_AT_ACCEPTANCE = (
    "PR #3's body is updated in place to report this exact accepted evidence, superseding all "
    "prior 'accepted'/'in progress' language. The disposable trigger commit is not an ancestor "
    "of the PR head."
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
    {"name": "pilot-repo-docker-java-parser-capture-a", "job_id": 87790677729, "conclusion": "success"},
    {"name": "pilot-repo-docker-java-parser-capture-b", "job_id": 87790677730, "conclusion": "success"},
    {"name": "pilot-repo-dockerfile-parser-rs-capture-a", "job_id": 87790677765, "conclusion": "success"},
    {"name": "pilot-repo-dockerfile-parser-rs-capture-b", "job_id": 87790677778, "conclusion": "success"},
    {"name": "pilot-repo-helm-values-capture-a", "job_id": 87790677768, "conclusion": "success"},
    {"name": "pilot-repo-helm-values-capture-b", "job_id": 87790677823, "conclusion": "success"},
    {"name": "pilot-repo-hyperfine-capture-a", "job_id": 87790677686, "conclusion": "success"},
    {"name": "pilot-repo-hyperfine-capture-b", "job_id": 87790677721, "conclusion": "success"},
    {"name": "pilot-repo-kubeops-generator-capture-a", "job_id": 87790677695, "conclusion": "success"},
    {"name": "pilot-repo-kubeops-generator-capture-b", "job_id": 87790677687, "conclusion": "success"},
    {"name": "pilot-repo-moshi-capture-a", "job_id": 87790677724, "conclusion": "success"},
    {"name": "pilot-repo-moshi-capture-b", "job_id": 87790677784, "conclusion": "success"},
    {"name": "pilot-repo-pyflakes-capture-a", "job_id": 87790677743, "conclusion": "success"},
    {"name": "pilot-repo-pyflakes-capture-b", "job_id": 87790677710, "conclusion": "success"},
    {"name": "pilot-repo-requests-capture-a", "job_id": 87790677811, "conclusion": "success"},
    {"name": "pilot-repo-requests-capture-b", "job_id": 87790677803, "conclusion": "success"},
    {"name": "pilot-repo-rustlings-capture-a", "job_id": 87790677799, "conclusion": "success"},
    {"name": "pilot-repo-rustlings-capture-b", "job_id": 87790677812, "conclusion": "success"},
]

PAIR_VERIFY_JOBS = [
    {"name": "pair-verify-repo-docker-java-parser", "job_id": 87791420726, "conclusion": "success"},
    {"name": "pair-verify-repo-dockerfile-parser-rs", "job_id": 87791420753, "conclusion": "success"},
    {"name": "pair-verify-repo-helm-values", "job_id": 87791420737, "conclusion": "success"},
    {"name": "pair-verify-repo-hyperfine", "job_id": 87791420732, "conclusion": "success"},
    {"name": "pair-verify-repo-kubeops-generator", "job_id": 87791420727, "conclusion": "success"},
    {"name": "pair-verify-repo-moshi", "job_id": 87791420760, "conclusion": "success"},
    {"name": "pair-verify-repo-pyflakes", "job_id": 87791420718, "conclusion": "success"},
    {"name": "pair-verify-repo-requests", "job_id": 87791420773, "conclusion": "success"},
    {"name": "pair-verify-repo-rustlings", "job_id": 87791420743, "conclusion": "success"},
]

OTHER_JOBS_NOT_PART_OF_REQUIRED_MATRIX = [
    {
        "name": "dockerfile-parser-rs-lockfile", "job_id": 87790638449, "conclusion": "success",
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
    {"name": "n2d1b-pilot-repo-docker-java-parser-capture-a", "artifact_id": 8395443914,
     "digest_sha256": "efeaba5de29c651cf5c0aaf32b131cea4192946bb6e1b83dfc118e584e9e93a7"},
    {"name": "n2d1b-pilot-repo-docker-java-parser-capture-b", "artifact_id": 8395446225,
     "digest_sha256": "a6c967eebac4560538537d9a447c5b8724aa93de3f46b8eca059e0ace4cab1b4"},
    {"name": "n2d1b-pilot-repo-dockerfile-parser-rs-capture-a", "artifact_id": 8395422395,
     "digest_sha256": "bb2499d38ae03761051442ec353a8618069eec962cb1e7b2f66817c4ab6641a2"},
    {"name": "n2d1b-pilot-repo-dockerfile-parser-rs-capture-b", "artifact_id": 8395422285,
     "digest_sha256": "98cdd0bd19d1ea5ba8d3b78f2d44341fb247511a1e0011ef20a6f20a05ad297b"},
    {"name": "n2d1b-pilot-repo-helm-values-capture-a", "artifact_id": 8395454071,
     "digest_sha256": "8103fff2bbae3a8219eb818838b58ceddd42f1cdbb315a0cbe3d92ba8ff20f54"},
    {"name": "n2d1b-pilot-repo-helm-values-capture-b", "artifact_id": 8395460492,
     "digest_sha256": "06e5bd25af97df0ca87fa8d36c2c2c8a6ad2eaa61f308b393f59d587cdf811ea"},
    {"name": "n2d1b-pilot-repo-hyperfine-capture-a", "artifact_id": 8395423562,
     "digest_sha256": "b5b0c67dbec58ac059ff8abaaedd687da6d8c75513686b7e8f7ab6df724a8a7e"},
    {"name": "n2d1b-pilot-repo-hyperfine-capture-b", "artifact_id": 8395421416,
     "digest_sha256": "3e61bc62b358a90611368a399c38ffdfad397e3ae8b971188d09af6fd1959781"},
    {"name": "n2d1b-pilot-repo-kubeops-generator-capture-a", "artifact_id": 8395428847,
     "digest_sha256": "32f0d738e3c5c4ef540727ce124a4de97e2ee7dd25c0a931a56ce48466234642"},
    {"name": "n2d1b-pilot-repo-kubeops-generator-capture-b", "artifact_id": 8395426596,
     "digest_sha256": "2ee917bd9795acd46dae130ee3b216eb37b92425bea06471574e4ab6165ff288"},
    {"name": "n2d1b-pilot-repo-moshi-capture-a", "artifact_id": 8395484398,
     "digest_sha256": "6eaafc736fdec47955ff2372af3c0fdd0b916615d5864ec1c19785b1b46767e3"},
    {"name": "n2d1b-pilot-repo-moshi-capture-b", "artifact_id": 8395494166,
     "digest_sha256": "cfb27a23d33ea83df97cb2a4b95bb861557370c26fd5428cff76b88b71cc23e7"},
    {"name": "n2d1b-pilot-repo-pyflakes-capture-a", "artifact_id": 8395433551,
     "digest_sha256": "1b720cad83191684d58daef09608768b794d73a142d1bce1b293d3d279fddc20"},
    {"name": "n2d1b-pilot-repo-pyflakes-capture-b", "artifact_id": 8395423659,
     "digest_sha256": "3228f40282b488c4cd866a1e890478dca9c2eb2efb6cf1a6552625c5ff6ca724"},
    {"name": "n2d1b-pilot-repo-requests-capture-a", "artifact_id": 8395455667,
     "digest_sha256": "488cbab90320581f1bd4c8d51cf7933e711945eb7a29056c861171aebdfa8792"},
    {"name": "n2d1b-pilot-repo-requests-capture-b", "artifact_id": 8395444024,
     "digest_sha256": "f345cf1e56ca89c33eae0f9f95900153bba1d40e253102ea610a4a5421b4fc1c"},
    {"name": "n2d1b-pilot-repo-rustlings-capture-a", "artifact_id": 8395433364,
     "digest_sha256": "d89a7563e2d65a748375648842024aadf00cc98298d2498d108198fddbbc2e7e"},
    {"name": "n2d1b-pilot-repo-rustlings-capture-b", "artifact_id": 8395424069,
     "digest_sha256": "1108a251046f09e0e1cd40f832656a9f86b1cd1a04c8ceb4adf46fe75c6939da"},
]

PAIR_REPORT_ARTIFACTS = [
    {"name": "n2d1b-pair-reproducibility-repo-docker-java-parser", "artifact_id": 8395496797,
     "digest_sha256": "eb80dece0133ce8e61221f1649a0a627ec90bc82436de3e427e57bd28f002181"},
    {"name": "n2d1b-pair-reproducibility-repo-dockerfile-parser-rs", "artifact_id": 8395498389,
     "digest_sha256": "0726139dc26adea253ec73059d5d9e11fc863de718ad4670172576df69495951"},
    {"name": "n2d1b-pair-reproducibility-repo-helm-values", "artifact_id": 8395496325,
     "digest_sha256": "24c3ef39c869ec6958d14f2f4380038a2519ad127ee7bc068b20b02381940cdd"},
    {"name": "n2d1b-pair-reproducibility-repo-hyperfine", "artifact_id": 8395496468,
     "digest_sha256": "a392806a103c5641c7061820ae0765c8f1dfd56e5eb4a92fc92023b804563ef0"},
    {"name": "n2d1b-pair-reproducibility-repo-kubeops-generator", "artifact_id": 8395497957,
     "digest_sha256": "e23bafa52506193e2bb67f041dfccc8f8f9203f3fccf245f76d104c88dd14bc5"},
    {"name": "n2d1b-pair-reproducibility-repo-moshi", "artifact_id": 8395498102,
     "digest_sha256": "f04e38e6febb218fb4a57a9a16291e2025e36cb3e281d1128f4d43d5c6e0afe4"},
    {"name": "n2d1b-pair-reproducibility-repo-pyflakes", "artifact_id": 8395496107,
     "digest_sha256": "e1366800863bc8ae88fb0312c108c93463b08c4c62a2e976672db1638b9dd4f0"},
    {"name": "n2d1b-pair-reproducibility-repo-requests", "artifact_id": 8395498696,
     "digest_sha256": "d20c2e2447b5fb7677fcd3fbc5853cf26b5fa945c565839814431f7bfd762785"},
    {"name": "n2d1b-pair-reproducibility-repo-rustlings", "artifact_id": 8395496831,
     "digest_sha256": "4d9eb1536dc4c8ae76d20c746f422e2945469ee647644480db38fba5c34308bc"},
]

OTHER_ARTIFACTS_NOT_PART_OF_REQUIRED_MATRIX = [
    {"name": "n2d1b-dockerfile-parser-rs-lockfile", "artifact_id": 8395412204,
     "digest_sha256": "44bc157f5e28b590035d91ad66309ed882996b8be36212faa04654550ad0fbe0"},
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
    "pytest_requests_duration_v1": {
        "file": "pytest-requests-duration-capture-canonicalization-policy-v1.json",
        "policy_sha256": "21543de45468f51c103d078f78acd3079bfd1d9e1b8927722913add6e16f3597",
        "policy_version": 1,
        "applicable_case_ids": ["repo-requests"],
        "canonicalizer_module": "pytest_requests_duration_canonicalizer_v1.py",
        "note": (
            "NEW, separate policy identity from the retired pytest_requests_canonicalizer.py "
            "(v1, REJECTED -- see pytest-requests-canonicalization-v1-rejection-record.json, "
            "derived from invalid run 29544801640). Built from the first genuinely successful "
            "repo-requests capture pair (diagnostic probe run 29549403465), independently "
            "derived from pytest 9.1.1's own installed _pytest/terminal.py source. Covers "
            "ONLY pytest's own final-summary duration token -- no object-address or "
            "thread-ident rule carried forward from the rejected v1 module."
        ),
    },
}

NETWORK_ENFORCEMENT_AUTHORIZED_CASES = {
    "repo-kubeops-generator": "outer-netns-loopback-only",
    "repo-moshi": "outer-netns-loopback-only",
    "repo-helm-values": "outer-netns-loopback-only",
    "repo-requests": "outer-netns-loopback-only",
}

NETWORK_ENFORCEMENT_APPROVAL_IDENTITIES = {
    "repo-requests": "n2d1b-repo-requests-loopback-only-authorization-2026-07-17",
}

# D1b remediation round 2 (2026-07-17): a SEPARATE, ADDITIONAL authorization
# layer from NETWORK_ENFORCEMENT_AUTHORIZED_CASES above -- never merged into
# it. See generic_sandbox_policy.py's TIMEOUT_SINK_AUTHORIZED_CASES.
TIMEOUT_SINK_AUTHORIZED_CASES = {"repo-requests": "10.255.255.1"}
TIMEOUT_SINK_APPROVAL_IDENTITIES = {
    "repo-requests": "n2d1b-repo-requests-timeout-sink-v1-authorization-2026-07-17",
}
TIMEOUT_SINK_TEST_NETWORK_FIXTURE_NAMES = {"repo-requests": "repo-requests-timeout-sink-v1"}

SOURCE_MTIME_MATERIALIZATION_AUTHORIZED_CASES = {"repo-requests": "2000-01-01T00:00:00Z"}
SOURCE_MTIME_MATERIALIZATION_POLICY_IDENTITY = "n2d1b-repo-requests-source-mtime-materialization-v1"

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

# Detailed per-case evidence map -- the user's explicit requirement: role,
# ecosystem, frozen source commit SHA, durable asset name/SHA-256, frozen/
# effective argv, selected stream, toolchain identity, sandbox-policy
# identity, canonicalization-policy identity or null, capture-a/b artifact
# IDs, raw/canonical SHA-256 for both captures, canonical_bytes_equal,
# canonical_capture, canonical_benchmark_input_sha256, content
# classification for both. Every value here is read directly from the real
# downloaded receipt.json / content-validation-report.json for this run --
# never hand-typed from memory.
CASES = {
    "repo-docker-java-parser": {
        "ecosystem": "jvm-maven",
        "frozen_source_commit_sha": "bc41f15b9f69879e414002feb5e73bfaac61862e",
        "durable_asset_name": "n2c-acquisition-repo-docker-java-parser.zip",
        "durable_asset_sha256": "e647c8fa1abbe73c03e8a08ef4c06f65bf5083383da6af3a138d270af211f459",
        "frozen_argv": ["mvn", "test"],
        "effective_argv": ["mvn", "test"],
        "selected_stream": "stdout",
        "toolchain_identity_classification": {"capture_a": "unexpected-resolution", "capture_b": "unexpected-resolution"},
        "sandbox_policy_identity": {
            "sandboy_commit_sha": "c7c2dcdc6c80eb5f0b629245e0bf6ca4746e8783",
            "network_enforcement_mode": None,
        },
        "canonicalization_policy_identity": "maven",
        "capture_artifact_ids": {"capture_a": 8395443914, "capture_b": 8395446225},
        "raw_selected_stream_sha256": {
            "capture_a": "71bd0d0b4b6448068eab034cd11ca729b1cce47afb7e0bda67fdeb52798d7f96",
            "capture_b": "57774b8eae608f5663e33ccf57144ddaa1e43060ed00d08e8a01e367e8a7c9c4",
        },
        "canonical_benchmark_input_sha256": {
            "capture_a": "6ec603bdb9461abfc170dcc4a3ab562883b8d02b6af4aabb6a421bc57b45dd36",
            "capture_b": "6ec603bdb9461abfc170dcc4a3ab562883b8d02b6af4aabb6a421bc57b45dd36",
        },
        "canonical_bytes_equal": True,
        "canonical_capture": "capture_a",
        "canonical_benchmark_input_sha256_final": "6ec603bdb9461abfc170dcc4a3ab562883b8d02b6af4aabb6a421bc57b45dd36",
        "content_classification": {"capture_a": "genuine-workload-output", "capture_b": "genuine-workload-output"},
    },
    "repo-dockerfile-parser-rs": {
        "ecosystem": "rust",
        "frozen_source_commit_sha": "bc52c98c6fbb2267d8c71bf000d5022b9ce75533",
        "durable_asset_name": "n2c-acquisition-repo-dockerfile-parser-rs.zip",
        "durable_asset_sha256": "898fc0869782af2dbf5fc42a3953f76e3ba6e22777049d28fd1bd43779973378",
        "frozen_argv": ["cargo", "test"],
        "effective_argv": ["cargo", "test"],
        "selected_stream": "stdout",
        "toolchain_identity_classification": {"capture_a": "unexpected-resolution", "capture_b": "unexpected-resolution"},
        "sandbox_policy_identity": {
            "sandboy_commit_sha": "c7c2dcdc6c80eb5f0b629245e0bf6ca4746e8783",
            "network_enforcement_mode": None,
        },
        "canonicalization_policy_identity": "cargo_test",
        "capture_artifact_ids": {"capture_a": 8395422395, "capture_b": 8395422285},
        "raw_selected_stream_sha256": {
            "capture_a": "cd841fa40ac8591ab536e807f0b4b2c4ef8a9d998681f1442f8d583539eca80d",
            "capture_b": "6f88f0f5040a44678ca5a3ef08c6c720f02c53a930f58606e64385139ac9ceb8",
        },
        "canonical_benchmark_input_sha256": {
            "capture_a": "d6100fd52cb44f1e76632430cdf1087c5442c59ab402387c735aac576a52684a",
            "capture_b": "d6100fd52cb44f1e76632430cdf1087c5442c59ab402387c735aac576a52684a",
        },
        "canonical_bytes_equal": True,
        "canonical_capture": "capture_a",
        "canonical_benchmark_input_sha256_final": "d6100fd52cb44f1e76632430cdf1087c5442c59ab402387c735aac576a52684a",
        "content_classification": {"capture_a": "genuine-workload-output", "capture_b": "genuine-workload-output"},
    },
    "repo-helm-values": {
        "ecosystem": "jvm-gradle",
        "frozen_source_commit_sha": "bcc4dc7cd7cd667995a9e6f1811335d8a239bc5c",
        "durable_asset_name": "n2c-acquisition-repo-helm-values.zip",
        "durable_asset_sha256": "7b4bf8d80f555b084e144bd1099ebde420ccafa6623b315628daf60a14bf4bb6",
        "frozen_argv": ["./gradlew", ":helm-values-shared:test"],
        "effective_argv": ["./gradlew", ":helm-values-shared:test"],
        "selected_stream": "stdout",
        "toolchain_identity_classification": {"capture_a": "exact-match", "capture_b": "exact-match"},
        "sandbox_policy_identity": {
            "sandboy_commit_sha": "c7c2dcdc6c80eb5f0b629245e0bf6ca4746e8783",
            "network_enforcement_mode": "outer-netns-loopback-only",
        },
        "canonicalization_policy_identity": "gradle_helm_values_v1",
        "capture_artifact_ids": {"capture_a": 8395454071, "capture_b": 8395460492},
        "raw_selected_stream_sha256": {
            "capture_a": "c0ed833fb4839efe3015a33e614534cfca05bb359a29d8d64a7561039ec21ce3",
            "capture_b": "ad6fe816a2962ad292401421d01f4395ae6bc760a914897129847e41eb483f20",
        },
        "canonical_benchmark_input_sha256": {
            "capture_a": "cf967cb267dd5d59c7d0b4f56f7a34fde10ed7129297882233d56202fdd81694",
            "capture_b": "cf967cb267dd5d59c7d0b4f56f7a34fde10ed7129297882233d56202fdd81694",
        },
        "canonical_bytes_equal": True,
        "canonical_capture": "capture_a",
        "canonical_benchmark_input_sha256_final": "cf967cb267dd5d59c7d0b4f56f7a34fde10ed7129297882233d56202fdd81694",
        "content_classification": {"capture_a": "genuine-workload-output", "capture_b": "genuine-workload-output"},
    },
    "repo-hyperfine": {
        "ecosystem": "rust",
        "frozen_source_commit_sha": "f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7",
        "durable_asset_name": "n2c-acquisition-repo-hyperfine.zip",
        "durable_asset_sha256": "2bf0eae973eb7384df7bda5f5ebabcff2967d1d964252478c265bd1aced4cf24",
        "frozen_argv": ["cargo", "run", "--", "--version"],
        "effective_argv": ["cargo", "run", "--", "--version"],
        "selected_stream": "stdout",
        "toolchain_identity_classification": {"capture_a": "unexpected-resolution", "capture_b": "unexpected-resolution"},
        "sandbox_policy_identity": {
            "sandboy_commit_sha": "c7c2dcdc6c80eb5f0b629245e0bf6ca4746e8783",
            "network_enforcement_mode": None,
        },
        "canonicalization_policy_identity": None,
        "capture_artifact_ids": {"capture_a": 8395423562, "capture_b": 8395421416},
        "raw_selected_stream_sha256": {
            "capture_a": "3ecde90858d8ec63c1eafbc0e9945547b4bef7c2fcf6741934421bc18276b48d",
            "capture_b": "3ecde90858d8ec63c1eafbc0e9945547b4bef7c2fcf6741934421bc18276b48d",
        },
        "canonical_benchmark_input_sha256": {
            "capture_a": "3ecde90858d8ec63c1eafbc0e9945547b4bef7c2fcf6741934421bc18276b48d",
            "capture_b": "3ecde90858d8ec63c1eafbc0e9945547b4bef7c2fcf6741934421bc18276b48d",
        },
        "canonical_bytes_equal": True,
        "canonical_capture": "capture_a",
        "canonical_benchmark_input_sha256_final": "3ecde90858d8ec63c1eafbc0e9945547b4bef7c2fcf6741934421bc18276b48d",
        "content_classification": {"capture_a": "genuine-workload-output", "capture_b": "genuine-workload-output"},
    },
    "repo-kubeops-generator": {
        "ecosystem": "dotnet",
        "frozen_source_commit_sha": "9f44d7ca3b545b0db2fdb990374c58f0205d0eef",
        "durable_asset_name": "n2c-acquisition-repo-kubeops-generator.zip",
        "durable_asset_sha256": "f89e1b38e3337caab1dfe7b449fffd1e186179fc9fa5f234ce2f7f57287dc979",
        "frozen_argv": ["dotnet", "test", "test/KubeOps.Generator.Test/KubeOps.Generator.Test.csproj"],
        "effective_argv": [
            "dotnet", "test", "test/KubeOps.Generator.Test/KubeOps.Generator.Test.csproj", "--no-restore",
        ],
        "selected_stream": "stdout",
        "toolchain_identity_classification": {"capture_a": "compatible-resolution", "capture_b": "compatible-resolution"},
        "sandbox_policy_identity": {
            "sandboy_commit_sha": "c7c2dcdc6c80eb5f0b629245e0bf6ca4746e8783",
            "network_enforcement_mode": "outer-netns-loopback-only",
        },
        "canonicalization_policy_identity": "vstest",
        "capture_artifact_ids": {"capture_a": 8395428847, "capture_b": 8395426596},
        "raw_selected_stream_sha256": {
            "capture_a": "ee62e09e881ac44fd0594775afe7e56b6f4dd0ef56d8ddc69aa83390f0858dfd",
            "capture_b": "ee62e09e881ac44fd0594775afe7e56b6f4dd0ef56d8ddc69aa83390f0858dfd",
        },
        "canonical_benchmark_input_sha256": {
            "capture_a": "e38369406a00c3d049970971e5b13b9c0ed4b834ee0b7d4e309809932ee4cf4b",
            "capture_b": "e38369406a00c3d049970971e5b13b9c0ed4b834ee0b7d4e309809932ee4cf4b",
        },
        "canonical_bytes_equal": True,
        "canonical_capture": "capture_a",
        "canonical_benchmark_input_sha256_final": "e38369406a00c3d049970971e5b13b9c0ed4b834ee0b7d4e309809932ee4cf4b",
        "content_classification": {"capture_a": "genuine-workload-output", "capture_b": "genuine-workload-output"},
    },
    "repo-moshi": {
        "ecosystem": "jvm-gradle",
        "frozen_source_commit_sha": "889013ec2edb8d8034902662a1dc8c4f3b3f8111",
        "durable_asset_name": "n2c-acquisition-repo-moshi.zip",
        "durable_asset_sha256": "00b6b71337dea3280ab409d26e8392b1eb58ed9d5f66adc81d8a760b2f7cdaf6",
        "frozen_argv": ["./gradlew", "test"],
        "effective_argv": ["./gradlew", "test"],
        "selected_stream": "stdout",
        "toolchain_identity_classification": {"capture_a": "exact-match", "capture_b": "exact-match"},
        "sandbox_policy_identity": {
            "sandboy_commit_sha": "c7c2dcdc6c80eb5f0b629245e0bf6ca4746e8783",
            "network_enforcement_mode": "outer-netns-loopback-only",
        },
        "canonicalization_policy_identity": "gradle_v2",
        "capture_artifact_ids": {"capture_a": 8395484398, "capture_b": 8395494166},
        "raw_selected_stream_sha256": {
            "capture_a": "411f0a78d282c1ccaeb7b295fd8a4515a1d07d340bb18a1f396bceb5c944a552",
            "capture_b": "70db00951be997824b9173f669ed9557f7fdc818c3c3e1418e089ce53402d82c",
        },
        "canonical_benchmark_input_sha256": {
            "capture_a": "c98f69759fb34ade6cbb60fe0d4632f9d906de5474c6e358359c2fd60293eb84",
            "capture_b": "c98f69759fb34ade6cbb60fe0d4632f9d906de5474c6e358359c2fd60293eb84",
        },
        "canonical_bytes_equal": True,
        "canonical_capture": "capture_a",
        "canonical_benchmark_input_sha256_final": "c98f69759fb34ade6cbb60fe0d4632f9d906de5474c6e358359c2fd60293eb84",
        "content_classification": {"capture_a": "genuine-workload-output", "capture_b": "genuine-workload-output"},
    },
    "repo-pyflakes": {
        "ecosystem": "python",
        "frozen_source_commit_sha": "59ec4593efd4c69ce00fdb13c40fcf5f3212ab10",
        "durable_asset_name": "n2c-acquisition-repo-pyflakes.zip",
        "durable_asset_sha256": "4dfe80499d91f501aa4fa742cb8cc09318bd984ffd175b8de0ad3868cdd3d96e",
        "frozen_argv": ["python", "-m", "pyflakes", "src/"],
        "effective_argv": ["/home/runner/work/_temp/venv-repo-pyflakes/bin/python", "-m", "pyflakes", "pyflakes/"],
        "selected_stream": "stdout",
        "toolchain_identity_classification": {"capture_a": "exact-match", "capture_b": "exact-match"},
        "sandbox_policy_identity": {
            "sandboy_commit_sha": "c7c2dcdc6c80eb5f0b629245e0bf6ca4746e8783",
            "network_enforcement_mode": None,
        },
        "canonicalization_policy_identity": None,
        "capture_artifact_ids": {"capture_a": 8395433551, "capture_b": 8395423659},
        "raw_selected_stream_sha256": {
            "capture_a": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "capture_b": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        "canonical_benchmark_input_sha256": {
            "capture_a": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "capture_b": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        "canonical_bytes_equal": True,
        "canonical_capture": "capture_a",
        "canonical_benchmark_input_sha256_final": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "content_classification": {
            "capture_a": "successful-empty-domain-result", "capture_b": "successful-empty-domain-result",
        },
    },
    "repo-requests": {
        "ecosystem": "python",
        "frozen_source_commit_sha": "f361ead047be5cb873174218582f7d8b9fcd9f49",
        "durable_asset_name": "n2c-acquisition-repo-requests.zip",
        "durable_asset_sha256": "37fb6b0957bcde366fef4b35a6f3d1e2e8afc3d26f4e130f60df2bdfa34fcb5e",
        "frozen_argv": ["pytest"],
        "effective_argv": ["/home/runner/work/_temp/venv-repo-requests/bin/pytest"],
        "selected_stream": "stdout",
        "toolchain_identity_classification": {"capture_a": "exact-match", "capture_b": "exact-match"},
        "sandbox_policy_identity": {
            "sandboy_commit_sha": "c7c2dcdc6c80eb5f0b629245e0bf6ca4746e8783",
            "network_enforcement_mode": "outer-netns-loopback-only",
        },
        "canonicalization_policy_identity": "pytest_requests_duration_v1",
        "capture_artifact_ids": {"capture_a": 8395455667, "capture_b": 8395444024},
        "raw_selected_stream_sha256": {
            "capture_a": "cab448e2d409563ebc259e2b3ea00ac118d6b267ea11605f683ab3315ddcaa0a",
            "capture_b": "74b587191100a20186240403fb01e963fd647dea104647e420e151376e810b28",
        },
        "canonical_benchmark_input_sha256": {
            "capture_a": "cf78ccb2ec1f801530576a96d25cda8d9a92399759e6f5cf2c13ebeac2d92c27",
            "capture_b": "cf78ccb2ec1f801530576a96d25cda8d9a92399759e6f5cf2c13ebeac2d92c27",
        },
        "canonical_bytes_equal": True,
        "canonical_capture": "capture_a",
        "canonical_benchmark_input_sha256_final": "cf78ccb2ec1f801530576a96d25cda8d9a92399759e6f5cf2c13ebeac2d92c27",
        "content_classification": {"capture_a": "genuine-workload-output", "capture_b": "genuine-workload-output"},
    },
    "repo-rustlings": {
        "ecosystem": "rust",
        "frozen_source_commit_sha": "925321705edd96b39995f77edf437f7db6f9b16a",
        "durable_asset_name": "n2c-acquisition-repo-rustlings.zip",
        "durable_asset_sha256": "7852586fb974e861d7b96ccf55f546e1fa28abd599552ff5d4b2f826b713a6bd",
        "frozen_argv": ["cargo", "test"],
        "effective_argv": ["cargo", "test"],
        "selected_stream": "stdout",
        "toolchain_identity_classification": {"capture_a": "unexpected-resolution", "capture_b": "unexpected-resolution"},
        "sandbox_policy_identity": {
            "sandboy_commit_sha": "c7c2dcdc6c80eb5f0b629245e0bf6ca4746e8783",
            "network_enforcement_mode": None,
        },
        "canonicalization_policy_identity": "cargo_test",
        "capture_artifact_ids": {"capture_a": 8395433364, "capture_b": 8395424069},
        "raw_selected_stream_sha256": {
            "capture_a": "3225168140b7e2d9eb1011948ddea7b066bf7e74c2cfe6c7216f473a1139aaf4",
            "capture_b": "3225168140b7e2d9eb1011948ddea7b066bf7e74c2cfe6c7216f473a1139aaf4",
        },
        "canonical_benchmark_input_sha256": {
            "capture_a": "11e611c7c40807f5be8639c9e6b511649ea4b8617c998786e97c8b8f0892dcaf",
            "capture_b": "11e611c7c40807f5be8639c9e6b511649ea4b8617c998786e97c8b8f0892dcaf",
        },
        "canonical_bytes_equal": True,
        "canonical_capture": "capture_a",
        "canonical_benchmark_input_sha256_final": "11e611c7c40807f5be8639c9e6b511649ea4b8617c998786e97c8b8f0892dcaf",
        "content_classification": {"capture_a": "genuine-workload-output", "capture_b": "genuine-workload-output"},
    },
}

# The nine per-case canonical_benchmark_input_sha256_final values, in one
# place -- the exact field the user asked to have "recorded" as a group.
CANONICAL_BENCHMARK_INPUT_SHA256_BY_CASE_ID = {
    case_id: entry["canonical_benchmark_input_sha256_final"] for case_id, entry in CASES.items()
}

# repo-requests-specific detailed binding: content acceptance is explicitly
# bound to duration canonicalization plus every round-2 fixture, per the
# user's explicit itemized requirement (2026-07-17).
REPO_REQUESTS_DETAILED_ACCEPTANCE = {
    "case_id": "repo-requests",
    "exit_code_zero_both_captures": True,
    "zero_failed_zero_errors_both_captures": True,
    "pytest_final_summary": {
        "capture_a": "619 passed, 15 skipped, 1 xfailed, 18 warnings in 78.55s (0:01:18)",
        "capture_b": "619 passed, 15 skipped, 1 xfailed, 18 warnings in 78.68s (0:01:18)",
    },
    "content_accepted_both_captures": True,
    "content_classification_both_captures": "genuine-workload-output",
    "toolchain_classification_both_captures": "exact-match",
    "test_network_fixture": "repo-requests-timeout-sink-v1",
    "test_network_fixture_approval_identity": "n2d1b-repo-requests-timeout-sink-v1-authorization-2026-07-17",
    "timeout_sink_target": "10.255.255.1",
    "timeout_sink_probe_argv": [
        "python3",
        "evals/interop/v2/n2/d1-identity-lock/tools/timeout_sink_target_probe.py",
        "10.255.255.1",
    ],
    "timeout_sink_verified_both_captures": True,
    "loopback_bind_connect_confirmed_allowed_both_captures": True,
    "other_external_connectivity_confirmed_blocked_both_captures": True,
    "network_enforcement_mode": "outer-netns-loopback-only",
    "network_enforcement_approval_identity": "n2d1b-repo-requests-loopback-only-authorization-2026-07-17",
    "network_enforcement_distinct_from_test_network_fixture": True,
    "source_mtime_materialization_policy_identity": "n2d1b-repo-requests-source-mtime-materialization-v1",
    "source_mtime_materialization_fixed_timestamp_iso8601_utc": "2000-01-01T00:00:00Z",
    "source_mtime_materialization_fixed_timestamp_epoch_seconds": 946684800,
    "source_mtime_materialization_affected_file_count_both_captures": 128,
    "canonicalization_policy_identity": "pytest_requests_duration_v1",
    "canonicalization_replacement_count": 1,
    "canonicalization_replacement_rule_name": "pytest_final_summary_duration",
    "raw_ab_diff_line_count": 1,
    "raw_ab_diff_is_exactly_the_pytest_duration_token": True,
    "canonical_bytes_equal": True,
    "canonical_capture": "capture_a",
    "canonical_benchmark_input_sha256": "cf78ccb2ec1f801530576a96d25cda8d9a92399759e6f5cf2c13ebeac2d92c27",
}

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
        "canonicalizer_module": "pytest_requests_duration_canonicalizer_v1.py",
        "capture_a_rederived_equals_committed": True,
        "capture_b_rederived_equals_committed": True,
        "capture_a_and_b_canonicalize_to_identical_bytes": True,
        "receipt_canonicalization_policy_sha256_matches_locally_built_policy": True,
        "note": (
            "First genuinely successful repo-requests capture pair ever observed: exit_code=0, "
            "zero failed, zero errors, on both captures. The raw capture-a/capture-b bytes "
            "differ in EXACTLY one line -- pytest's own final-summary duration -- confirmed by "
            "direct byte-level diff of the downloaded raw.stdout, independently of the pair-"
            "verify job's own report. See REPO_REQUESTS_DETAILED_ACCEPTANCE above for the full "
            "binding of content acceptance to this canonicalization."
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


def _load_replacement_selection_record() -> dict:
    return json.loads(REPLACEMENT_SELECTION_RECORD_PATH.read_text())


def _build_replacement_selection_link() -> dict:
    """Links (and re-verifies) stage2-replacement-selection-v1.json -- the
    record documenting repo-helm-values' deterministic selection as the
    jvm-gradle replacement for the permanently-rejected repo-spotless. Never
    copies its content; only its path and its own, independently
    recomputed self-hash."""
    from verify_stage2_replacement_selection import verify as verify_replacement_selection

    record = _load_replacement_selection_record()
    ok, message = verify_replacement_selection()
    if not ok:
        raise RuntimeError(f"stage2-replacement-selection-v1.json failed its own verifier: {message}")
    return {
        "record_path": "evals/interop/v2/n2/d1-identity-lock/stage2-replacement-selection-v1.json",
        "record_sha256": record["record_sha256"],
        "replacement_case_id": record["replacement_case_id"],
        "rejected_case_id": record["rejected_case_id"],
        "verified_by_its_own_verifier_at_build_time": True,
    }


JOBS_MANIFEST_PATH = Path(__file__).resolve().parents[1] / "stage2-run-29550102525-jobs-manifest.json"
ARTIFACTS_MANIFEST_PATH = Path(__file__).resolve().parents[1] / "stage2-run-29550102525-artifacts-manifest.json"


def _build_run_evidence_manifests_link() -> dict:
    """Links the two independently-committed, self-hash-locked run-evidence
    manifests (stage2-run-29550102525-jobs-manifest.json,
    stage2-run-29550102525-artifacts-manifest.json) -- each separately
    transcribed from the real GitHub API responses for this run, not derived
    from this module's own ARTIFACTS/PILOT_JOBS/etc. lists above. Never
    copies their content; only their paths and their own, independently
    recomputed self-hashes. verify_stage2_full_matrix_acceptance.py
    additionally requires this record's own jobs/artifacts lists to exactly
    match the manifests' contents -- this link records ONLY that the
    manifests exist and are self-consistent at build time."""
    import hashlib as _hashlib
    import json as _json

    def _recompute_sha256(body: dict) -> str:
        body_for_hash = dict(body)
        body_for_hash["record_sha256"] = None
        canonical = _json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + _hashlib.sha256(canonical).hexdigest()

    jobs_manifest = _json.loads(JOBS_MANIFEST_PATH.read_text())
    if _recompute_sha256(jobs_manifest) != jobs_manifest["record_sha256"]:
        raise RuntimeError(f"{JOBS_MANIFEST_PATH} failed its own self-hash check at build time")
    artifacts_manifest = _json.loads(ARTIFACTS_MANIFEST_PATH.read_text())
    if _recompute_sha256(artifacts_manifest) != artifacts_manifest["record_sha256"]:
        raise RuntimeError(f"{ARTIFACTS_MANIFEST_PATH} failed its own self-hash check at build time")

    return {
        "jobs_manifest_path": "evals/interop/v2/n2/d1-identity-lock/stage2-run-29550102525-jobs-manifest.json",
        "jobs_manifest_record_sha256": jobs_manifest["record_sha256"],
        "artifacts_manifest_path": (
            "evals/interop/v2/n2/d1-identity-lock/stage2-run-29550102525-artifacts-manifest.json"
        ),
        "artifacts_manifest_record_sha256": artifacts_manifest["record_sha256"],
        "verified_self_consistent_at_build_time": True,
    }


def build_record() -> dict:
    body = {
        "record_type": "n2d1b-stage2-full-matrix-acceptance-v1",
        "record_version": 2,
        "schema_version": 2,
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
        "remediation_history": (
            "Supersedes the prior stage2-full-matrix-acceptance.json (workflow run 29544801640), "
            "REVOKED because repo-requests' capture there genuinely failed (30 failed, 205 errors) "
            "and was wrongly accepted -- see pytest-requests-canonicalization-v1-rejection-record."
            "json. Round-1 remediation (fail-closed content gate, network authorization, toolchain "
            "identity fix, canonicalizer retirement) produced a fresh full run (29547420247), which "
            "correctly rejected repo-requests again -- two newly surfaced, genuine execution-"
            "environment incompatibilities: a network-namespace timeout-sink gap (four TestTimeout "
            "tests connecting to 10.255.255.1 hit an immediate ENETUNREACH instead of a socket."
            "timeout) and a source-mtime/zipfile-1980-floor gap (extracted files carried Unix-epoch "
            "mtimes; Python's zipfile rejects timestamps before 1980). Round-2 remediation fixed "
            "both: a repo-requests-only veth-pair timeout-sink network fixture (empirically "
            "validated via a local live probe before any production change) and a repo-requests-"
            "only deterministic ZIP-safe source-mtime materialization step. A first focused "
            "diagnostic probe (run 29548972173, repo-requests only) failed for an unrelated reason "
            "-- the timeout-sink probe's own target IP was passed via an env var Sandboy's "
            "env_clear()+env_allow confinement stripped before the confined child ran; fixed by "
            "passing it via argv instead. A second focused probe (run 29549403465) was genuinely "
            "successful -- the first-ever clean repo-requests capture pair -- differing from its "
            "own pair only in pytest's own final-summary duration, which became the basis for the "
            "new pytest_requests_duration_canonicalizer_v1.py policy. This record's own run "
            "(29550102525) is the fresh, complete nine-case matrix run required after all of the "
            "above, on a fresh implementation commit and disposable trigger branch, reusing no "
            "artifact from any prior run or diagnostic probe."
        ),
        "workflow": {
            "name": WORKFLOW_NAME,
            "run_id": WORKFLOW_RUN_ID,
            "run_number": 10,
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
        "network_enforcement_approval_identities": NETWORK_ENFORCEMENT_APPROVAL_IDENTITIES,
        "timeout_sink_authorized_cases": TIMEOUT_SINK_AUTHORIZED_CASES,
        "timeout_sink_approval_identities": TIMEOUT_SINK_APPROVAL_IDENTITIES,
        "timeout_sink_test_network_fixture_names": TIMEOUT_SINK_TEST_NETWORK_FIXTURE_NAMES,
        "source_mtime_materialization_authorized_cases": SOURCE_MTIME_MATERIALIZATION_AUTHORIZED_CASES,
        "source_mtime_materialization_policy_identity": SOURCE_MTIME_MATERIALIZATION_POLICY_IDENTITY,
        "gradle_deterministic_scheduling_profile_sha256_by_case_id": GRADLE_DETERMINISTIC_SCHEDULING_PROFILE_SHA256_BY_CASE_ID,
        "rust_deterministic_test_threads_authorized_case_ids": RUST_DETERMINISTIC_TEST_THREADS_AUTHORIZED_CASE_IDS,
        "cases": CASES,
        "canonical_benchmark_input_sha256_by_case_id": CANONICAL_BENCHMARK_INPUT_SHA256_BY_CASE_ID,
        "repo_requests_detailed_acceptance": REPO_REQUESTS_DETAILED_ACCEPTANCE,
        "replacement_selection": _build_replacement_selection_link(),
        "run_evidence_manifests": _build_run_evidence_manifests_link(),
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
            "test_count": 616,
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
