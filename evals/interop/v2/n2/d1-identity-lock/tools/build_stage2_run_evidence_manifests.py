#!/usr/bin/env python3
"""Builds the two minimal, self-hash-locked canonical evidence manifests for
workflow run 29550102525 -- the exact, sole source of Stage 2's full-matrix
acceptance evidence.

Both manifests are independently transcribed, byte-for-byte, from the real
GitHub Actions REST API responses captured for this run in this session:

- JOBS: `list_workflow_jobs` for run 29550102525 (28 jobs; response saved
  verbatim to this session's own tool-result transcript before being
  condensed here).
- ARTIFACTS: `list_workflow_run_artifacts` for run 29550102525 (28
  artifacts; response saved verbatim to this session's own tool-result
  transcript before being condensed here).

These manifests exist as an INDEPENDENT, separately-committed source of
ground truth: stage2-full-matrix-acceptance.json's own `jobs` /
`pair_verify_jobs` / `other_jobs_not_part_of_required_matrix` and
`artifacts` / `pair_report_artifacts` / `other_artifacts_not_part_of_required_matrix`
lists are transcribed separately (in build_stage2_full_matrix_acceptance.py)
from the same real API responses. verify_stage2_full_matrix_acceptance.py
requires EXACT equality between the two independently-transcribed sources,
so a tamper of either the acceptance record OR this manifest alone (but not
both, consistently) is caught.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parents[1]
JOBS_MANIFEST_PATH = OUT_DIR / "stage2-run-29550102525-jobs-manifest.json"
ARTIFACTS_MANIFEST_PATH = OUT_DIR / "stage2-run-29550102525-artifacts-manifest.json"

WORKFLOW_RUN_ID = 29550102525
HEAD_SHA = "c430812a604ec25fa68d40e55a5df156f6029707"
HEAD_BRANCH = "ci-trigger/n2d1b-stage2-478d70b"

# Transcribed directly from the real `list_workflow_jobs` API response for
# this run (28 jobs total), sorted by job_id.
JOBS = [
    {"job_id": 87790638449, "name": "dockerfile-parser-rs-lockfile", "conclusion": "success"},
    {"job_id": 87790677686, "name": "pilot-repo-hyperfine-capture-a", "conclusion": "success"},
    {"job_id": 87790677687, "name": "pilot-repo-kubeops-generator-capture-b", "conclusion": "success"},
    {"job_id": 87790677695, "name": "pilot-repo-kubeops-generator-capture-a", "conclusion": "success"},
    {"job_id": 87790677710, "name": "pilot-repo-pyflakes-capture-b", "conclusion": "success"},
    {"job_id": 87790677721, "name": "pilot-repo-hyperfine-capture-b", "conclusion": "success"},
    {"job_id": 87790677724, "name": "pilot-repo-moshi-capture-a", "conclusion": "success"},
    {"job_id": 87790677729, "name": "pilot-repo-docker-java-parser-capture-a", "conclusion": "success"},
    {"job_id": 87790677730, "name": "pilot-repo-docker-java-parser-capture-b", "conclusion": "success"},
    {"job_id": 87790677743, "name": "pilot-repo-pyflakes-capture-a", "conclusion": "success"},
    {"job_id": 87790677765, "name": "pilot-repo-dockerfile-parser-rs-capture-a", "conclusion": "success"},
    {"job_id": 87790677768, "name": "pilot-repo-helm-values-capture-a", "conclusion": "success"},
    {"job_id": 87790677778, "name": "pilot-repo-dockerfile-parser-rs-capture-b", "conclusion": "success"},
    {"job_id": 87790677784, "name": "pilot-repo-moshi-capture-b", "conclusion": "success"},
    {"job_id": 87790677799, "name": "pilot-repo-rustlings-capture-a", "conclusion": "success"},
    {"job_id": 87790677803, "name": "pilot-repo-requests-capture-b", "conclusion": "success"},
    {"job_id": 87790677811, "name": "pilot-repo-requests-capture-a", "conclusion": "success"},
    {"job_id": 87790677812, "name": "pilot-repo-rustlings-capture-b", "conclusion": "success"},
    {"job_id": 87790677823, "name": "pilot-repo-helm-values-capture-b", "conclusion": "success"},
    {"job_id": 87791420718, "name": "pair-verify-repo-pyflakes", "conclusion": "success"},
    {"job_id": 87791420726, "name": "pair-verify-repo-docker-java-parser", "conclusion": "success"},
    {"job_id": 87791420727, "name": "pair-verify-repo-kubeops-generator", "conclusion": "success"},
    {"job_id": 87791420732, "name": "pair-verify-repo-hyperfine", "conclusion": "success"},
    {"job_id": 87791420737, "name": "pair-verify-repo-helm-values", "conclusion": "success"},
    {"job_id": 87791420743, "name": "pair-verify-repo-rustlings", "conclusion": "success"},
    {"job_id": 87791420753, "name": "pair-verify-repo-dockerfile-parser-rs", "conclusion": "success"},
    {"job_id": 87791420760, "name": "pair-verify-repo-moshi", "conclusion": "success"},
    {"job_id": 87791420773, "name": "pair-verify-repo-requests", "conclusion": "success"},
]

# Transcribed directly from the real `list_workflow_run_artifacts` API
# response for this run (28 artifacts total), sorted by artifact_id.
ARTIFACTS = [
    {"artifact_id": 8395412204, "name": "n2d1b-dockerfile-parser-rs-lockfile",
     "digest_sha256": "44bc157f5e28b590035d91ad66309ed882996b8be36212faa04654550ad0fbe0"},
    {"artifact_id": 8395421416, "name": "n2d1b-pilot-repo-hyperfine-capture-b",
     "digest_sha256": "3e61bc62b358a90611368a399c38ffdfad397e3ae8b971188d09af6fd1959781"},
    {"artifact_id": 8395422285, "name": "n2d1b-pilot-repo-dockerfile-parser-rs-capture-b",
     "digest_sha256": "98cdd0bd19d1ea5ba8d3b78f2d44341fb247511a1e0011ef20a6f20a05ad297b"},
    {"artifact_id": 8395422395, "name": "n2d1b-pilot-repo-dockerfile-parser-rs-capture-a",
     "digest_sha256": "bb2499d38ae03761051442ec353a8618069eec962cb1e7b2f66817c4ab6641a2"},
    {"artifact_id": 8395423562, "name": "n2d1b-pilot-repo-hyperfine-capture-a",
     "digest_sha256": "b5b0c67dbec58ac059ff8abaaedd687da6d8c75513686b7e8f7ab6df724a8a7e"},
    {"artifact_id": 8395423659, "name": "n2d1b-pilot-repo-pyflakes-capture-b",
     "digest_sha256": "3228f40282b488c4cd866a1e890478dca9c2eb2efb6cf1a6552625c5ff6ca724"},
    {"artifact_id": 8395424069, "name": "n2d1b-pilot-repo-rustlings-capture-b",
     "digest_sha256": "1108a251046f09e0e1cd40f832656a9f86b1cd1a04c8ceb4adf46fe75c6939da"},
    {"artifact_id": 8395426596, "name": "n2d1b-pilot-repo-kubeops-generator-capture-b",
     "digest_sha256": "2ee917bd9795acd46dae130ee3b216eb37b92425bea06471574e4ab6165ff288"},
    {"artifact_id": 8395428847, "name": "n2d1b-pilot-repo-kubeops-generator-capture-a",
     "digest_sha256": "32f0d738e3c5c4ef540727ce124a4de97e2ee7dd25c0a931a56ce48466234642"},
    {"artifact_id": 8395433364, "name": "n2d1b-pilot-repo-rustlings-capture-a",
     "digest_sha256": "d89a7563e2d65a748375648842024aadf00cc98298d2498d108198fddbbc2e7e"},
    {"artifact_id": 8395433551, "name": "n2d1b-pilot-repo-pyflakes-capture-a",
     "digest_sha256": "1b720cad83191684d58daef09608768b794d73a142d1bce1b293d3d279fddc20"},
    {"artifact_id": 8395443914, "name": "n2d1b-pilot-repo-docker-java-parser-capture-a",
     "digest_sha256": "efeaba5de29c651cf5c0aaf32b131cea4192946bb6e1b83dfc118e584e9e93a7"},
    {"artifact_id": 8395444024, "name": "n2d1b-pilot-repo-requests-capture-b",
     "digest_sha256": "f345cf1e56ca89c33eae0f9f95900153bba1d40e253102ea610a4a5421b4fc1c"},
    {"artifact_id": 8395446225, "name": "n2d1b-pilot-repo-docker-java-parser-capture-b",
     "digest_sha256": "a6c967eebac4560538537d9a447c5b8724aa93de3f46b8eca059e0ace4cab1b4"},
    {"artifact_id": 8395454071, "name": "n2d1b-pilot-repo-helm-values-capture-a",
     "digest_sha256": "8103fff2bbae3a8219eb818838b58ceddd42f1cdbb315a0cbe3d92ba8ff20f54"},
    {"artifact_id": 8395455667, "name": "n2d1b-pilot-repo-requests-capture-a",
     "digest_sha256": "488cbab90320581f1bd4c8d51cf7933e711945eb7a29056c861171aebdfa8792"},
    {"artifact_id": 8395460492, "name": "n2d1b-pilot-repo-helm-values-capture-b",
     "digest_sha256": "06e5bd25af97df0ca87fa8d36c2c2c8a6ad2eaa61f308b393f59d587cdf811ea"},
    {"artifact_id": 8395484398, "name": "n2d1b-pilot-repo-moshi-capture-a",
     "digest_sha256": "6eaafc736fdec47955ff2372af3c0fdd0b916615d5864ec1c19785b1b46767e3"},
    {"artifact_id": 8395494166, "name": "n2d1b-pilot-repo-moshi-capture-b",
     "digest_sha256": "cfb27a23d33ea83df97cb2a4b95bb861557370c26fd5428cff76b88b71cc23e7"},
    {"artifact_id": 8395496107, "name": "n2d1b-pair-reproducibility-repo-pyflakes",
     "digest_sha256": "e1366800863bc8ae88fb0312c108c93463b08c4c62a2e976672db1638b9dd4f0"},
    {"artifact_id": 8395496325, "name": "n2d1b-pair-reproducibility-repo-helm-values",
     "digest_sha256": "24c3ef39c869ec6958d14f2f4380038a2519ad127ee7bc068b20b02381940cdd"},
    {"artifact_id": 8395496468, "name": "n2d1b-pair-reproducibility-repo-hyperfine",
     "digest_sha256": "a392806a103c5641c7061820ae0765c8f1dfd56e5eb4a92fc92023b804563ef0"},
    {"artifact_id": 8395496797, "name": "n2d1b-pair-reproducibility-repo-docker-java-parser",
     "digest_sha256": "eb80dece0133ce8e61221f1649a0a627ec90bc82436de3e427e57bd28f002181"},
    {"artifact_id": 8395496831, "name": "n2d1b-pair-reproducibility-repo-rustlings",
     "digest_sha256": "4d9eb1536dc4c8ae76d20c746f422e2945469ee647644480db38fba5c34308bc"},
    {"artifact_id": 8395497957, "name": "n2d1b-pair-reproducibility-repo-kubeops-generator",
     "digest_sha256": "e23bafa52506193e2bb67f041dfccc8f8f9203f3fccf245f76d104c88dd14bc5"},
    {"artifact_id": 8395498102, "name": "n2d1b-pair-reproducibility-repo-moshi",
     "digest_sha256": "f04e38e6febb218fb4a57a9a16291e2025e36cb3e281d1128f4d43d5c6e0afe4"},
    {"artifact_id": 8395498389, "name": "n2d1b-pair-reproducibility-repo-dockerfile-parser-rs",
     "digest_sha256": "0726139dc26adea253ec73059d5d9e11fc863de718ad4670172576df69495951"},
    {"artifact_id": 8395498696, "name": "n2d1b-pair-reproducibility-repo-requests",
     "digest_sha256": "d20c2e2447b5fb7677fcd3fbc5853cf26b5fa945c565839814431f7bfd762785"},
]


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _write(path: Path, body: dict) -> None:
    body = dict(body)
    body["record_sha256"] = compute_record_sha256(body)
    path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
    print(f"wrote {path} (record_sha256={body['record_sha256']})")


def build_jobs_manifest() -> dict:
    assert len(JOBS) == 28
    assert len({j["job_id"] for j in JOBS}) == 28
    assert len({j["name"] for j in JOBS}) == 28
    return {
        "record_type": "n2d1b-stage2-run-jobs-manifest-v1",
        "workflow_run_id": WORKFLOW_RUN_ID,
        "head_sha": HEAD_SHA,
        "head_branch": HEAD_BRANCH,
        "source": (
            "GitHub Actions REST API list_workflow_jobs response for workflow run "
            f"{WORKFLOW_RUN_ID}, independently transcribed job-by-job from that real "
            "response (saved verbatim to this session's own tool-result transcript "
            "before being condensed here). Not derived from, or shared code with, "
            "build_stage2_full_matrix_acceptance.py's own separate transcription of "
            "the same underlying API response."
        ),
        "total_count": len(JOBS),
        "jobs": sorted(JOBS, key=lambda j: j["job_id"]),
    }


def build_artifacts_manifest() -> dict:
    assert len(ARTIFACTS) == 28
    assert len({a["artifact_id"] for a in ARTIFACTS}) == 28
    assert len({a["name"] for a in ARTIFACTS}) == 28
    return {
        "record_type": "n2d1b-stage2-run-artifacts-manifest-v1",
        "workflow_run_id": WORKFLOW_RUN_ID,
        "head_sha": HEAD_SHA,
        "head_branch": HEAD_BRANCH,
        "source": (
            "GitHub Actions REST API list_workflow_run_artifacts response for workflow "
            f"run {WORKFLOW_RUN_ID}, independently transcribed artifact-by-artifact from "
            "that real response (saved verbatim to this session's own tool-result "
            "transcript before being condensed here). Not derived from, or shared code "
            "with, build_stage2_full_matrix_acceptance.py's own separate transcription "
            "of the same underlying API response."
        ),
        "total_count": len(ARTIFACTS),
        "artifacts": sorted(ARTIFACTS, key=lambda a: a["artifact_id"]),
    }


def main() -> None:
    _write(JOBS_MANIFEST_PATH, build_jobs_manifest())
    _write(ARTIFACTS_MANIFEST_PATH, build_artifacts_manifest())


if __name__ == "__main__":
    main()
