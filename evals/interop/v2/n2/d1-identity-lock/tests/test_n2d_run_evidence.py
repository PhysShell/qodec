"""Mutation tests for verify_n2d_run_evidence.py and
verify_n2d3_weighted_bootstrap_supplement.py -- the evidence-only closure
covering CI run 29575975971 (jobs manifest, artifacts manifest, trigger
patch proof, N2-D3 leg-evidence record) plus the separate weighted-total
bootstrap reporting supplement.
"""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import build_n2d3_leg_evidence  # noqa: E402
import build_n2d3_primary_benchmark  # noqa: E402
import build_n2d3_weighted_bootstrap_supplement  # noqa: E402
import build_n2d_run_artifacts_manifest  # noqa: E402
import build_n2d_run_jobs_manifest  # noqa: E402
import build_n2d_trigger_patch_proof  # noqa: E402
import verify_n2d3_weighted_bootstrap_supplement as supplement_verifier  # noqa: E402
import verify_n2d_run_evidence as verifier  # noqa: E402

BASE_DIR = Path(__file__).resolve().parents[1]
JOBS_MANIFEST_PATH = BASE_DIR / "n2d-run-29575975971-jobs-manifest-v1.json"
ARTIFACTS_MANIFEST_PATH = BASE_DIR / "n2d-run-29575975971-artifacts-manifest-v1.json"
TRIGGER_PATCH_PROOF_PATH = BASE_DIR / "n2d-trigger-patch-proof-v1.json"
LEG_EVIDENCE_PATH = BASE_DIR / "n2d3-run-29575975971-leg-evidence-v1.json"
BENCHMARK_PATH = BASE_DIR / "n2d3-primary-token-benchmark-v1.json"
WEIGHTED_SUPPLEMENT_PATH = BASE_DIR / "n2d3-weighted-total-bootstrap-supplement-v1.json"


def _write(tmp_path: Path, name: str, record: dict) -> Path:
    out = tmp_path / name
    out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return out


class TestBaselineActuallyPasses(unittest.TestCase):
    def test_real_committed_evidence_verifies(self):
        ok, message = verifier.verify()
        self.assertTrue(ok, message)

    def test_real_committed_supplement_verifies(self):
        ok, message = supplement_verifier.verify()
        self.assertTrue(ok, message)


class TestRunEvidenceMutationsAreCaught(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jobs = json.loads(JOBS_MANIFEST_PATH.read_text())
        cls.artifacts = json.loads(ARTIFACTS_MANIFEST_PATH.read_text())
        cls.trigger_proof = json.loads(TRIGGER_PATCH_PROOF_PATH.read_text())
        cls.leg_evidence = json.loads(LEG_EVIDENCE_PATH.read_text())
        cls.benchmark = json.loads(BENCHMARK_PATH.read_text())

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def _verify_with(self, *, jobs=None, artifacts=None, trigger_proof=None, leg_evidence=None, benchmark=None,
                      rehash_jobs=True, rehash_artifacts=True, rehash_trigger=True, rehash_leg=True, rehash_bench=True):
        jobs = copy.deepcopy(self.jobs) if jobs is None else jobs
        artifacts = copy.deepcopy(self.artifacts) if artifacts is None else artifacts
        trigger_proof = copy.deepcopy(self.trigger_proof) if trigger_proof is None else trigger_proof
        leg_evidence = copy.deepcopy(self.leg_evidence) if leg_evidence is None else leg_evidence
        benchmark = copy.deepcopy(self.benchmark) if benchmark is None else benchmark

        if rehash_jobs:
            jobs["record_sha256"] = build_n2d_run_jobs_manifest.compute_record_sha256(jobs)
        if rehash_artifacts:
            artifacts["record_sha256"] = build_n2d_run_artifacts_manifest.compute_record_sha256(artifacts)
        if rehash_trigger:
            trigger_proof["record_sha256"] = build_n2d_trigger_patch_proof.compute_record_sha256(trigger_proof)
        if rehash_leg:
            leg_evidence["record_sha256"] = build_n2d3_leg_evidence.compute_record_sha256(leg_evidence)
        if rehash_bench:
            benchmark["record_sha256"] = build_n2d3_primary_benchmark.compute_record_sha256(benchmark)

        return verifier.verify(
            jobs_manifest_path=_write(self.tmp_path, "jobs.json", jobs),
            artifacts_manifest_path=_write(self.tmp_path, "artifacts.json", artifacts),
            trigger_patch_proof_path=_write(self.tmp_path, "trigger.json", trigger_proof),
            leg_evidence_path=_write(self.tmp_path, "leg.json", leg_evidence),
            benchmark_path=_write(self.tmp_path, "bench.json", benchmark),
        )

    # --- unique but wrong job ID -----------------------------------------
    def test_unique_but_wrong_job_id_fails(self):
        jobs = copy.deepcopy(self.jobs)
        jobs["jobs"][0]["id"] = 999999999999  # unique, but not the real id
        ok, message = self._verify_with(jobs=jobs)
        self.assertFalse(ok)
        self.assertIn("jobs manifest", message)

    # --- unique but wrong artifact ID -------------------------------------
    def test_unique_but_wrong_artifact_id_fails(self):
        artifacts = copy.deepcopy(self.artifacts)
        artifacts["artifacts"][0]["id"] = 999999999999  # unique, but not the real id
        ok, message = self._verify_with(artifacts=artifacts)
        self.assertFalse(ok)
        self.assertIn("artifacts manifest", message)

    # --- well-formed but wrong artifact digest ----------------------------
    def test_well_formed_but_wrong_artifact_digest_fails(self):
        artifacts = copy.deepcopy(self.artifacts)
        artifacts["artifacts"][0]["digest"] = "sha256:" + "ab" * 32  # well-formed, wrong value
        ok, message = self._verify_with(artifacts=artifacts)
        self.assertFalse(ok)
        self.assertIn("artifacts manifest", message)

    # --- wrong run ID ------------------------------------------------------
    def test_wrong_run_id_fails(self):
        # Caught by the ground-truth full-equality recompute (stronger than
        # the standalone run_id pin check, since it never even needs to
        # reach the pin check to detect the tamper).
        jobs = copy.deepcopy(self.jobs)
        jobs["run_id"] = 1
        ok, message = self._verify_with(jobs=jobs)
        self.assertFalse(ok)
        self.assertIn("jobs manifest", message)

    # --- wrong trigger SHA ---------------------------------------------------
    def test_wrong_trigger_sha_fails(self):
        trigger_proof = copy.deepcopy(self.trigger_proof)
        trigger_proof["trigger_sha"] = "0" * 40
        ok, message = self._verify_with(trigger_proof=trigger_proof)
        self.assertFalse(ok)
        self.assertIn("trigger patch proof", message)

    def test_wrong_head_sha_in_jobs_manifest_fails(self):
        jobs = copy.deepcopy(self.jobs)
        jobs["head_sha"] = "0" * 40
        ok, message = self._verify_with(jobs=jobs)
        self.assertFalse(ok)
        self.assertIn("jobs manifest", message)

    # --- altered leg token count -------------------------------------------
    def test_altered_leg_token_count_fails(self):
        leg_evidence = copy.deepcopy(self.leg_evidence)
        case = leg_evidence["cases"]["repo-pyflakes"]
        case["a"]["qodec_tokens"] += 1
        case["b"]["qodec_tokens"] += 1  # keep legs agreeing so it isn't caught trivially by leg disagreement
        ok, message = self._verify_with(leg_evidence=leg_evidence)
        self.assertFalse(ok)
        self.assertIn("recomputed", message)

    # --- altered refusal classification -------------------------------------
    def test_altered_refusal_classification_fails(self):
        leg_evidence = copy.deepcopy(self.leg_evidence)
        case = leg_evidence["cases"]["dataset-loghub-v8"]
        case["a"]["qodec_failure_classification"] = "SOME_OTHER_CLASSIFICATION"
        case["b"]["qodec_failure_classification"] = "SOME_OTHER_CLASSIFICATION"
        ok, message = self._verify_with(leg_evidence=leg_evidence)
        self.assertFalse(ok)
        self.assertIn("refusal classification", message)

    # --- altered aggregate total ---------------------------------------------
    def test_altered_aggregate_total_fails(self):
        benchmark = copy.deepcopy(self.benchmark)
        agg = benchmark["token_aggregates_measured_text_domain_subset_n16"]["qodec"]
        agg["total_tokens"] += 1000
        ok, message = self._verify_with(benchmark=benchmark)
        self.assertFalse(ok)
        self.assertIn("recomputed benchmark", message)

    # --- altered bootstrap result ---------------------------------------------
    def test_altered_bootstrap_result_fails(self):
        benchmark = copy.deepcopy(self.benchmark)
        ci = benchmark["token_aggregates_measured_text_domain_subset_n16"]["qodec"]["bootstrap_macro_savings_pct_ci95"]
        ci["ci_low_2_5pct"] = ci["ci_low_2_5pct"] + 5.0
        ok, message = self._verify_with(benchmark=benchmark)
        self.assertFalse(ok)
        self.assertIn("recomputed benchmark", message)

    def test_bootstrap_seed_changed_post_run_fails(self):
        # Caught by the recompute-from-leg-evidence equality check first
        # (the real leg-evidence data can only ever reproduce the canonical
        # seed-20260716 bootstrap, so any different committed seed value
        # immediately mismatches) -- a stronger catch than reaching the
        # standalone seed-pin check.
        benchmark = copy.deepcopy(self.benchmark)
        for arm_key in ("qodec", "rtk", "rtk_plus_qodec_hybrid"):
            benchmark["token_aggregates_measured_text_domain_subset_n16"][arm_key][
                "bootstrap_macro_savings_pct_ci95"
            ]["seed"] = 20260717
        ok, message = self._verify_with(benchmark=benchmark)
        self.assertFalse(ok)
        self.assertIn("recomputed benchmark", message)

    def test_tampered_jobs_manifest_self_hash_fails(self):
        jobs = copy.deepcopy(self.jobs)
        jobs["record_sha256"] = "sha256:" + "0" * 64
        ok, message = self._verify_with(jobs=jobs, rehash_jobs=False)
        self.assertFalse(ok)
        self.assertIn("self-hash mismatch", message)

    def test_duplicate_artifact_id_fails(self):
        artifacts = copy.deepcopy(self.artifacts)
        artifacts["artifacts"][1]["id"] = artifacts["artifacts"][0]["id"]
        ok, message = self._verify_with(artifacts=artifacts)
        self.assertFalse(ok)

    def test_job_manifest_and_artifact_manifest_pair_mismatch_fails(self):
        # Rename one n2d3-measure job's case_id so the (case, leg) pair sets
        # between the jobs manifest and the artifacts manifest disagree,
        # even though each manifest is independently well-formed.
        jobs = copy.deepcopy(self.jobs)
        for j in jobs["jobs"]:
            if j["name"] == "n2d3-measure (repo-pyflakes, a, 30, 1200)":
                j["name"] = "n2d3-measure (repo-pyflakes-renamed, a, 30, 1200)"
                break
        ok, message = self._verify_with(jobs=jobs)
        self.assertFalse(ok)

    def test_trigger_patch_proof_with_extra_diff_line_fails(self):
        trigger_proof = copy.deepcopy(self.trigger_proof)
        trigger_proof["diff_text"] = trigger_proof["diff_text"].replace(
            "      - n2d/ci-trigger-full-run\n",
            "      - n2d/ci-trigger-full-run\n+  extra_key: injected\n",
        )
        ok, message = self._verify_with(trigger_proof=trigger_proof)
        self.assertFalse(ok)


class TestWeightedBootstrapSupplementMutationsAreCaught(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.supplement = json.loads(WEIGHTED_SUPPLEMENT_PATH.read_text())
        cls.benchmark = json.loads(BENCHMARK_PATH.read_text())

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_tampered_supplement_self_hash_fails(self):
        supplement = copy.deepcopy(self.supplement)
        supplement["record_sha256"] = "sha256:" + "0" * 64
        ok, message = supplement_verifier.verify(supplement_path=_write(self.tmp_path, "s.json", supplement))
        self.assertFalse(ok)
        self.assertIn("self-hash mismatch", message)

    def test_canonical_flag_flipped_true_fails(self):
        supplement = copy.deepcopy(self.supplement)
        supplement["canonical"] = True
        supplement["record_sha256"] = build_n2d3_weighted_bootstrap_supplement.compute_record_sha256(supplement)
        ok, message = supplement_verifier.verify(supplement_path=_write(self.tmp_path, "s.json", supplement))
        self.assertFalse(ok)
        self.assertIn("canonical", message)

    def test_altered_weighted_bootstrap_ci_fails(self):
        supplement = copy.deepcopy(self.supplement)
        supplement["weighted_total_bootstrap_ci95"]["qodec"]["ci_high_97_5pct"] += 10.0
        supplement["record_sha256"] = build_n2d3_weighted_bootstrap_supplement.compute_record_sha256(supplement)
        ok, message = supplement_verifier.verify(supplement_path=_write(self.tmp_path, "s.json", supplement))
        self.assertFalse(ok)
        self.assertIn("recomputed", message)

    def test_source_benchmark_sha_mismatch_fails(self):
        supplement = copy.deepcopy(self.supplement)
        supplement["source_benchmark_record_sha256"] = "sha256:" + "1" * 64
        supplement["record_sha256"] = build_n2d3_weighted_bootstrap_supplement.compute_record_sha256(supplement)
        ok, message = supplement_verifier.verify(supplement_path=_write(self.tmp_path, "s.json", supplement))
        self.assertFalse(ok)
        self.assertIn("source_benchmark_record_sha256", message)


if __name__ == "__main__":
    unittest.main()
