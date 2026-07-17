"""Mutation tests for verify_n2d_current_identity_closure.py."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import verify_n2d_current_identity_closure as verifier  # noqa: E402

BASE_DIR = Path(__file__).resolve().parents[1]
RECORD_PATH = BASE_DIR / "n2d-current-identity-closure-v1.json"


def _write_record(tmp_path: Path, record: dict) -> Path:
    out = tmp_path / "record.json"
    out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return out


class TestBaselineActuallyPasses(unittest.TestCase):
    def test_real_committed_record_verifies(self):
        ok, message = verifier.verify()
        self.assertTrue(ok, message)


class TestMutationsAreCaught(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_record = json.loads(RECORD_PATH.read_text())

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def _verify_mutated_record(self, mutator) -> tuple[bool, str]:
        mutated = copy.deepcopy(self.original_record)
        mutator(mutated)
        mutated["record_sha256"] = verifier.compute_record_sha256(mutated)
        record_path = _write_record(self.tmp_path, mutated)
        return verifier.verify(record_path=record_path)

    def test_tampered_record_sha256_fails(self):
        mutated = copy.deepcopy(self.original_record)
        mutated["record_sha256"] = "sha256:" + "0" * 64
        record_path = _write_record(self.tmp_path, mutated)
        ok, message = verifier.verify(record_path=record_path)
        self.assertFalse(ok)
        self.assertIn("self-hash mismatch", message)

    def test_tampered_n2d_base_main_sha_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["repository"].__setitem__("n2d_base_main_sha", "0" * 40)
        )
        self.assertFalse(ok)
        self.assertIn("n2d_base_main_sha", message)

    def test_tampered_root_cargo_lock_sha256_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["repository"].__setitem__("root_cargo_lock_sha256", "1" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("root_cargo_lock_sha256", message)

    def test_repository_root_is_qodec_crate_root_false_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["repository"].__setitem__("repository_root_is_qodec_crate_root", False)
        )
        self.assertFalse(ok)
        self.assertIn("repository_root_is_qodec_crate_root", message)

    def test_missing_case_fails(self):
        ok, message = self._verify_mutated_record(lambda r: r["cases"].pop("repo-requests"))
        self.assertFalse(ok)
        self.assertIn("cases", message)

    def test_extra_case_fails(self):
        def mutate(r):
            r["cases"]["repo-spotless"] = dict(r["cases"]["repo-moshi"])
            r["accepted_18_case_set"] = r["accepted_18_case_set"] + ["repo-spotless"]

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)

    def test_repo_spotless_smuggled_into_accepted_set_fails(self):
        def mutate(r):
            r["accepted_18_case_set"][0] = "repo-spotless"

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)

    def test_wrong_but_well_formed_canonical_sha256_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["canonical_benchmark_input_sha256_by_case_id"].__setitem__("repo-requests", "2" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("repo-requests", message)

    def test_case_sha256_diverges_from_top_level_map_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["cases"]["repo-pyflakes"].__setitem__("canonical_benchmark_input_sha256", "3" * 64)
        )
        self.assertFalse(ok)

    def test_stage2_link_sha256_mismatch_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["stage2_link"].__setitem__("record_sha256", "sha256:" + "4" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("stage2_link", message)

    def test_n2a_canary_sha256_wrong_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["cases"]["n2a-miner-canary"].__setitem__("canonical_benchmark_input_sha256", "5" * 64)
        )
        self.assertFalse(ok)

    def test_n2c_static_case_durable_asset_mismatch_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["cases"]["ci-log-jansson"].__setitem__("durable_release_asset_sha256", "6" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("ci-log-jansson", message)

    def test_repo_spotless_status_permanently_rejected_false_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["repo_spotless_status"].__setitem__("permanently_rejected", False)
        )
        self.assertFalse(ok)
        self.assertIn("permanently_rejected", message)

    def test_repo_spotless_status_sha256_mismatch_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["repo_spotless_status"].__setitem__("record_sha256", "sha256:" + "7" * 64)
        )
        self.assertFalse(ok)

    def test_qodec_binary_sha256_wrong_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["qodec_nix_identity"].__setitem__("qodec_binary_sha256", "8" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("qodec_binary_sha256", message)

    def test_rtk_binary_sha256_wrong_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["rtk_nix_identity"].__setitem__("rtk_binary_sha256", "9" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("rtk_binary_sha256", message)

    def test_live_capture_workflow_run_id_wrong_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["qodec_nix_identity"].__setitem__("live_capture_source_workflow_run_id", 1)
        )
        self.assertFalse(ok)

    def test_meter_rs_sha256_wrong_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["tokenizer_identity"].__setitem__("meter_rs_source_sha256", "a" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("meter_rs_source_sha256", message)

    def test_n2d2_gate_status_invalid_value_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("n2d2_gate_status", "maybe")
        )
        self.assertFalse(ok)
        self.assertIn("n2d2_gate_status", message)

    def test_n2d3_gate_status_invalid_value_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("n2d3_gate_status", "maybe")
        )
        self.assertFalse(ok)
        self.assertIn("n2d3_gate_status", message)

    def test_token_counts_computed_true_without_n2d3_passed_fails(self):
        def mutate(r):
            r["token_counts_computed"] = True
            r["n2d3_gate_status"] = "not_yet_run"

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("token_counts_computed", message)

    def test_token_counts_computed_non_bool_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("token_counts_computed", "false")
        )
        self.assertFalse(ok)

    def test_rtk_applicability_map_link_sha256_mismatch_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["rtk_applicability_map"].__setitem__("record_sha256", "sha256:" + "b" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("rtk_applicability_map", message)

    def test_rtk_applicability_map_not_verified_at_build_time_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["rtk_applicability_map"].__setitem__("verified_by_its_own_verifier_at_build_time", False)
        )
        self.assertFalse(ok)
        self.assertIn("verified_by_its_own_verifier_at_build_time", message)

    def test_supersedes_record_preserved_unmodified_false_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["supersedes"].__setitem__("record_preserved_unmodified", False)
        )
        self.assertFalse(ok)
        self.assertIn("record_preserved_unmodified", message)

    def test_n2d2_report_link_sha256_mismatch_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["n2d2_report_link"].__setitem__("record_sha256", "sha256:" + "c" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("n2d2_report_link", message)

    def test_n2d2_passed_but_report_not_deterministic_fails(self):
        def mutate(r):
            r["n2d2_gate_status"] = "passed"
            r["token_counts_computed"] = False
            r["n2d3_gate_status"] = "not_yet_run"
            r["n2d3_benchmark_link"] = None
            r["n2d2_report_link"]["record_sha256"] = "sha256:" + "d" * 64

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)

    def test_n2d3_benchmark_link_sha256_mismatch_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["n2d3_benchmark_link"].__setitem__("record_sha256", "sha256:" + "e" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("n2d3_benchmark_link", message)

    def test_n2d3_passed_with_wrong_corpus_breakdown_in_link_fails(self):
        def mutate(r):
            r["n2d3_benchmark_link"]["corpus"]["token_measurable_cases"] = 17
            r["n2d3_benchmark_link"]["corpus"]["non_utf8_measurement_refusals"] = 1

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("n2d3_benchmark_link.corpus", message)

    def test_n2d_run_evidence_run_id_wrong_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["n2d_run_evidence"].__setitem__("run_id", 1)
        )
        self.assertFalse(ok)
        self.assertIn("n2d_run_evidence.run_id", message)

    def test_n2d_run_evidence_trigger_sha_wrong_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["n2d_run_evidence"].__setitem__("trigger_sha", "0" * 40)
        )
        self.assertFalse(ok)
        self.assertIn("n2d_run_evidence.trigger_sha", message)

    def test_n2d_run_evidence_implementation_sha_wrong_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["n2d_run_evidence"].__setitem__("implementation_sha", "1" * 40)
        )
        self.assertFalse(ok)
        self.assertIn("n2d_run_evidence.implementation_sha", message)

    def test_n2d_run_evidence_jobs_manifest_link_sha256_mismatch_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["n2d_run_evidence"]["jobs_manifest"].__setitem__("record_sha256", "sha256:" + "2" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("jobs_manifest", message)

    def test_n2d_run_evidence_artifacts_manifest_link_sha256_mismatch_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["n2d_run_evidence"]["artifacts_manifest"].__setitem__("record_sha256", "sha256:" + "3" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("artifacts_manifest", message)

    def test_n2d_run_evidence_trigger_patch_proof_link_sha256_mismatch_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["n2d_run_evidence"]["trigger_patch_proof"].__setitem__("record_sha256", "sha256:" + "4" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("trigger_patch_proof", message)

    def test_n2d_run_evidence_leg_evidence_link_sha256_mismatch_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["n2d_run_evidence"]["leg_evidence"].__setitem__("record_sha256", "sha256:" + "5" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("leg_evidence", message)

    def test_n2d_run_evidence_weighted_supplement_link_sha256_mismatch_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["n2d_run_evidence"]["weighted_bootstrap_supplement"].__setitem__(
                "record_sha256", "sha256:" + "6" * 64
            )
        )
        self.assertFalse(ok)
        self.assertIn("weighted_bootstrap_supplement", message)

    def test_n2d_run_evidence_weighted_supplement_canonical_flipped_true_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["n2d_run_evidence"]["weighted_bootstrap_supplement"].__setitem__("canonical", True)
        )
        self.assertFalse(ok)
        self.assertIn("canonical", message)

    def test_n2d_run_evidence_bootstrap_seed_deviation_tampered_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["n2d_run_evidence"]["bootstrap_seed_deviation"].__setitem__(
                "originally_requested_seed", 1
            )
        )
        self.assertFalse(ok)
        self.assertIn("bootstrap_seed_deviation", message)

    def test_n2d_run_evidence_bootstrap_seed_deviation_not_accepted_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["n2d_run_evidence"]["bootstrap_seed_deviation"].__setitem__(
                "accepted_as_predeclared_deviation", False
            )
        )
        self.assertFalse(ok)
        self.assertIn("accepted_as_predeclared_deviation", message)

    def test_n2d_run_evidence_not_verified_at_build_time_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["n2d_run_evidence"].__setitem__("verified_by_its_own_verifiers_at_build_time", False)
        )
        self.assertFalse(ok)
        self.assertIn("verified_by_its_own_verifiers_at_build_time", message)


if __name__ == "__main__":
    unittest.main()
