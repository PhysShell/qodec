"""Mutation tests for verify_n2d3_content_family_report.py, covering the
22 fail-closed scenarios required for this evidence-only derived report."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import build_n2d3_content_family_report as builder  # noqa: E402
import build_n2d3_content_taxonomy as taxonomy_builder  # noqa: E402
import verify_n2d3_content_family_report as verifier  # noqa: E402
import verify_n2d3_content_taxonomy as taxonomy_verifier  # noqa: E402

BASE_DIR = Path(__file__).resolve().parents[1]
RECORD_PATH = BASE_DIR / "n2d3-token-results-by-content-family-v1.json"
TAXONOMY_PATH = BASE_DIR / "n2d3-content-taxonomy-v1.json"


def _write(tmp_path: Path, name: str, record: dict) -> Path:
    out = tmp_path / name
    out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return out


class TestBaselineActuallyPasses(unittest.TestCase):
    def test_real_committed_report_verifies(self):
        ok, message = verifier.verify()
        self.assertTrue(ok, message)


class TestReportMutationsAreCaught(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_record = json.loads(RECORD_PATH.read_text())

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def _verify_mutated(self, mutator) -> tuple[bool, str]:
        mutated = copy.deepcopy(self.original_record)
        mutator(mutated)
        mutated["record_sha256"] = builder.compute_record_sha256(mutated)
        record_path = _write(self.tmp_path, "report.json", mutated)
        return verifier.verify(record_path=record_path)

    # --- missing case classification (report-level: dropped from a group, not replaced) ---
    def test_missing_case_classification_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["views"]["content_family"]["pytest-output"]["case_ids"].remove("repo-requests")
        )
        self.assertFalse(ok)
        self.assertIn("18-case set", message)

    # --- duplicate case classification (same case in two groups of one axis) ---
    def test_duplicate_case_classification_fails(self):
        def mutate(r):
            r["views"]["content_family"]["cli-tool-output"]["case_ids"].append("repo-requests")

        ok, message = self._verify_mutated(mutate)
        self.assertFalse(ok)
        self.assertIn("more than one group", message)

    # --- unauthorized content_family (renamed group id) ---
    def test_unauthorized_content_family_fails(self):
        def mutate(r):
            r["views"]["content_family"]["made-up-family"] = r["views"]["content_family"].pop("cli-tool-output")
            r["views"]["content_family"]["made-up-family"]["group_id"] = "made-up-family"

        ok, message = self._verify_mutated(mutate)
        self.assertFalse(ok)
        self.assertIn("not an authorized", message)

    # --- wrong canonical input SHA (caught at the taxonomy dependency layer) ---
    def test_wrong_canonical_input_sha_caught_at_taxonomy_layer(self):
        taxonomy = json.loads(TAXONOMY_PATH.read_text())
        mutated_taxonomy = copy.deepcopy(taxonomy)
        mutated_taxonomy["cases"]["repo-requests"]["classification_evidence"]["canonical_benchmark_input_sha256"] = "1" * 64
        mutated_taxonomy["record_sha256"] = taxonomy_builder.compute_record_sha256(mutated_taxonomy)
        taxonomy_path = _write(self.tmp_path, "taxonomy.json", mutated_taxonomy)
        ok, message = taxonomy_verifier.verify(record_path=taxonomy_path)
        self.assertFalse(ok)
        # this is exactly the dependency verify_n2d3_content_family_report.verify()
        # calls first and refuses to proceed past if it fails
        self.assertIn("real committed", message)

    # --- wrong canonical source record hash (report's own taxonomy_link tampered) ---
    def test_wrong_canonical_source_record_hash_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["taxonomy_link"].__setitem__("record_sha256", "sha256:" + "2" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("taxonomy_link", message)

    def test_wrong_canonical_benchmark_link_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["canonical_benchmark_link"].__setitem__("record_sha256", "sha256:" + "3" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("canonical_benchmark_link", message)

    # --- classification based only on repository name (caught at the taxonomy layer:
    # reassigning repo-hyperfine to producer_family='cargo' as if "it's invoked via
    # cargo" would ignore that its actual measured payload is a one-line CLI version
    # string, not cargo-test-shaped output -- the taxonomy builder's own cross-check
    # against the real Stage 2 canonicalization_policy_identity evidence rejects this) ---
    def test_classification_by_repo_name_only_caught_at_taxonomy_layer(self):
        mutated_labels = dict(taxonomy_builder.CASE_LABELS)
        mutated_labels["repo-hyperfine"] = ("cargo-test-output", "repository-command-output", "cargo")
        original_labels = taxonomy_builder.CASE_LABELS
        taxonomy_builder.CASE_LABELS = mutated_labels
        try:
            with self.assertRaises(RuntimeError):
                taxonomy_builder.build_record()
        finally:
            taxonomy_builder.CASE_LABELS = original_labels

    # --- altered raw token total ---
    def test_altered_raw_token_total_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["views"]["content_family"]["ci-build-log"].__setitem__("raw_total_tokens", 999999)
        )
        self.assertFalse(ok)

    # --- altered QODEC group total ---
    def test_altered_qodec_group_total_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["views"]["content_family"]["ci-build-log"]["qodec"].__setitem__("total_tokens", 1)
        )
        self.assertFalse(ok)

    # --- altered RTK group total ---
    def test_altered_rtk_group_total_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["views"]["content_family"]["cargo-test-output"]["rtk"].__setitem__("total_tokens", 1)
        )
        self.assertFalse(ok)

    # --- altered hybrid group total ---
    def test_altered_hybrid_group_total_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["views"]["content_family"]["cargo-test-output"]["rtk_plus_qodec"].__setitem__("total_tokens", 1)
        )
        self.assertFalse(ok)

    # --- altered weighted savings ---
    def test_altered_weighted_savings_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["views"]["content_family"]["static-log-dataset"]["qodec"].__setitem__("weighted_savings_pct", 0.0)
        )
        self.assertFalse(ok)

    # --- altered macro savings ---
    def test_altered_macro_savings_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["views"]["content_family"]["ci-build-log"]["qodec"].__setitem__("macro_savings_pct", 0.0)
        )
        self.assertFalse(ok)

    # --- altered median ---
    def test_altered_median_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["views"]["content_family"]["ci-build-log"]["qodec"].__setitem__("median_savings_pct", 0.0)
        )
        self.assertFalse(ok)

    # --- altered raw token share ---
    def test_altered_raw_token_share_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["views"]["content_family"]["static-log-dataset"].__setitem__(
                "raw_token_share_of_measured_corpus_pct", 1.0
            )
        )
        self.assertFalse(ok)

    # --- altered dominant-case identity ---
    def test_altered_dominant_case_identity_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["views"]["content_family"]["ci-build-log"]["dominant_case"].__setitem__("case_id", "ci-log-jansson")
        )
        self.assertFalse(ok)

    # --- altered dominant-case percentage ---
    def test_altered_dominant_case_percentage_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["views"]["content_family"]["ci-build-log"]["dominant_case"].__setitem__(
                "share_of_group_raw_tokens_pct", 1.0
            )
        )
        self.assertFalse(ok)

    # --- refusal incorrectly included in token totals ---
    def test_refusal_incorrectly_included_in_totals_fails(self):
        def mutate(r):
            g = r["views"]["content_family"]["binary-archive-container"]
            g["raw_total_tokens"] = 1000
            g["qodec"]["total_tokens"] = 500
            g["qodec"]["weighted_savings_pct"] = 50.0

        ok, message = self._verify_mutated(mutate)
        self.assertFalse(ok)

    # --- zero-token case silently removed ---
    def test_zero_token_case_silently_removed_fails(self):
        def mutate(r):
            g = r["views"]["content_family"]["cli-tool-output"]
            g["case_ids"].remove("repo-pyflakes")
            g["total_case_count"] -= 1
            g["measured_case_count"] -= 1

        ok, message = self._verify_mutated(mutate)
        self.assertFalse(ok)
        self.assertIn("18-case set", message)

    # --- bootstrap CI on n=2 group ---
    def test_bootstrap_ci_on_n2_group_fails(self):
        def mutate(r):
            g = r["views"]["content_family"]["cargo-test-output"]
            self.assertEqual(g["measured_case_count"], 2)
            g["qodec"]["bootstrap_ci95"] = {
                "seed": 20260716, "resamples": 10000, "point_estimate": 10.0,
                "ci_low_2_5pct": 5.0, "ci_high_97_5pct": 15.0,
            }

        ok, message = self._verify_mutated(mutate)
        self.assertFalse(ok)
        self.assertIn("bootstrap CI present", message)

    # --- wrong bootstrap seed ---
    def test_wrong_bootstrap_seed_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["bootstrap_policy"].__setitem__("seed", 20260717)
        )
        self.assertFalse(ok)
        self.assertIn("bootstrap_policy.seed", message)

    # --- altered sensitivity result ---
    def test_altered_sensitivity_result_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["dominance_sensitivity_analysis"]["measured_subset_excluding_dataset_rtn_n15"]["qodec"].__setitem__(
                "weighted_savings_pct", 0.0
            )
        )
        self.assertFalse(ok)

    def test_altered_dominance_share_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["dominance_sensitivity_analysis"].__setitem__(
                "dataset_rtn_traffic_ids_share_of_total_raw_tokens_pct", 1.0
            )
        )
        self.assertFalse(ok)

    # --- altered equal-family result ---
    def test_altered_equal_family_result_fails(self):
        ok, message = self._verify_mutated(
            lambda r: r["equal_family_exploratory_summary"].__setitem__(
                "qodec_mean_family_weighted_savings_pct", 0.0
            )
        )
        self.assertFalse(ok)

    # --- malformed self-hash ---
    def test_malformed_self_hash_fails(self):
        mutated = copy.deepcopy(self.original_record)
        mutated["record_sha256"] = "not-a-real-hash"
        record_path = _write(self.tmp_path, "report.json", mutated)
        ok, message = verifier.verify(record_path=record_path)
        self.assertFalse(ok)
        self.assertIn("self-hash mismatch", message)

    def test_tampered_but_rehashed_self_hash_still_fails_rebuild(self):
        # Even a mutation that recomputes a valid self-hash over the tampered
        # content must still fail, because it will never match the ground-
        # truth rebuild from the real committed taxonomy + benchmark.
        ok, message = self._verify_mutated(
            lambda r: r.__setitem__("corpus_measured_raw_total_tokens_n16", 1)
        )
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
