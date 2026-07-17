"""Tests for build_n2d3_primary_benchmark.py's pure aggregation logic."""
import copy
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import build_n2d3_primary_benchmark as bench  # noqa: E402


def _measured_row(case_id, leg, raw, qodec, rtk, hybrid):
    return {
        "record_type": "n2d3-case-leg-measurement-v1",
        "case_id": case_id,
        "leg": leg,
        "input_sha256": f"sha-{case_id}",
        "input_bytes": 1000,
        "measurement_status": "MEASURED",
        "utf8_valid": True,
        "raw_tokens": raw,
        "qodec_tokens": qodec,
        "rtk_tokens": rtk,
        "rtk_plus_qodec_tokens": hybrid,
        "qodec_encode_stdout_sha256": f"enc-{case_id}",
        "qodec_encoded": True,
        "raw_roundtrip_ok": True,
        "rtk_exit_code": 0,
        "rtk_stdout_sha256": f"rtk-{case_id}",
        "hybrid_encode_stdout_sha256": f"hyb-{case_id}",
        "hybrid_encoded": True,
        "hybrid_roundtrip_ok": True,
        "excluded_from_token_aggregates": False,
        "excluded_from_corpus_count": False,
    }


def _refusal_row(case_id, leg):
    return {
        "record_type": "n2d3-case-leg-measurement-v1",
        "case_id": case_id,
        "leg": leg,
        "input_sha256": f"sha-{case_id}",
        "input_bytes": 2000,
        "measurement_status": "UNMEASURABLE_NON_UTF8",
        "utf8_valid": False,
        "raw_tokens": None,
        "qodec_tokens": None,
        "rtk_tokens": None,
        "rtk_plus_qodec_tokens": None,
        "qodec_exit_code": 1,
        "qodec_stderr_sha256": f"stderr-{case_id}",
        "qodec_failure_classification": "INVALID_UTF8_INPUT",
        "excluded_from_token_aggregates": True,
        "excluded_from_corpus_count": False,
    }


def _full_18_case_fixture():
    measured_ids = [f"case-{i}" for i in range(16)]
    pairs = {}
    for i, cid in enumerate(measured_ids):
        raw, qodec, rtk, hybrid = 1000 + i, 800 + i, 1000 + i, 750 + i
        pairs[cid] = (
            _measured_row(cid, "a", raw, qodec, rtk, hybrid),
            _measured_row(cid, "b", raw, qodec, rtk, hybrid),
        )
    for cid in bench.AUTHORIZED_NON_UTF8_CASE_IDS:
        pairs[cid] = (_refusal_row(cid, "a"), _refusal_row(cid, "b"))
    return pairs


class TestCombineCaseLegs(unittest.TestCase):
    def test_agreeing_measured_legs_combine(self):
        row = bench.combine_case_legs(
            _measured_row("c1", "a", 100, 80, 100, 75),
            _measured_row("c1", "b", 100, 80, 100, 75),
        )
        self.assertTrue(row["leg_agreement"])
        self.assertEqual(row["measurement_status"], "MEASURED")

    def test_disagreeing_measured_legs_flagged(self):
        row = bench.combine_case_legs(
            _measured_row("c1", "a", 100, 80, 100, 75),
            _measured_row("c1", "b", 100, 81, 100, 75),
        )
        self.assertFalse(row["leg_agreement"])
        self.assertIn("qodec_tokens", row["disagreements"])

    def test_agreeing_refusal_legs_combine(self):
        row = bench.combine_case_legs(
            _refusal_row("dataset-loghub-v8", "a"),
            _refusal_row("dataset-loghub-v8", "b"),
        )
        self.assertTrue(row["leg_agreement"])
        self.assertEqual(row["measurement_status"], "UNMEASURABLE_NON_UTF8")
        self.assertTrue(row["excluded_from_token_aggregates"])

    def test_refusal_on_unauthorized_case_id_rejected(self):
        with self.assertRaises(RuntimeError):
            bench.combine_case_legs(_refusal_row("repo-requests", "a"), _refusal_row("repo-requests", "b"))

    def test_status_mismatch_between_legs_rejected(self):
        leg_b = _measured_row("c1", "b", 100, 80, 100, 75)
        with self.assertRaises(RuntimeError):
            bench.combine_case_legs(_refusal_row("c1", "a"), leg_b)

    def test_input_sha256_mismatch_rejected(self):
        leg_b = _measured_row("c1", "b", 100, 80, 100, 75)
        leg_b["input_sha256"] = "different"
        with self.assertRaises(RuntimeError):
            bench.combine_case_legs(_measured_row("c1", "a", 100, 80, 100, 75), leg_b)


class TestBuildBenchmark(unittest.TestCase):
    def test_full_18_case_corpus_builds(self):
        benchmark = bench.build_benchmark(_full_18_case_fixture())
        c = benchmark["corpus"]
        self.assertEqual(c["total_corpus_cases"], 18)
        self.assertEqual(c["token_measurable_cases"], 16)
        self.assertEqual(c["non_utf8_measurement_refusals"], 2)
        self.assertFalse(benchmark["model_based_quality_evaluation_performed"])
        self.assertFalse(benchmark["leaderboard_constructed"])

    def test_rejects_wrong_case_count(self):
        pairs = _full_18_case_fixture()
        del pairs["case-0"]
        with self.assertRaises(RuntimeError):
            bench.build_benchmark(pairs)

    def test_rejects_leg_disagreement(self):
        pairs = _full_18_case_fixture()
        leg_a, leg_b = pairs["case-0"]
        leg_b = copy.deepcopy(leg_b)
        leg_b["qodec_tokens"] += 1
        pairs["case-0"] = (leg_a, leg_b)
        with self.assertRaises(RuntimeError):
            bench.build_benchmark(pairs)

    def test_rejects_wrong_refusal_set(self):
        pairs = _full_18_case_fixture()
        # one of the two required non-UTF-8 refusal cases is measured instead
        pairs["dataset-loghub-v8"] = (
            _measured_row("dataset-loghub-v8", "a", 100, 80, 100, 75),
            _measured_row("dataset-loghub-v8", "b", 100, 80, 100, 75),
        )
        with self.assertRaises(RuntimeError):
            bench.build_benchmark(pairs)

    def test_token_aggregates_labeled_n16(self):
        benchmark = bench.build_benchmark(_full_18_case_fixture())
        agg = benchmark["token_aggregates_measured_text_domain_subset_n16"]
        self.assertEqual(agg["n"], 16)
        self.assertIn("n=16", agg["note"])

    def test_weighted_savings_computed(self):
        benchmark = bench.build_benchmark(_full_18_case_fixture())
        qodec_stats = benchmark["token_aggregates_measured_text_domain_subset_n16"]["qodec"]
        self.assertGreater(qodec_stats["weighted_savings_pct"], 0)
        self.assertGreater(qodec_stats["macro_savings_pct"], 0)
        self.assertIn("ci_low_2_5pct", qodec_stats["bootstrap_macro_savings_pct_ci95"])

    def test_bootstrap_is_deterministic_across_runs(self):
        b1 = bench.build_benchmark(_full_18_case_fixture())
        b2 = bench.build_benchmark(_full_18_case_fixture())
        ci1 = b1["token_aggregates_measured_text_domain_subset_n16"]["qodec"]["bootstrap_macro_savings_pct_ci95"]
        ci2 = b2["token_aggregates_measured_text_domain_subset_n16"]["qodec"]["bootstrap_macro_savings_pct_ci95"]
        self.assertEqual(ci1, ci2)

    def test_record_self_hash_verifies(self):
        benchmark = bench.build_benchmark(_full_18_case_fixture())
        recomputed = bench.compute_record_sha256(benchmark)
        self.assertEqual(recomputed, benchmark["record_sha256"])

    def test_render_table_includes_every_case(self):
        benchmark = bench.build_benchmark(_full_18_case_fixture())
        table = bench.render_table(benchmark)
        for case_id in benchmark["cases"]:
            self.assertIn(case_id, table)
        self.assertIn("total corpus cases = 18", table)
        self.assertIn("token-measurable cases = 16", table)
        self.assertIn("non-UTF-8 measurement refusals = 2", table)

    def test_passthrough_and_roundtrip_counts_reported(self):
        benchmark = bench.build_benchmark(_full_18_case_fixture())
        c = benchmark["corpus"]
        self.assertEqual(c["exact_roundtrip_count_where_measurable"], 16)
        self.assertEqual(c["passthrough_count_where_observable"], 0)
        self.assertEqual(c["runtime_failure_count"], 0)


if __name__ == "__main__":
    unittest.main()
