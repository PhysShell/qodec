"""Tests for build_n2d3_token_benchmark.py's pure aggregation logic."""
import copy
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import build_n2d3_token_benchmark as benchmark_tool  # noqa: E402

FAKE_DETERMINISTIC_CANARY_REPORT = {
    "record_sha256": "sha256:" + "a" * 64,
    "repetitions_per_case": 20,
    "all_cases_deterministic": True,
    "cases": {
        "repo-requests": {
            "deterministic": True,
            "raw_tokens": 1000,
            "qodec_tokens": 800,
            "rtk_tokens": 1000,
            "hybrid_tokens": 800,
        },
        "n2a-miner-canary": {
            "deterministic": True,
            "raw_tokens": 500,
            "qodec_tokens": 500,
            "rtk_tokens": 500,
            "hybrid_tokens": 500,
        },
        "repo-pyflakes": {
            # a genuinely empty-domain-result case: zero raw tokens
            "deterministic": True,
            "raw_tokens": 0,
            "qodec_tokens": 0,
            "rtk_tokens": 0,
            "hybrid_tokens": 0,
        },
    },
}


class TestBuildBenchmarkGating(unittest.TestCase):
    def test_refuses_when_n2d2_gate_not_satisfied(self):
        report = copy.deepcopy(FAKE_DETERMINISTIC_CANARY_REPORT)
        report["all_cases_deterministic"] = False
        with self.assertRaises(RuntimeError):
            benchmark_tool.build_benchmark(report)

    def test_refuses_when_a_case_is_individually_nondeterministic(self):
        report = copy.deepcopy(FAKE_DETERMINISTIC_CANARY_REPORT)
        report["cases"]["repo-requests"]["deterministic"] = False
        with self.assertRaises(RuntimeError):
            benchmark_tool.build_benchmark(report)

    def test_succeeds_when_gate_satisfied(self):
        benchmark = benchmark_tool.build_benchmark(FAKE_DETERMINISTIC_CANARY_REPORT)
        self.assertEqual(benchmark["n2d2_gate_status"], "passed")
        self.assertFalse(benchmark["model_based_quality_evaluation_performed"])
        self.assertFalse(benchmark["leaderboard_constructed"])
        self.assertEqual(benchmark["case_count"], 3)

    def test_reduction_percent_computed_correctly(self):
        benchmark = benchmark_tool.build_benchmark(FAKE_DETERMINISTIC_CANARY_REPORT)
        row = benchmark["cases"]["repo-requests"]
        self.assertAlmostEqual(row["qodec_reduction_pct"], 20.0)

    def test_zero_raw_tokens_does_not_divide_by_zero(self):
        benchmark = benchmark_tool.build_benchmark(FAKE_DETERMINISTIC_CANARY_REPORT)
        row = benchmark["cases"]["repo-pyflakes"]
        self.assertIsNone(row["qodec_reduction_pct"])
        self.assertIsNone(row["rtk_reduction_pct"])
        self.assertIsNone(row["hybrid_reduction_pct"])

    def test_record_self_hash_verifies(self):
        benchmark = benchmark_tool.build_benchmark(FAKE_DETERMINISTIC_CANARY_REPORT)
        recomputed = benchmark_tool.compute_record_sha256(benchmark)
        self.assertEqual(recomputed, benchmark["record_sha256"])

    def test_render_table_includes_every_case(self):
        benchmark = benchmark_tool.build_benchmark(FAKE_DETERMINISTIC_CANARY_REPORT)
        table = benchmark_tool.render_table(benchmark)
        for case_id in FAKE_DETERMINISTIC_CANARY_REPORT["cases"]:
            self.assertIn(case_id, table)


if __name__ == "__main__":
    unittest.main()
