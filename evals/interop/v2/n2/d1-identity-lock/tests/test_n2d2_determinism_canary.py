"""Tests for n2d2_determinism_canary.py's pure combine_legs() logic."""
import copy
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import n2d2_determinism_canary as canary  # noqa: E402

DETERMINISTIC_LEG_A = {
    "record_type": "n2d2-canary-leg-report-v1",
    "leg": "a",
    "case_id": "n2a-miner-canary",
    "repetitions": 20,
    "deterministic": True,
    "raw_tokens": 100,
    "qodec_tokens": 80,
    "rtk_tokens": 100,
    "hybrid_tokens": 80,
    "canonical_qodec_stdout_sha256": "aaaa",
    "canonical_rtk_stdout_sha256": "bbbb",
    "canonical_hybrid_stdout_sha256": "cccc",
    "all_roundtrip_ok": True,
    "all_rtk_exit_zero": True,
}

DETERMINISTIC_LEG_B = {**DETERMINISTIC_LEG_A, "leg": "b"}


class TestCombineLegs(unittest.TestCase):
    def test_agreeing_legs_are_deterministic(self):
        result = canary.combine_legs(DETERMINISTIC_LEG_A, DETERMINISTIC_LEG_B)
        self.assertTrue(result["all_cases_deterministic"])
        self.assertTrue(result["within_leg_a_deterministic"])
        self.assertTrue(result["within_leg_b_deterministic"])
        self.assertTrue(result["between_leg_agreement"])
        self.assertEqual(result["raw_tokens"], 100)

    def test_leg_a_internally_nondeterministic_fails_combined(self):
        leg_a = copy.deepcopy(DETERMINISTIC_LEG_A)
        leg_a["deterministic"] = False
        result = canary.combine_legs(leg_a, DETERMINISTIC_LEG_B)
        self.assertFalse(result["all_cases_deterministic"])
        self.assertFalse(result["within_leg_a_deterministic"])

    def test_legs_disagree_on_token_count_fails(self):
        leg_b = copy.deepcopy(DETERMINISTIC_LEG_B)
        leg_b["qodec_tokens"] = 81
        result = canary.combine_legs(DETERMINISTIC_LEG_A, leg_b)
        self.assertFalse(result["all_cases_deterministic"])
        self.assertFalse(result["between_leg_agreement"])

    def test_legs_disagree_on_canonical_hash_fails(self):
        leg_b = copy.deepcopy(DETERMINISTIC_LEG_B)
        leg_b["canonical_qodec_stdout_sha256"] = "zzzz"
        result = canary.combine_legs(DETERMINISTIC_LEG_A, leg_b)
        self.assertFalse(result["all_cases_deterministic"])

    def test_wrong_leg_labels_rejected(self):
        with self.assertRaises(ValueError):
            canary.combine_legs(DETERMINISTIC_LEG_B, DETERMINISTIC_LEG_A)

    def test_wrong_case_id_rejected(self):
        leg_a = copy.deepcopy(DETERMINISTIC_LEG_A)
        leg_a["case_id"] = "repo-requests"
        with self.assertRaises(ValueError):
            canary.combine_legs(leg_a, DETERMINISTIC_LEG_B)

    def test_record_self_hash_verifies(self):
        result = canary.combine_legs(DETERMINISTIC_LEG_A, DETERMINISTIC_LEG_B)
        result["record_sha256"] = canary.compute_record_sha256(result)
        recomputed = canary.compute_record_sha256(result)
        self.assertEqual(recomputed, result["record_sha256"])

    def test_scoped_to_single_canary_case_id(self):
        self.assertEqual(canary.CANARY_CASE_ID, "n2a-miner-canary")

    def test_required_canary_input_sha256_pinned(self):
        self.assertEqual(
            canary.REQUIRED_CANARY_INPUT_SHA256,
            "09b023837a4a969f9bf12401595429aeefe65263a2705e8e3a3e62ee5aa437db",
        )


if __name__ == "__main__":
    unittest.main()
