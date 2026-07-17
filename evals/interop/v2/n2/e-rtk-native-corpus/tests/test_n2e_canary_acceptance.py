"""Fail-closed tests for canary aggregation/acceptance (§19/§22).

Uses synthetic per-case records over the real frozen 12-case membership so the
§22 canary mutations are exercised without needing a full CI run.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
TOOLS = N2E_DIR / "tools"
sys.path.insert(0, str(TOOLS))
import n2e_common as c  # noqa: E402
import build_n2e_canary_acceptance as agg  # noqa: E402

MEMBERSHIP = json.loads((N2E_DIR / "n2e-canary-membership-v1.json").read_text())
CASE_IDS = [m["case_id"] for m in MEMBERSHIP["membership"]]


def synthetic_case(case_id, savings=50.0, raw_det=True, rtk_det=True, raw_tok=1000, rtk_tok=500):
    return c.finalize(c.envelope(
        record_type="n2e-canary-case", generated_by="test",
        case_id=case_id, command_family="x", command_subfamily="y", status="MEASURED",
        rtk_binary_sha256="41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf",
        raw_arm={"exit_code": 0, "exit_code_stable": True, "canonical_deterministic": raw_det,
                 "o200k_tokens": raw_tok, "combined_sha256": "a"},
        rtk_arm={"exit_code": 0, "exit_code_stable": True, "canonical_deterministic": rtk_det,
                 "o200k_tokens": rtk_tok, "combined_sha256": "b"},
        semantic_oracle={"oracle": "x"},
        rtk_savings_pct_reporting_only=savings,
    ))


def write_cases(d: Path, cases):
    for i, rec in enumerate(cases):
        (d / f"n2e-canary-case-{i}.json").write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")


class TestCanaryAcceptance(unittest.TestCase):
    def _run(self, cases):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            write_cases(td, cases)
            body = agg.build(td, "test-run")
            return body

    def test_all_pass(self):
        body = self._run([synthetic_case(cid) for cid in CASE_IDS])
        self.assertTrue(body["canary_pass"])
        self.assertEqual(body["observed_case_count"], 12)

    def test_zero_and_negative_savings_do_not_fail(self):
        cases = [synthetic_case(cid) for cid in CASE_IDS]
        cases[0] = synthetic_case(CASE_IDS[0], savings=0.0, raw_tok=100, rtk_tok=100)
        cases[1] = synthetic_case(CASE_IDS[1], savings=-20.0, raw_tok=100, rtk_tok=120)
        body = self._run(cases)
        self.assertTrue(body["canary_pass"], "zero/negative savings must not fail a case")
        self.assertIn(CASE_IDS[0], body["zero_or_negative_saving_cases"])
        self.assertIn(CASE_IDS[1], body["zero_or_negative_saving_cases"])

    def test_missing_case_fails(self):
        body = self._run([synthetic_case(cid) for cid in CASE_IDS[:-1]])
        self.assertFalse(body["canary_pass"])
        self.assertEqual(len(body["missing_cases"]), 1)

    def test_nondeterministic_raw_fails_case(self):
        cases = [synthetic_case(cid) for cid in CASE_IDS]
        cases[0] = synthetic_case(CASE_IDS[0], raw_det=False)
        body = self._run(cases)
        self.assertFalse(body["canary_pass"])
        self.assertEqual(body["verdicts"][CASE_IDS[0]], "FAIL_RAW_NONDETERMINISTIC")

    def test_tampered_case_selfhash_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            cases = [synthetic_case(cid) for cid in CASE_IDS]
            write_cases(td, cases)
            # tamper one file's content without re-sealing
            p = next(td.glob("*.json"))
            rec = json.loads(p.read_text())
            rec["raw_arm"]["o200k_tokens"] = 999999
            p.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")
            with self.assertRaises(SystemExit):
                agg.build(td, "test-run")

    def test_extra_case_fails(self):
        cases = [synthetic_case(cid) for cid in CASE_IDS]
        cases.append(synthetic_case("not::in::membership"))
        body = self._run(cases)
        self.assertFalse(body["canary_pass"])
        self.assertTrue(body["extra_cases"])


if __name__ == "__main__":
    unittest.main()
