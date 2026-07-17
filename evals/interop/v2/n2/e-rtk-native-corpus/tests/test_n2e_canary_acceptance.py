"""Fail-closed tests for canary aggregation/acceptance (§7/§8/§19/§22).

Synthetic per-case records over the real frozen 12-case membership exercise the
primitive re-derivation and the §22 canary mutations.
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

RTK = "41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf"
MEMBERSHIP = json.loads((N2E_DIR / "n2e-canary-membership-v1.json").read_text())
CASE_IDS = [m["case_id"] for m in MEMBERSHIP["membership"]]


class Args:
    run_id = "test-run"
    impl_sha = "i" * 40
    trigger_sha = "t" * 40
    job_manifest = None
    artifact_manifest = None


def good_case(case_id, savings=50.0, family="logs", **over):
    rec = c.envelope(
        record_type="n2e-canary-case", generated_by="test",
        case_id=case_id, command_family=over.get("family", family),
        command_subfamily="log", status="PASS", rtk_binary_sha256=RTK,
        acquisition={"identity_verified": True},
        isolation={"denial_probe": {"denied": True}},
        raw_arm={"reps_completed": 3, "exit_code_stable": True, "canonical_deterministic": True,
                 "o200k_tokens": 1000},
        rtk_arm={"reps_completed": 3, "exit_code_stable": True, "canonical_deterministic": True,
                 "o200k_tokens": 500},
        raw_semantic_oracle={"oracle": "log", "verdict": True},
        rtk_semantic_oracle={"oracle": "log", "verdict": True},
        rtk_savings_pct_reporting_only=savings,
    )
    for k, v in over.items():
        if k != "family":
            rec[k] = v
    return c.finalize(rec)


def write(d, cases):
    for i, rec in enumerate(cases):
        (d / f"n2e-canary-case-{i}.json").write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")


class TestAcceptance(unittest.TestCase):
    def _run(self, cases):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            write(td, cases)
            return agg.build(td, Args())

    def test_all_pass(self):
        body = self._run([good_case(cid) for cid in CASE_IDS])
        self.assertTrue(body["canary_pass"])
        self.assertEqual(body["observed_case_count"], 12)

    def test_zero_and_negative_savings_do_not_fail(self):
        cases = [good_case(cid) for cid in CASE_IDS]
        cases[0] = good_case(CASE_IDS[0], savings=0.0)
        cases[1] = good_case(CASE_IDS[1], savings=-20.0)
        body = self._run(cases)
        self.assertTrue(body["canary_pass"])
        self.assertIn(CASE_IDS[0], body["zero_or_negative_saving_cases"])

    def test_producer_status_not_trusted(self):
        """A record claiming PASS but with nondeterministic RAW must FAIL."""
        cases = [good_case(cid) for cid in CASE_IDS]
        bad = json.loads(json.dumps(cases[0]))
        bad["raw_arm"]["canonical_deterministic"] = False
        bad["status"] = "PASS"  # lie
        c.finalize(bad)
        cases[0] = bad
        body = self._run(cases)
        self.assertFalse(body["canary_pass"])
        self.assertEqual(body["verdicts"][CASE_IDS[0]], "FAIL")

    def test_missing_rtk_arm_fails(self):
        cases = [good_case(cid) for cid in CASE_IDS]
        bad = json.loads(json.dumps(cases[0]))
        bad["rtk_arm"] = None
        c.finalize(bad)
        cases[0] = bad
        body = self._run(cases)
        self.assertFalse(body["canary_pass"])

    def test_isolation_leak_fails(self):
        cases = [good_case(cid) for cid in CASE_IDS]
        bad = json.loads(json.dumps(cases[0]))
        bad["isolation"] = {"denial_probe": {"denied": False}}
        c.finalize(bad)
        cases[0] = bad
        body = self._run(cases)
        self.assertFalse(body["canary_pass"])

    def test_rtk_oracle_fail(self):
        cases = [good_case(cid) for cid in CASE_IDS]
        bad = json.loads(json.dumps(cases[0]))
        bad["rtk_semantic_oracle"] = {"oracle": "log", "verdict": False}
        c.finalize(bad)
        cases[0] = bad
        body = self._run(cases)
        self.assertFalse(body["canary_pass"])

    def test_missing_case_fails(self):
        body = self._run([good_case(cid) for cid in CASE_IDS[:-1]])
        self.assertFalse(body["canary_pass"])
        self.assertEqual(len(body["missing_cases"]), 1)

    def test_duplicate_case_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            cases = [good_case(cid) for cid in CASE_IDS]
            cases.append(good_case(CASE_IDS[0]))  # duplicate case_id
            write(td, cases)
            with self.assertRaises(SystemExit):
                agg.build(td, Args())

    def test_tampered_selfhash_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            cases = [good_case(cid) for cid in CASE_IDS]
            write(td, cases)
            p = next(td.glob("*.json"))
            rec = json.loads(p.read_text())
            rec["raw_arm"]["o200k_tokens"] = 999999  # tamper, don't reseal
            p.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")
            with self.assertRaises(SystemExit):
                agg.build(td, Args())


if __name__ == "__main__":
    unittest.main()
