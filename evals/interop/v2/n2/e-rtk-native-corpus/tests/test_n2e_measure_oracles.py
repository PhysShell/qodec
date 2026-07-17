"""Tests for the RAW/RTK measurement harness (§13/§15) and oracles (§14)."""
import json
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
TOOLS = N2E_DIR / "tools"
sys.path.insert(0, str(TOOLS))
import n2e_measure as m  # noqa: E402
import n2e_oracles as ora  # noqa: E402


class TestHarness(unittest.TestCase):
    def test_mandated_env(self):
        env = m.measurement_env()
        self.assertEqual(env["LANG"], "C.UTF-8")
        self.assertEqual(env["TZ"], "UTC")
        self.assertEqual(env["NO_COLOR"], "1")

    def test_combine_policy_predeclared(self):
        self.assertEqual(m.combine(b"a", b"b"), b"ab")
        with self.assertRaises(ValueError):
            m.combine(b"a", b"b", policy="bogus")

    def test_deterministic_command_is_deterministic(self):
        r = m.run_repeated(["printf", "hello\\nworld\\n"], 3, timeout=30)
        self.assertTrue(r["byte_deterministic"])
        self.assertTrue(r["exit_code_stable"])
        self.assertEqual(r["exit_code"], 0)

    def test_stdout_stderr_captured_separately(self):
        r = m.run_once(["sh", "-c", "echo out; echo err 1>&2"], cwd="/tmp", timeout=30)
        self.assertNotEqual(r["stdout_sha256"], r["stderr_sha256"])
        self.assertEqual(r["_stdout"], b"out\n")
        self.assertEqual(r["_stderr"], b"err\n")


class TestOracles(unittest.TestCase):
    def test_log_severity_counts(self):
        raw = b"2020 ERROR boom\n2020 WARN careful\n2020 INFO ok\n2020 plain line\n"
        counts = ora.log_severity_counts(raw)
        self.assertEqual(counts["total_lines"], 4)
        self.assertEqual(counts["error"], 1)
        self.assertEqual(counts["warn"], 1)
        self.assertEqual(counts["info"], 1)

    def test_log_oracle_flags_dropped_content(self):
        raw = b"ERROR a\nERROR b\nWARN c\n"
        rtk_bad = b"Log Summary\n [error] 0 errors\n [warn] 0 warnings\n [info] 0 info\n"
        verdict = ora.check_log_oracle(raw, rtk_bad)
        self.assertFalse(verdict["severity_counts_preserved"])
        self.assertTrue(verdict["content_dropped"])

    def test_log_oracle_passes_when_preserved(self):
        raw = b"ERROR a\nERROR b\nWARN c\n"
        rtk_ok = b"Log Summary\n [error] 2 errors\n [warn] 1 warnings\n [info] 0 info\n"
        verdict = ora.check_log_oracle(raw, rtk_ok)
        self.assertTrue(verdict["severity_counts_preserved"])

    def test_grep_match_identities(self):
        raw = b"file.py:10:def foo():\nfile.py:20:return 1\n"
        ids = ora.grep_match_identities(raw)
        self.assertEqual(len(ids), 2)
        self.assertTrue(any(p == "file.py" and ln == 10 for (p, ln, _) in ids))


PILOT = N2E_DIR / "n2e-log-qualification-pilot-v1.json"


@unittest.skipUnless(PILOT.exists(), "pilot record not present")
class TestLogPilotRecord(unittest.TestCase):
    def setUp(self):
        self.rec = json.loads(PILOT.read_text())

    def test_self_hash(self):
        import n2e_common as c
        ok, msg = c.verify_self_hash(self.rec)
        self.assertTrue(ok, msg)

    def test_both_arms_deterministic(self):
        self.assertTrue(self.rec["raw_arm"]["byte_deterministic"])
        self.assertTrue(self.rec["rtk_arm"]["byte_deterministic"])

    def test_real_o200k_counts_present(self):
        self.assertIsInstance(self.rec["raw_arm"]["o200k_tokens"], int)
        self.assertIsInstance(self.rec["rtk_arm"]["o200k_tokens"], int)
        self.assertGreater(self.rec["raw_arm"]["o200k_tokens"], 0)

    def test_rtk_binary_identity(self):
        self.assertEqual(self.rec["rtk_binary_sha256"],
                         "41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf")


if __name__ == "__main__":
    unittest.main()
