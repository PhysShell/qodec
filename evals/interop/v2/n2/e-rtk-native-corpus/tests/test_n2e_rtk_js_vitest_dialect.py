"""Promotion P5.2A (vue JS/TS): rtk-js-vitest-summary-v1 semantics, proven against the pinned RTK
vitest parser's OWN sample I/O (rtk-ai/rtk @5d32d07, src/cmds/js/vitest_cmd.rs). Tier-1 JSON and
tier-2 regex must project the same totals; a human RAW vitest stream (tier 2) and the JSON RTK stream
(tier 1) must agree on outcome + counts; a hidden failure or wrong count breaks equivalence; garbage
is passthrough, never a manufactured PASS.
"""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_rtk_js_vitest_dialect as js  # noqa: E402

# tier-2 regex fixture (verbatim from test_vitest_parser_regex_fallback)
RAW_REGEX_OK = b"""
 Test Files  2 passed (2)
      Tests  13 passed (13)
   Duration  450ms
"""
# tier-1 JSON fixtures (verbatim from test_vitest_parser_with_pnpm_prefix / _with_dotenv_prefix)
RTK_JSON_OK = b'{"numTotalTests": 13, "numPassedTests": 13, "numFailedTests": 0, "numPendingTests": 0, "testResults": [], "startTime": 1000}'
JSON_FAIL = b'{"numTotalTests": 5, "numPassedTests": 4, "numFailedTests": 1, "numPendingTests": 0, "testResults": [{"name": "t.js", "assertionResults": [{"fullName": "adds", "status": "failed", "failureMessages": ["boom"]}]}], "startTime": 2000}'


class TestVitestDialect(unittest.TestCase):
    def test_regex_tier2_projection(self):
        p = js.parse_raw(RAW_REGEX_OK)
        self.assertEqual((p["tier"], p["outcome"], p["passed"], p["failed"], p["total"]), (2, "success", 13, 0, 13))

    def test_json_tier1_projection(self):
        p = js.parse_raw(RTK_JSON_OK)
        self.assertEqual((p["tier"], p["outcome"], p["passed"], p["failed"], p["total"]), (1, "success", 13, 0, 13))

    def test_json_failure_projection(self):
        p = js.parse_raw(JSON_FAIL)
        self.assertEqual(p["outcome"], "failure")
        self.assertEqual((p["passed"], p["failed"], p["total"]), (4, 1, 5))
        self.assertEqual(p["failing_ids"], ["adds"])

    # ---- RAW (human tier-2) <-> RTK (json tier-1) equivalence over the pinned counts ----
    def test_cross_tier_equivalence_ok(self):
        eq = js.equivalence(js.parse_raw(RAW_REGEX_OK), js.parse_rtk(RTK_JSON_OK))
        self.assertTrue(eq["equivalent"], eq["mismatches"])
        self.assertFalse(eq["same_tier"])

    def test_ansi_crlf_duration_non_semantic(self):
        noisy = RAW_REGEX_OK.replace(b"Tests", b"\x1b[32mTests\x1b[0m").replace(b"\n", b"\r\n").replace(b"450ms", b"1200ms")
        self.assertEqual(js.parse_raw(noisy), js.parse_raw(RAW_REGEX_OK))

    # ---- semantic differences break equivalence ----
    def test_hidden_failure_breaks_equivalence(self):
        # RTK json claims all pass while RAW regex shows a failure
        raw_fail = b" Test Files  1 failed | 1 passed (2)\n      Tests  1 failed | 12 passed (13)\n"
        eq = js.equivalence(js.parse_raw(raw_fail), js.parse_rtk(RTK_JSON_OK))
        self.assertFalse(eq["equivalent"])

    def test_wrong_total_breaks_equivalence(self):
        rtk_wrong = RTK_JSON_OK.replace(b'"numTotalTests": 13', b'"numTotalTests": 12').replace(b'"numPassedTests": 13', b'"numPassedTests": 12')
        eq = js.equivalence(js.parse_raw(RAW_REGEX_OK), js.parse_rtk(rtk_wrong))
        self.assertFalse(eq["equivalent"])

    def test_same_tier_failing_id_mismatch_breaks(self):
        other = JSON_FAIL.replace(b'"fullName": "adds"', b'"fullName": "subtracts"')
        eq = js.equivalence(js.parse_raw(JSON_FAIL), js.parse_rtk(other))
        self.assertFalse(eq["equivalent"])

    # ---- never manufactures a PASS ----
    def test_passthrough_is_not_success(self):
        p = js.parse_raw(b"random output with no structure")
        self.assertEqual(p["outcome"], "passthrough")
        self.assertFalse(p["terminal_summary_present"])

    def test_zero_total_regex_is_passthrough(self):
        # extract_stats_regex returns None when total == 0
        p = js.parse_raw(b"Tests  0 passed (0)\n")
        self.assertEqual(p["outcome"], "passthrough")


if __name__ == "__main__":
    unittest.main()
