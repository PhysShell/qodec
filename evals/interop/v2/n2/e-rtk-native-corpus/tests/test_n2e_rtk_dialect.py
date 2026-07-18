"""Dialect-aware test parsing: RTK's filtered Go stream (`rtk-go-test-summary-v1`) uses a
bounded, anchored `[FAIL] <id>` record -- NOT a generic 'FAIL' search. The RTK agreement
oracle compares NORMALIZED semantic events (failed_count + failing_ids), not byte format,
so RTK reformatting `--- FAIL: X` to `[FAIL] X` preserves the identity and agrees."""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_oracles as ora  # noqa: E402

SCEN = {"command_family": "go", "command_subfamily": "test", "snapshot_variant": "buggy",
        "target_test_ids": ["TestUnsyncedConfigAccess"]}
# exact measured RTK bytes shape (RTK source @5d32d07) from the diagnostic run
RTK_STREAM = (b"Go test: 0 passed, 1 failed in 1 packages\n\n"
              b"v2 (0 passed, 1 failed)\n"
              b"  [FAIL] TestUnsyncedConfigAccess\n"
              b"     admin_test.go:117: Test 4: Expected error return value, but got: <nil>\n"
              b"[full output: ~/.local/share/rtk/tee/<ts>_go_test.log]\n")
RAW_STREAM = (b"=== RUN   TestUnsyncedConfigAccess\n"
              b"--- FAIL: TestUnsyncedConfigAccess (<dur>)\nFAIL\n"
              b"FAIL\tgithub.com/caddyserver/caddy/v2\t<dur>\nFAIL\n")


DIA = ora.RTK_GO_DIALECT


def rtk_ids(b):
    return ora._test_summary(b, dialect=DIA)["failing_ids"]


def rtk_sum(b):
    return ora._test_summary(b, dialect=DIA)


class TestStrictGoSummaryGrammar(unittest.TestCase):
    OKFAIL = b"Go test: 0 passed, 1 failed in 1 packages\n  [FAIL] TestUnsyncedConfigAccess\n"

    def test_valid_fail_summary_parses_counts(self):
        s = rtk_sum(self.OKFAIL)
        self.assertEqual((s["passed"], s["failed"], s["packages"]), (0, 1, 1))
        self.assertTrue(s["aggregate_summary_present"])

    def test_prefixed_summary_rejected(self):
        s = rtk_sum(b"diagnostic Go test: 0 passed, 1 failed in 1 packages\n  [FAIL] X\n")
        self.assertIsNone(s["failed"])
        self.assertFalse(s["aggregate_summary_present"])

    def test_wrong_tool_name_rejected(self):
        s = rtk_sum(b"Tool test: 0 passed, 1 failed in 1 packages\n  [FAIL] X\n")
        self.assertIsNone(s["failed"])

    def test_fail_record_without_summary_is_incomplete(self):
        s = rtk_sum(b"  [FAIL] TestUnsyncedConfigAccess\n")
        self.assertIsNone(s["failed"])                       # counts NOT derived from [FAIL]
        self.assertEqual(s["failing_ids"], ["TestUnsyncedConfigAccess"])

    def test_summary_without_fail_identity(self):
        s = rtk_sum(b"Go test: 0 passed, 1 failed in 1 packages\n")
        self.assertEqual(s["failed"], 1)
        self.assertEqual(s["failing_ids"], [])               # aggregate present, no per-test id

    def test_package_suffix_removed_rejected(self):
        s = rtk_sum(b"Go test: 0 passed, 1 failed in 1\n  [FAIL] X\n")
        self.assertIsNone(s["failed"])

    def test_changed_counts_observable(self):
        self.assertEqual(rtk_sum(b"Go test: 3 passed, 0 failed in 2 packages\n")["failed"], 0)
        s = rtk_sum(b"Go test: 1 passed, 2 failed, 4 skipped in 2 packages\n")
        self.assertEqual((s["passed"], s["failed"], s["skipped"], s["packages"]), (1, 2, 4, 2))

    def test_two_conflicting_summaries_incomplete(self):
        s = rtk_sum(b"Go test: 0 passed, 1 failed in 1 packages\n"
                    b"Go test: 3 passed, 0 failed in 1 packages\n")
        self.assertIsNone(s["failed"])
        self.assertTrue(s["aggregate_summary_conflict"])

    def test_summary_embedded_mid_line_rejected(self):
        s = rtk_sum(b"prefix Go test: 0 passed, 1 failed in 1 packages suffix\n")
        self.assertIsNone(s["failed"])

    def test_success_forms(self):
        self.assertEqual(rtk_sum(b"Go test: 5 passed in 1 packages\n")["failed"], 0)
        self.assertEqual(rtk_sum(b"Go test: No tests found\n")["failed"], 0)


class TestRtkDialectParser(unittest.TestCase):
    def test_bracket_fail_yields_exact_id(self):
        self.assertEqual(rtk_ids(b"  [FAIL] TestUnsyncedConfigAccess\n"),
                         ["TestUnsyncedConfigAccess"])

    def test_bracket_pass_is_not_a_failure(self):
        self.assertEqual(rtk_ids(b"  [PASS] TestUnsyncedConfigAccess\n"), [])

    def test_marker_not_line_anchored_is_ignored(self):
        self.assertEqual(rtk_ids(b"some text [FAIL] TestUnsyncedConfigAccess\n"), [])

    def test_command_selector_is_ignored(self):
        self.assertEqual(rtk_ids(b"go test -v . -run TestUnsyncedConfigAccess\n"), [])

    def test_tee_pointer_is_ignored(self):
        self.assertEqual(rtk_ids(b"[full output: ~/.cache/rtk/tee/9_go.log :: TestUnsyncedConfigAccess]\n"), [])

    def test_unrelated_failure_stays_unrelated(self):
        self.assertEqual(rtk_ids(b"  [FAIL] TestSomethingElse\n"), ["TestSomethingElse"])

    def test_changed_failure_count_is_observable(self):
        s0 = ora._test_summary(b"Go test: 3 passed, 0 failed in 1 packages\n", dialect=ora.RTK_GO_DIALECT)
        s2 = ora._test_summary(b"Go test: 1 passed, 2 failed in 1 packages\n", dialect=ora.RTK_GO_DIALECT)
        self.assertEqual(s0["failed"], 0)
        self.assertEqual(s2["failed"], 2)

    def test_malformed_rtk_record_fails_closed(self):
        s = ora._test_summary(b"garbage prose with no bounded record\n", dialect=ora.RTK_GO_DIALECT)
        self.assertEqual(s["failing_ids"], [])
        self.assertIsNone(s["failed"])

    def test_native_dialect_does_not_parse_bracket_fail(self):
        # the RTK grammar must not leak into the native parser
        s = ora._test_summary(b"  [FAIL] TestUnsyncedConfigAccess\n", dialect="native")
        self.assertEqual(s["failing_ids"], [])


class TestRtkAgreementNormalized(unittest.TestCase):
    def test_reformatted_identity_agrees(self):
        v = ora.rtk_agrees(SCEN, RAW_STREAM, RTK_STREAM)
        self.assertTrue(v["verdict"], v["evidence"])
        self.assertEqual(v["evidence"]["raw_dialect"], "go-test-native-v1")
        self.assertEqual(v["evidence"]["rtk_dialect"], "rtk-go-test-summary-v1")

    def test_genuinely_dropped_identity_disagrees(self):
        # RTK stream that truly omits the failing id (count says 1 failed, no [FAIL] record)
        dropped = b"Go test: 0 passed, 1 failed in 1 packages\nv2 (0 passed, 1 failed)\n"
        v = ora.rtk_agrees(SCEN, RAW_STREAM, dropped)
        self.assertFalse(v["verdict"])

    def test_changed_count_disagrees(self):
        two = (b"Go test: 0 passed, 2 failed in 1 packages\n"
               b"  [FAIL] TestUnsyncedConfigAccess\n  [FAIL] TestOther\n")
        v = ora.rtk_agrees(SCEN, RAW_STREAM, two)
        self.assertFalse(v["verdict"])  # raw failed=1, rtk failed=2

    def test_unproven_family_fails_closed(self):
        # a family with no proven RTK dialect must FAIL CLOSED (never reuse the Go parser)
        for fam in ("rust_cargo", "js_ts", "jvm", "python"):
            self.assertIsNone(ora.rtk_dialect_for(fam), fam)
            scen = {"command_family": fam, "command_subfamily": "test", "snapshot_variant": "buggy"}
            v = ora.rtk_agrees(scen, RAW_STREAM, RTK_STREAM)
            self.assertFalse(v["verdict"], fam)
            self.assertIsNone(v["evidence"]["rtk_dialect"], fam)
            self.assertEqual(v["evidence"]["unproven_family"], fam)

    def test_go_family_has_proven_dialect(self):
        self.assertEqual(ora.rtk_dialect_for("go"), "rtk-go-test-summary-v1")


if __name__ == "__main__":
    unittest.main()
