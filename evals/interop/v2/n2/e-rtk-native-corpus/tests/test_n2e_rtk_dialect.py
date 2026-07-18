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


def rtk_ids(b):
    return ora._test_summary(b, dialect="rtk")["failing_ids"]


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
        s0 = ora._test_summary(b"Go test: 3 passed, 0 failed in 1 packages\n", dialect="rtk")
        s2 = ora._test_summary(b"Go test: 1 passed, 2 failed in 1 packages\n", dialect="rtk")
        self.assertEqual(s0["failed"], 0)
        self.assertEqual(s2["failed"], 2)

    def test_malformed_rtk_record_fails_closed(self):
        s = ora._test_summary(b"garbage prose with no bounded record\n", dialect="rtk")
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
