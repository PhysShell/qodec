"""Promotion P5.2B (gin): rtk-go-vet-oracle-v1 semantics, proven against the pinned RTK filter_go_vet
rules (rtk-ai/rtk @5d32d07, src/cmds/go/go_cmd.rs). go vet is a rtk_command_oracle, not a test
dialect: the projection is issue lines + count + the clean/issues outcome, EXIT-AGNOSTIC (as the
filter is). Required forms exercised: empty success, one diagnostic, multiple diagnostics, nonzero
exit without a recognizable `.go:` diagnostic, and the RTK synthetic 'No issues found' marker.
"""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_rtk_go_vet_oracle as gv  # noqa: E402

# a clean gin run (REAL committed streams from run 29682560680): go vet emits nothing (exit 0), and
# RTK's run_filtered token guard suppresses the synthetic marker back to empty (1-byte newline).
STREAMS = N2E_DIR / "evidence" / "gin-clean-run-29682560680" / "streams"
RAW_CLEAN = (STREAMS / "raw.canonical.bin").read_bytes()   # b"" (0 bytes)
RTK_CLEAN = (STREAMS / "rtk.canonical.bin").read_bytes()   # b"\n" (1 byte)
# the synthetic marker form is also accepted as clean (when RAW had enough tokens to survive the guard)
RTK_SYNTH_CLEAN = b"Go vet: No issues found"

# one diagnostic
RAW_ONE = b"# github.com/gin-gonic/gin\n./context.go:42:3: unreachable code\n"
RTK_ONE = b"Go vet: 1 issues\n1. ./context.go:42:3: unreachable code"

# multiple diagnostics
RAW_MULTI = b"""# github.com/gin-gonic/gin
./a.go:10:2: unreachable code
./b.go:20:5: struct field tag not compatible with reflect.StructTag.Get
"""
RTK_MULTI = b"""Go vet: 2 issues
1. ./a.go:10:2: unreachable code
2. ./b.go:20:5: struct field tag not compatible with reflect.StructTag.Get"""

# nonzero exit with a build error but NO `.go:` diagnostic line -> filter says "No issues found"
RAW_BUILD_ERR = b"# github.com/gin-gonic/gin\nbuild failed: cannot find package\n"


class TestGoVetOracle(unittest.TestCase):
    # ---------- clean (gin) ----------
    def test_clean_projection(self):
        rp = gv.parse_raw(RAW_CLEAN)
        self.assertEqual((rp["outcome"], rp["issue_count"]), ("clean", 0))
        kp = gv.parse_rtk(RTK_CLEAN)
        self.assertEqual((kp["outcome"], kp["issue_count"], kp["synthetic_no_issues"]), ("clean", 0, True))

    def test_clean_equivalence_real_streams(self):
        # empty RAW <-> newline RTK (token-guard-suppressed) -> both clean, equivalent
        self.assertTrue(gv.equivalence(gv.parse_raw(RAW_CLEAN), gv.parse_rtk(RTK_CLEAN))["equivalent"])

    def test_synthetic_marker_also_clean(self):
        kp = gv.parse_rtk(RTK_SYNTH_CLEAN)
        self.assertEqual((kp["outcome"], kp["issue_count"]), ("clean", 0))
        self.assertTrue(gv.equivalence(gv.parse_raw(RAW_CLEAN), kp)["equivalent"])

    # ---------- one / multiple diagnostics ----------
    def test_one_diagnostic_equivalence(self):
        rp, kp = gv.parse_raw(RAW_ONE), gv.parse_rtk(RTK_ONE)
        self.assertEqual((rp["outcome"], rp["issue_count"]), ("issues", 1))
        self.assertTrue(gv.equivalence(rp, kp)["equivalent"], gv.equivalence(rp, kp)["mismatches"])

    def test_multiple_diagnostics_equivalence(self):
        rp, kp = gv.parse_raw(RAW_MULTI), gv.parse_rtk(RTK_MULTI)
        self.assertEqual(rp["issue_count"], 2)
        self.assertTrue(gv.equivalence(rp, kp)["equivalent"], gv.equivalence(rp, kp)["mismatches"])

    def test_hash_prefixed_headers_dropped(self):
        # the `# pkg` line is not an issue; only the `.go:` line counts
        self.assertEqual(gv.parse_raw(RAW_ONE)["issue_count"], 1)

    # ---------- exit-agnostic: nonzero exit + no `.go:` line = clean (faithful to the filter) ----------
    def test_build_error_without_go_line_is_clean(self):
        rp = gv.parse_raw(RAW_BUILD_ERR)
        self.assertEqual((rp["outcome"], rp["issue_count"]), ("clean", 0))
        # RTK would also synthesize "No issues found" -> faithful equivalence, no invented exit field
        self.assertTrue(gv.equivalence(rp, gv.parse_rtk(RTK_CLEAN))["equivalent"])

    # ---------- presentation non-semantic ----------
    def test_ansi_crlf_non_semantic(self):
        noisy = RAW_ONE.replace(b"\n", b"\r\n").replace(b"unreachable", b"\x1b[31munreachable\x1b[0m")
        self.assertEqual(gv.parse_raw(noisy)["issue_count"], gv.parse_raw(RAW_ONE)["issue_count"])

    # ---------- semantic differences break equivalence ----------
    def test_rtk_drops_a_diagnostic_breaks(self):
        # RAW has 2 issues, RTK claims 1 -> break
        self.assertFalse(gv.equivalence(gv.parse_raw(RAW_MULTI), gv.parse_rtk(RTK_ONE))["equivalent"])

    def test_rtk_synthetic_ok_with_real_issue_breaks(self):
        # RAW has an issue, RTK says "No issues found" -> break (nonzero-turned-success on a real dx)
        self.assertFalse(gv.equivalence(gv.parse_raw(RAW_ONE), gv.parse_rtk(RTK_CLEAN))["equivalent"])

    def test_changed_message_breaks(self):
        rtk_altered = b"Go vet: 1 issues\n1. ./context.go:42:3: DIFFERENT message"
        self.assertFalse(gv.equivalence(gv.parse_raw(RAW_ONE), gv.parse_rtk(rtk_altered))["equivalent"])

    def test_changed_file_line_breaks(self):
        rtk_altered = b"Go vet: 1 issues\n1. ./other.go:99:9: unreachable code"
        self.assertFalse(gv.equivalence(gv.parse_raw(RAW_ONE), gv.parse_rtk(rtk_altered))["equivalent"])

    # ---------- never manufactures a verdict ----------
    def test_malformed_rtk_is_indeterminate(self):
        self.assertEqual(gv.parse_rtk(b"some unrelated output")["outcome"], "indeterminate")


if __name__ == "__main__":
    unittest.main()
