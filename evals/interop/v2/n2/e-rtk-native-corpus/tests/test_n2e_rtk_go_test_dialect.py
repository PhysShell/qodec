"""Promotion P5.2A (caddy Go): rtk-go-test-summary-v1 -- PROVE the existing frozen policy against
(a) the REAL committed caddy canonical streams (evidence/caddy-pass-run-29639560535) and (b) the
pinned RTK go filter's semantics (src/cmds/go/go_cmd.rs). The two ARM OUTPUT forms: RAW = human
`go test -v` (caddy argv has -v, not -json); RTK = the compact `Go test: N passed, M failed in K
packages` + `[FAIL] <Test>`. Both must project the same verdict. The go-specific no-double-count /
timeout rules are proven on the -json event form the filter consumes internally.
"""
import sys
import zlib
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_rtk_go_test_dialect as go  # noqa: E402

STREAMS = N2E_DIR / "evidence" / "caddy-pass-run-29639560535" / "streams"


def _dz(name):
    return zlib.decompress((STREAMS / name).read_bytes())


# real RAW human `go test -v` (caddy-go-test-v1 canonical) + real RTK compact form
RAW_HUMAN_FAIL = _dz("raw.rep0.zst")
RTK_COMPACT_FAIL = _dz("rtk.rep0.zst")

RAW_HUMAN_PASS = b"""=== RUN   TestOk
--- PASS: TestOk (<dur>)
PASS
ok\tgithub.com/example/foo\t<dur>
"""
RTK_COMPACT_PASS = b"Go test: 1 passed in 1 packages"

# -json event form (what RTK consumes internally) -- for the no-double-count / timeout rules
JSON_FAIL = b"""{"Action":"run","Package":"example.com/foo","Test":"TestFail"}
{"Action":"fail","Package":"example.com/foo","Test":"TestFail","Elapsed":0.5}
{"Action":"fail","Package":"example.com/foo","Elapsed":0.5}"""
JSON_TIMEOUT = b"""{"Action":"start","Package":"example.com/foo"}
{"Action":"output","Package":"example.com/foo","Output":"*** Test killed with quit: ran too long.\\n"}
{"Action":"fail","Package":"example.com/foo","Elapsed":63.003}"""


class TestGoDialect(unittest.TestCase):
    # ---------- REAL caddy streams: RAW human <-> RTK compact equivalence ----------
    def test_real_caddy_streams_equivalent(self):
        rp, kp = go.parse_raw(RAW_HUMAN_FAIL), go.parse_rtk(RTK_COMPACT_FAIL)
        self.assertEqual((rp["outcome"], rp["passed"], rp["failed"]), ("failure", 0, 1))
        self.assertEqual(rp["failing_ids"], ["TestUnsyncedConfigAccess"])
        self.assertEqual((kp["outcome"], kp["passed"], kp["failed"]), ("failure", 0, 1))
        self.assertTrue(go.equivalence(rp, kp)["equivalent"])

    def test_real_caddy_all_three_reps_equivalent(self):
        for i in range(3):
            eq = go.equivalence(go.parse_raw(_dz(f"raw.rep{i}.zst")), go.parse_rtk(_dz(f"rtk.rep{i}.zst")))
            self.assertTrue(eq["equivalent"], (i, eq["mismatches"]))

    # ---------- human RAW + compact RTK pass forms ----------
    def test_human_pass(self):
        p = go.parse_raw(RAW_HUMAN_PASS)
        self.assertEqual((p["outcome"], p["passed"], p["failed"]), ("success", 1, 0))

    def test_compact_pass_equivalence(self):
        eq = go.equivalence(go.parse_raw(RAW_HUMAN_PASS), go.parse_rtk(RTK_COMPACT_PASS))
        self.assertTrue(eq["equivalent"], eq["mismatches"])

    def test_compact_no_tests_found(self):
        self.assertEqual(go.parse_rtk(b"Go test: No tests found")["outcome"], "no_tests")

    # ---------- -json event rules (no double-count, timeout) ----------
    def test_json_failure_no_double_count(self):
        p = go.parse_raw(JSON_FAIL)
        self.assertEqual((p["outcome"], p["failed"]), ("failure", 1))
        self.assertEqual(p["failing_ids"], ["example.com/foo::TestFail"])

    def test_json_timeout_is_one_failure(self):
        p = go.parse_raw(JSON_TIMEOUT)
        self.assertEqual((p["outcome"], p["failed"]), ("failure", 1))

    # ---------- presentation is non-semantic ----------
    def test_ansi_crlf_non_semantic(self):
        noisy = RAW_HUMAN_FAIL.replace(b"\n", b"\r\n")
        self.assertEqual(go.parse_raw(noisy)["failed"], go.parse_raw(RAW_HUMAN_FAIL)["failed"])

    # ---------- semantic differences break equivalence ----------
    def test_rtk_hides_failure_breaks_equivalence(self):
        eq = go.equivalence(go.parse_raw(RAW_HUMAN_FAIL), go.parse_rtk(b"Go test: 1 passed in 1 packages"))
        self.assertFalse(eq["equivalent"])

    def test_wrong_count_breaks_equivalence(self):
        eq = go.equivalence(go.parse_raw(RAW_HUMAN_PASS), go.parse_rtk(b"Go test: 2 passed in 1 packages"))
        self.assertFalse(eq["equivalent"])

    # ---------- never manufactures a PASS ----------
    def test_noise_is_indeterminate(self):
        p = go.parse_raw(b"just some noise with no go markers\n")
        self.assertEqual(p["outcome"], "indeterminate")
        self.assertFalse(p["terminal_summary_present"])


if __name__ == "__main__":
    unittest.main()
