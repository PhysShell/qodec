"""rtk-log-hdfs-oracle-v1: grounded in the pinned RTK source (src/cmds/system/log_cmd.rs @5d32d07,
analyze_logs). RTK's `log` command reports SEVERITY TOTALS (error/warn/info by substring
categorization) -- the ONLY overlap this oracle claims. It reports no loghub EventIds and its unique
counts are normalizer-specific (block ids not normalized), so the oracle compares totals only.
"""
import hashlib
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import n2e_rtk_log_hdfs_oracle as orc  # noqa: E402
import verify_n2e_command_oracle_source_proof as V  # noqa: E402


class TestCategorization(unittest.TestCase):
    def test_priority_and_keywords(self):
        # mirrors the pinned analyze_logs test: CRITICAL/ALERT/emerg/SEVERE -> error; notice -> warn
        self.assertEqual(orc.rtk_categorize("2024 CRITICAL: disk full"), "error")
        self.assertEqual(orc.rtk_categorize("ALERT: memory pressure"), "error")
        self.assertEqual(orc.rtk_categorize("emerg: shutdown"), "error")
        self.assertEqual(orc.rtk_categorize("SEVERE: corruption"), "error")
        self.assertEqual(orc.rtk_categorize("notice: config reloaded"), "warn")
        self.assertEqual(orc.rtk_categorize("081109 1 1 WARN x: retry"), "warn")
        self.assertEqual(orc.rtk_categorize("081109 1 1 INFO x: ok"), "info")
        self.assertEqual(orc.rtk_categorize("a plain line with no severity word"), "other")

    def test_error_priority_over_info(self):
        # a line containing BOTH "info" and "error" -> error (error checked first)
        self.assertEqual(orc.rtk_categorize("INFO: an error occurred"), "error")


class TestParseRtk(unittest.TestCase):
    OUT = (b"Log Summary\n"
           b"   [error] 7 errors (3 unique)\n"
           b"   [warn] 12 warnings (5 unique)\n"
           b"   [info] 900 info messages\n\n[ERRORS]\n   [x7] boom\n")

    def test_parse_totals(self):
        p = orc.parse_rtk(self.OUT)
        self.assertTrue(p["derivable"])
        self.assertEqual((p["total_errors"], p["error_unique"]), (7, 3))
        self.assertEqual((p["total_warnings"], p["warn_unique"]), (12, 5))
        self.assertEqual(p["total_info"], 900)

    def test_missing_header_not_derivable(self):
        self.assertFalse(orc.parse_rtk(b"some raw content, no summary")["derivable"])


class TestEquivalence(unittest.TestCase):
    def _cap(self, e, w, i, o=0):
        return {"rtk_semantic_projection": {"error": e, "warn": w, "info": i, "other": o}}

    def test_totals_match(self):
        raw = orc.raw_projection_from_capsule(self._cap(7, 12, 900))
        rtk = orc.parse_rtk(b"Log Summary\n   [error] 7 errors (3 unique)\n   [warn] 12 warnings (5 unique)\n   [info] 900 info messages\n")
        self.assertTrue(orc.equivalence(raw, rtk)["equivalent"])

    def test_total_mismatch_rejected(self):
        raw = orc.raw_projection_from_capsule(self._cap(8, 12, 900))
        rtk = orc.parse_rtk(b"Log Summary\n   [error] 7 errors (3 unique)\n   [warn] 12 warnings (5 unique)\n   [info] 900 info messages\n")
        eq = orc.equivalence(raw, rtk)
        self.assertFalse(eq["equivalent"])
        self.assertIn("total_errors", eq["mismatches"])

    def test_not_derivable_rejected(self):
        raw = orc.raw_projection_from_capsule(self._cap(1, 1, 1))
        self.assertFalse(orc.equivalence(raw, orc.parse_rtk(b"no summary"))["equivalent"])

    def test_unique_counts_not_compared(self):
        # RTK's unique counts differ from anything RAW-derived, but equivalence is on totals only
        raw = orc.raw_projection_from_capsule(self._cap(7, 12, 900))
        rtk = orc.parse_rtk(b"Log Summary\n   [error] 7 errors (999 unique)\n   [warn] 12 warnings (999 unique)\n   [info] 900 info messages\n")
        self.assertTrue(orc.equivalence(raw, rtk)["equivalent"])


class TestSourceIdentity(unittest.TestCase):
    def test_pinned_source_matches_committed(self):
        p = N2E_DIR / "evidence" / "rtk-source" / "log_cmd.rs"
        self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),
                         "e72549e7a8a18f0601386e90dcf57033c660b4f5b2462542158c7c2346489236")
        self.assertEqual(orc.RTK_SOURCE_FILE, "src/cmds/system/log_cmd.rs")
        self.assertEqual(orc.RTK_SOURCE_COMMIT, "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2")

    def test_source_proof_verifies(self):
        rec = c.load_record(N2E_DIR / "n2e-command-oracle-source-proof-rtk-log-hdfs-oracle-v1.json")
        f = V.verify_proof(rec)   # raises OracleProofError on any mismatch
        self.assertEqual(f["policy"], "rtk-log-hdfs-oracle-v1")
        self.assertEqual(f["cases"], ["loghub::HDFS::log"])


class TestRealOutputRegression(unittest.TestCase):
    """Freeze the oracle against the REAL rtk log output on the full HDFS stream (diagnostic run
    29900168290): parse_rtk must reproduce the observed totals exactly, and the source-grounded
    rtk_categorize projection must equal RTK's reported totals (severity equivalence closed)."""

    REAL = N2E_DIR / "evidence" / "loghub-diag" / "rtk-log-summary.real.txt"
    PROV = N2E_DIR / "n2e-loghub-diagnostic-provenance-v1.json"

    def test_fixture_identity(self):
        self.assertEqual(hashlib.sha256(self.REAL.read_bytes()).hexdigest(),
                         "02a1e023f3008c99b9f1cda07f075cc0a6034dc097b6f8f5d1728cf68a38c4d9")

    def test_parse_rtk_reproduces_real_totals(self):
        p = orc.parse_rtk(self.REAL.read_bytes())
        self.assertTrue(p["derivable"])
        self.assertEqual(p["total_errors"], 5545)
        self.assertEqual(p["total_warnings"], 356273)
        self.assertEqual(p["total_info"], 10805922)
        self.assertEqual(p["error_unique"], 5010)
        self.assertEqual(p["warn_unique"], 116839)

    def test_severity_projection_closed_on_real_stream(self):
        # the RAW-side rtk_semantic_projection (source-grounded categorization) == RTK's reported totals
        prov = c.load_record(self.PROV)
        proj = prov["raw_capsule"]["rtk_semantic_projection"]
        rtk = orc.parse_rtk(self.REAL.read_bytes())
        self.assertEqual(proj["error"], rtk["total_errors"])
        self.assertEqual(proj["warn"], rtk["total_warnings"])
        self.assertEqual(proj["info"], rtk["total_info"])
        self.assertTrue(prov["severity_equivalence"]["equivalent"])

    def test_provenance_is_barred(self):
        prov = c.load_record(self.PROV)
        self.assertTrue(prov["barred_from_qualification"])
        self.assertEqual(prov["record_kind"], "loghub_diagnostic_capture")
        # the RAW capsule validated the published authority on the real full log
        self.assertTrue(prov["raw_capsule"]["occurrence_counts_match_published"])
        self.assertEqual(prov["raw_capsule"]["unique_template_count"], 46)
        self.assertEqual(prov["input_member"]["line_count"], 11167740)


if __name__ == "__main__":
    unittest.main()
