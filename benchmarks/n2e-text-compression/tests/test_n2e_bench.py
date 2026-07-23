"""Focused tests for the N2-E text-compression benchmark.

Pure-Python tests (manifest shape, digest verification logic, aggregate math, family grouping,
semantic classification, no-case-disappears) always run. Tests that exercise the real Qodec adapter
(token counting, zero-length, invalid UTF-8, roundtrip, failed process) are skipped when the release
binary is absent.
"""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent
REPO = BENCH.parents[1]
sys.path.insert(0, str(BENCH))
import bench_lib as B  # noqa: E402
import run_benchmark as R  # noqa: E402

QODEC = REPO / "target/release/qodec"
HAVE_QODEC = QODEC.is_file()
MANIFEST = json.loads((BENCH / "benchmark-manifest.json").read_text())

TWELVE = {"coreutils", "caddy", "lucene", "vue", "scrapy", "gin", "preact", "lombok",
          "loghub", "rubocop", "php-cs-fixer", "redis"}
FAMILIES = {"Test output", "Diagnostics", "File content", "Large structured logs",
            "Git output", "Docker inventory"}


class TestManifest(unittest.TestCase):
    def test_exactly_twelve_frozen_cases(self):
        cases = MANIFEST["cases"]
        self.assertEqual(len(cases), 12)
        self.assertEqual({c["case"] for c in cases}, TWELVE)
        self.assertEqual(len({c["case_id"] for c in cases}), 12)  # no duplicate case ids
        self.assertEqual({c["family"] for c in cases}, FAMILIES)

    def test_raw_and_rtk_digests_verify_on_disk(self):
        for c in MANIFEST["cases"]:
            for arm in ("raw", "rtk"):
                m = c["arms"][arm]
                if not m.get("available"):
                    continue  # loghub RAW capsule
                p = REPO / m["source"]
                self.assertTrue(p.is_file(), f"{c['case']}/{arm} source missing")
                import hashlib
                self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), m["sha256"],
                                 f"{c['case']}/{arm} digest drift")

    def test_loghub_raw_is_bounded_capsule(self):
        lh = next(c for c in MANIFEST["cases"] if c["case"] == "loghub")
        self.assertFalse(lh["arms"]["raw"].get("available"))
        self.assertEqual(lh["arms"]["raw"].get("nature"), "bounded_capsule")
        self.assertTrue(lh["arms"]["rtk"]["available"])

    def test_tokenizers_pinned(self):
        tk = MANIFEST["tokenizers"]
        self.assertEqual(tk["primary"]["vocabulary"], "o200k_base")
        self.assertEqual(tk["secondary"]["vocabulary"], "cl100k_base")
        self.assertIn("tiktoken-rs", tk["primary"]["provider"])


class TestDigestGuards(unittest.TestCase):
    def test_load_arm_bytes_rejects_digest_drift(self):
        c = next(x for x in MANIFEST["cases"] if x["case"] == "rubocop")
        bad = copy.deepcopy(c["arms"]["raw"]); bad["sha256"] = "0" * 64
        with self.assertRaises(SystemExit):
            R._load_arm_bytes(bad)

    def test_load_arm_bytes_accepts_matching_digest(self):
        c = next(x for x in MANIFEST["cases"] if x["case"] == "rubocop")
        data = R._load_arm_bytes(c["arms"]["raw"])
        self.assertEqual(len(data), c["arms"]["raw"]["bytes"])


class TestMetrics(unittest.TestCase):
    def test_basic_metrics_valid_utf8(self):
        m = B.basic_metrics(b"hello\nworld\n")
        self.assertEqual(m["bytes"], 12)
        self.assertEqual(m["lines"], 2)
        self.assertTrue(m["valid_utf8"])
        self.assertEqual(m["unicode_chars"], 12)

    def test_basic_metrics_invalid_utf8(self):
        m = B.basic_metrics(b"\xff\xfe\x00bad")
        self.assertFalse(m["valid_utf8"])
        self.assertIsNone(m["unicode_chars"])
        self.assertEqual(m["bytes"], 6)

    def test_basic_metrics_no_trailing_newline_counts_last_line(self):
        self.assertEqual(B.basic_metrics(b"a\nb")["lines"], 2)
        self.assertEqual(B.basic_metrics(b"")["lines"], 0)

    def test_ratio_and_saving(self):
        self.assertEqual(B.ratio(50, 100), 0.5)
        self.assertAlmostEqual(B.saving_percent(50, 100), 50.0)
        self.assertIsNone(B.ratio(10, 0))       # zero-token raw -> undefined
        self.assertIsNone(B.saving_percent(10, None))
        self.assertAlmostEqual(B.saving_percent(120, 100), -20.0)  # output larger than raw


class TestSemanticClassification(unittest.TestCase):
    @unittest.skipUnless(HAVE_QODEC, "qodec release binary not built")
    def test_qodec_arm_lossless_pass(self):
        # PASS path tokenizes the artifact under the secondary meter, so it needs a real qodec.
        q = B.Qodec(QODEC, timeout=60)
        with tempfile.TemporaryDirectory() as td:
            enc = q.encode_deep(b"repeat me\n" * 20, "o200k", Path(td))
            arm = R._qodec_arm(q, enc, Path(td))
        self.assertEqual(arm["semantic_check"], B.PASS)
        self.assertTrue(arm["roundtrip_lossless"])

    def test_qodec_arm_lossy_fail(self):
        arm = R._qodec_arm(None, {"status": B.FAILED, "error": "roundtrip NOT byte-identical"}, Path("/"))
        self.assertEqual(arm["status"], B.FAILED)
        self.assertEqual(arm["semantic_check"], B.FAILED)

    def test_qodec_arm_timeout_unsupported(self):
        arm = R._qodec_arm(None, {"status": B.UNSUPPORTED, "error": "meter/codec timeout"}, Path("/"))
        self.assertEqual(arm["semantic_check"], B.UNSUPPORTED)


class TestAggregates(unittest.TestCase):
    def _synthetic(self):
        # raw/qodec token pairs designed to exercise weighted vs macro + a regression + a zero-raw case
        def case(name, fam, raw, rtk, qod, winner=None):
            def arm(tok, sem=B.PASS):
                return {"tokens": {"o200k": tok, "cl100k": tok}, "semantic_check": sem,
                        "pct_tokens_saved": {"o200k": B.saving_percent(tok, raw)}}
            c = {"case": name, "family": fam,
                 "arms": {"raw": {"tokens": {"o200k": raw, "cl100k": raw}, "semantic_check": "reference",
                                  "pct_tokens_saved": {"o200k": 0.0}},
                          "rtk": arm(rtk), "qodec": arm(qod),
                          "rtk_then_qodec": arm(qod)}}
            c["winner"] = winner
            return c
        return {"results": [
            case("big", "Large structured logs", 10000, 5000, 4000, "qodec"),
            case("small", "Test output", 100, 50, 120, "rtk"),   # qodec regresses on small
        ]}

    def test_aggregate_weighted_vs_macro(self):
        res = self._synthetic()
        g = R._aggregate(res, res["results"])["qodec"]
        # weighted dominated by big: (10000+100 raw) vs (4000+120) -> ~59.2%
        self.assertAlmostEqual(g["weighted_pct_tokens_saved"], 100 * (1 - (4000 + 120) / (10000 + 100)), places=4)
        # macro median of [60.0, -20.0]
        self.assertAlmostEqual(g["macro_median_pct_saved"], 20.0, places=4)
        self.assertEqual(g["cases_that_increased_text"], 1)  # 'small' regressed

    def test_winner_and_semantic_tally(self):
        res = self._synthetic()
        agg = R._aggregate(res, res["results"])
        self.assertEqual(agg["winners"]["qodec"], 1)
        self.assertEqual(agg["winners"]["rtk"], 1)
        self.assertEqual(agg["semantic_tally"][B.FAILED], 0)

    def test_loghub_excluded_subset(self):
        res = self._synthetic()
        no_log = [c for c in res["results"] if c["family"] != "Large structured logs"]
        self.assertEqual(len(no_log), 1)
        self.assertEqual(no_log[0]["case"], "small")


class TestFamilyGrouping(unittest.TestCase):
    def test_families_group_and_keep_case_identity(self):
        res = {"results": [
            {"case": "a", "family": "Test output",
             "arms": {k: {"pct_tokens_saved": {"o200k": 40.0}, "semantic_check": B.PASS} for k in
                      ("raw", "rtk", "qodec", "rtk_then_qodec")}},
            {"case": "b", "family": "Test output",
             "arms": {k: {"pct_tokens_saved": {"o200k": 10.0}, "semantic_check": B.PASS} for k in
                      ("raw", "rtk", "qodec", "rtk_then_qodec")}},
        ]}
        rows = R._family_stats(res)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["family"], "Test output")
        self.assertEqual(sorted(rows[0]["cases"]), ["a", "b"])
        self.assertEqual(rows[0]["n_cases"], 2)
        self.assertAlmostEqual(rows[0]["qodec_median_pct_saved"], 25.0)


class TestResultsIntegrity(unittest.TestCase):
    """The frozen results.json (if present) must not silently drop a case."""
    def test_no_case_disappears(self):
        rp = BENCH / "results.json"
        if not rp.is_file():
            self.skipTest("results.json not generated yet")
        res = json.loads(rp.read_text())
        self.assertEqual({c["case"] for c in res["results"]}, TWELVE)
        # per-case.csv must carry every case
        pc = (BENCH / "per-case.csv").read_text().splitlines()[1:]
        cases_in_csv = {ln.split(",", 1)[0] for ln in pc if ln}
        self.assertEqual(cases_in_csv, TWELVE)


@unittest.skipUnless(HAVE_QODEC, "qodec release binary not built")
class TestQodecAdapter(unittest.TestCase):
    def setUp(self):
        self.q = B.Qodec(QODEC, timeout=60)
        self._td = tempfile.TemporaryDirectory()
        self.wd = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def test_token_counting_deterministic_and_nonzero(self):
        data = b"the quick brown fox jumps over the lazy dog\n" * 4
        r1 = self.q.tokenize(data, "o200k", self.wd)
        r2 = self.q.tokenize(data, "o200k", self.wd)
        self.assertEqual(r1["status"], B.PASS)
        self.assertIsInstance(r1["tokens"], int)
        self.assertGreater(r1["tokens"], 0)
        self.assertEqual(r1["tokens"], r2["tokens"])  # deterministic

    def test_zero_length_input(self):
        r = self.q.tokenize(b"", "o200k", self.wd)
        self.assertEqual(r["status"], B.PASS)
        self.assertEqual(r["tokens"], 0)

    def test_invalid_utf8_handled_gracefully(self):
        # Qodec reads input as UTF-8 and errors on invalid UTF-8 (a documented limitation). The adapter
        # must classify that as failed/unsupported WITHOUT crashing, and never report a token count.
        r = self.q.tokenize(b"\xff\xfe\x00\x01rand\xc3", "o200k", self.wd)
        self.assertIn(r["status"], (B.FAILED, B.UNSUPPORTED))
        self.assertIsNone(r["tokens"])

    def test_roundtrip_lossless_and_gain(self):
        data = (b"ERROR at line 42: connection refused\n" * 30)
        enc = self.q.encode_deep(data, "o200k", self.wd)
        self.assertEqual(enc["status"], B.PASS)
        self.assertTrue(enc["roundtrip_lossless"])
        self.assertLess(enc["tokens_out"], enc["tokens_in"])  # repetitive input compresses

    def test_output_larger_than_raw_still_lossless(self):
        data = b"unique-\xe2\x9c\x93-prose no repetition here at all zzz\n"
        enc = self.q.encode_deep(data, "o200k", self.wd)
        self.assertEqual(enc["status"], B.PASS)
        self.assertTrue(enc["roundtrip_lossless"])  # even when it doesn't shrink, it's lossless

    def test_failed_process_no_partial_acceptance(self):
        bad = B.Qodec(Path("/nonexistent/qodec"), timeout=10)
        r = bad.tokenize(b"x", "o200k", self.wd)
        self.assertIn(r["status"], (B.FAILED, B.UNSUPPORTED))
        self.assertIsNone(r["tokens"])


if __name__ == "__main__":
    unittest.main()
