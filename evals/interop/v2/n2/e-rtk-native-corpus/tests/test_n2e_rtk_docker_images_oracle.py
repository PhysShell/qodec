"""rtk-docker-images-oracle-v1: grounded in pinned RTK source (src/cmds/cloud/container.rs @5d32d07,
docker_images). RTK's `docker images` filter emits ONLY repository:tag + human size (no image ID, no
digest, no CREATED); the oracle claims exactly that -- outcome + output_mode + count + (repo:tag,size)
multiset -- with the source's GB/MB-only total arithmetic. Identity lives in `docker image inspect`
(parse_inspect), proven as an execution determinant, not here.
"""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_rtk_docker_images_oracle as orc  # noqa: E402

# a single redis image, pulled by digest then tagged; the exact --format projection RTK derives from
RAW_FMT = b"redis:7.4.1\t117MB\n"
RTK_COMPACT = b"[docker] 1 images (117MB)\n  redis:7.4.1 [117MB]\n"
RTK_PASSTHROUGH = (b"REPOSITORY   TAG       IMAGE ID       CREATED       SIZE\n"
                   b"redis        7.4.1     abc123def456   2 weeks ago   117MB\n")


class TestTotalSize(unittest.TestCase):
    def test_mb_only(self):
        self.assertEqual(orc.total_size_display([("a", "117MB")]), "117MB")

    def test_gb_sum_over_1024(self):
        self.assertEqual(orc.total_size_display([("a", "1.5GB"), ("b", "600MB")]), "2.1GB")

    def test_kb_and_bytes_ignored(self):
        # the source only sums GB/MB tokens; kB and B contribute nothing
        self.assertEqual(orc.total_size_display([("a", "834kB"), ("b", "12B"), ("c", "50MB")]), "50MB")

    def test_boundary_exactly_1024_stays_mb(self):
        # source condition is > 1024.0 (strict), so exactly 1024MB displays as MB
        self.assertEqual(orc.total_size_display([("a", "1024MB")]), "1024MB")


class TestParseRtk(unittest.TestCase):
    def test_compact(self):
        p = orc.parse_rtk(RTK_COMPACT)
        self.assertEqual(p["output_mode"], "compact")
        self.assertEqual(p["header_count"], 1)
        self.assertEqual(p["rows"], [("redis:7.4.1", "117MB")])
        self.assertEqual(p["total_display"], "117MB")
        self.assertEqual(p["truncated"], 0)

    def test_passthrough(self):
        p = orc.parse_rtk(RTK_PASSTHROUGH)
        self.assertEqual(p["output_mode"], "passthrough")
        self.assertIsNone(p["rows"])

    def test_truncated_marker(self):
        data = b"[docker] 52 images (6.0GB)\n  a:1 [100MB]\n  \xe2\x80\xa6 +2 more\n"
        p = orc.parse_rtk(data)
        self.assertEqual(p["truncated"], 2)


class TestParseFormatRows(unittest.TestCase):
    def test_rows(self):
        p = orc.parse_format_rows(RAW_FMT)
        self.assertTrue(p["derivable"])
        self.assertEqual(p["rows"], [("redis:7.4.1", "117MB")])
        self.assertEqual(p["count"], 1)

    def test_empty_not_derivable(self):
        self.assertFalse(orc.parse_format_rows(b"\n")["derivable"])


class TestEquivalence(unittest.TestCase):
    def test_green_compact(self):
        eq = orc.equivalence(orc.parse_format_rows(RAW_FMT), orc.parse_rtk(RTK_COMPACT))
        self.assertTrue(eq["equivalent"], eq["mismatches"])
        self.assertEqual(eq["output_mode"], "compact")
        self.assertEqual(eq["image_count"], 1)

    def test_multiset_mismatch_rejected(self):
        raw = orc.parse_format_rows(b"redis:7.4.1\t117MB\n")
        rtk = orc.parse_rtk(b"[docker] 1 images (117MB)\n  redis:7.4.0 [117MB]\n")  # wrong tag
        eq = orc.equivalence(raw, rtk)
        self.assertFalse(eq["equivalent"])
        self.assertIn("listing_multiset_raw != rtk", eq["mismatches"])

    def test_size_mismatch_rejected(self):
        raw = orc.parse_format_rows(b"redis:7.4.1\t117MB\n")
        rtk = orc.parse_rtk(b"[docker] 1 images (120MB)\n  redis:7.4.1 [120MB]\n")  # size differs
        eq = orc.equivalence(raw, rtk)
        self.assertFalse(eq["equivalent"])
        self.assertIn("listing_multiset_raw != rtk", eq["mismatches"])

    def test_count_mismatch_rejected(self):
        raw = orc.parse_format_rows(b"redis:7.4.1\t117MB\nnginx:1.27\t60MB\n")
        rtk = orc.parse_rtk(b"[docker] 1 images (117MB)\n  redis:7.4.1 [117MB]\n")
        eq = orc.equivalence(raw, rtk)
        self.assertFalse(eq["equivalent"])
        self.assertIn("raw_count != rtk_count", eq["mismatches"])

    def test_header_count_unfaithful_rejected(self):
        raw = orc.parse_format_rows(RAW_FMT)
        rtk = orc.parse_rtk(b"[docker] 5 images (117MB)\n  redis:7.4.1 [117MB]\n")  # header lies
        eq = orc.equivalence(raw, rtk)
        self.assertFalse(eq["equivalent"])
        self.assertIn("rtk_header_count != rtk_row_count", eq["mismatches"])

    def test_header_total_unfaithful_rejected(self):
        raw = orc.parse_format_rows(RAW_FMT)
        rtk = orc.parse_rtk(b"[docker] 1 images (999MB)\n  redis:7.4.1 [117MB]\n")  # total lies
        eq = orc.equivalence(raw, rtk)
        self.assertFalse(eq["equivalent"])
        self.assertIn("rtk_header_total != recomputed_from_rows", eq["mismatches"])

    def test_passthrough_rejected_by_default(self):
        eq = orc.equivalence(orc.parse_format_rows(RAW_FMT), orc.parse_rtk(RTK_PASSTHROUGH))
        self.assertFalse(eq["equivalent"])
        self.assertIn("rtk_never_worse_passthrough_rejected", eq["mismatches"])

    def test_passthrough_allowed_when_policy_opts_in(self):
        eq = orc.equivalence(orc.parse_format_rows(RAW_FMT), orc.parse_rtk(RTK_PASSTHROUGH),
                             allow_passthrough=True)
        self.assertTrue(eq["equivalent"])
        self.assertEqual(eq["output_mode"], "passthrough")

    def test_truncated_over_cap_rejected(self):
        raw = orc.parse_format_rows(b"".join(b"img%d:1\t10MB\n" % i for i in range(52)))
        rtk_rows = b"".join(b"  img%d:1 [10MB]\n" % i for i in range(50))
        rtk = orc.parse_rtk(b"[docker] 52 images (520MB)\n" + rtk_rows + b"  \xe2\x80\xa6 +2 more\n")
        eq = orc.equivalence(raw, rtk)
        self.assertFalse(eq["equivalent"])
        self.assertIn("rtk_output_truncated_over_cap", eq["mismatches"])


class TestParseInspect(unittest.TestCase):
    def test_single_image(self):
        data = (b'[{"Id":"sha256:395033a3","RepoDigests":["redis@sha256:c1e88455"],'
                b'"RepoTags":["redis:7.4.1"],"Architecture":"amd64","Os":"linux","Size":117000000}]')
        p = orc.parse_inspect(data)
        self.assertTrue(p["derivable"])
        self.assertEqual(p["architecture"], "amd64")
        self.assertEqual(p["repo_digests"], ["redis@sha256:c1e88455"])

    def test_multi_image_rejected(self):
        self.assertFalse(orc.parse_inspect(b"[{},{}]")["derivable"])


class TestSourceIdentity(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(orc.ORACLE_ID, "rtk-docker-images-oracle-v1")
        self.assertEqual(orc.RTK_SOURCE_COMMIT, "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2")
        self.assertEqual(orc.RTK_SOURCE_FILE, "src/cmds/cloud/container.rs")
        self.assertEqual(orc.RTK_SOURCE_FUNCTION, "docker_images")
        self.assertEqual(orc.CAP_INVENTORY, 50)


if __name__ == "__main__":
    unittest.main()
