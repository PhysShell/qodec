"""rtk-git-show-oracle-v1: grounded in pinned RTK source (src/cmds/git/git_cmd.rs @5d32d07, run_show
+ compact_diff; core/guard.rs never_worse). `rtk git show` preserves the STAT + IDENTITY core
(full_commit_oid via abbreviated-prefix, affected_paths set, files_changed/insertions/deletions);
%ar / author / subject / dates / full patch are non-normative. parse_rtk supports BOTH legitimate
output modes (compact | raw_fallback) and REJECTS a compact-looking-but-incomplete output instead of
silently reparsing it as RAW. RAW insertions/deletions are counted inside hunks only (never the
+++/--- headers or binary markers).
"""
import hashlib
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_rtk_git_show_oracle as orc  # noqa: E402

OID = "f0ec1b58283bbf89625883b45d2aec5e515c95b3"
ABBR = "f0ec1b58"


def raw_show(commit, body_diff):
    hdr = (f"commit {commit}\n"
           "Author: A Dev <dev@example.com>\n"
           "Date:   Mon Jan 1 00:00:00 2024 +0000\n\n"
           "    Some subject line\n\n")
    return (hdr + body_diff).encode()


# a two-file modify: lib/a.rb (+2 -1), lib/b.rb (+1 -0)
DIFF_TWO = (
    "diff --git a/lib/a.rb b/lib/a.rb\n"
    "index 111..222 100644\n"
    "--- a/lib/a.rb\n"
    "+++ b/lib/a.rb\n"
    "@@ -1,3 +1,4 @@\n"
    " context\n"
    "+added one\n"
    "+added two\n"
    "-removed one\n"
    " context\n"
    "diff --git a/lib/b.rb b/lib/b.rb\n"
    "index 333..444 100644\n"
    "--- a/lib/b.rb\n"
    "+++ b/lib/b.rb\n"
    "@@ -0,0 +1 @@\n"
    "+only added\n")

COMPACT_TWO = (
    f"{ABBR} Some subject (2 years ago) <A Dev>\n"
    " lib/a.rb | 3 +++-\n"
    " lib/b.rb | 1 +\n"
    " 2 files changed, 3 insertions(+), 1 deletion(-)\n"
    "\nlib/a.rb\n"
    "  @@ -1,3 +1,4 @@\n"
    "  +added one\n"
    "  +added two\n"
    "  -removed one\n"
    "  +2 -1\n"
    "\nlib/b.rb\n"
    "  @@ -0,0 +1 @@\n"
    "  +only added\n"
    "  +1 -0\n").encode()


class TestRawProjection(unittest.TestCase):
    def test_two_file_modify(self):
        p = orc.parse_raw(raw_show(OID, DIFF_TWO))
        self.assertTrue(p["derivable"])
        self.assertEqual(p["full_commit_oid"], OID)
        self.assertEqual(p["files_changed"], 2)
        self.assertEqual((p["insertions"], p["deletions"]), (3, 1))
        self.assertEqual(p["affected_paths"], ["lib/a.rb", "lib/b.rb"])

    def test_no_commit_header_not_derivable(self):
        self.assertFalse(orc.parse_raw(b"diff --git a/x b/x\n")["derivable"])

    def test_plus_plus_content_line_counts_once(self):
        # a hunk content line that is C++-ish "++counter" must count as ONE insertion, and the
        # `+++ b/file` / `--- a/file` HEADERS must never be counted
        d = ("diff --git a/c.rb b/c.rb\nindex 1..2 100644\n--- a/c.rb\n+++ b/c.rb\n"
             "@@ -1 +1,2 @@\n ctx\n+++counter\n")
        p = orc.parse_raw(raw_show(OID, d))
        self.assertEqual((p["insertions"], p["deletions"]), (1, 0))

    def test_binary_file(self):
        d = ("diff --git a/img.png b/img.png\nindex 1..2 100644\n"
             "Binary files a/img.png and b/img.png differ\n")
        p = orc.parse_raw(raw_show(OID, d))
        self.assertEqual(p["files_changed"], 1)
        self.assertEqual((p["insertions"], p["deletions"]), (0, 0))
        self.assertEqual(p["binary_paths"], ["img.png"])

    def test_rename_uses_new_path(self):
        d = ("diff --git a/old/name.rb b/new/name.rb\nsimilarity index 100%\n"
             "rename from old/name.rb\nrename to new/name.rb\n")
        p = orc.parse_raw(raw_show(OID, d))
        self.assertEqual(p["files_changed"], 1)
        self.assertEqual(p["affected_paths"], ["new/name.rb"])
        self.assertEqual((p["insertions"], p["deletions"]), (0, 0))

    def test_copy_uses_new_path(self):
        d = ("diff --git a/src.rb b/copy.rb\nsimilarity index 100%\n"
             "copy from src.rb\ncopy to copy.rb\n")
        p = orc.parse_raw(raw_show(OID, d))
        self.assertEqual(p["affected_paths"], ["copy.rb"])

    def test_deletion_uses_a_side_path(self):
        d = ("diff --git a/gone.rb b/gone.rb\ndeleted file mode 100644\nindex 1..0\n"
             "--- a/gone.rb\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-line one\n-line two\n")
        p = orc.parse_raw(raw_show(OID, d))
        self.assertEqual(p["affected_paths"], ["gone.rb"])
        self.assertEqual((p["insertions"], p["deletions"]), (0, 2))

    def test_mode_only_change(self):
        d = ("diff --git a/script.sh b/script.sh\nold mode 100644\nnew mode 100755\n")
        p = orc.parse_raw(raw_show(OID, d))
        self.assertEqual(p["files_changed"], 1)
        self.assertEqual((p["insertions"], p["deletions"]), (0, 0))
        self.assertEqual(p["affected_paths"], ["script.sh"])

    def test_quoted_path_with_space(self):
        d = ('diff --git "a/dir/f g.rb" "b/dir/f g.rb"\nindex 1..2 100644\n'
             '--- "a/dir/f g.rb"\n+++ "b/dir/f g.rb"\n@@ -1 +1 @@\n-x\n+y\n')
        p = orc.parse_raw(raw_show(OID, d))
        self.assertEqual(p["affected_paths"], ["dir/f g.rb"])
        self.assertEqual((p["insertions"], p["deletions"]), (1, 1))


class TestRtkParseCompact(unittest.TestCase):
    def test_compact_projection(self):
        p = orc.parse_rtk(COMPACT_TWO)
        self.assertTrue(p["derivable"])
        self.assertEqual(p["rtk_output_mode"], "compact")
        self.assertEqual(p["abbreviated_oid"], ABBR)
        self.assertEqual(p["files_changed"], 2)
        self.assertEqual((p["insertions"], p["deletions"]), (3, 1))
        self.assertEqual(p["affected_paths"], ["lib/a.rb", "lib/b.rb"])

    def test_compact_stat_rename_compression_expands(self):
        out = (f"{ABBR} subj (x) <a>\n"
               " lib/{old => new}/f.rb | 2 +-\n"
               " 1 file changed, 1 insertion(+), 1 deletion(-)\n").encode()
        p = orc.parse_rtk(out)
        self.assertEqual(p["affected_paths"], ["lib/new/f.rb"])

    def test_compact_singular_stat_summary(self):
        out = (f"{ABBR} subj (x) <a>\n"
               " a.rb | 1 +\n"
               " 1 file changed, 1 insertion(+)\n").encode()
        p = orc.parse_rtk(out)
        self.assertEqual((p["files_changed"], p["insertions"], p["deletions"]), (1, 1, 0))

    def test_compact_incomplete_is_rejected_not_reparsed_as_raw(self):
        # compact-looking (abbrev summary + a stat-ish line) but NO `N files changed` summary line
        out = (f"{ABBR} subj (x) <a>\n"
               " lib/a.rb | 3 +++-\n"
               "\nlib/a.rb\n  @@ -1 +1 @@\n  +truncated here\n").encode()
        p = orc.parse_rtk(out)
        self.assertFalse(p["derivable"])
        self.assertIn("files changed", p["reason"])


class TestRtkParseRawFallback(unittest.TestCase):
    def test_raw_fallback_parsed_as_raw(self):
        p = orc.parse_rtk(raw_show(OID, DIFF_TWO))
        self.assertTrue(p["derivable"])
        self.assertEqual(p["rtk_output_mode"], "raw_fallback")
        self.assertEqual(p["abbreviated_oid"], OID)
        self.assertEqual(p["files_changed"], 2)
        self.assertEqual((p["insertions"], p["deletions"]), (3, 1))


class TestEquivalence(unittest.TestCase):
    def test_green_compact(self):
        raw = orc.parse_raw(raw_show(OID, DIFF_TWO))
        rtk = orc.parse_rtk(COMPACT_TWO)
        eq = orc.equivalence(raw, rtk, OID)
        self.assertTrue(eq["equivalent"], eq)
        self.assertEqual(eq["rtk_output_mode"], "compact")

    def test_green_raw_fallback(self):
        raw = orc.parse_raw(raw_show(OID, DIFF_TWO))
        rtk = orc.parse_rtk(raw_show(OID, DIFF_TWO))
        self.assertTrue(orc.equivalence(raw, rtk, OID)["equivalent"])

    def test_abbrev_not_prefix_rejected(self):
        raw = orc.parse_raw(raw_show(OID, DIFF_TWO))
        rtk = orc.parse_rtk(COMPACT_TWO)
        eq = orc.equivalence(raw, rtk, "aaaa" + OID[4:])  # different full oid -> abbrev not a prefix
        self.assertFalse(eq["equivalent"])
        self.assertIn("abbreviated_oid_not_prefix", eq["mismatches"])

    def test_raw_commit_oid_must_equal_pinned(self):
        raw = orc.parse_raw(raw_show("0" * 40, DIFF_TWO))
        rtk = orc.parse_rtk(COMPACT_TWO)
        eq = orc.equivalence(raw, rtk, OID)
        self.assertFalse(eq["equivalent"])
        self.assertIn("raw_commit_oid", eq["mismatches"])

    def test_same_totals_different_paths_rejected(self):
        # the user's explicit trap: identical files_changed/insertions/deletions but a DIFFERENT
        # affected-path set must NOT be equivalent
        raw = orc.parse_raw(raw_show(OID, DIFF_TWO))
        rtk = orc.parse_rtk(COMPACT_TWO.replace(b"lib/b.rb", b"lib/OTHER.rb"))
        eq = orc.equivalence(raw, rtk, OID)
        self.assertFalse(eq["equivalent"])
        self.assertIn("affected_paths", eq["mismatches"])

    def test_stat_total_mismatch_rejected(self):
        raw = orc.parse_raw(raw_show(OID, DIFF_TWO))
        rtk = orc.parse_rtk(COMPACT_TWO.replace(b"3 insertions(+)", b"9 insertions(+)"))
        eq = orc.equivalence(raw, rtk, OID)
        self.assertFalse(eq["equivalent"])
        self.assertIn("insertions", eq["mismatches"])

    def test_not_derivable_rejected(self):
        raw = orc.parse_raw(raw_show(OID, DIFF_TWO))
        self.assertFalse(orc.equivalence(raw, orc._not_derivable("x"), OID)["equivalent"])


class TestPlumbingAuthority(unittest.TestCase):
    def test_numstat_totals_paths_binary(self):
        ns = orc.parse_numstat(b"2\t1\tlib/a.rb\n1\t0\tlib/b.rb\n-\t-\timg.png\n")
        self.assertEqual(ns["files_changed"], 3)
        self.assertEqual((ns["insertions"], ns["deletions"]), (3, 1))
        self.assertEqual(ns["affected_paths"], ["img.png", "lib/a.rb", "lib/b.rb"])
        self.assertEqual(ns["binary_paths"], ["img.png"])

    def test_numstat_rename_resulting_path(self):
        ns = orc.parse_numstat(b"0\t0\tlib/{old => new}/f.rb\n")
        self.assertEqual(ns["affected_paths"], ["lib/new/f.rb"])

    def test_name_status_paths(self):
        nsp = orc.parse_name_status(b"M\tlib/a.rb\nR100\told/x.rb\tnew/x.rb\nD\tgone.rb\n")
        self.assertEqual(nsp, ["gone.rb", "lib/a.rb", "new/x.rb"])

    def test_shortstat(self):
        ss = orc.parse_shortstat(b" 2 files changed, 3 insertions(+), 1 deletion(-)\n")
        self.assertEqual((ss["files_changed"], ss["insertions"], ss["deletions"]), (2, 3, 1))

    def test_crosscheck_consistent(self):
        raw = orc.parse_raw(raw_show(OID, DIFF_TWO))
        cc = orc.plumbing_crosscheck(
            raw, OID,
            b"2\t1\tlib/a.rb\n1\t0\tlib/b.rb\n",
            b"M\tlib/a.rb\nA\tlib/b.rb\n",
            b" 2 files changed, 3 insertions(+), 1 deletion(-)\n", OID)
        self.assertTrue(cc["consistent"], cc["mismatches"])

    def test_crosscheck_detects_path_disagreement(self):
        raw = orc.parse_raw(raw_show(OID, DIFF_TWO))
        cc = orc.plumbing_crosscheck(
            raw, OID,
            b"2\t1\tlib/a.rb\n1\t0\tlib/OTHER.rb\n",
            b"M\tlib/a.rb\nA\tlib/OTHER.rb\n",
            b" 2 files changed, 3 insertions(+), 1 deletion(-)\n", OID)
        self.assertFalse(cc["consistent"])
        self.assertIn("numstat.affected_paths", cc["mismatches"])

    def test_crosscheck_detects_head_mismatch(self):
        raw = orc.parse_raw(raw_show(OID, DIFF_TWO))
        cc = orc.plumbing_crosscheck(
            raw, "0" * 40,
            b"2\t1\tlib/a.rb\n1\t0\tlib/b.rb\n",
            b"M\tlib/a.rb\nA\tlib/b.rb\n",
            b" 2 files changed, 3 insertions(+), 1 deletion(-)\n", OID)
        self.assertFalse(cc["consistent"])
        self.assertIn("rev_parse_head != pinned_oid", cc["mismatches"])


class TestSourceIdentity(unittest.TestCase):
    def test_pinned_sources_match_committed(self):
        expect = {
            "git_cmd.rs": "28afec6faa88abf611f4e4963a931cce5d91bc8428854c3d0144a7a959c41726",
            "diff_cmd.rs": "42d6786800d6085576100dcf2f57ae46e157ed6e957a43ac1b7705119120f4e9",
            "guard.rs": "446015732c47b0b726b10141e0e7460836067ad6a39d1633535544a1427485c4",
        }
        for name, sha in expect.items():
            p = N2E_DIR / "evidence" / "rtk-source" / name
            self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), sha, name)
        self.assertEqual(orc.RTK_SOURCE_COMMIT, "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2")
        self.assertEqual(orc.RTK_SOURCE_FILE, "src/cmds/git/git_cmd.rs")


if __name__ == "__main__":
    unittest.main()
