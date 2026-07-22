"""rtk-git-show-merge-first-parent-oracle-v1: case-scoped to the rubocop merge commit f0ec1b58...
The diagnostic proved bare `git show` on a merge shows NO diff (degenerate RAW), so authority is split
EXPLICITLY: RAW = identity + topology, git plumbing = first-parent delta (numstat+shortstat, agreeing;
NOT empty --name-status), RTK = compact stat. Equivalence requires all conditions; raw_fallback is
rejected. Covers the mandatory RED matrix.
"""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_rtk_git_show_merge_oracle as mo  # noqa: E402

MERGE = "f0ec1b58283bbf89625883b45d2aec5e515c95b3"
P1 = "f852457aa0d3d0b7f0b0a6b1d3c8e9f0a1b2c3d4"    # synthetic full first parent (prefix f852457)
P2 = "0a417350000000000000000000000000000000aa"    # synthetic full second parent (prefix 0a41735)
PATH = "spec/rubocop/cop/style/redundant_line_continuation_spec.rb"

RAW_MERGE = (
    f"commit {MERGE}\n"
    "Merge: f852457 0a41735\n"
    "Author: Daniel Vandersluis <daniel.vandersluis@gmail.com>\n"
    "Date:   Mon Jan 13 16:25:34 2025 -0500\n\n"
    "    Merge pull request #13691 ...\n").encode()

REVLIST = f"{MERGE} {P1} {P2}\n"
NUMSTAT_FP = f"15\t1\t{PATH}\n".encode()
SHORTSTAT_FP = b" 1 file changed, 15 insertions(+), 1 deletion(-)\n"
SHOW_STAT = (f" {PATH} | 16 +++++++++++++++-\n"
             " 1 file changed, 15 insertions(+), 1 deletion(-)\n").encode()
RTK_COMPACT = (
    f"f0ec1b5 Merge pull request #13691 (2 years ago) <Daniel Vandersluis>\n"
    f" {PATH} | 16 +++++++++++++++-\n"
    " 1 file changed, 15 insertions(+), 1 deletion(-)\n").encode()


def _ids():
    return (mo.parse_raw_merge_identity(RAW_MERGE),
            mo.parse_first_parent_stat(NUMSTAT_FP, SHORTSTAT_FP),
            mo.parse_rtk_compact(RTK_COMPACT),
            mo.parse_rev_list_parents(REVLIST))


class TestParsers(unittest.TestCase):
    def test_raw_identity_topology(self):
        r = mo.parse_raw_merge_identity(RAW_MERGE)
        self.assertTrue(r["derivable"] and r["is_merge"])
        self.assertEqual(r["full_commit_oid"], MERGE)
        self.assertEqual(r["abbreviated_parents"], ["f852457", "0a41735"])
        self.assertFalse(r["raw_has_diff"])           # expected: merge shows no diff

    def test_first_parent_stat_numstat_shortstat_agree(self):
        fp = mo.parse_first_parent_stat(NUMSTAT_FP, SHORTSTAT_FP)
        self.assertTrue(fp["derivable"])
        self.assertEqual((fp["files_changed"], fp["insertions"], fp["deletions"]), (1, 15, 1))
        self.assertEqual(fp["affected_paths"], [PATH])

    def test_first_parent_stat_disagreement_rejected(self):
        bad = b" 1 file changed, 99 insertions(+), 1 deletion(-)\n"
        self.assertFalse(mo.parse_first_parent_stat(NUMSTAT_FP, bad)["derivable"])

    def test_show_stat_crosscheck(self):
        ss = mo.parse_show_stat_crosscheck(SHOW_STAT)
        self.assertEqual((ss["files_changed"], ss["insertions"], ss["deletions"]), (1, 15, 1))
        self.assertEqual(ss["affected_paths"], [PATH])

    def test_rtk_compact_ok(self):
        p = mo.parse_rtk_compact(RTK_COMPACT)
        self.assertEqual(p["rtk_output_mode"], "compact")
        self.assertEqual(p["abbreviated_oid"], "f0ec1b5")

    def test_rev_list_parents(self):
        pp = mo.parse_rev_list_parents(REVLIST)
        self.assertEqual(pp["merge_oid"], MERGE)
        self.assertEqual(pp["first_parent_oid"], P1)
        self.assertEqual(pp["parents"], [P1, P2])


class TestEquivalenceGreen(unittest.TestCase):
    def test_green(self):
        raw, fp, rtk, pp = _ids()
        eq = mo.equivalence(raw, fp, rtk, pp, MERGE, MERGE)   # abbrev uniquely resolves to MERGE
        self.assertTrue(eq["equivalent"], eq["mismatches"])
        self.assertEqual(eq["first_parent_oid"], P1)


class TestRedMatrix(unittest.TestCase):
    def setUp(self):
        self.raw, self.fp, self.rtk, self.pp = _ids()

    def _eq(self, **over):
        a = dict(raw_id=self.raw, fp_stat=self.fp, rtk=self.rtk, plumbing_parents=self.pp,
                 contract_oid=MERGE, abbrev_resolved_oid=MERGE)
        a.update(over)
        return mo.equivalence(a["raw_id"], a["fp_stat"], a["rtk"], a["plumbing_parents"],
                              a["contract_oid"], a["abbrev_resolved_oid"])

    def test_red_rtk_totals_match_second_parent(self):
        # RTK stat reflects a DIFFERENT delta than the first-parent authority -> reject
        rtk2 = mo.parse_rtk_compact(RTK_COMPACT.replace(b"15 insertions(+)", b"40 insertions(+)"))
        eq = self._eq(rtk=rtk2)
        self.assertFalse(eq["equivalent"])
        self.assertIn("stat.insertions", eq["mismatches"])

    def test_red_parent_order_changed(self):
        pp2 = mo.parse_rev_list_parents(f"{MERGE} {P2} {P1}\n")   # swapped
        eq = self._eq(plumbing_parents=pp2)
        self.assertFalse(eq["equivalent"])
        self.assertIn("parent_order_or_identity_mismatch", eq["mismatches"])

    def test_red_same_stat_different_path(self):
        rtk2 = mo.parse_rtk_compact(RTK_COMPACT.replace(PATH.encode(), b"lib/OTHER.rb"))
        eq = self._eq(rtk=rtk2)
        self.assertFalse(eq["equivalent"])
        self.assertIn("affected_paths", eq["mismatches"])

    def test_red_abbrev_not_prefix(self):
        rtk2 = mo.parse_rtk_compact(RTK_COMPACT.replace(b"f0ec1b5 ", b"deadbee ", 1))
        eq = self._eq(rtk=rtk2)
        self.assertFalse(eq["equivalent"])
        self.assertIn("abbreviated_oid_not_prefix", eq["mismatches"])

    def test_red_abbrev_ambiguous_not_uniquely_resolved(self):
        # prefix is fine, but git could not uniquely resolve it (rev-parse returned a different/empty oid)
        eq = self._eq(abbrev_resolved_oid="0" * 40)
        self.assertFalse(eq["equivalent"])
        self.assertIn("abbreviated_oid_not_uniquely_resolved", eq["mismatches"])

    def test_red_plumbing_on_different_commit(self):
        pp2 = mo.parse_rev_list_parents(f"{'0'*40} {P1} {P2}\n")   # plumbing merge oid != contract
        eq = self._eq(plumbing_parents=pp2)
        self.assertFalse(eq["equivalent"])
        self.assertIn("plumbing_merge_oid != contract_oid", eq["mismatches"])

    def test_red_metadata_claims_merge_but_single_parent(self):
        pp1 = mo.parse_rev_list_parents(f"{MERGE} {P1}\n")   # only ONE parent -> not a merge
        eq = self._eq(plumbing_parents=pp1)
        self.assertFalse(eq["equivalent"])
        self.assertIn("plumbing_not_merge", eq["mismatches"])

    def test_red_raw_fallback_rejected_as_not_derivable(self):
        # RTK emitted raw git show (never_worse fallback) -> not derivable for this case
        raw_fallback = (f"commit {MERGE}\nMerge: f852457 0a41735\nAuthor: x <x>\n\n    subj\n").encode()
        p = mo.parse_rtk_compact(raw_fallback)
        self.assertFalse(p["derivable"])
        eq = self._eq(rtk=p)
        self.assertFalse(eq["equivalent"])
        self.assertIn("rtk_not_derivable", eq["mismatches"])

    def test_red_empty_name_status_is_not_zero_files(self):
        # the merge trap: empty --name-status must NOT be read as "0 files". The first-parent stat
        # authority is numstat+shortstat, which still report the real change.
        fp = mo.parse_first_parent_stat(NUMSTAT_FP, SHORTSTAT_FP)
        self.assertTrue(fp["derivable"] and fp["files_changed"] == 1)
        # name-status parsing of an empty merge output yields [] but is never the stat authority
        import n2e_rtk_git_show_oracle as base
        self.assertEqual(base.parse_name_status(b"\n"), [])

    def test_red_raw_not_merge(self):
        raw1 = mo.parse_raw_merge_identity(
            (f"commit {MERGE}\nAuthor: x <x>\nDate: d\n\n    subj\n"
             "diff --git a/f b/f\n@@ -1 +1 @@\n-x\n+y\n").encode())
        eq = self._eq(raw_id=raw1)
        self.assertFalse(eq["equivalent"])
        self.assertIn("raw_not_merge", eq["mismatches"])

    def test_red_rtk_raw_fallback_mode_guard(self):
        # even if a projection were derivable but mode != compact, the mode guard rejects it
        rtk = dict(mo.parse_rtk_compact(RTK_COMPACT)); rtk["rtk_output_mode"] = "raw_fallback"
        eq = self._eq(rtk=rtk)
        self.assertFalse(eq["equivalent"])
        self.assertIn("rtk_output_mode_not_compact", eq["mismatches"])


class TestSourceIdentity(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(mo.ORACLE_ID, "rtk-git-show-merge-first-parent-oracle-v1")
        self.assertEqual(mo.RTK_SOURCE_COMMIT, "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2")
        self.assertEqual(mo.RTK_SOURCE_FILE, "src/cmds/git/git_cmd.rs")


if __name__ == "__main__":
    unittest.main()
