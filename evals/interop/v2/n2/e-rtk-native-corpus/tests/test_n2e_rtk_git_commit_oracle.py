"""rtk-git-commit-oracle-v1: grounded in pinned RTK source (src/cmds/git/git_cmd.rs @5d32d07,
run_commit + classify_commit_outcome + parse_commit_output). `rtk git commit` preserves ONLY the
OUTCOME and the created commit's ABBREVIATED OID (`ok <7-hex>`); it drops the subject and reports no
parent/paths/author. The normative claim is the resulting-ref identity: under pinned determinants the
RAW and RTK full commit OIDs are EQUAL (the hash is never normalized), both parents == base, and the
RTK 7-hex is a prefix.
"""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_rtk_git_commit_oracle as orc  # noqa: E402

BASE = "f0a95a77782538eafca6c4d2f2f2792be3dbbfcf"
NEW = "abcd1234ef5678901234567890abcdef12345678"   # synthetic reproduced new-commit OID (prefix abcd123)
NAME_STATUS = b"A\tN2E_DIRTY.txt\n"


def _state(exit_code=0, head=NEW, parent=BASE, ns=NAME_STATUS):
    return orc.parse_git_state(exit_code, head, parent, ns, BASE)


class TestRtkParse(unittest.TestCase):
    def test_ok_with_hash(self):
        p = orc.parse_rtk(b"ok abcd123\n")
        self.assertTrue(p["derivable"] and p["created"])
        self.assertEqual(p["abbreviated_oid"], "abcd123")

    def test_ok_bare(self):
        p = orc.parse_rtk(b"ok\n")
        self.assertTrue(p["created"])
        self.assertIsNone(p["abbreviated_oid"])

    def test_failure_not_derivable(self):
        self.assertFalse(orc.parse_rtk(b"error: nothing to commit\n")["derivable"])


class TestGitState(unittest.TestCase):
    def test_committed(self):
        s = _state()
        self.assertTrue(s["derivable"] and s["created"])
        self.assertEqual(s["full_commit_oid"], NEW)
        self.assertEqual(s["parent_oid"], BASE)
        self.assertEqual(s["changed_paths"], ["N2E_DIRTY.txt"])

    def test_nonzero_exit_not_derivable(self):
        self.assertFalse(_state(exit_code=1)["derivable"])

    def test_head_still_base_not_created(self):
        s = _state(head=BASE, parent="0" * 40)
        self.assertFalse(s["created"])

    def test_parent_not_base_not_created(self):
        s = _state(parent="1" * 40)
        self.assertFalse(s["created"])


class TestEquivalence(unittest.TestCase):
    def test_green_reproducible(self):
        raw = _state(); rtk = _state()
        eq = orc.equivalence(raw, rtk, orc.parse_rtk(b"ok abcd123\n"), BASE)
        self.assertTrue(eq["equivalent"], eq["mismatches"])

    def test_oid_divergence_rejected(self):
        # the crux: a DIFFERENT resulting OID (a hidden determinant leaked) must be rejected, not
        # normalized away
        raw = _state(head=NEW)
        rtk = _state(head="ffff1234ef5678901234567890abcdef12345678")
        eq = orc.equivalence(raw, rtk, orc.parse_rtk(b"ok ffff123\n"), BASE)
        self.assertFalse(eq["equivalent"])
        self.assertIn("raw_commit_oid != rtk_commit_oid", eq["mismatches"])

    def test_abbrev_not_prefix_rejected(self):
        raw = _state(); rtk = _state()
        eq = orc.equivalence(raw, rtk, orc.parse_rtk(b"ok deadbee\n"), BASE)
        self.assertFalse(eq["equivalent"])
        self.assertIn("rtk_abbreviated_oid_not_prefix", eq["mismatches"])

    def test_raw_parent_not_base_rejected(self):
        raw = _state(parent="2" * 40, head=NEW)  # created False -> raw_did_not_create_commit
        rtk = _state()
        eq = orc.equivalence(raw, rtk, orc.parse_rtk(b"ok abcd123\n"), BASE)
        self.assertFalse(eq["equivalent"])

    def test_rtk_nonzero_exit_rejected(self):
        raw = _state(); rtk = _state(exit_code=1)
        eq = orc.equivalence(raw, rtk, orc.parse_rtk(b"ok abcd123\n"), BASE)
        self.assertFalse(eq["equivalent"])
        self.assertIn("rtk_state_not_derivable", eq["mismatches"])

    def test_rtk_output_says_failed_rejected(self):
        raw = _state(); rtk = _state()
        eq = orc.equivalence(raw, rtk, orc.parse_rtk(b"error\n"), BASE)
        self.assertFalse(eq["equivalent"])
        self.assertIn("rtk_output_not_committed", eq["mismatches"])

    def test_no_new_commit_rejected(self):
        # both arms report HEAD unchanged (nothing was committed) -> not equivalent
        raw = _state(head=BASE, parent="0" * 40)
        rtk = _state(head=BASE, parent="0" * 40)
        eq = orc.equivalence(raw, rtk, orc.parse_rtk(b"ok\n"), BASE)
        self.assertFalse(eq["equivalent"])


class TestSourceIdentity(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(orc.ORACLE_ID, "rtk-git-commit-oracle-v1")
        self.assertEqual(orc.RTK_SOURCE_COMMIT, "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2")
        self.assertEqual(orc.RTK_SOURCE_FILE, "src/cmds/git/git_cmd.rs")
        self.assertEqual(orc.RTK_SOURCE_FUNCTION, "run_commit")


if __name__ == "__main__":
    unittest.main()
