"""Mechanical Option-D reserve resolution: outcome-blind, frozen-order, constraint-
re-checking. Uses the REAL frozen selection/reserve records for the caddy slot plus
synthetic constraint scenarios."""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import build_n2e_canary_resolved_membership as R  # noqa: E402
import n2e_common as c  # noqa: E402

CADDY = "caddyserver__caddy-5870::go::test::buggy"
SEL = c.load_record(R.SELECTION)["selection"]
RES = c.load_record(R.RESERVES)["reserves"]
MEM = c.load_record(R.MEMBERSHIP)["membership"]


class TestRepoDerivation(unittest.TestCase):
    def test_repository(self):
        self.assertEqual(R._repository("gohugoio__hugo-12768::go::test::buggy"), "gohugoio/hugo")
        self.assertEqual(R._repository("caddyserver__caddy-5870::go::test::buggy"), "caddyserver/caddy")

    def test_cluster(self):
        self.assertEqual(R._cluster("gohugoio__hugo-12768::go::test::buggy"),
                         "swebench:gohugoio__hugo-12768")


class TestCaddyResolution(unittest.TestCase):
    def _survivors(self):
        return [m for m in MEM if m["case_id"] != CADDY]

    def test_first_reserve_wins_when_unconstrained(self):
        r, trace = R.resolve_slot(CADDY, self._survivors(), [], SEL, RES, 2)
        self.assertEqual(r["resolved_case_id"], "gohugoio__hugo-12768::go::test::buggy")
        self.assertEqual(r["reserve_rank"], 0)
        self.assertEqual(r["slot"], "go_test_fail")
        self.assertTrue(trace[0]["accepted"])

    def test_like_for_like_signature(self):
        r, _ = R.resolve_slot(CADDY, self._survivors(), [], SEL, RES, 2)
        self.assertEqual(r["resolved_case_id"].split("::")[1:], CADDY.split("::")[1:])

    def test_skips_candidate_that_duplicates_a_surviving_cluster(self):
        # inject a survivor occupying the first reserve's cluster -> resolver skips it
        surv = self._survivors() + [{"case_id": "gohugoio__hugo-12768::go::build"}]
        r, trace = R.resolve_slot(CADDY, surv, [], SEL, RES, 2)
        self.assertNotEqual(r["resolved_case_id"], "gohugoio__hugo-12768::go::test::buggy")
        self.assertFalse(trace[0]["accepted"])
        self.assertIn("duplicate source cluster", trace[0]["reasons"])

    def test_respects_repository_cap(self):
        # two survivors already on gohugoio/hugo (cap=2) -> a 3rd hugo reserve is rejected
        surv = self._survivors() + [{"case_id": "gohugoio__hugo-1::go::vet"},
                                    {"case_id": "gohugoio__hugo-2::go::build"}]
        r, trace = R.resolve_slot(CADDY, surv, [], SEL, RES, 2)
        # the winner must not be on gohugoio/hugo
        self.assertNotEqual(R._repository(r["resolved_case_id"]), "gohugoio/hugo")

    def test_outcome_blind_no_savings_field_consulted(self):
        # resolve_slot signature takes no savings/ease input at all
        import inspect
        params = set(inspect.signature(R.resolve_slot).parameters)
        self.assertFalse({"savings", "ease", "tokens"} & params)


if __name__ == "__main__":
    unittest.main()
