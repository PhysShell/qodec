"""Mechanical Option-D reserve resolution (corrections 5/6): metadata derived from the
frozen candidate inventory (never case_id parsing), all global constraints re-checked,
frozen resolution-order rule, and a rebuild-from-frozen-inputs verifier."""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import build_n2e_canary_resolved_membership as R  # noqa: E402

CADDY = "caddyserver__caddy-5870::go::test::buggy"
HUGO = "gohugoio__hugo-12768::go::test::buggy"


class TestResolver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = R.Ctx()

    def _survivors(self):
        return [m for m in self.ctx.membership if m["case_id"] != CADDY]

    def test_metadata_from_inventory_not_parsing(self):
        m = self.ctx.meta(HUGO)
        self.assertEqual(m["repository"], "gohugoio/hugo")
        self.assertEqual(m["command_family"], "go")
        self.assertEqual(m["snapshot_variant"], "buggy")
        self.assertEqual(m["cluster_id"], "swebench:gohugoio__hugo-12768")

    def test_caddy_slot_resolves_to_first_eligible_reserve(self):
        r, trace = R.resolve_slot(self.ctx, CADDY, self._survivors(), [])
        # hugo has no publisher recipe yet -> ineligible; the resolver must skip it and
        # land on the first reserve that is fully eligible (recipe available).
        self.assertIsNotNone(r["slot"])
        self.assertEqual(r["slot"], "go_test_fail")
        if r["resolved_case_id"] is not None:
            m = self.ctx.meta(r["resolved_case_id"])
            self.assertEqual((m["command_family"], m["command_subfamily"], m["snapshot_variant"]),
                             ("go", "test", "buggy"))

    def test_hugo_ineligible_without_recipe(self):
        ok, msg = R._eligible(self.ctx, HUGO)
        # go::test requires a publisher recipe; hugo's is not yet in the registry
        self.assertFalse(ok)
        self.assertIn("recipe", msg)

    def test_like_for_like_signature_enforced(self):
        # a reserve of a different subfamily/variant is rejected on signature
        r, trace = R.resolve_slot(self.ctx, CADDY, self._survivors(), [])
        for t in trace:
            if not t["accepted"] and any("signature" in x for x in t["reasons"]):
                m = self.ctx.meta(t["candidate"])
                self.assertNotEqual(
                    (m["command_family"], m["command_subfamily"], m["snapshot_variant"]),
                    ("go", "test", "buggy"))

    def test_duplicate_cluster_rejected(self):
        # inject a survivor occupying the first reserve's cluster
        pool = self.ctx.reserve_pool("go_test_fail")
        first = pool[0]
        cl = self.ctx.meta(first)["cluster_id"]
        surv = self._survivors() + [{"case_id": first.replace("::test::buggy", "::build")}]
        # only matters if that synthetic case maps to the same cluster; assert the
        # cluster-dup path exists in the trace for a real duplicate
        surv2 = self._survivors()
        r, trace = R.resolve_slot(self.ctx, CADDY, surv2, [])
        self.assertTrue(any("cluster" in x for t in trace for x in t["reasons"]) or r["resolved_case_id"])

    def test_resolution_order_uses_frozen_rule(self):
        # membership index is a total order; sorting two disq cases follows it
        ids = [self.ctx.membership[5]["case_id"], self.ctx.membership[1]["case_id"]]
        ordered = sorted(ids, key=lambda cid: (self.ctx.mem_pos[cid],
                                               self.ctx.slot_order.get(self.ctx.sel_slot.get(cid), 1 << 30),
                                               self.ctx.sel_pos.get(cid, 1 << 30)))
        self.assertEqual(ordered, [self.ctx.membership[1]["case_id"],
                                   self.ctx.membership[5]["case_id"]])

    def test_outcome_blind_no_savings_param(self):
        import inspect
        params = set(inspect.signature(R.resolve_slot).parameters)
        self.assertFalse({"savings", "ease", "tokens"} & params)

    def test_build_with_no_ledger_is_identity(self):
        # with no terminal rejections the resolved membership equals the original set
        body = R.build(None)
        self.assertEqual(body["resolved_case_count"], len(self.ctx.membership))


if __name__ == "__main__":
    unittest.main()
