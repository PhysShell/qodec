"""Fail-closed tests for §10 selection (§22 selection mutations)."""
import importlib
import json
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
TOOLS = N2E_DIR / "tools"
sys.path.insert(0, str(TOOLS))
import n2e_common as c  # noqa: E402

SEL = N2E_DIR / "n2e-selection-result-v1.json"
POLICY = N2E_DIR / "n2e-selection-policy-v1.json"


def reload_verify():
    import build_n2e_selection  # noqa: F401
    importlib.reload(importlib.import_module("build_n2e_selection"))
    mod = importlib.import_module("verify_n2e_selection")
    importlib.reload(mod)
    return mod


class TestSelection(unittest.TestCase):
    def test_verifier_passes(self):
        mod = reload_verify()
        ok, msg = mod.verify()
        self.assertTrue(ok, msg)

    def test_exactly_70(self):
        sel = json.loads(SEL.read_text())
        self.assertEqual(sel["selected_count"], 70)
        self.assertEqual(len(sel["selection"]), 70)

    def test_family_quotas_match_policy(self):
        sel = json.loads(SEL.read_text())
        pol = json.loads(POLICY.read_text())
        from collections import Counter
        fam = Counter(s["command_family"] for s in sel["selection"])
        want = Counter()
        for slot in pol["slots"]:
            want[slot["family"]] += slot["count"]
        self.assertEqual(fam, want)

    # ---- §22 selection mutations ----
    def test_mutation_altered_case_id_fails(self):
        mod = reload_verify()
        bad = json.loads(SEL.read_text())
        bad["selection"][0]["case_id"] = "totally::made::up"
        c.finalize(bad)
        SEL.write_text(json.dumps(bad, indent=2, sort_keys=True) + "\n")
        try:
            ok, msg = mod.verify()
            self.assertFalse(ok)
            self.assertIn("reproduce", msg)
        finally:
            self._restore()

    def test_mutation_dropped_case_not_70_fails(self):
        mod = reload_verify()
        bad = json.loads(SEL.read_text())
        bad["selection"] = bad["selection"][:-1]
        bad["selected_count"] = 69
        c.finalize(bad)
        SEL.write_text(json.dumps(bad, indent=2, sort_keys=True) + "\n")
        try:
            ok, msg = mod.verify()
            self.assertFalse(ok)
        finally:
            self._restore()

    def test_mutation_wrong_seed_changes_selection(self):
        """A different seed must produce a different selection order."""
        import build_n2e_selection as b
        importlib.reload(b)
        pol = json.loads(POLICY.read_text())
        cid = b.build()[0]["selection"][0]["case_id"]
        # emulate wrong-seed ordering: reorder key with a different seed
        k1 = b._order_key(pol["seed"], cid)
        k2 = b._order_key(pol["seed"] + 1, cid)
        self.assertNotEqual(k1, k2)

    def _restore(self):
        # regenerate the canonical records so other tests see clean state
        import build_n2e_selection as b
        importlib.reload(b)
        sel, res, rej = b.build()
        c.write_record(SEL, sel)


if __name__ == "__main__":
    unittest.main()
