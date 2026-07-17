"""Fail-closed tests for the §8 candidate inventory (structural + §22 mutations)."""
import copy
import importlib
import json
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
TOOLS = N2E_DIR / "tools"
sys.path.insert(0, str(TOOLS))
import n2e_common as c  # noqa: E402

RECORD = N2E_DIR / "n2e-candidate-inventory-v1.json"


def verify_dict(rec: dict) -> tuple[bool, str]:
    mod = importlib.import_module("verify_n2e_candidate_inventory")
    importlib.reload(mod)
    tmp = N2E_DIR / "_tmp_ci.json"
    tmp.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")
    try:
        return mod.verify(tmp)
    finally:
        tmp.unlink(missing_ok=True)


class TestCandidateInventory(unittest.TestCase):
    def setUp(self):
        self.rec = json.loads(RECORD.read_text())

    def test_ok(self):
        ok, msg = verify_dict(self.rec)
        self.assertTrue(ok, msg)

    def test_outcome_blind(self):
        blob = json.dumps(self.rec["candidates"]).lower()
        for banned in ("rtk", "token", "saving", "qodec"):
            self.assertNotIn(banned, blob)

    def test_diversity_min_repos(self):
        from collections import defaultdict
        fr = defaultdict(set)
        for x in self.rec["candidates"]:
            fr[x["command_family"]].add(x["repository"])
        for fam in ("rust_cargo", "go", "js_ts", "jvm"):
            self.assertGreaterEqual(len(fr[fam]), 4, fam)

    # ---- §22 mutations ----
    def test_duplicate_candidate_rejected(self):
        bad = copy.deepcopy(self.rec)
        bad["candidates"].append(copy.deepcopy(bad["candidates"][0]))
        bad["candidate_count"] += 1
        c.finalize(bad)
        ok, _ = verify_dict(bad)
        self.assertFalse(ok)

    def test_wrong_raw_outcome_rejected(self):
        bad = copy.deepcopy(self.rec)
        for x in bad["candidates"]:
            if x["command_subfamily"] == "test" and x["snapshot_variant"] == "buggy":
                x["expected_raw_outcome"] = "pass"  # buggy must fail
                break
        c.finalize(bad)
        ok, _ = verify_dict(bad)
        self.assertFalse(ok)

    def test_missing_command_metadata_rejected(self):
        bad = copy.deepcopy(self.rec)
        del bad["candidates"][0]["command_family"]
        c.finalize(bad)
        ok, _ = verify_dict(bad)
        self.assertFalse(ok)

    def test_shell_string_instead_of_argv_rejected(self):
        bad = copy.deepcopy(self.rec)
        bad["candidates"][0]["raw_command_argv"] = "cargo test"  # shell string
        c.finalize(bad)
        ok, _ = verify_dict(bad)
        self.assertFalse(ok)

    def test_smuggled_rtk_field_rejected(self):
        bad = copy.deepcopy(self.rec)
        bad["candidates"][0]["rtk_savings_pct"] = 90
        c.finalize(bad)
        ok, msg = verify_dict(bad)
        self.assertFalse(ok)
        self.assertIn("outcome-blind", msg)


if __name__ == "__main__":
    unittest.main()
