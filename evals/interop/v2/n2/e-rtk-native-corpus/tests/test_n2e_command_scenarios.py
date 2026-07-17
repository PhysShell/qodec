"""Fail-closed tests for §12 scenario contracts and §19 canary membership (§22)."""
import importlib
import json
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
TOOLS = N2E_DIR / "tools"
sys.path.insert(0, str(TOOLS))
import n2e_common as c  # noqa: E402

SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
CANARY = N2E_DIR / "n2e-canary-membership-v1.json"


def verifiers():
    mod = importlib.import_module("verify_n2e_command_scenarios")
    importlib.reload(mod)
    return mod


class TestScenarios(unittest.TestCase):
    def test_verifier_passes(self):
        m = verifiers()
        ok, msg = m.verify_scenarios()
        self.assertTrue(ok, msg)
        ok, msg = m.verify_canary()
        self.assertTrue(ok, msg)

    def test_70_scenarios(self):
        self.assertEqual(json.loads(SCEN.read_text())["scenario_count"], 70)

    def test_all_argv_arrays(self):
        for s in json.loads(SCEN.read_text())["scenarios"]:
            self.assertIsInstance(s["original_argv"], list)

    def test_canary_12(self):
        self.assertEqual(json.loads(CANARY.read_text())["canary_case_count"], 12)

    # ---- §22 mutations (scenario registry) ----
    def _write_scen(self, rec):
        SCEN.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")

    def _restore(self):
        import build_n2e_command_scenarios as b
        importlib.reload(b)
        c.write_record(SCEN, b.build())

    def test_mutation_shell_string_rejected(self):
        m = verifiers()
        bad = json.loads(SCEN.read_text())
        bad["scenarios"][0]["original_argv"] = "cargo test"
        c.finalize(bad)
        self._write_scen(bad)
        try:
            ok, msg = m.verify_scenarios()
            self.assertFalse(ok)
            self.assertIn("array", msg)
        finally:
            self._restore()

    def test_mutation_altered_environment_rejected(self):
        m = verifiers()
        bad = json.loads(SCEN.read_text())
        bad["scenarios"][0]["environment"]["TZ"] = "America/New_York"
        c.finalize(bad)
        self._write_scen(bad)
        try:
            ok, msg = m.verify_scenarios()
            self.assertFalse(ok)
            self.assertIn("environment", msg)
        finally:
            self._restore()

    def test_mutation_bad_classification_rejected(self):
        m = verifiers()
        bad = json.loads(SCEN.read_text())
        bad["scenarios"][0]["rtk_support_classification"] = "TOTALLY_NATIVE"
        c.finalize(bad)
        self._write_scen(bad)
        try:
            ok, _ = m.verify_scenarios()
            self.assertFalse(ok)
        finally:
            self._restore()

    def test_mutation_wrong_rtk_binary_rejected(self):
        m = verifiers()
        bad = json.loads(SCEN.read_text())
        bad["rtk_binary_sha256"] = "0" * 64
        c.finalize(bad)
        self._write_scen(bad)
        try:
            ok, _ = m.verify_scenarios()
            self.assertFalse(ok)
        finally:
            self._restore()


if __name__ == "__main__":
    unittest.main()
