"""Promotion P5.3 harness wiring: the acceptance adapter registry is the "not arbitrary JSON"
contract. The Caddy adapter binds ONLY when its frozen constants match the frozen execution contract
+ scenario (double-lock); a manifest/contract that supplies a different argv/env/target/canon/dialect
is rejected; an unregistered case has no adapter.
"""
import copy
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402
import n2e_case_adapters as A  # noqa: E402

CADDY = "caddyserver__caddy-5870::go::test::buggy"


def _frozen():
    contract = next(e for e in c.load_record(L.CONTRACT)["contracts"] if e["case_id"] == CADDY)
    scenario = next(s for s in c.load_record(L.SCEN)["scenarios"] if s["case_id"] == CADDY)
    return contract, scenario


class TestCaseAdapters(unittest.TestCase):
    def setUp(self):
        self.contract, self.scenario = _frozen()
        self.adapter = A.adapter_for(CADDY)

    # ---------- GREEN: adapter binds against the real frozen contract ----------
    def test_green_bind(self):
        d = self.adapter.bind(self.contract, self.scenario)
        self.assertEqual(d["raw_argv"], ["go", "test", "-v", ".", "-run", "TestUnsyncedConfigAccess"])
        self.assertEqual(d["rtk_argv"][0], "rtk")
        self.assertEqual(d["rtk_argv"][1:], d["raw_argv"])  # same target, rtk-wrapped
        self.assertEqual(d["canonicalization_policy_id"], "caddy-go-test-v1")
        self.assertEqual(d["rtk_test_dialect_policy_id"], "rtk-go-test-summary-v1")
        self.assertTrue(d["execution_isolation"]["fresh_gocache_per_arm"])
        self.assertTrue(d["execution_isolation"]["no_p52_fixture_reuse"])

    # ---------- unregistered case -> no adapter ----------
    def test_red_unregistered_case(self):
        with self.assertRaises(A.AdapterBindingError):
            A.adapter_for("gin-gonic__gin-2755::go::vet")

    # ---------- double-lock: a contract supplying different determinants is rejected ----------
    def test_red_contract_argv_override(self):
        bad = copy.deepcopy(self.contract)
        bad["effective_raw_argv"] = ["go", "test", "./...", "-run", "Evil"]
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)

    def test_red_contract_rtk_argv_not_wrapping_same_target(self):
        bad = copy.deepcopy(self.contract)
        bad["effective_rtk_argv"] = ["rtk", "go", "test", "-v", ".", "-run", "OtherTest"]
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)

    def test_red_contract_env_override(self):
        bad = copy.deepcopy(self.contract)
        bad["scheduler_env"] = {"GOFLAGS": "-mod=mod", "GOPROXY": "https://proxy.evil"}
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)

    def test_red_contract_canon_override(self):
        bad = copy.deepcopy(self.contract); bad["canonicalization_policy_id"] = "arbitrary-v9"
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)

    def test_red_contract_dialect_override(self):
        bad = copy.deepcopy(self.contract); bad["rtk_test_dialect_policy_id"] = "rtk-rust-cargo-test-summary-v1"
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)

    def test_red_scenario_target_override(self):
        bad = copy.deepcopy(self.scenario); bad["target_test_ids"] = ["SomethingElse"]
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(self.contract, bad)

    def test_red_protected_files_override(self):
        bad = copy.deepcopy(self.contract); bad["protected_files"] = ["go.mod"]
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)


if __name__ == "__main__":
    unittest.main()
