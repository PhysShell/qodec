"""Tests for the normative argv resolver + execution-contract record (correction #3)."""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import n2e_argv_resolver as resolver  # noqa: E402
import build_n2e_execution_contract as B  # noqa: E402
import verify_n2e_execution_contract as V  # noqa: E402

SCEN = {s["case_id"]: s for s in c.load_record(N2E_DIR / "n2e-command-scenarios-v1.json")["scenarios"]}


class TestResolver(unittest.TestCase):
    def test_static_family_is_frozen_verbatim(self):
        s = SCEN["caddyserver__caddy-5870::go::test::buggy"]
        r = resolver.resolve(s)
        self.assertEqual(r["resolution_rule"], "frozen_argv_verbatim")
        self.assertEqual(r["effective_raw_argv"], ["go", "test", "./..."])
        self.assertEqual(r["effective_rtk_argv"], ["rtk", "go", "test", "./..."])
        self.assertEqual(r["scheduler_env"]["GOFLAGS"], "-mod=readonly")
        self.assertEqual(r["scheduler_env"]["GOPROXY"], "off")

    def test_js_and_jvm_are_runtime_resolved_without_repo(self):
        for cid, rule in (("vuejs__core-11589::js_ts::test::buggy",
                           "test_runner_from_package_json+sequential_scheduler"),
                          ("apache__lucene-13704::jvm::test::buggy", "build_system_from_repo")):
            r = resolver.resolve(SCEN[cid])
            self.assertTrue(r["runtime_resolved"])
            self.assertEqual(r["resolution_rule"], rule)
            self.assertIsNone(r["effective_raw_argv"])

    def test_rust_scheduler_env(self):
        r = resolver.resolve(SCEN["tokio-rs__tokio-4384::rust_cargo::test::fixed"])
        self.assertEqual(r["effective_raw_argv"], ["cargo", "test"])
        self.assertEqual(r["scheduler_env"]["CARGO_BUILD_JOBS"], "1")
        self.assertEqual(r["scheduler_env"]["RUST_TEST_THREADS"], "1")


class TestContract(unittest.TestCase):
    def test_offline_verifier_passes_on_committed_record(self):
        ok, msg = V.verify_offline()
        self.assertTrue(ok, msg)

    def test_caddy_contract_is_case_scoped_policy(self):
        rec = c.load_record(N2E_DIR / "n2e-canary-execution-contract-v1.json")
        caddy = next(x for x in rec["contracts"] if x["case_id"] == "caddyserver__caddy-5870::go::test::buggy")
        self.assertEqual(caddy["canonicalization_policy_id"], "caddy-go-test-v1")

    def test_committed_record_matches_fresh_build(self):
        fresh = B.build()  # rebuild body
        committed = c.load_record(N2E_DIR / "n2e-canary-execution-contract-v1.json")
        self.assertEqual(fresh["contracts"], committed["contracts"])


if __name__ == "__main__":
    unittest.main()
