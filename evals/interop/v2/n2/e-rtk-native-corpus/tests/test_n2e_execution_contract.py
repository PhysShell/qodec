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
import n2e_publisher_registry as pub  # noqa: E402
import verify_n2e_publisher_registry as VP  # noqa: E402

SCEN = {s["case_id"]: s for s in c.load_record(N2E_DIR / "n2e-command-scenarios-v1.json")["scenarios"]}


class TestResolver(unittest.TestCase):
    def test_swebench_cases_resolve_to_publisher_recipe(self):
        # the four SWE-bench test cases must resolve to their PUBLISHER-scoped test
        # command (from the self-hash-locked registry), never a generic whole-suite one
        cases = {
            "caddyserver__caddy-5870::go::test::buggy":
                ["go", "test", "-v", ".", "-run", "TestUnsyncedConfigAccess"],
            "tokio-rs__tokio-4384::rust_cargo::test::fixed":
                ["cargo", "test", "--package", "tokio", "--test", "net_types_unwind",
                 "--features", "full", "--no-fail-fast"],
            "vuejs__core-11589::js_ts::test::buggy":
                ["pnpm", "run", "test", "packages/runtime-core/__tests__/apiWatch.spec.ts",
                 "--no-watch", "--reporter=verbose"],
            "apache__lucene-13704::jvm::test::buggy":
                ["./gradlew", "test", "--tests",
                 "org.apache.lucene.search.TestLatLonDocValuesQueries"],
        }
        for cid, argv in cases.items():
            r = resolver.resolve(SCEN[cid])
            self.assertEqual(r["resolution_rule"], "publisher_recipe", cid)
            self.assertFalse(r["runtime_resolved"], cid)
            self.assertEqual(r["effective_raw_argv"], argv, cid)
            self.assertEqual(r["effective_rtk_argv"], ["rtk", *argv], cid)

    def test_rust_publisher_carries_toolchain_and_rustflags(self):
        r = resolver.resolve(SCEN["tokio-rs__tokio-4384::rust_cargo::test::fixed"])
        self.assertEqual(r["scheduler_env"]["RUSTUP_TOOLCHAIN"], "1.83")
        self.assertEqual(r["scheduler_env"]["RUSTFLAGS"], "-Awarnings")
        self.assertEqual(r["scheduler_env"]["RUST_TEST_THREADS"], "1")

    def test_gin_vet_is_frozen_verbatim(self):  # non-recipe SWE-bench case stays generic
        r = resolver.resolve(SCEN["gin-gonic__gin-2755::go::vet"])
        self.assertEqual(r["resolution_rule"], "frozen_argv_verbatim")
        self.assertEqual(r["scheduler_env"]["GOPROXY"], "off")


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


class TestPublisherRegistry(unittest.TestCase):
    def test_registry_verifies(self):
        ok, msg = VP.verify()
        self.assertTrue(ok, msg)

    def test_recipe_lookup_and_toolchain(self):
        r = pub.recipe_for("tokio-rs__tokio-4384")
        self.assertEqual(r["toolchain"]["version"], "1.83")
        self.assertEqual(r["lockfile"]["sha256"],
                         "6f7401a1c6c2690bc5b48d54b1be4a87a443252febe89ccc74ac4e9e65f38dba")
        self.assertIsNone(pub.recipe_for("gin-gonic__gin-2755"))  # vet case: no test recipe

    def test_parse_command_strips_env_prefix(self):
        self.assertEqual(pub.parse_command("RUSTFLAGS=-Awarnings cargo test --package tokio"),
                         ["cargo", "test", "--package", "tokio"])


if __name__ == "__main__":
    unittest.main()
