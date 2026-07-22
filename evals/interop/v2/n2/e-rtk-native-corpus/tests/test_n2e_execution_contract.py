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
            # publisher argv is the PREFIX; execution-control args (lucene seed) follow
            self.assertEqual(r["effective_raw_argv"][:len(argv)], argv, cid)
            self.assertEqual(r["effective_rtk_argv"][:len(argv) + 1], ["rtk", *argv], cid)

    def test_lucene_carries_fixed_seed_execution_control(self):
        import n2e_execution_control as xctl  # noqa: E402
        cid = "apache__lucene-13704::jvm::test::buggy"
        r = resolver.resolve(SCEN[cid])
        # execution policy v2: seed derivation unchanged (lucene-randomized-seed-v1), but the frozen
        # execution determinants now include the Gradle-concurrency controls (single worker, no
        # parallel, plain console) in a fixed order after the seed + single test JVM.
        self.assertEqual(r["execution_control"]["policy_id"], "lucene-gradle-test-execution-v2")
        self.assertEqual(r["execution_control"]["seed_policy_id"], "lucene-randomized-seed-v1")
        seed_arg = xctl.seed_arg(cid)
        tail = [seed_arg, "-Ptests.jvms=1", "--max-workers=1", "-Dorg.gradle.parallel=false", "--console=plain"]
        for arm in ("effective_raw_argv", "effective_rtk_argv"):
            self.assertIn(seed_arg, r[arm])
            self.assertEqual(r[arm][-len(tail):], tail)  # exact ordered v2 determinants, seed first
        self.assertRegex(seed_arg, r"^-Ptests\.seed=[0-9A-F]{16}$")
        # non-seed cases carry no execution-control
        self.assertIsNone(resolver.resolve(SCEN["caddyserver__caddy-5870::go::test::buggy"])["execution_control"])

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
    def test_registry_verifies_against_source(self):
        ok, msg = VP.verify()
        self.assertTrue(ok, msg)

    def test_recipe_lookup_and_toolchain(self):
        r = pub.recipe_for_case("tokio-rs__tokio-4384::rust_cargo::test::fixed")
        self.assertEqual(r["toolchain"]["kind"], "rust")
        self.assertEqual(r["toolchain"]["version"], "1.83")
        self.assertEqual(r["test_env"]["RUSTFLAGS"], "-Awarnings")

    def test_exact_case_binding_not_by_instance(self):
        # tokio-rs__tokio-4384 has TWO frozen scenarios; only the registered rust test
        # case gets the recipe -- the git::add scenario sharing the instance must not.
        self.assertIsNotNone(pub.recipe_for_case("tokio-rs__tokio-4384::rust_cargo::test::fixed"))
        self.assertIsNone(pub.recipe_for_case("tokio-rs__tokio-4384::git::add"))
        r = resolver.resolve(SCEN["tokio-rs__tokio-4384::git::add"])
        self.assertNotEqual(r["resolution_rule"], "publisher_recipe")

    def test_split_env_and_parse_command(self):
        env, argv = pub.split_env("RUSTFLAGS=-Awarnings cargo test --package tokio")
        self.assertEqual(env, {"RUSTFLAGS": "-Awarnings"})
        self.assertEqual(argv, ["cargo", "test", "--package", "tokio"])
        self.assertEqual(pub.parse_command("go test -v . -run X"), ["go", "test", "-v", ".", "-run", "X"])

    def test_recipes_extracted_from_pinned_source(self):
        # provenance: every recipe carries the pinned source-file blob id + sha256
        for r in pub.load()["recipes"]:
            self.assertRegex(r["source"]["git_blob_sha1"], r"^[0-9a-f]{40}$")
            self.assertRegex(r["source"]["sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
