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
            A.adapter_for("nobody__nothing-0000::void::none")


LUCENE = "apache__lucene-13704::jvm::test::buggy"


def _lucene_frozen():
    contract = next(e for e in c.load_record(L.CONTRACT)["contracts"] if e["case_id"] == LUCENE)
    scenario = next(s for s in c.load_record(L.SCEN)["scenarios"] if s["case_id"] == LUCENE)
    return contract, scenario


class TestLuceneGradleAdapter(unittest.TestCase):
    """The fourth proven test dialect (jvm/gradle). v2 execution-determinant double-lock: the argv tail
    is RE-DERIVED from the execution-control policy (seed-first, then the Gradle-concurrency flags), the
    runtime canon disjunction resolves to the gradle branch, and the offline-isolation flags are NOT
    part of the frozen contract argv (owned by gradle-offline-isolation-v1, applied at runtime)."""

    def setUp(self):
        self.contract, self.scenario = _lucene_frozen()
        self.adapter = A.adapter_for(LUCENE)

    # ---------- GREEN ----------
    def test_green_bind(self):
        d = self.adapter.bind(self.contract, self.scenario)
        self.assertEqual(d["qualification_kind"], "rtk_test_dialect")
        self.assertEqual(d["raw_argv"][:4],
                         ["./gradlew", "test", "--tests", "org.apache.lucene.search.TestLatLonDocValuesQueries"])
        # seed FIRST, then the exact ordered Gradle-concurrency determinants
        self.assertTrue(d["raw_argv"][4].startswith("-Ptests.seed="))
        self.assertEqual(d["raw_argv"][5:],
                         ["-Ptests.jvms=1", "--max-workers=1", "-Dorg.gradle.parallel=false", "--console=plain"])
        self.assertEqual(d["rtk_argv"][0], "rtk")
        self.assertEqual(d["rtk_argv"][1:], d["raw_argv"])   # same gradlew target, rtk-wrapped
        self.assertEqual(d["canonicalization_policy_id"], "RUNTIME:gradle-test-v1|maven-test-v1")
        self.assertEqual(d["resolved_canonicalization_policy_id"], "gradle-test-v1")
        self.assertEqual(d["rtk_test_dialect_policy_id"], "rtk-jvm-test-summary-v1")
        self.assertEqual(d["execution_control_policy_id"], "lucene-gradle-test-execution-v2")
        # the offline-isolation flags are NOT in the semantic argv
        for flag in ("--offline", "--no-daemon", "-Dorg.gradle.vfs.watch=false"):
            self.assertNotIn(flag, d["raw_argv"])

    # ---------- RED: v2 double-lock ----------
    def test_red_contract_drops_a_concurrency_flag(self):
        bad = copy.deepcopy(self.contract)
        bad["effective_raw_argv"] = [a for a in bad["effective_raw_argv"] if a != "--max-workers=1"]
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)

    def test_red_contract_reorders_tail_seed_not_first(self):
        bad = copy.deepcopy(self.contract)
        argv = bad["effective_raw_argv"]
        seed_i = next(i for i, a in enumerate(argv) if a.startswith("-Ptests.seed="))
        # move the seed to the END of the tail (no longer seed-first)
        seed = argv.pop(seed_i); argv.append(seed)
        bad["effective_rtk_argv"] = ["rtk", *argv]
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)

    def test_red_contract_execution_control_policy_v1(self):
        bad = copy.deepcopy(self.contract)
        bad["execution_control"] = {**bad["execution_control"], "policy_id": "lucene-randomized-seed-v1"}
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)

    def test_red_contract_execution_control_args_mutated_seed(self):
        bad = copy.deepcopy(self.contract)
        args = list(bad["execution_control"]["args"])
        args[0] = "-Ptests.seed=DEADBEEFDEADBEEF"   # a mutated (post-hoc) seed
        bad["execution_control"] = {**bad["execution_control"], "args": args}
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)

    def test_red_contract_canon_not_runtime_disjunction(self):
        bad = copy.deepcopy(self.contract); bad["canonicalization_policy_id"] = "gradle-test-v1"
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)

    def test_red_scenario_target_override(self):
        bad = copy.deepcopy(self.scenario); bad["target_test_ids"] = ["TestLatLonDocValuesQueries > testOther"]
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(self.contract, bad)

    def test_red_rtk_not_wrapping_gradlew(self):
        bad = copy.deepcopy(self.contract)
        bad["effective_rtk_argv"] = ["rtk", "mvn", "test"]
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)

    # ---------- gin (command-oracle) binds; the second qualification_kind ----------
    def test_green_gin_bind(self):
        GIN = "gin-gonic__gin-2755::go::vet"
        contract = next(e for e in c.load_record(L.CONTRACT)["contracts"] if e["case_id"] == GIN)
        scenario = next(s for s in c.load_record(L.SCEN)["scenarios"] if s["case_id"] == GIN)
        d = A.adapter_for(GIN).bind(contract, scenario)
        self.assertEqual(d["qualification_kind"], "rtk_command_oracle")
        self.assertEqual(d["raw_argv"], ["go", "vet", "./..."])
        self.assertEqual(d["rtk_argv"][1:], d["raw_argv"])          # same target, rtk-wrapped
        self.assertEqual(d["command_semantic_oracle_policy_id"], "rtk-go-vet-oracle-v1")
        self.assertIsNone(d["rtk_test_dialect_policy_id"])          # exactly one policy active

    def test_red_gin_contract_argv_override(self):
        GIN = "gin-gonic__gin-2755::go::vet"
        contract = next(e for e in c.load_record(L.CONTRACT)["contracts"] if e["case_id"] == GIN)
        scenario = next(s for s in c.load_record(L.SCEN)["scenarios"] if s["case_id"] == GIN)
        bad = copy.deepcopy(contract); bad["effective_raw_argv"] = ["go", "vet", "-x", "./..."]
        with self.assertRaises(A.AdapterBindingError):
            A.adapter_for(GIN).bind(bad, scenario)

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


LOGHUB = "loghub::HDFS::log"


def _loghub_frozen():
    contract = next(e for e in c.load_record(L.CONTRACT)["contracts"] if e["case_id"] == LOGHUB)
    scenario = next(s for s in c.load_record(L.SCEN)["scenarios"] if s["case_id"] == LOGHUB)
    return contract, scenario


class TestLoghubHdfsAdapter(unittest.TestCase):
    """Command oracle where RTK is a distinct reimplementation (`rtk log`), both arms read the SAME
    pinned member, and the RAW arm is measured through the full-stream capsule (never a 1500-line
    slice). Identity authority is the published Loghub set."""

    def setUp(self):
        self.contract, self.scenario = _loghub_frozen()
        self.adapter = A.adapter_for(LOGHUB)

    def test_green_bind(self):
        d = self.adapter.bind(self.contract, self.scenario)
        self.assertEqual(d["qualification_kind"], "rtk_command_oracle")
        self.assertEqual(d["raw_argv"], ["cat", "HDFS.log"])
        self.assertEqual(d["rtk_argv"], ["rtk", "log", "HDFS.log"])
        self.assertEqual(d["command_semantic_oracle_policy_id"], "rtk-log-hdfs-oracle-v1")
        self.assertIsNone(d["rtk_test_dialect_policy_id"])
        self.assertEqual(d["input_file"], "HDFS.log")
        self.assertEqual(d["evidence_model"], "log-evidence-capsule-v1")
        self.assertEqual(d["published_reference"], "n2e-loghub-hdfs-reference-v1")
        self.assertEqual(d["execution_isolation"]["shared_input_file"], "HDFS.log")
        self.assertTrue(d["execution_isolation"]["full_stream_no_slice"])

    def test_red_raw_argv_override(self):
        bad = copy.deepcopy(self.contract); bad["effective_raw_argv"] = ["head", "-c", "1000", "HDFS.log"]
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)

    def test_red_rtk_reads_different_file(self):
        # a contract whose RTK arm reads a DIFFERENT input than RAW is rejected (same-input invariant)
        bad = copy.deepcopy(self.contract); bad["effective_rtk_argv"] = ["rtk", "log", "OTHER.log"]
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)

    def test_red_rtk_not_rtk_log(self):
        bad = copy.deepcopy(self.contract); bad["effective_rtk_argv"] = ["rtk", "read", "HDFS.log"]
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)

    def test_red_canon_override(self):
        bad = copy.deepcopy(self.contract); bad["canonicalization_policy_id"] = "arbitrary-v9"
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)

    def test_red_family_override(self):
        bad = copy.deepcopy(self.contract); bad["command_family"] = "files_search"
        with self.assertRaises(A.AdapterBindingError):
            self.adapter.bind(bad, self.scenario)


if __name__ == "__main__":
    unittest.main()
