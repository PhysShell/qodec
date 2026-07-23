"""Guards the tokio DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE closure (ruling steps 1-6).

Instance-level recipe applicability (proven offline from the pinned harness bundle) makes
the substrate PROVEN; the corrected parity verifier then re-derives the terminal candidate
outcome from the preserved V4 evidence; the ledger folds it in with full provenance; and
the resolved membership replaces tokio with the frozen-order reserve (coreutils-6731).
"""
import sys
import tempfile
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import n2e_classification as cls  # noqa: E402
import build_n2e_canary_rejection_ledger as L  # noqa: E402

TOKIO = "tokio-rs__tokio-4384::rust_cargo::test::fixed"
COREUTILS = "uutils__coreutils-6731::rust_cargo::test::fixed"


class TestTokioEnvUnreproducible(unittest.TestCase):
    def test_instance_applicability_proven_and_hashlocked(self):
        r = c.load_record(N2E_DIR / "tokio-4384-instance-recipe-applicability-v1.json")
        ok, msg = c.verify_self_hash(r)
        self.assertTrue(ok, msg)
        self.assertTrue(r["instance_recipe_applicable"])
        self.assertTrue(all(r["equalities"].values()))
        # the applicability is derived purely from (repo, version) -> recipe, no cross-pin
        self.assertIn("MAP_REPO_VERSION_TO_SPECS", r["recipe_selection_mechanism"])

    def test_ledger_tokio_entry_terminal_with_provenance(self):
        entry, unmet = L.derive_tokio_environment_unreproducible()
        self.assertIsNotNone(entry, f"unmet: {unmet}")
        self.assertEqual(entry["classification"], cls.DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE)
        self.assertTrue(entry["terminal"])
        self.assertEqual(entry["substrate_status"], cls.SUBSTRATE_PROVEN)
        self.assertEqual(entry["unmet_preconditions"], [])
        # mandated references present (ruling step 4)
        self.assertEqual(entry["probe_provenance"]["run_id"], "29639827628")
        self.assertEqual(entry["probe_provenance"]["artifact_id"], "8428264892")
        self.assertEqual(entry["diagnostic_unlocked_lock_diff"]["removed_count"], 22)
        self.assertEqual(entry["n2e_failure_class"], "cargo_locked_resolution_refusal")
        self.assertEqual(entry["upstream_failure_class"], "cargo_locked_resolution_refusal")
        # corrected lockfile terminology: NO false "byte-identical" claim; accurate predicates
        pt = entry["precondition_truth"]
        self.assertNotIn("publisher_lockfile_byte_identical", pt)
        for k in ("fixture_source_equal_between_reproductions",
                  "materialized_lock_equal_between_reproductions",
                  "materialization_matches_publisher_transform",
                  "publisher_lockfile_reproduced_faithfully"):
            self.assertTrue(pt[k], k)
        f = entry["publisher_lockfile_facts"]
        self.assertEqual(f["fixture_bytes"], 43465)
        self.assertEqual(f["materialized_bytes"], 43466)
        self.assertFalse(f["fixture_equals_materialized"])
        self.assertTrue(f["materialized_equals_fixture_plus_trailing_newline"])
        self.assertTrue(f["n2e_materialized_equals_upstream_materialized"])
        # savings / ease / size / replacement availability never inform the decision
        for k in ("rtk_savings", "result_size", "execution_ease", "replacement_availability"):
            self.assertIn(k, entry["decision_inputs_excluded"])

    def test_resolved_membership_replaces_tokio_with_frozen_reserve(self):
        rm = c.load_record(N2E_DIR / "n2e-canary-resolved-membership-v1.json")
        self.assertTrue(rm["constraints_ok"])
        self.assertFalse(rm["corpus_feasibility_blocker"])
        self.assertEqual(rm["resolved_case_count"], 12)
        self.assertEqual(rm["original_tokio_outcome"], cls.DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE)
        self.assertFalse(rm["original_canary_pass"])
        self.assertTrue(rm["resolved_membership_required"])
        self.assertFalse(rm["resolved_canary_pass"])
        res = {x["disqualified_case_id"]: x for x in rm["resolutions"]}
        self.assertEqual(res[TOKIO]["resolved_case_id"], COREUTILS)
        self.assertEqual(res[TOKIO]["reserve_rank"], 0)
        # tokio is gone, coreutils is in
        ids = {m["case_id"] for m in rm["resolved_membership"]}
        self.assertNotIn(TOKIO, ids)
        self.assertIn(COREUTILS, ids)


if __name__ == "__main__":
    unittest.main()
