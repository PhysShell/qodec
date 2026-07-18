"""Fail-closed rejection-ledger derivation for DISQUALIFIED_RTK_SEMANTIC_LOSS (caddy).

A terminal entry is emitted ONLY when every precondition holds on primitive evidence;
missing the sidecar-only proof, a non-strict-qualified RAW, or a nondeterministic RTK
arm must downgrade the case to insufficient_evidence, never a terminal rejection."""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import build_n2e_canary_rejection_ledger as L  # noqa: E402
import n2e_classification as cls  # noqa: E402

CADDY = "caddyserver__caddy-5870::go::test::buggy"


def caddy_record(**over):
    raw_summary = {"passed": 3, "failed": 1, "failing_ids": ["TestUnsyncedConfigAccess"]}
    rtk_summary = {"passed": 3, "failed": 1, "failing_ids": []}  # id dropped from measured stream
    rec = {
        "case_id": CADDY, "command_family": "go", "command_subfamily": "test",
        "record_sha256": "deadbeef",
        "acquisition": {"publisher_recipe": "GO_SPECS[caddy]",
                        "environment_identity": {"toolchain_pin": {"kind": "go", "version": "1.23.8"},
                                                 "publisher": {"case_id": CADDY}}},
        "raw_arm": {"reps_completed": 3, "exit_code": 1, "canonical_deterministic": True,
                    "runs": [{"canonical_sha256": "r1"}, {"canonical_sha256": "r1"},
                             {"canonical_sha256": "r1"}]},
        "rtk_arm": {"reps_completed": 3, "exit_code": 1, "canonical_deterministic": True,
                    "runs": [{"canonical_sha256": "k1"}, {"canonical_sha256": "k1"},
                             {"canonical_sha256": "k1"}],
                    "rtk_sidecar_proof": {"identity_only_in_unmeasured_sidecar": True,
                                          "semantic_loss_confirmed": True,
                                          "reps": [{"target_in_sidecar": ["TestUnsyncedConfigAccess"],
                                                    "target_in_measured": [], "tee_pointer_present": True}]}},
        "raw_semantic_oracle": {"oracle": "test_outcome", "verdict": True,
                                "evidence": {"required_targets": ["TestUnsyncedConfigAccess"],
                                             "observed_failing": ["TestUnsyncedConfigAccess"]}},
        "rtk_semantic_oracle": {"oracle": "test_agreement", "verdict": False,
                                "evidence": {"raw": raw_summary, "rtk": rtk_summary}},
    }
    rec["_impl_sha"], rec["_run_id"] = "i" * 40, "run-1"
    rec.update(over)
    return rec


class TestSemanticLossLedger(unittest.TestCase):
    def test_full_evidence_yields_terminal_entry(self):
        entry, unmet = L.derive_rtk_semantic_loss(caddy_record())
        self.assertEqual(unmet, [], unmet)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["classification"], cls.DISQUALIFIED_RTK_SEMANTIC_LOSS)
        self.assertTrue(entry["terminal"])
        self.assertEqual(entry["missing_identity_set"], ["TestUnsyncedConfigAccess"])
        self.assertEqual(entry["required_failing_ids"], ["TestUnsyncedConfigAccess"])
        self.assertEqual(entry["rtk_observed_failing_ids"], [])
        self.assertFalse(entry["outcome_flags"]["rtk_required_semantic_identity_preserved"])

    def test_missing_sidecar_proof_is_insufficient(self):
        rec = caddy_record()
        rec["rtk_arm"]["rtk_sidecar_proof"] = {"identity_only_in_unmeasured_sidecar": False}
        entry, unmet = L.derive_rtk_semantic_loss(rec)
        self.assertIsNone(entry)
        self.assertIn("identity_only_in_unmeasured_sidecar", unmet)

    def test_raw_not_strictly_qualified_is_insufficient(self):
        rec = caddy_record()
        rec["raw_semantic_oracle"]["verdict"] = False  # RAW target did not actually fail
        entry, unmet = L.derive_rtk_semantic_loss(rec)
        self.assertIsNone(entry)
        self.assertIn("raw_qualified_strict_target", unmet)

    def test_nondeterministic_rtk_is_insufficient(self):
        rec = caddy_record()
        rec["rtk_arm"]["canonical_deterministic"] = False
        entry, unmet = L.derive_rtk_semantic_loss(rec)
        self.assertIsNone(entry)
        self.assertIn("rtk_deterministic", unmet)

    def test_count_not_preserved_is_insufficient(self):
        rec = caddy_record()
        rec["rtk_semantic_oracle"]["evidence"]["rtk"]["failed"] = 0
        entry, unmet = L.derive_rtk_semantic_loss(rec)
        self.assertIsNone(entry)
        self.assertIn("rtk_outcome_count_preserved", unmet)

    def test_candidate_detection(self):
        self.assertTrue(L._looks_like_semantic_loss(caddy_record()))
        passing = caddy_record()
        passing["rtk_semantic_oracle"]["verdict"] = True
        self.assertFalse(L._looks_like_semantic_loss(passing))


if __name__ == "__main__":
    unittest.main()
