"""Promotion P5.1: the resolved-twelve manifest names EXACTLY the frozen twelve, in order, with
every per-case policy field matching the live frozen contract. GREEN closes; every cardinality /
ordering / substitution / generation / policy-drift mutation fails closed.
"""
import copy
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402
import build_n2e_resolved_twelve_manifest as B  # noqa: E402
import verify_n2e_resolved_twelve_manifest as V  # noqa: E402

MANIFEST = N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"


def _refinalize(rec: dict) -> dict:
    """Re-seal a mutated record so the self-hash stays valid and the mutation is what's tested."""
    rec = copy.deepcopy(rec)
    rec["record_sha256"] = None
    rec["record_sha256"] = c.compute_self_hash(rec)
    return rec


class TestTwelveManifest(unittest.TestCase):
    def setUp(self):
        self.rec = c.load_record(MANIFEST)

    def _v(self, rec=None, **kw):
        return V.verify_manifest(rec if rec is not None else self.rec, **kw)

    # ---------- GREEN ----------
    def test_green_manifest_verifies(self):
        f = self._v()
        self.assertEqual(f["cardinality"], 12)
        self.assertEqual(len(f["case_ids"]), 12)

    def test_green_matches_builder(self):
        self.assertEqual([x["case_id"] for x in B.build_manifest()["cases"]], self.rec["case_ids"])

    # ---------- cardinality ----------
    def test_red_eleven_entries(self):
        rec = copy.deepcopy(self.rec)
        rec["cases"] = rec["cases"][:11]; rec["case_ids"] = rec["case_ids"][:11]
        rec["cardinality"] = 11
        with self.assertRaises(V.ManifestError):
            self._v(_refinalize(rec))

    def test_red_thirteen_entries(self):
        rec = copy.deepcopy(self.rec)
        extra = copy.deepcopy(rec["cases"][0]); extra["case_id"] = "zzz__new-1::go::test::buggy"
        rec["cases"].append(extra); rec["case_ids"].append(extra["case_id"])
        rec["cardinality"] = 13
        with self.assertRaises(V.ManifestError):
            self._v(_refinalize(rec))

    def test_red_cardinality_field_lies(self):
        rec = copy.deepcopy(self.rec); rec["cardinality"] = 13
        with self.assertRaises(V.ManifestError):
            self._v(_refinalize(rec))

    # ---------- duplicates / unknown / substitution / order ----------
    def test_red_duplicate_case_id(self):
        rec = copy.deepcopy(self.rec)
        rec["cases"][1] = copy.deepcopy(rec["cases"][0]); rec["case_ids"][1] = rec["case_ids"][0]
        with self.assertRaises(V.ManifestError):
            self._v(_refinalize(rec))

    def test_red_unknown_extra_case_substituted(self):
        # keep cardinality 12 but swap one case for an unknown one
        rec = copy.deepcopy(self.rec)
        rec["cases"][3]["case_id"] = "unknown__case-1::go::test::buggy"
        rec["case_ids"][3] = "unknown__case-1::go::test::buggy"
        with self.assertRaises(V.ManifestError):
            self._v(_refinalize(rec))

    def test_red_reordered_roster(self):
        rec = copy.deepcopy(self.rec)
        rec["cases"][0], rec["cases"][1] = rec["cases"][1], rec["cases"][0]
        rec["case_ids"][0], rec["case_ids"][1] = rec["case_ids"][1], rec["case_ids"][0]
        with self.assertRaises(V.ManifestError):
            self._v(_refinalize(rec))

    def test_red_case_ids_disagree_with_cases(self):
        rec = copy.deepcopy(self.rec); rec["case_ids"][5] = rec["case_ids"][6]
        with self.assertRaises(V.ManifestError):
            self._v(_refinalize(rec))

    # ---------- generation ----------
    def test_red_wrong_manifest_generation_field(self):
        rec = copy.deepcopy(self.rec); rec["manifest_generation"] = 2
        with self.assertRaises(V.ManifestError):
            self._v(_refinalize(rec))

    def test_red_verifier_expects_different_generation(self):
        # a manifest from generation 1 presented where generation 2 is expected -> reject
        with self.assertRaises(V.ManifestError):
            self._v(expected_generation=2)

    # ---------- policy drift ----------
    def test_red_canon_policy_drift(self):
        rec = copy.deepcopy(self.rec)
        rec["cases"][0]["canonicalization_policy_id"] = "made-up-v9"
        with self.assertRaises(V.ManifestError):
            self._v(_refinalize(rec))

    def test_red_dialect_policy_drift(self):
        rec = copy.deepcopy(self.rec)
        # claim a family-level rust dialect on the JVM case
        rec["cases"][0]["rtk_test_dialect_policy_id"] = "rtk-rust-cargo-test-summary-v1"
        with self.assertRaises(V.ManifestError):
            self._v(_refinalize(rec))

    def test_red_contract_generation_drift(self):
        rec = copy.deepcopy(self.rec)
        # claim the JVM base case is contract generation 3
        rec["cases"][0]["contract_generation"] = 3
        with self.assertRaises(V.ManifestError):
            self._v(_refinalize(rec))

    def test_red_expected_qual_type_drift(self):
        rec = copy.deepcopy(self.rec)
        # relabel coreutils' concrete qualification type
        idx = rec["case_ids"].index(L.REPLACEMENT_CASE_ID)
        rec["cases"][idx]["expected_qualification_record_type"] = "n2e-resolved-case-qualification"
        with self.assertRaises(V.ManifestError):
            self._v(_refinalize(rec))

    def test_red_rtk_binary_identity_drift(self):
        rec = copy.deepcopy(self.rec)
        rec["cases"][0]["required_rtk_binary_identity_ref"]["sha256"] = "0" * 64
        with self.assertRaises(V.ManifestError):
            self._v(_refinalize(rec))

    # ---------- stale pins ----------
    def test_red_stale_membership_pin(self):
        rec = copy.deepcopy(self.rec); rec["resolved_membership_sha256"] = "sha256:" + "0" * 64
        with self.assertRaises(V.ManifestError):
            self._v(_refinalize(rec))

    def test_red_stale_contract_pin(self):
        rec = copy.deepcopy(self.rec); rec["resolved_execution_contract_sha256"] = "sha256:" + "0" * 64
        with self.assertRaises(V.ManifestError):
            self._v(_refinalize(rec))

    # ---------- integrity ----------
    def test_red_self_hash_broken(self):
        rec = copy.deepcopy(self.rec); rec["cases"][0]["family"] = "tampered"
        with self.assertRaises(V.ManifestError):
            self._v(rec)  # not re-finalized -> self-hash fails first


if __name__ == "__main__":
    unittest.main()
