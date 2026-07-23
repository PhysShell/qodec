"""Promotion P5.2A step 1 (caddy): the rtk-go-test-summary-v1 source-identity + case-scope proof
closes fail-closed; every source / module / scope / binary / manifest-binding mutation is rejected.
"""
import copy
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import verify_n2e_test_dialect_source_proof as V  # noqa: E402

PROOF = N2E_DIR / "n2e-test-dialect-source-proof-rtk-go-test-summary-v1.json"


def _reseal(rec):
    rec = copy.deepcopy(rec)
    rec["record_sha256"] = None
    rec["record_sha256"] = c.compute_self_hash(rec)
    return rec


class TestSourceProof(unittest.TestCase):
    def setUp(self):
        self.rec = c.load_record(PROOF)

    def test_green(self):
        f = V.verify_proof(self.rec)
        self.assertEqual(f["cases"], ["caddyserver__caddy-5870::go::test::buggy"])

    def test_red_wrong_record_type(self):
        rec = _reseal({**self.rec, "record_type": "x"})
        with self.assertRaises(V.SourceProofError):
            V.verify_proof(rec)

    def test_red_source_content_sha_drift(self):
        rec = copy.deepcopy(self.rec); rec["rtk_source_identity"]["content_sha256"] = "0" * 64
        with self.assertRaises(V.SourceProofError):
            V.verify_proof(_reseal(rec))

    def test_red_source_blob_sha_drift(self):
        rec = copy.deepcopy(self.rec); rec["rtk_source_identity"]["git_blob_sha1"] = "0" * 40
        with self.assertRaises(V.SourceProofError):
            V.verify_proof(_reseal(rec))

    def test_red_wrong_commit(self):
        rec = copy.deepcopy(self.rec); rec["rtk_source_identity"]["commit"] = "0" * 40
        with self.assertRaises(V.SourceProofError):
            V.verify_proof(_reseal(rec))

    def test_red_module_sha_drift(self):
        rec = copy.deepcopy(self.rec); rec["semantics_module"]["sha256"] = "0" * 64
        with self.assertRaises(V.SourceProofError):
            V.verify_proof(_reseal(rec))

    def test_red_rtk_binary_drift(self):
        rec = copy.deepcopy(self.rec); rec["pinned_rtk_binary_identity"]["sha256"] = "0" * 64
        with self.assertRaises(V.SourceProofError):
            V.verify_proof(_reseal(rec))

    def test_red_family_level_scope(self):
        rec = copy.deepcopy(self.rec); rec["dialect_scope"] = "family"
        with self.assertRaises(V.SourceProofError):
            V.verify_proof(_reseal(rec))

    def test_red_extra_case_family_creep(self):
        # adding a second (unproven) case id -> family creep -> reject
        rec = copy.deepcopy(self.rec)
        rec["proven_case_ids"] = rec["proven_case_ids"] + ["gin-gonic__gin-2755::go::vet"]
        with self.assertRaises(V.SourceProofError):
            V.verify_proof(_reseal(rec))

    def test_red_wrong_case(self):
        rec = copy.deepcopy(self.rec); rec["proven_case_ids"] = ["gin-gonic__gin-2755::go::vet"]
        with self.assertRaises(V.SourceProofError):
            V.verify_proof(_reseal(rec))

    def test_red_stale_manifest_binding(self):
        rec = copy.deepcopy(self.rec); rec["manifest_binding"]["manifest_sha256"] = "sha256:" + "0" * 64
        with self.assertRaises(V.SourceProofError):
            V.verify_proof(_reseal(rec))


if __name__ == "__main__":
    unittest.main()
