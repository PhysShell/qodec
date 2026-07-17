"""Fail-closed tests for the §2 source registry (structural + §22 mutations)."""
import copy
import importlib
import json
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
TOOLS = N2E_DIR / "tools"
sys.path.insert(0, str(TOOLS))
import n2e_common as c  # noqa: E402

RECORD = N2E_DIR / "n2e-source-registry-v1.json"


def verify_dict(rec: dict) -> tuple[bool, str]:
    mod = importlib.import_module("verify_n2e_source_registry")
    tmp = N2E_DIR / "_tmp_srcreg.json"
    tmp.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")
    try:
        return mod.verify(tmp)
    finally:
        tmp.unlink(missing_ok=True)


class TestSourceRegistry(unittest.TestCase):
    def setUp(self):
        self.rec = json.loads(RECORD.read_text())

    def test_self_hash_and_structure_ok(self):
        ok, msg = verify_dict(self.rec)
        self.assertTrue(ok, msg)

    def test_every_source_has_typed_reason(self):
        for s in self.rec["sources"]:
            self.assertTrue(s.get("typed_reason"), s["source_id"])

    def test_primary_has_immutable_identity(self):
        for s in self.rec["sources"]:
            if s["classification"] == "ACCEPTED_PRIMARY":
                self.assertIsNotNone(s.get("identity"), s["source_id"])

    # ---- §22 mutations ----
    def test_moving_dataset_revision_rejected(self):
        bad = copy.deepcopy(self.rec)
        for s in bad["sources"]:
            if s.get("identity", {}) and s["identity"].get("kind") == "huggingface_dataset":
                s["identity"]["immutable_revision"] = "main"  # moving ref
        c.finalize(bad)
        ok, msg = verify_dict(bad)
        self.assertFalse(ok)

    def test_mutable_image_without_digest_rejected(self):
        bad = copy.deepcopy(self.rec)
        for s in bad["sources"]:
            if s.get("oci_digest_example"):
                s["oci_digest_example"]["immutable_digest"] = "latest"  # not a digest
        c.finalize(bad)
        ok, msg = verify_dict(bad)
        self.assertFalse(ok)

    def test_unverified_digest_rejected(self):
        bad = copy.deepcopy(self.rec)
        for s in bad["sources"]:
            if s.get("oci_digest_example"):
                s["oci_digest_example"]["digest_verified"] = False
        c.finalize(bad)
        ok, _ = verify_dict(bad)
        self.assertFalse(ok)

    def test_rejected_source_presented_as_primary_without_identity(self):
        bad = copy.deepcopy(self.rec)
        for s in bad["sources"]:
            if s["classification"] == "DEFERRED":
                s["classification"] = "ACCEPTED_PRIMARY"  # but no identity resolved
                break
        c.finalize(bad)
        ok, _ = verify_dict(bad)
        self.assertFalse(ok)

    def test_duplicate_source_id_rejected(self):
        bad = copy.deepcopy(self.rec)
        bad["sources"].append(copy.deepcopy(bad["sources"][0]))
        bad["source_count"] += 1
        c.finalize(bad)
        ok, _ = verify_dict(bad)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
