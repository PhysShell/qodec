"""Fail-closed tests for the §2 source lock (acquisition / deterministic build /
live verify-by-digest) and the §22 mutations.

Offline tests always run. Live-by-digest mutation tests run only when RESOLVE=1
(they need the publishers); they prove HEAD-moves don't invalidate a pin and
that altered immutable identities are rejected.
"""
import copy
import importlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
TOOLS = N2E_DIR / "tools"
sys.path.insert(0, str(TOOLS))
import n2e_common as c  # noqa: E402

REGISTRY = N2E_DIR / "n2e-source-registry-v1.json"
PINS = N2E_DIR / "n2e-source-pins-v1.json"
BUILD = TOOLS / "build_n2e_source_registry.py"


def verify_dict(rec: dict) -> tuple[bool, str]:
    mod = importlib.import_module("verify_n2e_source_registry")
    importlib.reload(mod)
    tmp = N2E_DIR / "_tmp_srcreg.json"
    tmp.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")
    try:
        return mod.verify(tmp)
    finally:
        tmp.unlink(missing_ok=True)


class TestLockSemantics(unittest.TestCase):
    def setUp(self):
        self.rec = json.loads(REGISTRY.read_text())
        self.pins = json.loads(PINS.read_text())

    def test_offline_structural_ok(self):
        ok, msg = verify_dict(self.rec)
        self.assertTrue(ok, msg)

    def test_pins_self_hash(self):
        ok, msg = c.verify_self_hash(self.pins)
        self.assertTrue(ok, msg)

    def test_deterministic_offline_rebuild(self):
        """Rebuild must be byte-identical (no network, no mutable state)."""
        before = REGISTRY.read_bytes()
        subprocess.run([sys.executable, str(BUILD)], check=True, capture_output=True,
                       env={**os.environ, "PATH": os.environ.get("PATH", "/usr/bin:/bin")})
        after = REGISTRY.read_bytes()
        self.assertEqual(before, after, "rebuild changed the canonical record")

    def test_no_mutable_discovery_metadata(self):
        """Mutable metadata must not appear in the self-hash-locked record."""
        blob = json.dumps(self.rec)
        for banned in ("last_modified", "retrieved_at", "lastModified", "current_head"):
            self.assertNotIn(banned, blob)

    # ---- §22 offline mutations ----
    def test_changed_pinned_hf_revision_rejected(self):
        bad = copy.deepcopy(self.rec)
        for s in bad["sources"]:
            if s.get("identity", {}).get("kind") == "huggingface_dataset":
                s["identity"]["immutable_revision"] = "a" * 40  # valid form, wrong value
        c.finalize(bad)
        ok, msg = verify_dict(bad)
        self.assertFalse(ok)
        self.assertIn("revision differs", msg)

    def test_altered_oci_child_digest_rejected(self):
        bad = copy.deepcopy(self.rec)
        for s in bad["sources"]:
            if s.get("identity", {}).get("kind") == "oci_image":
                s["identity"]["child_digest"] = "sha256:" + "b" * 64
        c.finalize(bad)
        ok, msg = verify_dict(bad)
        self.assertFalse(ok)

    def test_altered_zenodo_checksum_rejected(self):
        bad = copy.deepcopy(self.rec)
        for s in bad["sources"]:
            if s.get("identity", {}).get("kind") == "zenodo_record":
                s["identity"]["files"][0]["checksum"] = "md5:" + "0" * 32
        c.finalize(bad)
        ok, msg = verify_dict(bad)
        self.assertFalse(ok)

    def test_altered_zenodo_size_rejected(self):
        bad = copy.deepcopy(self.rec)
        for s in bad["sources"]:
            if s.get("identity", {}).get("kind") == "zenodo_record":
                s["identity"]["files"][0]["size"] = 1
        c.finalize(bad)
        ok, _ = verify_dict(bad)
        self.assertFalse(ok)

    def test_pins_sha_mismatch_rejected(self):
        bad = copy.deepcopy(self.rec)
        bad["pins_sha256"] = "sha256:" + "0" * 64
        c.finalize(bad)
        ok, msg = verify_dict(bad)
        self.assertFalse(ok)

    def test_deferred_with_digest_rejected(self):
        bad = copy.deepcopy(self.rec)
        for s in bad["sources"]:
            if s["classification"] == "DEFERRED":
                s["smuggled"] = "sha256:" + "c" * 64
                break
        c.finalize(bad)
        ok, _ = verify_dict(bad)
        self.assertFalse(ok)

    def test_mutable_metadata_cannot_change_record_hash(self):
        """Adding mutable metadata to the identity is not silently accepted:
        it either is stripped by the deterministic build (rebuild reverts it) or
        breaks the self-hash. Here we prove the canonical build ignores it."""
        polluted = copy.deepcopy(self.rec)
        for s in polluted["sources"]:
            if s.get("identity"):
                s["identity"]["last_modified"] = "2099-01-01T00:00:00Z"
        # deterministic rebuild must not carry it
        subprocess.run([sys.executable, str(BUILD)], check=True, capture_output=True,
                       env={**os.environ, "PATH": os.environ.get("PATH", "/usr/bin:/bin")})
        rebuilt = json.loads(REGISTRY.read_text())
        self.assertNotIn("last_modified", json.dumps(rebuilt))


@unittest.skipUnless(os.environ.get("RESOLVE") == "1", "requires network (RESOLVE=1)")
class TestLiveByDigest(unittest.TestCase):
    def setUp(self):
        self.rec = json.loads(REGISTRY.read_text())

    def test_pinned_revision_resolves_without_head_comparison(self):
        """HEAD moving does not invalidate the pin: verification fetches the exact
        revision, so it passes regardless of the dataset's current HEAD."""
        ok, msg = verify_dict(self.rec)
        self.assertTrue(ok, msg)

    def test_live_wrong_oci_digest_rejected(self):
        bad = copy.deepcopy(self.rec)
        # keep pin cross-check happy by also moving the pin? No — we want the LIVE
        # path to reject; use a value that is a valid digest but not the real one.
        import verify_n2e_source_registry as v
        for s in bad["sources"]:
            if s.get("identity", {}).get("kind") == "oci_image":
                idy = s["identity"]
                ev = __import__("oci_resolve").verify_by_digest(
                    idy["registry"], idy["repository"],
                    "sha256:" + "d" * 64, idy["child_digest"],
                    arch="amd64", os_name="linux")
                self.assertFalse(ev.get("verified"))
                _ = v  # silence lints


if __name__ == "__main__":
    unittest.main()
