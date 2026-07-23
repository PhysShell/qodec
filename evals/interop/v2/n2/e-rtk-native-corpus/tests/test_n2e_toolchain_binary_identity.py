"""Promotion P2 acceptance: the executed-binary identity record (n2e-resolved-toolchain-binary-
identity-v1.json). Records the exact rustc/cargo binaries that executed (measured identity), keeps
Rust and Cargo separate, resolves wrappers explicitly (invoked path vs measured target), and ties
to the frozen toolchain overlay's exact_binary_identity_ref. The loader validates every measured
identity against BOTH the committed frozen installed-identity evidence AND the proven immutable
binary anchor.

Acceptance:
  GREEN: the exact installed rustc and cargo binaries close through the loader.
  RED:   changed executable byte; changed reported version; wrapper target substitution; invoked
         path -> different measured target; rust-A + cargo-B cross pairing; duplicate identity per
         role; metadata-only identity with no executable digest; missing record; wrong overlay tie;
         barred diagnostic-only provenance.
  Regression: Phase 1 frozen evidence + all five overlays remain loadable/unchanged.
"""
import copy
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_resolved_loader as L  # noqa: E402
import n2e_common as c  # noqa: E402


def _inputs():
    rec = c.load_record(L.BINID)
    ref = c.load_record(L.OV_TOOLCHAIN)["resolved_rust_toolchain"]["exact_binary_identity_ref"]
    rm = c.sha256_json_file(L.RESOLVED_MEMBERSHIP)
    base = c.sha256_json_file(L.LOCK)
    ovsha = c.sha256_json_file(L.OV_TOOLCHAIN)
    return rec, ref, rm, base, ovsha


class TestToolchainBinaryIdentity(unittest.TestCase):
    def setUp(self):
        self.rec, self.ref, self.rm, self.base, self.ovsha = _inputs()
        self.ev = Path(tempfile.mkdtemp())
        shutil.copy(L.BINID_DIR / "installed-identity.json", self.ev / "installed-identity.json")

    def _v(self, rec=None, ovsha=None):
        return L.validate_toolchain_binary_identity(
            self.rec if rec is None else rec, self.ref, self.rm, self.base,
            self.ovsha if ovsha is None else ovsha, self.ev)

    def _role(self, rec, role):
        return next(r for r in rec["role_identities"] if r["role"] == role)

    def _frozen_mut(self, fn):
        p = self.ev / "installed-identity.json"
        d = json.loads(p.read_text())
        fn(d["installed_identity"])
        p.write_text(json.dumps(d))

    # ---------- GREEN ----------
    def test_green_exact_binaries_validate(self):
        rec = self._v()
        roles = {r["role"]: r for r in rec["role_identities"]}
        self.assertEqual(roles["rust"]["measured_sha256"], L.PROVEN_BINARY_IDENTITY["rust"]["sha256"])
        self.assertEqual(roles["cargo"]["measured_sha256"], L.PROVEN_BINARY_IDENTITY["cargo"]["sha256"])

    def test_green_full_closure(self):
        cl = L.validate_resolved_closure()
        self.assertIn("toolchain_binary_identity", cl["overlays"])

    # ---------- RED ----------
    def test_red_changed_executable_byte(self):
        # coordinated tamper (record + frozen evidence agree on a wrong sha) -> proven anchor rejects
        rec = copy.deepcopy(self.rec)
        self._role(rec, "cargo")["measured_sha256"] = "0" * 64
        self._frozen_mut(lambda ii: ii.__setitem__("cargo_binary_sha256", "0" * 64))
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_changed_reported_version(self):
        rec = copy.deepcopy(self.rec)
        self._role(rec, "rust")["version_verbose"] = "rustc 1.99.0 (deadbeef 2099-01-01)\nhost: x\n"
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_wrapper_target_substitution(self):
        rec = copy.deepcopy(self.rec)
        rec["invoked_wrapper"]["sha256"] = "0" * 64
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_invoked_path_different_measured_target(self):
        rec = copy.deepcopy(self.rec)
        self._role(rec, "rust")["invoked_path"] = "/home/runner/.cargo/bin/cargo"  # rustc role -> cargo proxy
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_rustA_cargoB_cross_pairing(self):
        rec = copy.deepcopy(self.rec)
        self._role(rec, "cargo")["run_id"] = "99999999999"  # cargo measured under a different run
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_duplicate_role(self):
        rec = copy.deepcopy(self.rec)
        rust = self._role(rec, "rust")
        rec["role_identities"] = [rust, copy.deepcopy(rust)]
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_metadata_only_no_digest(self):
        rec = copy.deepcopy(self.rec)
        self._role(rec, "cargo")["measured_sha256"] = None
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_missing_record(self):
        with self.assertRaises(L.ResolvedScopeError):
            L._load_binid(self.ev / "does-not-exist.json")

    def test_red_wrong_toolchain_overlay_tie(self):
        with self.assertRaises(L.ResolvedScopeError):
            self._v(ovsha="sha256:" + "0" * 64)

    def test_red_barred_diagnostic_provenance(self):
        rec = copy.deepcopy(self.rec)
        rec["provenance"]["run_id"] = "29652684349"  # 3dbbf2b diagnostic-only run
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    # ---------- Regression ----------
    def test_regression_phase1_and_five_overlays(self):
        cl = L.validate_resolved_closure()
        for k in ("publisher_env", "toolchain", "command_scenario", "execution_contract", "dependency_snapshot"):
            self.assertIn(k, cl["overlays"])
        self.assertEqual(cl["effective_record_hash_map"]["frozen_dependency_snapshot"]
                         ["host_resolved_package_count"], 346)
        b = L.load_case_bundle(L.REPLACEMENT_CASE_ID, "resolved")
        self.assertIsNotNone(b["resolved_dependency_snapshot"])


if __name__ == "__main__":
    unittest.main()
