"""Hardened independent-verifier derivations (post-run pass): toolchain identity, acquisition
classification + parity, final A/B parity, approved semantic env, and the RTK source chain
verified from RETAINED bytes. Each derivation is exercised directly with synthetic primitives
so the verifier never has to trust a producer summary boolean."""
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import verify_coreutils_diagnostic as V  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402

PINS = L.validate_resolved_closure()["overlays"]["toolchain"]["resolved_rust_toolchain"]
CM = PINS["channel_manifest"]
COMPS = PINS["components_x86_64_unknown_linux_gnu"]


def _good_toolchain_rec():
    return {"toolchain_enforcement": {
        "manifest_sha256": CM["sha256"], "manifest_date": CM["manifest_date"],
        "distribution_artifacts": {n: {"hash": COMPS[n]["hash"], "xz_hash": COMPS[n]["xz_hash"]}
                                   for n in ("cargo", "rustc", "rust")},
        "installed_identity": {
            "host_target": PINS["host_target"], "resolved_channel_exact": PINS["resolved_channel"],
            "cargo_binary_sha256": "a" * 64, "rustc_binary_sha256": "b" * 64,
            "cargo_version_verbose": f"cargo {PINS['resolved_channel']} (abc 2024)",
            "rustc_version_verbose": f"rustc {PINS['resolved_channel']} (abc 2024)",
        }}}


class TestDeriveToolchain(unittest.TestCase):
    def test_matching_pins_pass(self):
        fail = []
        self.assertTrue(V._derive_toolchain(_good_toolchain_rec(), PINS, fail))
        self.assertEqual(fail, [])

    def test_manifest_sha_mismatch_fails(self):
        rec = _good_toolchain_rec(); rec["toolchain_enforcement"]["manifest_sha256"] = "0" * 64
        fail = []
        self.assertFalse(V._derive_toolchain(rec, PINS, fail))
        self.assertTrue(any("manifest sha" in f for f in fail))

    def test_component_hash_mismatch_fails(self):
        rec = _good_toolchain_rec(); rec["toolchain_enforcement"]["distribution_artifacts"]["cargo"]["hash"] = "0" * 64
        fail = []
        self.assertFalse(V._derive_toolchain(rec, PINS, fail))
        self.assertTrue(any("cargo component hash" in f for f in fail))

    def test_missing_installed_binary_sha_fails(self):
        rec = _good_toolchain_rec(); rec["toolchain_enforcement"]["installed_identity"]["cargo_binary_sha256"] = None
        fail = []
        self.assertFalse(V._derive_toolchain(rec, PINS, fail))
        self.assertTrue(any("cargo_binary_sha256" in f for f in fail))

    def test_version_not_attested_fails(self):
        rec = _good_toolchain_rec(); rec["toolchain_enforcement"]["installed_identity"]["cargo_version_verbose"] = "cargo 1.99.0"
        fail = []
        self.assertFalse(V._derive_toolchain(rec, PINS, fail))
        self.assertTrue(any("cargo_version_verbose" in f for f in fail))


def _state(lock_present, lock_sha="l" * 64, tracked=()):
    return {"workspace_cargo_tomls": {"Cargo.toml": "t"}, "cargo_config": None, "cargo_config_toml": None,
            "rust_toolchain": None, "rust_toolchain_toml": None, "tracked_status": list(tracked),
            "tracked_diff_sha256": "d" * 64,
            "cargo_lock": {"present": lock_present, "sha256": (lock_sha if lock_present else None),
                           "bytes": (10 if lock_present else 0)}}


def _acq(pristine, post, exit=0):
    return {"install": {"exit": exit, "timed_out": False}, "pristine_state": pristine, "post_install_state": post,
            "post_install_metadata": {"members": ["coreutils 0.0.27"]},
            "cargo_cache_stable_manifest_hash": "cache" + "0" * 59}


class TestDeriveAcqClassification(unittest.TestCase):
    def test_pristine_dependency_state(self):
        # no Cargo.lock ever created; pristine==post
        p = _state(False); post = _state(False)
        cls, parity = V._derive_acq_classification(_acq(p, post), _acq(dict(p), dict(post)))
        self.assertEqual(cls["outcome"], "pristine_dependency_state")
        self.assertTrue(all(parity.values()))

    def test_publisher_install_snapshot_when_lock_created(self):
        p = _state(False); post = _state(True, tracked=[" M Cargo.lock"])
        cls, _ = V._derive_acq_classification(_acq(p, post), _acq(dict(p), dict(post)))
        self.assertEqual(cls["outcome"], "publisher_install_dependency_snapshot")

    def test_unauthorized_mutation_on_nonlock_tracked(self):
        p = _state(False); post = _state(False, tracked=[" M src/main.rs"])
        cls, _ = V._derive_acq_classification(_acq(p, post), _acq(dict(p), dict(post)))
        self.assertEqual(cls["outcome"], "COREUTILS_ACQUISITION_UNAUTHORIZED_MUTATION")

    def test_nondeterministic_when_AB_disagree(self):
        pa = _state(False); posta = _state(True, lock_sha="a" * 64, tracked=[" M Cargo.lock"])
        pb = _state(False); postb = _state(True, lock_sha="c" * 64, tracked=[" M Cargo.lock"])
        cls, parity = V._derive_acq_classification(_acq(pa, posta), _acq(pb, postb))
        self.assertEqual(cls["outcome"], "COREUTILS_ACQUISITION_NONDETERMINISTIC")
        self.assertFalse(parity["cargo_lock_equal"])

    def test_install_failure(self):
        p = _state(False)
        cls, _ = V._derive_acq_classification(_acq(p, p, exit=101), _acq(p, p))
        self.assertEqual(cls["outcome"], "COREUTILS_ACQUISITION_INSTALL_FAILURE")


class TestDeriveFinalParity(unittest.TestCase):
    def _fin(self, sha):
        return {"final_state": {"tracked_diff_sha256": sha, "cargo_lock": {"present": True, "sha256": sha},
                                "workspace_cargo_tomls": {"Cargo.toml": "t"}},
                "final_metadata": {"members": ["coreutils 0.0.27"]}, "all_ok": True}

    def test_equal_all_equal(self):
        rec = {"finalize_A": self._fin("z" * 64), "finalize_B": self._fin("z" * 64)}
        self.assertTrue(V._derive_final_parity(rec)["all_equal"])

    def test_diff_not_all_equal(self):
        rec = {"finalize_A": self._fin("z" * 64), "finalize_B": self._fin("y" * 64)}
        self.assertFalse(V._derive_final_parity(rec)["all_equal"])

    def test_apply_failure_not_all_equal(self):
        a = self._fin("z" * 64); b = self._fin("z" * 64); b["all_ok"] = False
        rec = {"finalize_A": a, "finalize_B": b}
        self.assertFalse(V._derive_final_parity(rec)["all_equal"])


class TestCheckEnvApproved(unittest.TestCase):
    APPROVED = {"RUSTUP_TOOLCHAIN": "1.81.0", "CARGO_NET_OFFLINE": "true",
                "RUST_TEST_THREADS": "1", "CARGO_BUILD_JOBS": "1"}

    def test_exact_match_passes(self):
        fail = []
        V._check_env_approved({"measurement_semantic_env": dict(self.APPROVED)}, self.APPROVED, fail)
        self.assertEqual(fail, [])

    def test_unapproved_variable_rejected(self):
        fail = []
        mse = dict(self.APPROVED); mse["RUSTFLAGS"] = "-Cdebuginfo=0"
        V._check_env_approved({"measurement_semantic_env": mse}, self.APPROVED, fail)
        self.assertTrue(any("unapproved" in f for f in fail))

    def test_missing_variable_rejected(self):
        fail = []
        mse = dict(self.APPROVED); del mse["CARGO_BUILD_JOBS"]
        V._check_env_approved({"measurement_semantic_env": mse}, self.APPROVED, fail)
        self.assertTrue(any("missing" in f for f in fail))

    def test_wrong_value_rejected(self):
        fail = []
        mse = dict(self.APPROVED); mse["RUST_TEST_THREADS"] = "4"
        V._check_env_approved({"measurement_semantic_env": mse}, self.APPROVED, fail)
        self.assertTrue(any("RUST_TEST_THREADS" in f for f in fail))


# --- RTK source chain verified from retained bytes ---
FROM_SRC = (b"pub fn dispatch_cargo() {\n"
            b"    let f = build_cargo_test_filter();\n"  # reference to the to-file symbol
            b"}\n")
TO_SRC = b"pub fn build_cargo_test_filter() -> Filter {\n    Filter::new()\n}\n"


def _sha(b):
    return hashlib.sha256(b).hexdigest()


class TestVerifyRtkChainBytes(unittest.TestCase):
    def setUp(self):
        self.ev = Path(tempfile.mkdtemp())
        src = self.ev / "rtk-source-evidence"
        src.mkdir(parents=True)
        (src / "src__dispatch.rs").write_bytes(FROM_SRC)
        (src / "src__filter.rs").write_bytes(TO_SRC)
        # single edge suffices to exercise the byte-level checks; build a minimal 4-role prov
        sym = "build_cargo_test_filter"
        roff = FROM_SRC.index(sym.encode())
        doff = next(m.start() for m in V._VDEF.finditer(TO_SRC) if m.group(2) == sym.encode())
        self.edge = {"from_path": "src/dispatch.rs", "to_path": "src/filter.rs",
                     "target_symbol": sym, "target_def_offset": doff, "reference_offset": roff,
                     "from_blob": {"sha256": _sha(FROM_SRC), "bytes": len(FROM_SRC)},
                     "to_blob": {"sha256": _sha(TO_SRC), "bytes": len(TO_SRC)}}

    def _prov(self, **edge_over):
        e = dict(self.edge); e.update(edge_over)
        # every role anchored; all three consecutive edges reuse the same validated edge
        roles = {r: ["src/dispatch.rs"] for r in V.CHAIN_ORDER}
        edges = {f"{a}->{b}": dict(e) for a, b in zip(V.CHAIN_ORDER, V.CHAIN_ORDER[1:])}
        return {"rtk_cargo_filter_source": {"commit": V.RTK_SOURCE_COMMIT, "head": V.RTK_SOURCE_COMMIT,
                                            "head_proven": True, "role_files": roles, "edges": edges}}

    def test_valid_chain_no_failures(self):
        fail = []
        V._verify_rtk_chain_bytes(self._prov(), self.ev, fail)
        self.assertEqual(fail, [], fail)

    def test_tampered_byte_sha_mismatch(self):
        (self.ev / "rtk-source-evidence" / "src__filter.rs").write_bytes(TO_SRC + b"// tampered\n")
        fail = []
        V._verify_rtk_chain_bytes(self._prov(), self.ev, fail)
        self.assertTrue(any("sha256 != recorded" in f for f in fail))

    def test_wrong_def_offset(self):
        # the true def offset is 0 (match starts at line position 0); 7 is a wrong offset
        fail = []
        V._verify_rtk_chain_bytes(self._prov(target_def_offset=7), self.ev, fail)
        self.assertTrue(any("not defined at recorded offset" in f for f in fail))

    def test_wrong_ref_offset(self):
        fail = []
        V._verify_rtk_chain_bytes(self._prov(reference_offset=0), self.ev, fail)
        self.assertTrue(any("not referenced at recorded offset" in f for f in fail))

    def test_missing_retained_bytes(self):
        (self.ev / "rtk-source-evidence" / "src__filter.rs").unlink()
        fail = []
        V._verify_rtk_chain_bytes(self._prov(), self.ev, fail)
        self.assertTrue(any("retained to bytes missing" in f for f in fail))

    def test_head_not_proven(self):
        prov = self._prov()
        prov["rtk_cargo_filter_source"]["head_proven"] = False
        fail = []
        V._verify_rtk_chain_bytes(prov, self.ev, fail)
        self.assertTrue(any("HEAD not proven" in f for f in fail))


if __name__ == "__main__":
    unittest.main()
