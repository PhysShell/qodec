"""Promotion P4 verifier-side acceptance: the independent qualification VERIFIER
(verify_coreutils_qualification) -- the sole PASS authority -- accepts a well-formed acceptance
OBSERVATION + its captured streams, and fails closed on every verifier-domain mutation the loader
cannot see: a producer that declares its own verdict, a diagnostic record substituted for an
acceptance artifact, a non-deterministic / mis-canonicalized rep, an unqualified RAW arm, argv that
disagrees with the committed contract, and a stream role swap. Synthetic observation + synthetic
streams built from the proven P3 rep0-2 cargo-test-v3 canonical bytes (which are v3-reproducible).
"""
import copy
import shutil
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402
import verify_coreutils_qualification as vq  # noqa: E402

P3 = L.DIALECT_DIR / "streams"
V3 = "cargo-test-v3"


def _zc(b: bytes) -> bytes:
    return zlib.compress(b, 9)


def _populate(ev: Path):
    """Copy the P3 rep0-2 streams into the verifier's .zst layout (canonical + pre-canonical)."""
    for i in range(3):
        (ev / f"raw.rep{i}.zst").write_bytes(_zc((P3 / f"raw.canonical.rep{i}.bin").read_bytes()))
        (ev / f"raw.raw.rep{i}.zst").write_bytes(_zc((P3 / f"raw.raw.rep{i}.bin").read_bytes()))
        (ev / f"rtk.rep{i}.zst").write_bytes(_zc((P3 / f"rtk.canonical.rep{i}.bin").read_bytes()))
        (ev / f"rtk.raw.rep{i}.zst").write_bytes(_zc((P3 / f"rtk.raw.rep{i}.bin").read_bytes()))


def _runs(ev: Path, role: str) -> list:
    return [{"canonical_sha256": c.sha256_bytes((P3 / f"{role}.canonical.rep{i}.bin").read_bytes())}
            for i in range(3)]


def _obs_body(ev: Path) -> dict:
    return {
        "case_id": vq.CASE_ID, "record_kind": "coreutils_qualification_acceptance",
        "qualification_pass": None, "acceptance_pass": False,
        "outcome": "COREUTILS_QUALIFICATION_OBSERVED",
        "bound_dialect_policy_id": L.DIALECT_ID, "canonicalization_policy_id": V3,
        "toolchain_enforcement": {"ok": True, "installed_identity": {
            "cargo_binary_sha256": L.PROVEN_BINARY_IDENTITY["cargo"]["sha256"],
            "rustc_binary_sha256": L.PROVEN_BINARY_IDENTITY["rust"]["sha256"]}},
        "rtk_binary_sha256": L.DIALECT_RTK_SHA, "rtk_binary_bytes": L.DIALECT_RTK_BYTES,
        "acquired_lock_matches_frozen_p1": True,
        "raw_arm": {"role": "raw", "raw_qualified": True, "deterministic": True,
                    "actual_argv_equal_contract": True, "runs": _runs(ev, "raw")},
        "rtk_arm": {"role": "rtk", "deterministic": True,
                    "actual_argv_equal_contract": True, "runs": _runs(ev, "rtk")},
    }


class TestQualVerifier(unittest.TestCase):
    def setUp(self):
        self.ev = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.ev, ignore_errors=True)
        _populate(self.ev)
        self.recdir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.recdir, ignore_errors=True)

    def _write(self, body: dict) -> Path:
        p = self.recdir / "obs.json"
        c.write_record(p, c.envelope(record_type="n2e-coreutils-qualification-observation",
                                     generated_by="test", **body))
        return p

    def _verify(self, body=None):
        return vq.verify(self._write(body or _obs_body(self.ev)), self.ev)

    # ---------- GREEN ----------
    def test_green_verifier_pass(self):
        ok, fail, facts = self._verify()
        self.assertTrue(ok, fail)
        self.assertTrue(facts["coreutils_qualification_pass"])

    # ---------- producer must not declare a verdict ----------
    def test_red_producer_declares_pass(self):
        b = _obs_body(self.ev); b["qualification_pass"] = True
        ok, fail, _ = self._verify(b)
        self.assertFalse(ok)

    def test_red_producer_acceptance_pass_true(self):
        b = _obs_body(self.ev); b["acceptance_pass"] = True
        ok, fail, _ = self._verify(b)
        self.assertFalse(ok)

    # ---------- diagnostic substituted for an acceptance artifact ----------
    def test_red_diagnostic_record_kind(self):
        b = _obs_body(self.ev); b["record_kind"] = "coreutils_diagnostic"
        ok, _, _ = self._verify(b)
        self.assertFalse(ok)

    def test_red_wrong_record_type(self):
        p = self.recdir / "obs.json"
        c.write_record(p, c.envelope(record_type="n2e-coreutils-diagnostic-observation",
                                     generated_by="test", **_obs_body(self.ev)))
        ok, _, _ = vq.verify(p, self.ev)
        self.assertFalse(ok)

    def test_red_wrong_outcome(self):
        b = _obs_body(self.ev); b["outcome"] = "COREUTILS_QUAL_ACQUISITION_FAILURE"
        ok, _, _ = self._verify(b)
        self.assertFalse(ok)

    # ---------- identity ----------
    def test_red_wrong_cargo_identity(self):
        b = _obs_body(self.ev)
        b["toolchain_enforcement"]["installed_identity"]["cargo_binary_sha256"] = "0" * 64
        ok, _, _ = self._verify(b)
        self.assertFalse(ok)

    def test_red_wrong_rtk_identity(self):
        b = _obs_body(self.ev); b["rtk_binary_sha256"] = "0" * 64
        ok, _, _ = self._verify(b)
        self.assertFalse(ok)

    def test_red_lock_mismatch_frozen_p1(self):
        b = _obs_body(self.ev); b["acquired_lock_matches_frozen_p1"] = False
        ok, _, _ = self._verify(b)
        self.assertFalse(ok)

    # ---------- stream / semantic ----------
    def test_red_missing_stream_role(self):
        (self.ev / "rtk.rep0.zst").unlink()
        ok, _, _ = self._verify()
        self.assertFalse(ok)

    def test_red_stream_role_swap(self):
        a = (self.ev / "raw.rep0.zst").read_bytes()
        b = (self.ev / "rtk.rep0.zst").read_bytes()
        (self.ev / "raw.rep0.zst").write_bytes(b)
        (self.ev / "rtk.rep0.zst").write_bytes(a)
        ok, _, _ = self._verify()
        self.assertFalse(ok)

    def test_red_counts_changed(self):
        bad = b"cargo test: 9 passed, 3205 filtered out (3 suites, <dur>)\n"
        (self.ev / "rtk.rep0.zst").write_bytes(_zc(bad))
        ok, _, _ = self._verify()
        self.assertFalse(ok)

    def test_red_rtk_not_reproducible_across_reps(self):
        # rep1 canonical differs from rep0 -> RTK canonical not reproducible
        bad = b"cargo test: 10 passed, 3205 filtered out (3 suites, <dur>) x\n"
        (self.ev / "rtk.rep1.zst").write_bytes(_zc(bad))
        ok, _, _ = self._verify()
        self.assertFalse(ok)

    def test_red_raw_precanonical_not_v3_reproducible(self):
        # tamper raw.raw.rep0 so re-deriving cargo-test-v3 canonical != the frozen canonical file
        (self.ev / "raw.raw.rep0.zst").write_bytes(_zc(b"garbage that is not cargo output\n"))
        ok, _, _ = self._verify()
        self.assertFalse(ok)

    # ---------- arm qualification / argv ----------
    def test_red_raw_arm_not_qualified(self):
        b = _obs_body(self.ev); b["raw_arm"]["raw_qualified"] = False
        ok, _, _ = self._verify(b)
        self.assertFalse(ok)

    def test_red_arm_not_deterministic(self):
        b = _obs_body(self.ev); b["rtk_arm"]["deterministic"] = False
        ok, _, _ = self._verify(b)
        self.assertFalse(ok)

    def test_red_argv_not_equal_contract(self):
        b = _obs_body(self.ev); b["raw_arm"]["actual_argv_equal_contract"] = False
        ok, _, _ = self._verify(b)
        self.assertFalse(ok)

    def test_red_recorded_canonical_sha_disagrees(self):
        b = _obs_body(self.ev); b["raw_arm"]["runs"][0]["canonical_sha256"] = "0" * 64
        ok, _, _ = self._verify(b)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
