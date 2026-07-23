"""Promotion P4 loader-level acceptance: the standalone Coreutils qualification predicate carrier
closes through validate_coreutils_qualification, and every identity / binding / captured-byte /
semantic / verdict mutation fails closed. The verdict is INDEPENDENTLY recomputed by the loader
from the committed frozen canonical streams -- a record claiming PASS while the recomputation yields
FAIL is rejected. Synthetic record + synthetic canonical streams (the proven P3 rep0 canonical
bytes, which parse to success / 10 passed / 3205 filtered / 3 suites / equivalent).

The verifier-side gates (producer-declared verdict, diagnostic record_kind substituted, per-rep
determinism, RAW-arm qualification) are covered in test_n2e_coreutils_qual_verifier.py.
"""
import copy
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_resolved_loader as L  # noqa: E402
import n2e_common as c  # noqa: E402
import n2e_rtk_rust_cargo_dialect as rcd  # noqa: E402

P3_STREAMS = L.DIALECT_DIR / "streams"


def _green(evidence: Path) -> dict:
    """A valid synthetic qualification record + frozen canonical streams under `evidence`."""
    raw = (P3_STREAMS / "raw.canonical.rep0.bin").read_bytes()
    rtk = (P3_STREAMS / "rtk.canonical.rep0.bin").read_bytes()
    (evidence / "raw.canonical.bin").write_bytes(raw)
    (evidence / "rtk.canonical.bin").write_bytes(rtk)
    rp, kp = rcd.parse_raw(raw), rcd.parse_rtk(rtk)
    return {
        "record_type": "n2e-coreutils-qualification", "record_version": "v1",
        "qualifications": [{"case_id": L.REPLACEMENT_CASE_ID, "passed": 10,
                            "filtered_out": 3205, "suites": 3}],
        "resolved_membership_sha256": c.sha256_json_file(L.RESOLVED_MEMBERSHIP),
        "contract_generation3_sha256": c.sha256_json_file(L.OV_CONTRACT),
        "p2_binary_identity_ref": {"sha256": c.sha256_json_file(L.BINID)},
        "p3_dialect_ref": {"sha256": c.sha256_json_file(L.DIALECT)},
        "bound_dialect_policy_id": L.DIALECT_ID,
        "canonicalization_policy_id": "cargo-test-v3",
        "acceptance_run": {"workflow": L.QUAL_WORKFLOW, "run_id": "30000000001",
                           "run_attempt": "1", "impl_commit": "abc1234",
                           "artifact_sha256": "a" * 64, "artifact_bytes": 4096},
        "identities": {"cargo_sha256": L.PROVEN_BINARY_IDENTITY["cargo"]["sha256"],
                       "rustc_sha256": L.PROVEN_BINARY_IDENTITY["rust"]["sha256"],
                       "rtk_sha256": L.DIALECT_RTK_SHA, "rtk_bytes": L.DIALECT_RTK_BYTES},
        "captured_stream_digests": {
            "raw.canonical": {"sha256": c.sha256_bytes(raw), "bytes": len(raw)},
            "rtk.canonical": {"sha256": c.sha256_bytes(rtk), "bytes": len(rtk)}},
        "re_derived_semantic_projection": {"raw_projection": rp, "rtk_projection": kp},
        "coreutils_qualification_pass": True,
    }


class TestQualificationLoader(unittest.TestCase):
    def setUp(self):
        self.ev = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.ev, ignore_errors=True)
        self.rec = _green(self.ev)
        self.rm = c.sha256_json_file(L.RESOLVED_MEMBERSHIP)
        self.contract = c.sha256_json_file(L.OV_CONTRACT)
        self.p2 = c.sha256_json_file(L.BINID)
        self.p3 = c.sha256_json_file(L.DIALECT)

    def _v(self, rec=None, contract=None, p2=None, p3=None):
        return L.validate_coreutils_qualification(
            self.rec if rec is None else rec, self.rm,
            self.contract if contract is None else contract,
            self.p2 if p2 is None else p2, self.p3 if p3 is None else p3, self.ev)

    # ---------- GREEN ----------
    def test_green_qualification_closes(self):
        self.assertTrue(self._v())

    # ---------- record-type / version / structural ----------
    def test_red_wrong_record_type_diagnostic_substituted(self):
        rec = copy.deepcopy(self.rec); rec["record_type"] = "n2e-coreutils-diagnostic-observation"
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_wrong_record_version(self):
        rec = copy.deepcopy(self.rec); rec["record_version"] = "v2"
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_duplicate_qualification_records(self):
        rec = copy.deepcopy(self.rec); rec["qualifications"] = rec["qualifications"] * 2
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_wrong_case_id(self):
        rec = copy.deepcopy(self.rec)
        rec["qualifications"][0]["case_id"] = "uutils__coreutils-9999::rust_cargo::test::fixed"
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_tokio_case_id(self):
        rec = copy.deepcopy(self.rec); rec["qualifications"][0]["case_id"] = L.REPLACED_CASE_ID
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_no_qualifications(self):
        rec = copy.deepcopy(self.rec); rec["qualifications"] = []
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    # ---------- binding mutations ----------
    def test_red_membership_sha_mismatch(self):
        rec = copy.deepcopy(self.rec); rec["resolved_membership_sha256"] = "sha256:" + "0" * 64
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_contract_gen3_sha_mismatch(self):
        with self.assertRaises(L.ResolvedScopeError):
            self._v(contract="sha256:" + "0" * 64)

    def test_red_p2_ref_mismatch(self):
        with self.assertRaises(L.ResolvedScopeError):
            self._v(p2="sha256:" + "0" * 64)

    def test_red_p3_ref_mismatch(self):
        with self.assertRaises(L.ResolvedScopeError):
            self._v(p3="sha256:" + "0" * 64)

    def test_red_wrong_bound_dialect(self):
        rec = copy.deepcopy(self.rec); rec["bound_dialect_policy_id"] = "rtk-go-test-summary-v1"
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_wrong_canon_policy(self):
        rec = copy.deepcopy(self.rec); rec["canonicalization_policy_id"] = "cargo-test-v2"
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    # ---------- acceptance-run identity (diagnostic run substituted) ----------
    def test_red_acceptance_run_wrong_workflow(self):
        rec = copy.deepcopy(self.rec)
        rec["acceptance_run"]["workflow"] = "qodec-n2e-coreutils-diagnostic"
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_acceptance_run_missing_attempt(self):
        rec = copy.deepcopy(self.rec); rec["acceptance_run"]["run_attempt"] = ""
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_acceptance_run_missing_artifact_digest(self):
        rec = copy.deepcopy(self.rec); del rec["acceptance_run"]["artifact_sha256"]
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_acceptance_run_barred_diagnostic_run(self):
        rec = copy.deepcopy(self.rec); rec["acceptance_run"]["run_id"] = "29652684349"  # 3dbbf2b
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_acceptance_run_barred_impl(self):
        rec = copy.deepcopy(self.rec); rec["acceptance_run"]["impl_commit"] = "3dbbf2b"
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    # ---------- identity mutations ----------
    def test_red_wrong_cargo_identity(self):
        rec = copy.deepcopy(self.rec); rec["identities"]["cargo_sha256"] = "0" * 64
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_wrong_rustc_identity(self):
        rec = copy.deepcopy(self.rec); rec["identities"]["rustc_sha256"] = "0" * 64
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_wrong_rtk_identity(self):
        rec = copy.deepcopy(self.rec); rec["identities"]["rtk_sha256"] = "0" * 64
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_wrong_rtk_bytes(self):
        rec = copy.deepcopy(self.rec); rec["identities"]["rtk_bytes"] = 1
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    # ---------- captured-bytes layer ----------
    def test_red_no_captured_digests_metadata_only(self):
        rec = copy.deepcopy(self.rec); rec["captured_stream_digests"] = {}
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_changed_stream_digest(self):
        rec = copy.deepcopy(self.rec)
        rec["captured_stream_digests"]["raw.canonical"]["sha256"] = "0" * 64
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_missing_stream_role(self):
        (self.ev / "rtk.canonical.bin").unlink()
        with self.assertRaises(L.ResolvedScopeError):
            self._v()

    def test_red_frozen_stream_tampered_but_digest_updated(self):
        # tamper the frozen RTK stream to (9 passed) AND update the recorded digest to isolate the
        # verdict-recomputation check: streams now say FAIL while the record still claims PASS.
        bad = b"cargo test: 9 passed, 3205 filtered out (3 suites, <dur>)\n"
        (self.ev / "rtk.canonical.bin").write_bytes(bad)
        rec = copy.deepcopy(self.rec)
        rec["captured_stream_digests"]["rtk.canonical"] = {"sha256": c.sha256_bytes(bad),
                                                           "bytes": len(bad)}
        # the recorded projection is left as the (valid) one -> also disagrees with re-derivation
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    # ---------- semantic / verdict recomputation ----------
    def test_red_recorded_projection_tampered(self):
        rec = copy.deepcopy(self.rec)
        rec["re_derived_semantic_projection"]["raw_projection"]["passed"] = 9
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_record_claims_pass_but_streams_fail(self):
        # the core promotion invariant: streams recompute to FAIL, record claims PASS -> reject.
        # rewrite BOTH the frozen stream, its digest, AND the recorded projection so only the
        # loader's independent (10,3205,3)+equivalence recomputation catches the lie.
        bad_raw = (self.ev / "raw.canonical.bin").read_bytes().replace(b"10 passed", b"9 passed")
        (self.ev / "raw.canonical.bin").write_bytes(bad_raw)
        rec = copy.deepcopy(self.rec)
        rec["captured_stream_digests"]["raw.canonical"] = {"sha256": c.sha256_bytes(bad_raw),
                                                          "bytes": len(bad_raw)}
        rec["re_derived_semantic_projection"]["raw_projection"] = rcd.parse_raw(bad_raw)
        # record still claims PASS -> loader recomputes FAIL (equivalence/counts) -> reject
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_producer_does_not_claim_pass(self):
        rec = copy.deepcopy(self.rec); rec["coreutils_qualification_pass"] = None
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_claim_false(self):
        rec = copy.deepcopy(self.rec); rec["coreutils_qualification_pass"] = False
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)


class TestQualificationClosureWiring(unittest.TestCase):
    """The predicate is HELD (False) while the standalone record is absent, and the closure stays
    green -- promotion is never flipped by the wiring commit alone."""

    def test_predicate_held_when_record_absent(self):
        if L.QUALIFICATION.is_file():
            self.skipTest("qualification record present (post-acceptance)")
        cl = L.validate_resolved_closure()
        self.assertFalse(cl["coreutils_qualification_pass"])
        self.assertFalse(cl["effective_record_hash_map"]["coreutils_qualification_pass"])
        self.assertNotIn("coreutils_qualification", cl["overlays"])


if __name__ == "__main__":
    unittest.main()
