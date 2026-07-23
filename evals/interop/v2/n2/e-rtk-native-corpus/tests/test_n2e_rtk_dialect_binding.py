"""Promotion P3 loader-level acceptance: the identity-bound, CASE-scoped Rust cargo-test RTK
dialect record closes through the loader; every identity / byte-stream / semantic / structural /
case-binding mutation fails closed. Complements the parser/equivalence matrix in
test_n2e_rtk_rust_cargo_dialect.py (semantic + byte-stream projection mutations).
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
import n2e_oracles as ora  # noqa: E402


def _inputs():
    rec = c.load_record(L.DIALECT)
    rm = c.sha256_json_file(L.RESOLVED_MEMBERSHIP)
    base = c.sha256_json_file(L.CONTRACT)
    resolved = c.sha256_json_file(L.OV_CONTRACT)
    p2 = c.sha256_json_file(L.BINID)
    bound = c.load_record(L.OV_CONTRACT)["overlay_contracts"][0]["rtk_test_dialect_policy_id"]
    return rec, bound, rm, base, resolved, p2


class TestDialectBinding(unittest.TestCase):
    def setUp(self):
        self.rec, self.bound, self.rm, self.base, self.resolved, self.p2 = _inputs()
        self.ev = Path(tempfile.mkdtemp())
        shutil.copytree(L.DIALECT_DIR / "streams", self.ev / "streams")
        shutil.copy(L.DIALECT_DIR / "streams-manifest.json", self.ev / "streams-manifest.json")

    def _v(self, rec=None, bound=None, base=None, resolved=None, p2=None):
        return L.validate_rtk_rust_cargo_dialect(
            self.rec if rec is None else rec, self.bound if bound is None else bound,
            self.rm, self.base if base is None else base,
            self.resolved if resolved is None else resolved,
            self.p2 if p2 is None else p2, self.ev)

    # ---------- GREEN ----------
    def test_green_dialect_closes(self):
        r = self._v()
        self.assertEqual(r["dialect_policy_id"], L.DIALECT_ID)
        self.assertTrue(r["semantic_projection"]["equivalence"]["equivalent"])

    def test_green_full_closure(self):
        cl = L.validate_resolved_closure()
        self.assertIn("rtk_rust_cargo_dialect", cl["overlays"])

    # ---------- identity mutations ----------
    def test_red_commit_changed(self):
        rec = copy.deepcopy(self.rec); rec["rtk_source_identity"]["commit"] = "0" * 40
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_source_tree_changed(self):
        rec = copy.deepcopy(self.rec); rec["rtk_source_identity"]["source_tree"] = "0" * 40
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_exe_byte_changed(self):
        rec = copy.deepcopy(self.rec); rec["rtk_executable_identity"]["sha256"] = "0" * 64
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_exe_byte_length_changed(self):
        rec = copy.deepcopy(self.rec); rec["rtk_executable_identity"]["bytes"] = 1
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_p2_identity_ref_disagrees(self):
        with self.assertRaises(L.ResolvedScopeError):
            self._v(p2="sha256:" + "0" * 64)

    def test_red_cross_run_stream_tamper(self):
        # a stream from a different run (byte-changed) -> sha mismatch
        f = self.ev / "streams" / "rtk.canonical.rep0.bin"
        f.write_bytes(f.read_bytes() + b"x")
        with self.assertRaises(L.ResolvedScopeError):
            self._v()

    def test_red_provenance_barred_run(self):
        rec = copy.deepcopy(self.rec); rec["provenance"]["run_id"] = "29652684349"  # 3dbbf2b
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    # ---------- byte-stream / semantic mutations (loader layer) ----------
    def test_red_metadata_only_no_streams(self):
        rec = copy.deepcopy(self.rec); rec["captured_bytes"]["streams"] = {}
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_recorded_projection_tampered(self):
        rec = copy.deepcopy(self.rec)
        rec["semantic_projection"]["rtk_projection"]["passed"] = 9  # disagrees with re-derived
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_stdout_stderr_role_swap(self):
        # swap the RAW and RTK canonical stream files -> re-derived projection != recorded
        s = self.ev / "streams"
        a, b = (s / "raw.canonical.rep0.bin").read_bytes(), (s / "rtk.canonical.rep0.bin").read_bytes()
        (s / "raw.canonical.rep0.bin").write_bytes(b)
        (s / "rtk.canonical.rep0.bin").write_bytes(a)
        with self.assertRaises(L.ResolvedScopeError):
            self._v()

    def test_red_equivalence_claimed_true_but_streams_disagree(self):
        # tamper the frozen RTK stream so the re-derived equivalence is False, while the record
        # still claims equivalent -> reject (also updates manifest sha to isolate the check)
        s = self.ev / "streams" / "rtk.canonical.rep0.bin"
        bad = b"cargo test: 9 passed, 3205 filtered out (3 suites, <dur>)\n"
        s.write_bytes(bad)
        man = json.loads((self.ev / "streams-manifest.json").read_text())
        man["streams"]["rtk.canonical.rep0.bin"] = {"sha256": c.sha256_bytes(bad), "bytes": len(bad)}
        (self.ev / "streams-manifest.json").write_text(json.dumps(man, indent=2, sort_keys=True) + "\n")
        rec = copy.deepcopy(self.rec)
        rec["captured_bytes"]["streams_manifest_sha256"] = c.sha256_json_file(self.ev / "streams-manifest.json")
        rec["captured_bytes"]["streams"]["rtk.canonical.rep0.bin"] = man["streams"]["rtk.canonical.rep0.bin"]
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    # ---------- structural mutations ----------
    def test_red_missing_dialect_record(self):
        with self.assertRaises(L.ResolvedScopeError):
            L._load_dialect(self.ev / "nope.json")

    def test_red_wrong_record_version(self):
        rec = copy.deepcopy(self.rec); rec["record_version"] = "v2"
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_wrong_exec_contract_ref(self):
        with self.assertRaises(L.ResolvedScopeError):
            self._v(resolved="sha256:" + "0" * 64)

    def test_red_unmaterialized_dialect_ref(self):
        # the record does not materialize the contract's bound dialect id
        rec = copy.deepcopy(self.rec); rec["materializes_rtk_test_dialect_policy_id"] = "other"
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_wrong_dialect_policy_id(self):
        rec = copy.deepcopy(self.rec); rec["dialect_policy_id"] = "rtk-go-test-summary-v1"
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    # ---------- case-binding mutations (the five user-required negatives) ----------
    def test_red_tokio_case_id(self):
        rec = copy.deepcopy(self.rec); rec["resolved_case_id"] = L.REPLACED_CASE_ID  # tokio
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_missing_or_changed_case_id(self):
        rec = copy.deepcopy(self.rec); rec["resolved_case_id"] = "some::other::case"
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)

    def test_red_family_level_binding_rejected(self):
        # a family-level rust_cargo binding while only case-scoped proof exists -> reject
        ora.RTK_DIALECTS["rust_cargo"] = L.DIALECT_ID
        try:
            with self.assertRaises(L.ResolvedScopeError):
                self._v()
        finally:
            ora.RTK_DIALECTS.pop("rust_cargo", None)

    def test_red_duplicate_case_binding_changed(self):
        # the case-scoped binding resolves to a DIFFERENT dialect (duplicate/altered) -> reject
        orig = ora.RTK_CASE_DIALECTS[L.REPLACEMENT_CASE_ID]
        ora.RTK_CASE_DIALECTS[L.REPLACEMENT_CASE_ID] = ("rust_cargo", "rtk-rust-cargo-test-summary-v2")
        try:
            with self.assertRaises(L.ResolvedScopeError):
                self._v()
        finally:
            ora.RTK_CASE_DIALECTS[L.REPLACEMENT_CASE_ID] = orig

    def test_red_contract_binds_dialect_for_different_case(self):
        # a contract whose resolved case is not coreutils, but still binds this dialect -> reject
        rec = copy.deepcopy(self.rec); rec["resolved_case_id"] = "uutils__coreutils-9999::rust_cargo::test::fixed"
        with self.assertRaises(L.ResolvedScopeError):
            self._v(rec)


if __name__ == "__main__":
    unittest.main()
