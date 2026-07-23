"""Promotion P5.3 harness 3/3: the independent per-case acceptance verifier accepts a well-formed
caddy observation + frozen go streams and derives PASS via the go dialect; it fails closed on a
producer-declared verdict, non-equivalent streams, an adapter-binding mismatch, wrong RTK identity,
non-determinism, and a tampered stream digest. Synthetic observation + frozen go streams (from the
pinned go fixtures) -- no CI run needed.
"""
import copy
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402
import n2e_case_adapters as adapters  # noqa: E402
import n2e_rtk_go_test_dialect as go  # noqa: E402
import verify_case_qualification as V  # noqa: E402

CADDY = adapters.CaddyGoTestAdapter.case_id
RAW_GO = b"""{"Action":"run","Package":"github.com/caddyserver/caddy","Test":"TestUnsyncedConfigAccess"}
{"Action":"output","Package":"github.com/caddyserver/caddy","Test":"TestUnsyncedConfigAccess","Output":"    config_test.go:12: got 3 want 5\\n"}
{"Action":"fail","Package":"github.com/caddyserver/caddy","Test":"TestUnsyncedConfigAccess","Elapsed":0.2}
{"Action":"fail","Package":"github.com/caddyserver/caddy","Elapsed":0.2}"""
RTK_GO = b"""Go test: 0 passed, 1 failed, 1 packages
--- FAIL: TestUnsyncedConfigAccess"""


def _frozen():
    contract = next(e for e in c.load_record(L.CONTRACT)["contracts"] if e["case_id"] == CADDY)
    scenario = next(s for s in c.load_record(L.SCEN)["scenarios"] if s["case_id"] == CADDY)
    return contract, scenario


class TestCaseQualVerifier(unittest.TestCase):
    def setUp(self):
        self.ev = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, self.ev, ignore_errors=True)
        self.recdir = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, self.recdir, ignore_errors=True)
        (self.ev / "raw.canonical.bin").write_bytes(RAW_GO)
        (self.ev / "rtk.canonical.bin").write_bytes(RTK_GO)
        contract, scenario = _frozen()
        self.det = adapters.adapter_for(CADDY).bind(contract, scenario)
        self.body = {
            "case_id": CADDY, "record_kind": "resolved_case_qualification_acceptance",
            "qualification_pass": None, "acceptance_pass": False,
            "outcome": "RESOLVED_CASE_OBSERVED", "adapter_binding": self.det,
            "raw_argv_equals_adapter": True, "rtk_argv_equals_adapter": True,
            "rtk_binary_sha256": L.DIALECT_RTK_SHA, "rtk_binary_bytes": L.DIALECT_RTK_BYTES,
            "raw_arm": {"deterministic": True}, "rtk_arm": {"deterministic": True},
            "captured_stream_digests": {
                "raw.canonical": {"sha256": c.sha256_bytes(RAW_GO), "bytes": len(RAW_GO)},
                "rtk.canonical": {"sha256": c.sha256_bytes(RTK_GO), "bytes": len(RTK_GO)}}}

    def _write(self, body=None):
        p = self.recdir / "obs.json"
        c.write_record(p, c.envelope(record_type="n2e-resolved-case-observation",
                                     generated_by="test", **(body or self.body)))
        return p

    def _verify(self, body=None):
        return V.verify(self._write(body), self.ev)

    # ---------- GREEN: buggy caddy case qualifies on faithful RAW<->RTK equivalence ----------
    def test_green_pass(self):
        ok, fail, facts = self._verify()
        self.assertTrue(ok, fail)
        self.assertTrue(facts["case_qualification_pass"])
        self.assertEqual(facts["raw_projection"]["outcome"], "failure")  # buggy case fails, yet qualifies

    # ---------- producer must not declare a verdict ----------
    def test_red_producer_declares_pass(self):
        b = copy.deepcopy(self.body); b["qualification_pass"] = True
        ok, _, _ = self._verify(b); self.assertFalse(ok)

    def test_red_wrong_outcome(self):
        b = copy.deepcopy(self.body); b["outcome"] = "CASE_PROBE_ERROR"
        ok, _, _ = self._verify(b); self.assertFalse(ok)

    # ---------- adapter binding / argv ----------
    def test_red_adapter_binding_tampered(self):
        b = copy.deepcopy(self.body); b["adapter_binding"]["raw_argv"] = ["go", "test", "./..."]
        ok, _, _ = self._verify(b); self.assertFalse(ok)

    def test_red_argv_not_equal_adapter(self):
        b = copy.deepcopy(self.body); b["raw_argv_equals_adapter"] = False
        ok, _, _ = self._verify(b); self.assertFalse(ok)

    # ---------- identity / determinism ----------
    def test_red_wrong_rtk_identity(self):
        b = copy.deepcopy(self.body); b["rtk_binary_sha256"] = "0" * 64
        ok, _, _ = self._verify(b); self.assertFalse(ok)

    def test_red_raw_not_deterministic(self):
        b = copy.deepcopy(self.body); b["raw_arm"]["deterministic"] = False
        ok, _, _ = self._verify(b); self.assertFalse(ok)

    # ---------- streams / equivalence ----------
    def test_red_tampered_digest(self):
        b = copy.deepcopy(self.body); b["captured_stream_digests"]["raw.canonical"]["sha256"] = "0" * 64
        ok, _, _ = self._verify(b); self.assertFalse(ok)

    def test_red_rtk_hides_failure(self):
        (self.ev / "rtk.canonical.bin").write_bytes(b"Go test: 1 passed, 1 packages")
        b = copy.deepcopy(self.body)
        b["captured_stream_digests"]["rtk.canonical"] = {
            "sha256": c.sha256_bytes(b"Go test: 1 passed, 1 packages"), "bytes": 29}
        ok, _, _ = self._verify(b); self.assertFalse(ok)

    def test_red_missing_stream(self):
        (self.ev / "rtk.canonical.bin").unlink()
        ok, _, _ = self._verify(); self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
