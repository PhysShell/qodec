"""Promotion P5.3 framework: the generic per-case qualification recompute for an rtk_test_dialect
case, proven END-TO-END through the aggregator with a synthetic caddy (go) record + frozen go
streams (from the pinned go fixtures). This de-risks the second dispatch path BEFORE any CI run:
 * the shared qualification record is NOT test-summary-shaped by accident (a `::buggy` case, where
   RTK faithfully reflects a FAILURE, qualifies);
 * case-scoped dispatch resolves the right dialect from the record's policy id;
 * the aggregator accepts a non-Rust record with no hidden schema rework;
 * a producer PASS that disagrees with the dialect recomputation is rejected.
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
import n2e_resolved_case_qualification as cq  # noqa: E402
import n2e_rtk_go_test_dialect as go  # noqa: E402
import aggregate_n2e_resolved_twelve as A  # noqa: E402

CADDY = "caddyserver__caddy-5870::go::test::buggy"
# a buggy caddy run: one go test FAILS; RTK faithfully reflects the failure -> qualifies on equivalence
RAW_GO = b"""{"Action":"run","Package":"github.com/caddyserver/caddy","Test":"TestBuggy"}
{"Action":"output","Package":"github.com/caddyserver/caddy","Test":"TestBuggy","Output":"    config_test.go:12: got 3 want 5\\n"}
{"Action":"fail","Package":"github.com/caddyserver/caddy","Test":"TestBuggy","Elapsed":0.2}
{"Action":"fail","Package":"github.com/caddyserver/caddy","Elapsed":0.2}"""
RTK_GO = b"""Go test: 0 passed, 1 failed, 1 packages
--- FAIL: TestBuggy"""


CE_SHA = "sha256:" + "e" * 64  # synthetic gen-3 case_entry_sha256 for the caddy fixture


def _entry():
    return {"case_id": CADDY, "expected_qualification_record_type": "n2e-resolved-case-qualification",
            "qualification_kind": "rtk_test_dialect",
            "rtk_test_dialect_policy_id": "rtk-go-test-summary-v1",
            "command_semantic_oracle_policy_id": None,
            "canonicalization_policy_id": "caddy-go-test-v1", "contract_generation": 1,
            "manifest_generation": 3, "case_entry_sha256": CE_SHA,
            "manifest_binding": {"manifest_generation": 3, "manifest_sha256": "sha256:" + "d" * 64,
                                 "resolved_execution_contract_sha256": "sha256:" + "c" * 64,
                                 "resolved_membership_sha256": "sha256:" + "m" * 64,
                                 "migration_bridge": None}}


def _record(ev: Path):
    (ev / "raw.canonical.bin").write_bytes(RAW_GO)
    (ev / "rtk.canonical.bin").write_bytes(RTK_GO)
    rp, kp = go.parse_raw(RAW_GO), go.parse_rtk(RTK_GO)
    return {
        "record_type": "n2e-resolved-case-qualification", "case_id": CADDY,
        "case_entry_sha256": CE_SHA,  # gen-3 native per-case binding
        "frozen_code_identity": cq.frozen_code_identity(_entry()),
        "qualification_kind": "rtk_test_dialect",
        "rtk_test_dialect_policy_id": "rtk-go-test-summary-v1",
        "command_semantic_oracle_policy_id": None,
        "canonicalization_policy_id": "caddy-go-test-v1", "contract_generation": 1,
        "acceptance_run": {"workflow": "qodec-n2e-case-qualification", "run_id": "31000000001",
                           "run_attempt": "1", "impl_commit": "cad0001",
                           "artifact_sha256": "ca" + "d" * 62, "artifact_bytes": 2048},
        "raw_arm": {"deterministic": True}, "rtk_arm": {"deterministic": True},
        "captured_stream_digests": {
            "raw.canonical": {"sha256": c.sha256_bytes(RAW_GO), "bytes": len(RAW_GO)},
            "rtk.canonical": {"sha256": c.sha256_bytes(RTK_GO), "bytes": len(RTK_GO)}},
        "re_derived_semantic_projection": {"raw_projection": rp, "rtk_projection": kp,
                                           "equivalence": go.equivalence(rp, kp)},
        "evidence": {"dir": None},  # set to the temp dir at test time
        "case_qualification_pass": True,
    }


class TestCaseQualificationRecompute(unittest.TestCase):
    def setUp(self):
        self.ev = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.ev, ignore_errors=True)
        self.entry = _entry()
        self.rec = _record(self.ev)

    def _recompute(self, rec=None):
        return cq.recompute_test_dialect_verdict(rec or self.rec, self.entry, self.ev)

    # ---------- a ::buggy case qualifies on faithful RAW<->RTK equivalence (not on tests passing) ----------
    def test_buggy_case_qualifies_on_equivalence(self):
        self.assertTrue(self._recompute())

    def test_raw_outcome_is_failure_but_still_qualifies(self):
        rp = go.parse_raw(RAW_GO)
        self.assertEqual(rp["outcome"], "failure")  # the buggy test fails
        self.assertTrue(self._recompute())          # yet RTK faithfully reflects it -> qualifies

    # ---------- RTK that hides the failure breaks equivalence -> recompute FAIL ----------
    def test_rtk_hides_failure_fails_recompute(self):
        (self.ev / "rtk.canonical.bin").write_bytes(b"Go test: 1 passed, 1 packages")
        rec = copy.deepcopy(self.rec)
        rec["captured_stream_digests"]["rtk.canonical"] = {
            "sha256": c.sha256_bytes(b"Go test: 1 passed, 1 packages"), "bytes": 29}
        rec["re_derived_semantic_projection"]["rtk_projection"] = go.parse_rtk(b"Go test: 1 passed, 1 packages")
        self.assertFalse(self._recompute(rec))

    def test_tampered_digest_rejected(self):
        rec = copy.deepcopy(self.rec)
        rec["captured_stream_digests"]["raw.canonical"]["sha256"] = "0" * 64
        with self.assertRaises(cq.CaseQualificationError):
            self._recompute(rec)

    def test_missing_raw_determinism_rejected(self):
        rec = copy.deepcopy(self.rec); rec["raw_arm"]["deterministic"] = False
        with self.assertRaises(cq.CaseQualificationError):
            self._recompute(rec)

    def test_recorded_projection_mismatch_rejected(self):
        rec = copy.deepcopy(self.rec)
        rec["re_derived_semantic_projection"]["raw_projection"]["failed"] = 99
        with self.assertRaises(cq.CaseQualificationError):
            self._recompute(rec)

    # ---------- END-TO-END through the aggregator: caddy record drives 1/12 -> 2/12 ----------
    def test_aggregator_counts_caddy_via_dialect(self):
        # a full synthetic roster where only caddy has a record; recompute via the real go dialect
        roster = [self.entry] + [
            {"case_id": f"other-{i}::x::y", "expected_qualification_record_type": "n2e-resolved-case-qualification",
             "qualification_kind": "rtk_test_dialect", "rtk_test_dialect_policy_id": "rtk-go-test-summary-v1",
             "command_semantic_oracle_policy_id": None, "canonicalization_policy_id": "x", "contract_generation": 1,
             "manifest_generation": 2, "manifest_binding": self.entry["manifest_binding"]}
            for i in range(11)]
        rec = copy.deepcopy(self.rec); rec["evidence"] = {"dir": str(self.ev)}
        recompute = {"n2e-resolved-case-qualification":
                     lambda r, e: cq.recompute_test_dialect_verdict(r, e, Path(r["evidence"]["dir"]))}
        bind = {"n2e-resolved-case-qualification": A._bind_case_generation}
        r = A.aggregate(roster, {CADDY: rec}, recompute, bind)
        self.assertEqual(r["derived_pass_count"], 1)   # caddy present + derived; 11 absent
        self.assertFalse(r["resolved_canary_pass"])    # 1/12 -> held


if __name__ == "__main__":
    unittest.main()
