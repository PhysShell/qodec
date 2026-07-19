"""Promotion P5.2B (gin): the command-oracle dispatch path, proven END-TO-END through the verifier +
aggregator with a synthetic gin (go vet) observation + frozen go-vet streams. Proves the SECOND
qualification_kind without bending the shared schema to test summaries:
 * a clean gin run (RAW empty <-> RTK synthetic "No issues found") qualifies on faithful equivalence;
 * kind dispatch: a command-oracle record is NOT accepted by the test-dialect path and vice versa;
 * a producer PASS that disagrees with the oracle recomputation is rejected.
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
import n2e_rtk_go_vet_oracle as gv  # noqa: E402
import n2e_resolved_case_qualification as cq  # noqa: E402
import aggregate_n2e_resolved_twelve as A  # noqa: E402
import verify_case_qualification as V  # noqa: E402

GIN = "gin-gonic__gin-2755::go::vet"
RAW_CLEAN = b""                       # clean gin: no vet issues
RTK_CLEAN = b"Go vet: No issues found"


def _frozen():
    contract = next(e for e in c.load_record(L.CONTRACT)["contracts"] if e["case_id"] == GIN)
    scenario = next(s for s in c.load_record(L.SCEN)["scenarios"] if s["case_id"] == GIN)
    return contract, scenario


def _entry():
    man = c.load_record(N2E_DIR / "n2e-resolved-twelve-manifest-v1.json")
    e = next(x for x in man["cases"] if x["case_id"] == GIN)
    return {**e, "manifest_generation": man["manifest_generation"],
            "manifest_binding": {"manifest_generation": man["manifest_generation"],
                                 "manifest_sha256": c.sha256_json_file(N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"),
                                 "resolved_execution_contract_sha256": man["resolved_execution_contract_sha256"],
                                 "resolved_membership_sha256": man["resolved_membership_sha256"]}}


class TestCommandOracleQual(unittest.TestCase):
    def setUp(self):
        self.ev = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, self.ev, ignore_errors=True)
        (self.ev / "raw.canonical.bin").write_bytes(RAW_CLEAN)
        (self.ev / "rtk.canonical.bin").write_bytes(RTK_CLEAN)
        self.entry = _entry()
        rp, kp = gv.parse_raw(RAW_CLEAN), gv.parse_rtk(RTK_CLEAN)
        self.rec = {
            "record_type": "n2e-resolved-case-qualification", "case_id": GIN,
            "qualification_kind": "rtk_command_oracle",
            "rtk_test_dialect_policy_id": None,
            "command_semantic_oracle_policy_id": "rtk-go-vet-oracle-v1",
            "raw_arm": {"deterministic": True}, "rtk_arm": {"deterministic": True},
            "captured_stream_digests": {
                "raw.canonical": {"sha256": c.sha256_bytes(RAW_CLEAN), "bytes": len(RAW_CLEAN)},
                "rtk.canonical": {"sha256": c.sha256_bytes(RTK_CLEAN), "bytes": len(RTK_CLEAN)}},
            "re_derived_semantic_projection": {"raw_projection": rp, "rtk_projection": kp,
                                               "equivalence": gv.equivalence(rp, kp)},
            "evidence": {"dir": str(self.ev)}, "case_qualification_pass": True}

    # ---------- clean gin qualifies on faithful equivalence ----------
    def test_clean_case_qualifies(self):
        self.assertTrue(cq.recompute_command_oracle_verdict(self.rec, self.entry, self.ev))

    def test_dispatch_routes_by_kind(self):
        self.assertTrue(cq.recompute_case_verdict(self.rec, self.entry, self.ev))

    # ---------- kind dispatch errors ----------
    def test_command_oracle_not_run_through_test_dialect_path(self):
        with self.assertRaises(cq.CaseQualificationError):
            cq.recompute_test_dialect_verdict(self.rec, self.entry, self.ev)

    def test_test_dialect_entry_not_run_through_oracle_path(self):
        bad = {**self.entry, "qualification_kind": "rtk_test_dialect"}
        with self.assertRaises(cq.CaseQualificationError):
            cq.recompute_command_oracle_verdict(self.rec, bad, self.ev)

    # ---------- RTK drops the failure / producer lies ----------
    def test_rtk_hides_a_diagnostic_fails(self):
        raw_issue = b"# pkg\n./x.go:1:1: unreachable code\n"
        (self.ev / "raw.canonical.bin").write_bytes(raw_issue)
        rec = copy.deepcopy(self.rec)
        rec["captured_stream_digests"]["raw.canonical"] = {
            "sha256": c.sha256_bytes(raw_issue), "bytes": len(raw_issue)}
        rec["re_derived_semantic_projection"]["raw_projection"] = gv.parse_raw(raw_issue)
        # RTK still says "No issues found" -> recompute FAIL
        self.assertFalse(cq.recompute_command_oracle_verdict(rec, self.entry, self.ev))

    def test_projection_tamper_rejected(self):
        rec = copy.deepcopy(self.rec)
        rec["re_derived_semantic_projection"]["raw_projection"]["issue_count"] = 9
        with self.assertRaises(cq.CaseQualificationError):
            cq.recompute_command_oracle_verdict(rec, self.entry, self.ev)

    def test_missing_raw_determinism_rejected(self):
        rec = copy.deepcopy(self.rec); rec["raw_arm"]["deterministic"] = False
        with self.assertRaises(cq.CaseQualificationError):
            cq.recompute_command_oracle_verdict(rec, self.entry, self.ev)

    # ---------- END-TO-END through the aggregator ----------
    def test_aggregator_counts_gin_via_oracle(self):
        roster = [{**self.entry, "expected_qualification_record_type": "n2e-resolved-case-qualification"}] + [
            {"case_id": f"o-{i}::x::y", "expected_qualification_record_type": "n2e-resolved-case-qualification",
             "qualification_kind": "rtk_command_oracle", "rtk_test_dialect_policy_id": None,
             "command_semantic_oracle_policy_id": "rtk-go-vet-oracle-v1", "canonicalization_policy_id": "go-vet-v1",
             "contract_generation": 1, "manifest_generation": self.entry["manifest_generation"],
             "manifest_binding": self.entry["manifest_binding"]} for i in range(11)]
        rec = copy.deepcopy(self.rec)
        rec.update({"manifest_generation": self.entry["manifest_generation"],
                    "manifest_sha256": self.entry["manifest_binding"]["manifest_sha256"],
                    "canonicalization_policy_id": "go-vet-v1", "contract_generation": 1,
                    "acceptance_run": {"workflow": "qodec-n2e-case-qualification", "run_id": "31500000001",
                                       "run_attempt": "1", "impl_commit": "gin0001",
                                       "artifact_sha256": "91" + "n" * 62, "artifact_bytes": 512}})
        recompute = {"n2e-resolved-case-qualification":
                     lambda r, e: cq.recompute_case_verdict(r, e, Path(r["evidence"]["dir"]))}
        bind = {"n2e-resolved-case-qualification": A._bind_case_generation}
        r = A.aggregate(roster, {GIN: rec}, recompute, bind)
        self.assertEqual(r["derived_pass_count"], 1)
        self.assertFalse(r["resolved_canary_pass"])


if __name__ == "__main__":
    unittest.main()
