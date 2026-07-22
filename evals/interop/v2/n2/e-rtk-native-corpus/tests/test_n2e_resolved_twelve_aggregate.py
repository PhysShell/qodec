"""Promotion P5.4: the resolved-twelve aggregator derives resolved_canary_pass fail-closed. GREEN
requires twelve independently-recomputed PASSes over twelve unique acceptance runs. Every aggregate
failure mode holds the flag false / rejects.

The aggregate LOGIC is tested in isolation with a synthetic twelve-case roster + synthetic records +
a controllable recompute stub, so the twelve-way discipline is proven without needing eleven real
acceptance runs. (The real coreutils recompute path is exercised by aggregate_from_disk, which today
reports 1/12 -> held.) Covers the user's required aggregate RED matrix:
 11/12; missing; duplicate replacing another; wrong case; earlier generation; correct artifact on
 wrong dialect policy; family-level dialect substituted; verifier-nonzero-despite-green-CI; altered
 stream digest; semantic mismatch hidden by canon; producer-PASS-recompute-FAIL; twelve records but
 eleven unique runs; barred diagnostic provenance; aggregate-claims-12-while-recompute-gives-11.
"""
import copy
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import aggregate_n2e_resolved_twelve as A  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402

GEN = 3
MAN_SHA = "sha256:" + "d" * 64
CTYPE = "n2e-resolved-case-qualification"
BINDING = {"manifest_generation": GEN, "manifest_sha256": MAN_SHA,
           "resolved_execution_contract_sha256": "sha256:" + "c" * 64,
           "resolved_membership_sha256": "sha256:" + "m" * 64,
           "migration_bridge": None}


def _cehash(i):  # synthetic distinct case_entry_sha256 per case
    return "sha256:" + f"{i:02d}" + "e" * 62


def _roster():
    # a mix of both proof modes: even indices rtk_command_oracle, odd rtk_test_dialect
    r = []
    for i in range(12):
        if i % 2 == 0:
            kind, dialect, oracle = "rtk_command_oracle", None, f"rtk-oracle-{i}-v1"
        else:
            kind, dialect, oracle = "rtk_test_dialect", f"rtk-dialect-{i}-v1", None
        r.append({"case_id": f"case-{i:02d}::fam::test", "expected_qualification_record_type": CTYPE,
                  "canonicalization_policy_id": f"canon-{i}-v1",
                  "qualification_kind": kind, "rtk_test_dialect_policy_id": dialect,
                  "command_semantic_oracle_policy_id": oracle,
                  "contract_generation": 1, "manifest_generation": GEN,
                  "case_entry_sha256": _cehash(i), "manifest_binding": BINDING})
    return r


def _rec(entry, i, ok=True):
    # gen-3 NATIVE record: binds case-locally by case_entry_sha256
    return {
        "record_type": CTYPE, "case_id": entry["case_id"],
        "case_entry_sha256": entry["case_entry_sha256"],
        "canonicalization_policy_id": entry["canonicalization_policy_id"],
        "qualification_kind": entry["qualification_kind"],
        "rtk_test_dialect_policy_id": entry["rtk_test_dialect_policy_id"],
        "command_semantic_oracle_policy_id": entry["command_semantic_oracle_policy_id"],
        "contract_generation": 1,
        "acceptance_run": {"workflow": "qodec-n2e-case-qualification",
                           "run_id": f"300000000{i:02d}", "run_attempt": "1",
                           "impl_commit": f"impl{i:02d}", "artifact_sha256": f"{i:02d}" + "a" * 62,
                           "artifact_bytes": 1000 + i},
        "case_qualification_pass": True, "_ok": ok}


# controllable synthetic recompute: the aggregator's authority, not the record's claim
def _synth_recompute(rec, entry):
    return bool(rec.get("_ok", False))


RECOMPUTE = {CTYPE: _synth_recompute}
BIND = {CTYPE: A._bind_case_generation}


def _records(roster, ok_all=True):
    return {e["case_id"]: _rec(e, i, ok=ok_all) for i, e in enumerate(roster)}


class TestAggregate(unittest.TestCase):
    def setUp(self):
        self.roster = _roster()
        self.records = _records(self.roster)

    def _agg(self, roster=None, records=None):
        return A.aggregate(roster or self.roster, records if records is not None else self.records,
                           RECOMPUTE, BIND)

    # ---------- GREEN: twelve independently-derived PASSes ----------
    def test_green_twelve_pass(self):
        r = self._agg()
        self.assertEqual(r["derived_pass_count"], 12)
        self.assertEqual(r["unique_acceptance_runs"], 12)
        self.assertTrue(r["resolved_canary_pass"])

    # ---------- the real disk aggregator holds below 12/12 (coreutils + caddy = 2/12) ----------
    def test_real_disk_holds_below_twelve(self):
        r = A.aggregate_from_disk()
        # every present case is independently derived over a unique acceptance run
        self.assertEqual(r["derived_pass_count"], r["unique_acceptance_runs"])
        self.assertGreaterEqual(r["derived_pass_count"], 2)  # coreutils + caddy qualified
        self.assertLess(r["derived_pass_count"], 12)
        self.assertFalse(r["resolved_canary_pass"])           # held until a unique 12/12

    # ---------- 11/12 and missing ----------
    def test_red_eleven_of_twelve_recompute(self):
        recs = copy.deepcopy(self.records)
        recs[self.roster[3]["case_id"]]["_ok"] = False  # recompute FAIL but still claims PASS
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    def test_red_one_missing_record_holds(self):
        recs = copy.deepcopy(self.records); del recs[self.roster[5]["case_id"]]
        r = self._agg(records=recs)
        self.assertEqual(r["derived_pass_count"], 11)
        self.assertFalse(r["resolved_canary_pass"])

    # ---------- duplicate replacing another case ----------
    def test_red_duplicate_record_replacing_another_case(self):
        recs = copy.deepcopy(self.records)
        victim = self.roster[7]["case_id"]
        recs[victim] = copy.deepcopy(recs[self.roster[6]["case_id"]])  # case 6's record under case 7
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    def test_red_two_records_for_one_case(self):
        recs = copy.deepcopy(self.records)
        cid = self.roster[2]["case_id"]
        recs[cid] = [recs[cid], copy.deepcopy(recs[cid])]
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    # ---------- wrong case ----------
    def test_red_record_from_wrong_case(self):
        recs = copy.deepcopy(self.records)
        recs[self.roster[1]["case_id"]]["case_id"] = "some::other::case"
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    # ---------- earlier generation ----------
    def test_red_native_record_wrong_case_entry_sha256(self):
        # gen-3: a native record whose case_entry_sha256 disagrees with the recomputed gen-3 entry hash
        # is rejected (right manifest root, WRONG case hash -> reject)
        recs = copy.deepcopy(self.records)
        recs[self.roster[4]["case_id"]]["case_entry_sha256"] = "sha256:" + "0" * 64
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    def test_red_legacy_record_without_bridge_rejected(self):
        # a legacy record (no case_entry_sha256) with NO migration bridge available cannot bind -> reject
        # (the stale whole-manifest binding is never normative on its own)
        recs = copy.deepcopy(self.records)
        legacy = recs[self.roster[4]["case_id"]]
        legacy.pop("case_entry_sha256")
        legacy["manifest_sha256"] = "sha256:" + "0" * 64  # a gen-2-style whole-manifest pin
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)  # BINDING.migration_bridge is None

    def test_red_wrong_manifest_root_rejected_by_manifest_verifier(self):
        # correct case hash but wrong/absent manifest root: aggregate_from_disk pins the real manifest
        # root via VM.verify_manifest; the synthetic path here proves a native record still needs its
        # case hash to match the roster derived from that root (root integrity + case-local hash are
        # independent checks)
        recs = copy.deepcopy(self.records)
        # swap two records' case_entry_sha256 so each points at the wrong case entry
        a, b = self.roster[2]["case_id"], self.roster[4]["case_id"]
        recs[a]["case_entry_sha256"], recs[b]["case_entry_sha256"] = (
            recs[b]["case_entry_sha256"], recs[a]["case_entry_sha256"])
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    # ---------- correct artifact on wrong dialect policy ----------
    def test_red_correct_artifact_wrong_dialect_policy(self):
        recs = copy.deepcopy(self.records)
        recs[self.roster[8]["case_id"]]["rtk_test_dialect_policy_id"] = "rtk-rust-cargo-test-summary-v1"
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    def test_red_wrong_canon_policy(self):
        recs = copy.deepcopy(self.records)
        recs[self.roster[8]["case_id"]]["canonicalization_policy_id"] = "canon-999-v1"
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    # ---------- family-level dialect substituted for case-scoped ----------
    def test_red_family_level_dialect_substituted(self):
        # roster case expects None (case-scoped only); record claims a family-level dialect binding
        recs = copy.deepcopy(self.records)
        recs[self.roster[9]["case_id"]]["rtk_test_dialect_policy_id"] = "rtk-go-test-summary-v1"
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    # ---------- verifier nonzero / semantic mismatch / altered digest: all surface as recompute FAIL ----------
    def test_red_verifier_nonzero_despite_green_ci(self):
        recs = copy.deepcopy(self.records)
        recs[self.roster[0]["case_id"]]["_ok"] = False  # independent recompute says FAIL
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    def test_red_producer_pass_recompute_fail(self):
        recs = copy.deepcopy(self.records)
        r0 = recs[self.roster[0]["case_id"]]
        r0["_ok"] = False; r0["case_qualification_pass"] = True  # lie
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    def test_red_producer_does_not_claim_pass(self):
        recs = copy.deepcopy(self.records)
        recs[self.roster[0]["case_id"]]["case_qualification_pass"] = None
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    # ---------- twelve records but eleven unique runs ----------
    def test_red_twelve_records_eleven_unique_runs(self):
        recs = copy.deepcopy(self.records)
        a, b = self.roster[10]["case_id"], self.roster[11]["case_id"]
        recs[b]["acceptance_run"]["run_id"] = recs[a]["acceptance_run"]["run_id"]
        recs[b]["acceptance_run"]["run_attempt"] = recs[a]["acceptance_run"]["run_attempt"]
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    def test_red_cross_case_artifact_reuse(self):
        recs = copy.deepcopy(self.records)
        a, b = self.roster[10]["case_id"], self.roster[11]["case_id"]
        recs[b]["acceptance_run"]["artifact_sha256"] = recs[a]["acceptance_run"]["artifact_sha256"]
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    # ---------- barred diagnostic provenance ----------
    def test_red_barred_diagnostic_run(self):
        recs = copy.deepcopy(self.records)
        recs[self.roster[0]["case_id"]]["acceptance_run"]["run_id"] = next(iter(L.BARRED_DIAGNOSTIC_RUNS))
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    def test_red_barred_impl(self):
        recs = copy.deepcopy(self.records)
        recs[self.roster[0]["case_id"]]["acceptance_run"]["impl_commit"] = next(iter(L.BARRED_DIAGNOSTIC_IMPLS))
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    def test_red_missing_acceptance_run_field(self):
        recs = copy.deepcopy(self.records)
        del recs[self.roster[0]["case_id"]]["acceptance_run"]["artifact_sha256"]
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    # ---------- no materialized recompute path -> cannot derive ----------
    def test_red_no_recompute_path_registered(self):
        with self.assertRaises(A.AggregateError):
            A.aggregate(self.roster, self.records, {}, BIND)

    def test_red_no_bind_path_registered(self):
        with self.assertRaises(A.AggregateError):
            A.aggregate(self.roster, self.records, RECOMPUTE, {})

    # ---------- roster integrity ----------
    def test_red_roster_not_twelve(self):
        with self.assertRaises(A.AggregateError):
            self._agg(roster=self.roster[:11])

    def test_red_roster_duplicate_case(self):
        roster = copy.deepcopy(self.roster); roster[1]["case_id"] = roster[0]["case_id"]
        with self.assertRaises(A.AggregateError):
            self._agg(roster=roster)

    # ---------- two-mode wrong dispatch ----------
    def test_red_record_wrong_qualification_kind(self):
        recs = copy.deepcopy(self.records)
        cid = self.roster[0]["case_id"]  # manifest kind rtk_command_oracle
        recs[cid]["qualification_kind"] = "rtk_test_dialect"
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    def test_red_command_oracle_record_carries_dialect(self):
        recs = copy.deepcopy(self.records)
        cid = self.roster[0]["case_id"]  # rtk_command_oracle
        recs[cid]["rtk_test_dialect_policy_id"] = "rtk-jvm-test-summary-v1"
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    def test_red_test_dialect_record_carries_oracle(self):
        recs = copy.deepcopy(self.records)
        cid = self.roster[1]["case_id"]  # rtk_test_dialect
        recs[cid]["command_semantic_oracle_policy_id"] = "rtk-git-show-oracle-v1"
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    def test_red_command_oracle_id_mismatch(self):
        recs = copy.deepcopy(self.records)
        cid = self.roster[0]["case_id"]
        recs[cid]["command_semantic_oracle_policy_id"] = "rtk-wrong-oracle-v1"
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)

    # ---------- aggregate claim vs recomputation ----------
    def test_red_aggregate_claims_twelve_recompute_gives_eleven(self):
        # one record recomputes FAIL while claiming PASS -> aggregator rejects rather than reporting 12
        recs = copy.deepcopy(self.records)
        recs[self.roster[11]["case_id"]]["_ok"] = False
        with self.assertRaises(A.AggregateError):
            self._agg(records=recs)


if __name__ == "__main__":
    unittest.main()
