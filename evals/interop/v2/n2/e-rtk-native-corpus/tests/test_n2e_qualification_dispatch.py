"""RED matrix for the n2e-qualification-dispatch-v2 layer (Loghub step 6, checkpoint 1).

dispatch-v2 is the versioned, immutable, registry-bound path that lets a NEW command oracle
(rtk-log-hdfs-oracle-v1) qualify WITHOUT editing the frozen cq -- the eight legacy records pin cq's
identity, so cq is sealed. This suite proves the two paths are STRICTLY separated and every bypass is
fail-closed:

  * legacy record on the registry path / dispatch record through cq  (mutual exclusion);
  * unknown dispatch_policy_id (no dispatch generation registered);
  * registry / oracle-module / RTK-source DRIFT (checksum-pinned dispatch_code_identity);
  * oracle bound to another case, or a family-level ('::'-less) binding;
  * both a test dialect and a command oracle, or neither semantic id;
  * a dynamic import path smuggled in the artifact (no discovery, no fallback);
  * a policy with no registry-bound module (no generic-oracle fallback);
  * diagnostic provenance replayed as acceptance;
  * a producer PASS whose recompute is FAIL (bad capsule outcome / broken published authority /
    severity totals that do not close).

GREEN anchor: a fully-valid synthetic dispatch record binds + recomputes PASS on the real frozen RTK
fixture. No new gate PASS is claimed here -- checkpoint 2's fresh acceptance run produces the real
record; this suite only proves the mechanism.
"""
import copy
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import n2e_qualification_dispatch as disp  # noqa: E402
import aggregate_n2e_resolved_twelve as A  # noqa: E402

MANIFEST = N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"
LOGHUB = "loghub::HDFS::log"
REAL_FIXTURE = "evidence/loghub-diag/rtk-log-summary.real.txt"
REAL_FIXTURE_SHA = "02a1e023f3008c99b9f1cda07f075cc0a6034dc097b6f8f5d1728cf68a38c4d9"
REAL_FIXTURE_BYTES = 1877
# RTK's own reported totals on the full pinned HDFS stream (diagnostic run 29900168290)
REAL_TOTALS = {"error": 5545, "warn": 356273, "info": 10805922, "other": 0}


def _loghub_entry() -> dict:
    man = c.load_record(MANIFEST)
    return next(e for e in man["cases"] if e["case_id"] == LOGHUB)


def _valid_rec(entry: dict) -> dict:
    """A fully-valid dispatch-v2 acceptance record for the loghub case, anchored on the real frozen
    RTK fixture + a capsule summary whose severity projection closes against it."""
    return {
        "record_type": "n2e-resolved-case-qualification",
        "case_id": LOGHUB,
        "case_entry_sha256": entry["case_entry_sha256"],
        "qualification_kind": "rtk_command_oracle",
        "command_semantic_oracle_policy_id": "rtk-log-hdfs-oracle-v1",
        "rtk_test_dialect_policy_id": None,
        "canonicalization_policy_id": "log-v1",
        "contract_generation": entry.get("contract_generation"),
        "dispatch_policy_id": disp.DISPATCH_POLICY_ID,
        "dispatch_code_identity": disp.dispatch_code_identity(entry),
        "raw_capsule_summary": {
            "outcome": "parsed", "unmatched_lines": 0, "ambiguous_lines": 0,
            "occurrence_counts_match_published": True,
            "rtk_semantic_projection": dict(REAL_TOTALS),
        },
        "rtk_output": {"evidence_path": REAL_FIXTURE, "sha256": REAL_FIXTURE_SHA,
                       "bytes": REAL_FIXTURE_BYTES},
        "acceptance_run": {"workflow": "qodec-n2e-case-qualification",
                           "run_id": "39999999999", "run_attempt": "1",
                           "impl_commit": "acceptimpl0000", "artifact_sha256": "f" * 64,
                           "artifact_bytes": 4242},
        "case_qualification_pass": True,
    }


class TestDispatchGreen(unittest.TestCase):
    """The mechanism accepts a genuine, fully-consistent dispatch record."""

    def setUp(self):
        self.entry = _loghub_entry()
        self.rec = _valid_rec(self.entry)

    def test_manifest_routes_loghub_to_v2(self):
        self.assertEqual(self.entry["dispatch_policy_id"], disp.DISPATCH_POLICY_ID)
        self.assertEqual(self.entry["qualification_kind"], "rtk_command_oracle")
        self.assertIsNone(self.entry["rtk_test_dialect_policy_id"])

    def test_valid_record_binds_and_recomputes_pass(self):
        disp.verify_dispatch_binding(self.rec, self.entry)
        disp.bind_dispatch_v2(self.rec, self.entry)
        self.assertTrue(disp.recompute_dispatch_v2(self.rec, self.entry))

    def test_registry_self_hash_and_exact_one_match(self):
        reg = disp.load_registry()
        e = disp._registry_entry(reg, "rtk-log-hdfs-oracle-v1", LOGHUB)
        self.assertEqual(e["allowed_case_ids"], [LOGHUB])
        self.assertEqual(e["dispatch_policy_id"], disp.DISPATCH_POLICY_ID)


class TestMutualExclusion(unittest.TestCase):
    """A legacy cq record and a dispatch record can never launder each other's evidence."""

    def setUp(self):
        self.entry = _loghub_entry()
        self.rec = _valid_rec(self.entry)

    def test_legacy_record_on_dispatch_path_rejected(self):
        # a record carrying a cq frozen_code_identity has no place on the registry path
        r = copy.deepcopy(self.rec)
        r["frozen_code_identity"] = {"canonicalization_policy_definition_sha256": "x"}
        with self.assertRaises(disp.DispatchError):
            disp.verify_dispatch_binding(r, self.entry)

    def test_dispatch_record_missing_dispatch_identity_rejected(self):
        r = copy.deepcopy(self.rec)
        r.pop("dispatch_code_identity")
        with self.assertRaises(disp.DispatchError):
            disp.verify_dispatch_binding(r, self.entry)

    def test_record_dispatch_policy_not_v2_rejected(self):
        r = copy.deepcopy(self.rec)
        r["dispatch_policy_id"] = "n2e-qualification-dispatch-v3"
        with self.assertRaises(disp.DispatchError):
            disp.verify_dispatch_binding(r, self.entry)

    def test_manifest_entry_not_routed_to_v2_rejected(self):
        e = copy.deepcopy(self.entry)
        e["dispatch_policy_id"] = None
        with self.assertRaises(disp.DispatchError):
            disp.verify_dispatch_binding(self.rec, e)


class TestDriftFailClosed(unittest.TestCase):
    """dispatch_code_identity is checksum-pinned; any drift in the layer, registry, oracle module or
    pinned RTK source is DETECTED, never silently absorbed."""

    def setUp(self):
        self.entry = _loghub_entry()
        self.rec = _valid_rec(self.entry)

    def _drift(self, key, val):
        r = copy.deepcopy(self.rec)
        r["dispatch_code_identity"] = dict(r["dispatch_code_identity"])
        r["dispatch_code_identity"][key] = val
        with self.assertRaises(disp.DispatchError):
            disp.verify_dispatch_binding(r, self.entry)

    def test_registry_digest_drift(self):
        self._drift("registry_sha256", "0" * 64)

    def test_oracle_module_hash_drift(self):
        self._drift("oracle_module_sha256", "0" * 64)

    def test_dispatch_module_hash_drift(self):
        self._drift("dispatch_module_sha256", "0" * 64)

    def test_rtk_source_identity_drift(self):
        self._drift("rtk_source_identity_sha256", "0" * 64)

    def test_canon_policy_drift(self):
        self._drift("canonicalization_policy_id", "log-v2")


class TestRegistryScoping(unittest.TestCase):
    """The registry match is EXACTLY-ONE and CASE-SCOPED: no family-level binding, no wrong-case
    reuse, no zero/duplicate match, no unregistered oracle (no discovery, no fallback)."""

    def setUp(self):
        self.reg = disp.load_registry()

    def test_wrong_case_no_match(self):
        with self.assertRaises(disp.DispatchError):
            disp._registry_entry(self.reg, "rtk-log-hdfs-oracle-v1", "some::other::case")

    def test_unknown_policy_no_match(self):
        with self.assertRaises(disp.DispatchError):
            disp._registry_entry(self.reg, "rtk-nonexistent-oracle-v9", LOGHUB)

    def test_family_level_binding_barred(self):
        reg = copy.deepcopy(self.reg)
        reg["entries"][0]["allowed_case_ids"] = ["loghub"]  # no '::' -> family-level
        with self.assertRaises(disp.DispatchError):
            disp._registry_entry(reg, "rtk-log-hdfs-oracle-v1", "loghub")

    def test_duplicate_entry_not_exactly_one(self):
        reg = copy.deepcopy(self.reg)
        reg["entries"].append(copy.deepcopy(reg["entries"][0]))
        with self.assertRaises(disp.DispatchError):
            disp._registry_entry(reg, "rtk-log-hdfs-oracle-v1", LOGHUB)

    def test_oracle_bound_to_another_case_only(self):
        # a registry that binds the policy to a DIFFERENT case cannot qualify loghub
        reg = copy.deepcopy(self.reg)
        reg["entries"][0]["allowed_case_ids"] = ["other::HDFS::log"]
        with self.assertRaises(disp.DispatchError):
            disp._registry_entry(reg, "rtk-log-hdfs-oracle-v1", LOGHUB)


class TestNoDiscoveryNoFallback(unittest.TestCase):
    def setUp(self):
        self.entry = _loghub_entry()
        self.rec = _valid_rec(self.entry)

    def test_dynamic_import_path_barred(self):
        for k in ("oracle_module_path", "oracle_import", "module_path", "import_path", "entry_point"):
            r = copy.deepcopy(self.rec)
            r[k] = "tools/evil.py"
            with self.assertRaises(disp.DispatchError):
                disp.verify_dispatch_binding(r, self.entry)

    def test_policy_without_registered_module_has_no_path(self):
        # dispatch_code_identity refuses to bind a policy that is not in the static oracle table
        e = copy.deepcopy(self.entry)
        e["command_semantic_oracle_policy_id"] = "rtk-unregistered-oracle-v1"
        with self.assertRaises(disp.DispatchError):
            disp.dispatch_code_identity(e)

    def test_both_test_dialect_and_command_oracle(self):
        e = copy.deepcopy(self.entry)
        e["rtk_test_dialect_policy_id"] = "rtk-jvm-test-summary-v1"
        with self.assertRaises(disp.DispatchError):
            disp.verify_dispatch_binding(self.rec, e)

    def test_neither_semantic_id(self):
        e = copy.deepcopy(self.entry)
        e["command_semantic_oracle_policy_id"] = None
        with self.assertRaises(disp.DispatchError):
            disp.verify_dispatch_binding(self.rec, e)

    def test_kind_not_command_oracle(self):
        e = copy.deepcopy(self.entry)
        e["qualification_kind"] = "rtk_test_dialect"
        with self.assertRaises(disp.DispatchError):
            disp.verify_dispatch_binding(self.rec, e)


class TestRecomputeFailClosed(unittest.TestCase):
    """recompute derives the RAW<->RTK severity equivalence from the FROZEN capsule + RTK output; it
    never trusts a producer PASS string. Diagnostic provenance is barred; a broken published-authority
    capsule or non-closing severity totals recompute to FALSE (the aggregator then rejects the PASS)."""

    def setUp(self):
        self.entry = _loghub_entry()
        self.rec = _valid_rec(self.entry)

    def test_diagnostic_provenance_barred(self):
        r = copy.deepcopy(self.rec)
        r["record_kind"] = "loghub_diagnostic_capture"
        with self.assertRaises(disp.DispatchError):
            disp.recompute_dispatch_v2(r, self.entry)

    def test_barred_flag_rejected(self):
        r = copy.deepcopy(self.rec)
        r["barred_from_qualification"] = True
        with self.assertRaises(disp.DispatchError):
            disp.recompute_dispatch_v2(r, self.entry)

    def test_capsule_not_parsed_is_false(self):
        r = copy.deepcopy(self.rec)
        r["raw_capsule_summary"]["outcome"] = "unmatched_line"
        self.assertFalse(disp.recompute_dispatch_v2(r, self.entry))

    def test_unmatched_lines_is_false(self):
        r = copy.deepcopy(self.rec)
        r["raw_capsule_summary"]["unmatched_lines"] = 3
        self.assertFalse(disp.recompute_dispatch_v2(r, self.entry))

    def test_published_authority_not_held_is_false(self):
        r = copy.deepcopy(self.rec)
        r["raw_capsule_summary"]["occurrence_counts_match_published"] = False
        self.assertFalse(disp.recompute_dispatch_v2(r, self.entry))

    def test_severity_totals_do_not_close_is_false(self):
        r = copy.deepcopy(self.rec)
        r["raw_capsule_summary"]["rtk_semantic_projection"]["error"] = 9999
        self.assertFalse(disp.recompute_dispatch_v2(r, self.entry))

    def test_tampered_frozen_rtk_output_rejected(self):
        r = copy.deepcopy(self.rec)
        r["rtk_output"]["sha256"] = "0" * 64
        with self.assertRaises(disp.DispatchError):
            disp.recompute_dispatch_v2(r, self.entry)

    def test_missing_capsule_rejected(self):
        r = copy.deepcopy(self.rec)
        r.pop("raw_capsule_summary")
        with self.assertRaises(disp.DispatchError):
            disp.recompute_dispatch_v2(r, self.entry)


class TestAggregatorRouting(unittest.TestCase):
    """The aggregator chooses the path ONLY from the manifest entry's dispatch_policy_id. A dispatch
    record on a dispatch entry recomputes through dispatch-v2; a legacy record stays on cq. The two
    never cross, and an unknown dispatch generation is fail-closed."""

    def setUp(self):
        self.roster = A._roster_from_manifest(c.load_record(MANIFEST), MANIFEST)
        self.entry = next(e for e in self.roster if e["case_id"] == LOGHUB)
        self.rec = _valid_rec(self.entry)

    def _agg(self, roster=None, records=None):
        return A.aggregate(roster or self.roster,
                           records if records is not None else {LOGHUB: self.rec},
                           A.PRODUCTION_RECOMPUTE, A.PRODUCTION_BIND)

    def test_loghub_only_derives_one_pass_via_dispatch(self):
        # only the loghub dispatch record present; all others absent -> held, but loghub itself derives
        r = self._agg()
        self.assertTrue(r["per_case"][LOGHUB]["derived_pass"])
        self.assertFalse(r["resolved_canary_pass"])

    def test_unknown_dispatch_policy_id_rejected(self):
        roster = copy.deepcopy(self.roster)
        for e in roster:
            if e["case_id"] == LOGHUB:
                e["dispatch_policy_id"] = "n2e-qualification-dispatch-v7"
        with self.assertRaises(A.AggregateError):
            self._agg(roster=roster)

    def test_dispatch_identity_on_non_dispatch_entry_rejected(self):
        # a record carrying a dispatch_code_identity presented on a case NOT routed to a dispatch layer
        # (e.g. a legacy cq case) is barred by the aggregator's legacy-branch guard
        legacy = next(e for e in self.roster if e["case_id"] != LOGHUB
                      and e.get("dispatch_policy_id") is None)
        rec = {"record_type": legacy["expected_qualification_record_type"],
               "case_id": legacy["case_id"], "case_entry_sha256": legacy["case_entry_sha256"],
               "qualification_kind": legacy["qualification_kind"],
               "rtk_test_dialect_policy_id": legacy["rtk_test_dialect_policy_id"],
               "command_semantic_oracle_policy_id": legacy["command_semantic_oracle_policy_id"],
               "canonicalization_policy_id": legacy["canonicalization_policy_id"],
               "dispatch_code_identity": self.rec["dispatch_code_identity"],
               "acceptance_run": self.rec["acceptance_run"], "case_qualification_pass": True}
        with self.assertRaises(A.AggregateError):
            self._agg(records={legacy["case_id"]: rec})

    def test_loghub_record_without_dispatch_fields_rejected(self):
        # loghub entry IS routed to dispatch; a record missing the dispatch identity cannot bind
        r = copy.deepcopy(self.rec)
        r.pop("dispatch_code_identity")
        r.pop("dispatch_policy_id")
        with self.assertRaises(A.AggregateError):
            self._agg(records={LOGHUB: r})

    def test_producer_pass_recompute_fail_rejected(self):
        # capsule broken (published authority not held) -> recompute FALSE while record claims PASS
        r = copy.deepcopy(self.rec)
        r["raw_capsule_summary"]["occurrence_counts_match_published"] = False
        with self.assertRaises(A.AggregateError):
            self._agg(records={LOGHUB: r})

    def test_barred_diagnostic_provenance_rejected_by_aggregator(self):
        r = copy.deepcopy(self.rec)
        r["record_kind"] = "loghub_diagnostic_capture"
        with self.assertRaises(A.AggregateError):
            self._agg(records={LOGHUB: r})


if __name__ == "__main__":
    unittest.main()
