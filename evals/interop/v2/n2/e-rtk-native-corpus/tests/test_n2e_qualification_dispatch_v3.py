"""RED matrix for the n2e-qualification-dispatch-v3 layer (rubocop merge-aware oracle).

dispatch-v3 is a NEW immutable, case-scoped generation (v2 froze after Loghub). It binds the rubocop
merge oracle ONLY, and replays the split-authority merge equivalence from the frozen record evidence.
This suite proves the generation is strictly separated (from cq AND v2), checksum-pinned (layer +
registry + oracle module + parser-library dependency + RTK source), case-scoped (exact-one-match, no
family-level), and fail-closed on drift / dynamic import / diagnostic provenance / a recompute that
does not close.

GREEN anchor: a synthetic acceptance-shaped record whose evidence points at the FROZEN diagnostic
fixtures binds + recomputes True. (The REAL acceptance record uses fresh acceptance evidence over a
unique run; that is the aggregator's concern, exercised separately.)
"""
import copy
import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import n2e_qualification_dispatch_v3 as d3  # noqa: E402

RUBOCOP = "rubocop__rubocop-13687::git::show"
FX = "evidence/rubocop-git-show-diag"
_FILES = {"raw_stdout": "raw.stdout.bin", "rtk_stdout": "rtk.stdout.bin",
          "rev_list_parents": "plumb.rev_list_parents.bin",
          "first_parent_numstat": "plumb.first_parent_numstat.bin",
          "first_parent_shortstat": "plumb.first_parent_shortstat.bin",
          "abbrev_resolve": "plumb.abbrev_resolve.bin"}


def _entry():
    man = c.load_record(N2E_DIR / "n2e-resolved-twelve-manifest-v1.json")
    return next(e for e in man["cases"] if e["case_id"] == RUBOCOP)


def _ev(pathrel):
    b = (N2E_DIR / pathrel).read_bytes()
    return {"evidence_path": pathrel, "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)}


def _rec(entry):
    return {
        "record_type": "n2e-resolved-case-qualification", "case_id": RUBOCOP,
        "record_kind": "rubocop_git_show_acceptance_qualification",
        "case_entry_sha256": entry["case_entry_sha256"], "qualification_kind": "rtk_command_oracle",
        "command_semantic_oracle_policy_id": "rtk-git-show-merge-first-parent-oracle-v1",
        "rtk_test_dialect_policy_id": None, "canonicalization_policy_id": "git-v1",
        "dispatch_policy_id": "n2e-qualification-dispatch-v3",
        "dispatch_code_identity": d3.dispatch_code_identity(entry),
        "merge_evidence": {k: _ev(f"{FX}/{v}") for k, v in _FILES.items()},
        "case_qualification_pass": True,
    }


class TestGreen(unittest.TestCase):
    def setUp(self):
        self.entry = _entry(); self.rec = _rec(self.entry)

    def test_manifest_routes_rubocop_to_v3(self):
        self.assertEqual(self.entry["dispatch_policy_id"], "n2e-qualification-dispatch-v3")
        self.assertEqual(self.entry["command_semantic_oracle_policy_id"],
                         "rtk-git-show-merge-first-parent-oracle-v1")

    def test_valid_record_binds_and_recomputes(self):
        d3.verify_dispatch_binding(self.rec, self.entry)
        d3.bind_dispatch_v3(self.rec, self.entry)
        self.assertTrue(d3.recompute_dispatch_v3(self.rec, self.entry))

    def test_registry_exact_one_case_scoped(self):
        reg = d3.load_registry()
        e = d3._registry_entry(reg, "rtk-git-show-merge-first-parent-oracle-v1", RUBOCOP)
        self.assertEqual(e["allowed_case_ids"], [RUBOCOP])


class TestMutualExclusion(unittest.TestCase):
    def setUp(self):
        self.entry = _entry(); self.rec = _rec(self.entry)

    def test_cq_frozen_identity_on_dispatch_path_rejected(self):
        r = copy.deepcopy(self.rec); r["frozen_code_identity"] = {"x": 1}
        with self.assertRaises(d3.DispatchError):
            d3.verify_dispatch_binding(r, self.entry)

    def test_missing_dispatch_identity_rejected(self):
        r = copy.deepcopy(self.rec); r.pop("dispatch_code_identity")
        with self.assertRaises(d3.DispatchError):
            d3.verify_dispatch_binding(r, self.entry)

    def test_v2_record_on_v3_path_rejected(self):
        r = copy.deepcopy(self.rec); r["dispatch_policy_id"] = "n2e-qualification-dispatch-v2"
        with self.assertRaises(d3.DispatchError):
            d3.verify_dispatch_binding(r, self.entry)

    def test_manifest_not_routed_to_v3_rejected(self):
        e = copy.deepcopy(self.entry); e["dispatch_policy_id"] = None
        with self.assertRaises(d3.DispatchError):
            d3.verify_dispatch_binding(self.rec, e)


class TestDrift(unittest.TestCase):
    def setUp(self):
        self.entry = _entry(); self.rec = _rec(self.entry)

    def _drift(self, key):
        r = copy.deepcopy(self.rec)
        r["dispatch_code_identity"] = dict(r["dispatch_code_identity"]); r["dispatch_code_identity"][key] = "0" * 64
        with self.assertRaises(d3.DispatchError):
            d3.verify_dispatch_binding(r, self.entry)

    def test_registry_drift(self): self._drift("registry_sha256")
    def test_oracle_module_drift(self): self._drift("oracle_module_sha256")
    def test_dispatch_module_drift(self): self._drift("dispatch_module_sha256")
    def test_parser_library_drift(self): self._drift("parser_library_sha256")
    def test_rtk_source_drift(self): self._drift("rtk_source_identity_sha256")

    def test_canon_drift(self):
        r = copy.deepcopy(self.rec)
        r["dispatch_code_identity"] = dict(r["dispatch_code_identity"])
        r["dispatch_code_identity"]["canonicalization_policy_id"] = "git-v2"
        with self.assertRaises(d3.DispatchError):
            d3.verify_dispatch_binding(r, self.entry)


class TestRegistryScoping(unittest.TestCase):
    def setUp(self):
        self.reg = d3.load_registry()

    def test_wrong_case_no_match(self):
        with self.assertRaises(d3.DispatchError):
            d3._registry_entry(self.reg, "rtk-git-show-merge-first-parent-oracle-v1", "other::case::x")

    def test_unknown_policy_no_match(self):
        with self.assertRaises(d3.DispatchError):
            d3._registry_entry(self.reg, "rtk-nonexistent-v9", RUBOCOP)

    def test_family_level_barred(self):
        reg = copy.deepcopy(self.reg); reg["entries"][0]["allowed_case_ids"] = ["rubocop"]
        with self.assertRaises(d3.DispatchError):
            d3._registry_entry(reg, "rtk-git-show-merge-first-parent-oracle-v1", "rubocop")

    def test_duplicate_not_exactly_one(self):
        reg = copy.deepcopy(self.reg); reg["entries"].append(copy.deepcopy(reg["entries"][0]))
        with self.assertRaises(d3.DispatchError):
            d3._registry_entry(reg, "rtk-git-show-merge-first-parent-oracle-v1", RUBOCOP)

    def test_oracle_bound_to_another_case_only(self):
        reg = copy.deepcopy(self.reg); reg["entries"][0]["allowed_case_ids"] = ["other::git::show"]
        with self.assertRaises(d3.DispatchError):
            d3._registry_entry(reg, "rtk-git-show-merge-first-parent-oracle-v1", RUBOCOP)


class TestNoDiscoveryNoFallback(unittest.TestCase):
    def setUp(self):
        self.entry = _entry(); self.rec = _rec(self.entry)

    def test_dynamic_import_path_barred(self):
        for k in ("oracle_module_path", "oracle_import", "module_path", "import_path", "entry_point"):
            r = copy.deepcopy(self.rec); r[k] = "tools/evil.py"
            with self.assertRaises(d3.DispatchError):
                d3.verify_dispatch_binding(r, self.entry)

    def test_unregistered_policy_has_no_module(self):
        e = copy.deepcopy(self.entry); e["command_semantic_oracle_policy_id"] = "rtk-unregistered-v1"
        with self.assertRaises(d3.DispatchError):
            d3.dispatch_code_identity(e)

    def test_test_dialect_id_present_rejected(self):
        e = copy.deepcopy(self.entry); e["rtk_test_dialect_policy_id"] = "rtk-x"
        with self.assertRaises(d3.DispatchError):
            d3.verify_dispatch_binding(self.rec, e)


class TestRecomputeFailClosed(unittest.TestCase):
    def setUp(self):
        self.entry = _entry(); self.rec = _rec(self.entry)

    def test_diagnostic_kind_rejected(self):
        r = copy.deepcopy(self.rec); r["record_kind"] = "rubocop_git_show_diagnostic_capture"
        with self.assertRaises(d3.DispatchError):
            d3.recompute_dispatch_v3(r, self.entry)

    def test_barred_flag_rejected(self):
        r = copy.deepcopy(self.rec); r["barred_from_qualification"] = True
        with self.assertRaises(d3.DispatchError):
            d3.recompute_dispatch_v3(r, self.entry)

    def test_tampered_evidence_sha_rejected(self):
        r = copy.deepcopy(self.rec)
        r["merge_evidence"]["rtk_stdout"] = dict(r["merge_evidence"]["rtk_stdout"])
        r["merge_evidence"]["rtk_stdout"]["sha256"] = "0" * 64
        with self.assertRaises(d3.DispatchError):
            d3.recompute_dispatch_v3(r, self.entry)

    def test_missing_evidence_rejected(self):
        r = copy.deepcopy(self.rec); r["merge_evidence"].pop("first_parent_numstat")
        with self.assertRaises(d3.DispatchError):
            d3.recompute_dispatch_v3(r, self.entry)

    def test_recompute_false_when_stat_does_not_close(self):
        # evidence that passes integrity but whose first-parent numstat totals disagree with RTK's
        # compact stat -> equivalence FALSE (recompute returns False; aggregator then rejects the PASS)
        tmp = N2E_DIR / "evidence" / "_dispatchv3_red_tmp"
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        tmp.mkdir(parents=True, exist_ok=True)
        # copy all fixtures, then replace numstat with mismatching totals (+99 instead of +15)
        src = N2E_DIR / FX
        for k, fn in _FILES.items():
            (tmp / fn).write_bytes((src / fn).read_bytes())
        (tmp / "plumb.first_parent_numstat.bin").write_bytes(
            b"99\t1\tspec/rubocop/cop/style/redundant_line_continuation_spec.rb\n")
        r = copy.deepcopy(self.rec)
        rel = "evidence/_dispatchv3_red_tmp"
        r["merge_evidence"] = {k: {"evidence_path": f"{rel}/{fn}",
                                   "sha256": hashlib.sha256((tmp / fn).read_bytes()).hexdigest(),
                                   "bytes": (tmp / fn).stat().st_size}
                               for k, fn in _FILES.items()}
        self.assertFalse(d3.recompute_dispatch_v3(r, self.entry))


if __name__ == "__main__":
    unittest.main()
