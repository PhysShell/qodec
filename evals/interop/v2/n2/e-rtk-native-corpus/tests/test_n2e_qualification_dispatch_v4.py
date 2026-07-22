"""RED matrix for the n2e-qualification-dispatch-v4 layer (php-cs-fixer commit-identity oracle).

dispatch-v4 is a NEW immutable, case-scoped generation (v2 froze after Loghub, v3 after the rubocop
merge oracle). It binds the php-cs-fixer commit oracle ONLY, and replays the resulting-ref identity
from the frozen record evidence (RAW/RTK commit plumbing + RTK stdout). This suite proves the
generation is strictly separated (from cq AND v2/v3), checksum-pinned (layer + registry + oracle
module + parser-library dependency + RTK source), case-scoped (exact-one-match, no family-level), and
fail-closed on drift / dynamic import / diagnostic provenance / a recompute that does not close (an
OID that fails to reproduce -- the hash is never normalized).

GREEN anchor: a synthetic acceptance-shaped record whose evidence points at the FROZEN diagnostic
fixtures binds + recomputes True. (The REAL acceptance record uses fresh acceptance evidence over a
unique run; that is the aggregator's concern, exercised separately.)
"""
import copy
import hashlib
import shutil
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import n2e_qualification_dispatch_v4 as d4  # noqa: E402

PHPCS = "php-cs-fixer__php-cs-fixer-8075::git::commit"
FX = "evidence/php-cs-fixer-git-commit-diag"
_FILES = {"raw_head": "raw.plumb.head.bin", "raw_parent": "raw.plumb.parent.bin",
          "raw_name_status": "raw.plumb.name_status.bin",
          "rtk_head": "rtk.plumb.head.bin", "rtk_parent": "rtk.plumb.parent.bin",
          "rtk_name_status": "rtk.plumb.name_status.bin", "rtk_stdout": "rtk.stdout.bin"}


def _entry():
    man = c.load_record(N2E_DIR / "n2e-resolved-twelve-manifest-v1.json")
    return next(e for e in man["cases"] if e["case_id"] == PHPCS)


def _ev(pathrel):
    b = (N2E_DIR / pathrel).read_bytes()
    return {"evidence_path": pathrel, "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)}


def _rec(entry):
    return {
        "record_type": "n2e-resolved-case-qualification", "case_id": PHPCS,
        "record_kind": "php_cs_fixer_git_commit_acceptance_qualification",
        "case_entry_sha256": entry["case_entry_sha256"], "qualification_kind": "rtk_command_oracle",
        "command_semantic_oracle_policy_id": "rtk-git-commit-oracle-v1",
        "rtk_test_dialect_policy_id": None, "canonicalization_policy_id": "git-v1",
        "dispatch_policy_id": "n2e-qualification-dispatch-v4",
        "dispatch_code_identity": d4.dispatch_code_identity(entry),
        "commit_evidence": {k: _ev(f"{FX}/{v}") for k, v in _FILES.items()},
        "case_qualification_pass": True,
    }


class TestGreen(unittest.TestCase):
    def setUp(self):
        self.entry = _entry(); self.rec = _rec(self.entry)

    def test_manifest_routes_phpcs_to_v4(self):
        self.assertEqual(self.entry["dispatch_policy_id"], "n2e-qualification-dispatch-v4")
        self.assertEqual(self.entry["command_semantic_oracle_policy_id"], "rtk-git-commit-oracle-v1")

    def test_valid_record_binds_and_recomputes(self):
        d4.verify_dispatch_binding(self.rec, self.entry)
        d4.bind_dispatch_v4(self.rec, self.entry)
        self.assertTrue(d4.recompute_dispatch_v4(self.rec, self.entry))

    def test_registry_exact_one_case_scoped(self):
        reg = d4.load_registry()
        e = d4._registry_entry(reg, "rtk-git-commit-oracle-v1", PHPCS)
        self.assertEqual(e["allowed_case_ids"], [PHPCS])


class TestMutualExclusion(unittest.TestCase):
    def setUp(self):
        self.entry = _entry(); self.rec = _rec(self.entry)

    def test_cq_frozen_identity_on_dispatch_path_rejected(self):
        r = copy.deepcopy(self.rec); r["frozen_code_identity"] = {"x": 1}
        with self.assertRaises(d4.DispatchError):
            d4.verify_dispatch_binding(r, self.entry)

    def test_missing_dispatch_identity_rejected(self):
        r = copy.deepcopy(self.rec); r.pop("dispatch_code_identity")
        with self.assertRaises(d4.DispatchError):
            d4.verify_dispatch_binding(r, self.entry)

    def test_v3_record_on_v4_path_rejected(self):
        r = copy.deepcopy(self.rec); r["dispatch_policy_id"] = "n2e-qualification-dispatch-v3"
        with self.assertRaises(d4.DispatchError):
            d4.verify_dispatch_binding(r, self.entry)

    def test_manifest_not_routed_to_v4_rejected(self):
        e = copy.deepcopy(self.entry); e["dispatch_policy_id"] = None
        with self.assertRaises(d4.DispatchError):
            d4.verify_dispatch_binding(self.rec, e)


class TestDrift(unittest.TestCase):
    def setUp(self):
        self.entry = _entry(); self.rec = _rec(self.entry)

    def _drift(self, key):
        r = copy.deepcopy(self.rec)
        r["dispatch_code_identity"] = dict(r["dispatch_code_identity"]); r["dispatch_code_identity"][key] = "0" * 64
        with self.assertRaises(d4.DispatchError):
            d4.verify_dispatch_binding(r, self.entry)

    def test_registry_drift(self): self._drift("registry_sha256")
    def test_oracle_module_drift(self): self._drift("oracle_module_sha256")
    def test_dispatch_module_drift(self): self._drift("dispatch_module_sha256")
    def test_parser_library_drift(self): self._drift("parser_library_sha256")
    def test_rtk_source_drift(self): self._drift("rtk_source_identity_sha256")

    def test_canon_drift(self):
        r = copy.deepcopy(self.rec)
        r["dispatch_code_identity"] = dict(r["dispatch_code_identity"])
        r["dispatch_code_identity"]["canonicalization_policy_id"] = "git-v2"
        with self.assertRaises(d4.DispatchError):
            d4.verify_dispatch_binding(r, self.entry)


class TestRegistryScoping(unittest.TestCase):
    def setUp(self):
        self.reg = d4.load_registry()

    def test_wrong_case_no_match(self):
        with self.assertRaises(d4.DispatchError):
            d4._registry_entry(self.reg, "rtk-git-commit-oracle-v1", "other::case::x")

    def test_unknown_policy_no_match(self):
        with self.assertRaises(d4.DispatchError):
            d4._registry_entry(self.reg, "rtk-nonexistent-v9", PHPCS)

    def test_family_level_barred(self):
        reg = copy.deepcopy(self.reg); reg["entries"][0]["allowed_case_ids"] = ["php-cs-fixer"]
        with self.assertRaises(d4.DispatchError):
            d4._registry_entry(reg, "rtk-git-commit-oracle-v1", "php-cs-fixer")

    def test_duplicate_not_exactly_one(self):
        reg = copy.deepcopy(self.reg); reg["entries"].append(copy.deepcopy(reg["entries"][0]))
        with self.assertRaises(d4.DispatchError):
            d4._registry_entry(reg, "rtk-git-commit-oracle-v1", PHPCS)

    def test_oracle_bound_to_another_case_only(self):
        reg = copy.deepcopy(self.reg); reg["entries"][0]["allowed_case_ids"] = ["other::git::commit"]
        with self.assertRaises(d4.DispatchError):
            d4._registry_entry(reg, "rtk-git-commit-oracle-v1", PHPCS)


class TestNoDiscoveryNoFallback(unittest.TestCase):
    def setUp(self):
        self.entry = _entry(); self.rec = _rec(self.entry)

    def test_dynamic_import_path_barred(self):
        for k in ("oracle_module_path", "oracle_import", "module_path", "import_path", "entry_point"):
            r = copy.deepcopy(self.rec); r[k] = "tools/evil.py"
            with self.assertRaises(d4.DispatchError):
                d4.verify_dispatch_binding(r, self.entry)

    def test_unregistered_policy_has_no_module(self):
        e = copy.deepcopy(self.entry); e["command_semantic_oracle_policy_id"] = "rtk-unregistered-v1"
        with self.assertRaises(d4.DispatchError):
            d4.dispatch_code_identity(e)

    def test_test_dialect_id_present_rejected(self):
        e = copy.deepcopy(self.entry); e["rtk_test_dialect_policy_id"] = "rtk-x"
        with self.assertRaises(d4.DispatchError):
            d4.verify_dispatch_binding(self.rec, e)


class TestRecomputeFailClosed(unittest.TestCase):
    def setUp(self):
        self.entry = _entry(); self.rec = _rec(self.entry)

    def test_diagnostic_kind_rejected(self):
        r = copy.deepcopy(self.rec); r["record_kind"] = "php_cs_fixer_git_commit_diagnostic_capture"
        with self.assertRaises(d4.DispatchError):
            d4.recompute_dispatch_v4(r, self.entry)

    def test_barred_flag_rejected(self):
        r = copy.deepcopy(self.rec); r["barred_from_qualification"] = True
        with self.assertRaises(d4.DispatchError):
            d4.recompute_dispatch_v4(r, self.entry)

    def test_tampered_evidence_sha_rejected(self):
        r = copy.deepcopy(self.rec)
        r["commit_evidence"]["rtk_stdout"] = dict(r["commit_evidence"]["rtk_stdout"])
        r["commit_evidence"]["rtk_stdout"]["sha256"] = "0" * 64
        with self.assertRaises(d4.DispatchError):
            d4.recompute_dispatch_v4(r, self.entry)

    def test_missing_evidence_rejected(self):
        r = copy.deepcopy(self.rec); r["commit_evidence"].pop("rtk_head")
        with self.assertRaises(d4.DispatchError):
            d4.recompute_dispatch_v4(r, self.entry)

    def test_recompute_false_when_oid_does_not_reproduce(self):
        # evidence that passes integrity but where RTK's resulting commit OID differs from RAW's --
        # a hidden determinant leaked. equivalence FALSE (the hash is never normalized); recompute
        # returns False and the aggregator then rejects the PASS.
        tmp = N2E_DIR / "evidence" / "_dispatchv4_red_tmp"
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        tmp.mkdir(parents=True, exist_ok=True)
        src = N2E_DIR / FX
        for fn in _FILES.values():
            (tmp / fn).write_bytes((src / fn).read_bytes())
        # RTK arm resolves to a DIFFERENT 40-hex commit than RAW (OID did not reproduce)
        (tmp / "rtk.plumb.head.bin").write_bytes(b"ffff1234ef5678901234567890abcdef12345678\n")
        r = copy.deepcopy(self.rec)
        rel = "evidence/_dispatchv4_red_tmp"
        r["commit_evidence"] = {k: {"evidence_path": f"{rel}/{fn}",
                                    "sha256": hashlib.sha256((tmp / fn).read_bytes()).hexdigest(),
                                    "bytes": (tmp / fn).stat().st_size}
                                for k, fn in _FILES.items()}
        self.assertFalse(d4.recompute_dispatch_v4(r, self.entry))


if __name__ == "__main__":
    unittest.main()
