"""RED matrix for the n2e-qualification-dispatch-v5 layer (redis docker-images oracle).

dispatch-v5 is a NEW immutable, case-scoped generation (v2 Loghub, v3 rubocop merge, v4 php-cs-fixer
commit). It binds the redis docker-images oracle ONLY and replays TWO authorities from the frozen
evidence: the RTK compact projection (repository:tag,size multiset + count, faithful, compact -- not
never_worse passthrough) and the image IDENTITY (config Id + RepoDigest == the pinned
redis-docker-images-execution-v1 determinants, both isolated daemons agreeing). This suite proves the
generation is strictly separated (from cq AND v2/v3/v4), checksum-pinned (layer + registry + oracle +
RTK source + execution policy), case-scoped, and fail-closed on drift / dynamic import / diagnostic
provenance / passthrough / a mismatched or tampered identity.

GREEN anchor: a synthetic acceptance-shaped record whose evidence points at the FROZEN diagnostic
fixtures binds + recomputes True.
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
import n2e_qualification_dispatch_v5 as d5  # noqa: E402

REDIS = "container::redis::docker::images"
FX = "evidence/redis-docker-images-diag"
_FILES = {"raw_format_rows": "raw.format_rows.bin", "rtk_stdout": "rtk.stdout.bin",
          "raw_inspect": "raw.inspect.json", "rtk_inspect": "rtk.inspect.json"}


def _entry():
    man = c.load_record(N2E_DIR / "n2e-resolved-twelve-manifest-v1.json")
    return next(e for e in man["cases"] if e["case_id"] == REDIS)


def _ev(pathrel):
    b = (N2E_DIR / pathrel).read_bytes()
    return {"evidence_path": pathrel, "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)}


def _rec(entry):
    return {
        "record_type": "n2e-resolved-case-qualification", "case_id": REDIS,
        "record_kind": "redis_docker_images_acceptance_qualification",
        "case_entry_sha256": entry["case_entry_sha256"], "qualification_kind": "rtk_command_oracle",
        "command_semantic_oracle_policy_id": "rtk-docker-images-oracle-v1",
        "rtk_test_dialect_policy_id": None, "canonicalization_policy_id": "docker-v1",
        "dispatch_policy_id": "n2e-qualification-dispatch-v5",
        "dispatch_code_identity": d5.dispatch_code_identity(entry),
        "docker_evidence": {k: _ev(f"{FX}/{v}") for k, v in _FILES.items()},
        "case_qualification_pass": True,
    }


class TestGreen(unittest.TestCase):
    def setUp(self):
        self.entry = _entry(); self.rec = _rec(self.entry)

    def test_manifest_routes_redis_to_v5(self):
        self.assertEqual(self.entry["dispatch_policy_id"], "n2e-qualification-dispatch-v5")
        self.assertEqual(self.entry["command_semantic_oracle_policy_id"], "rtk-docker-images-oracle-v1")

    def test_valid_record_binds_and_recomputes(self):
        d5.verify_dispatch_binding(self.rec, self.entry)
        d5.bind_dispatch_v5(self.rec, self.entry)
        self.assertTrue(d5.recompute_dispatch_v5(self.rec, self.entry))

    def test_registry_exact_one_case_scoped(self):
        reg = d5.load_registry()
        e = d5._registry_entry(reg, "rtk-docker-images-oracle-v1", REDIS)
        self.assertEqual(e["allowed_case_ids"], [REDIS])


class TestMutualExclusion(unittest.TestCase):
    def setUp(self):
        self.entry = _entry(); self.rec = _rec(self.entry)

    def test_cq_frozen_identity_on_dispatch_path_rejected(self):
        r = copy.deepcopy(self.rec); r["frozen_code_identity"] = {"x": 1}
        with self.assertRaises(d5.DispatchError):
            d5.verify_dispatch_binding(r, self.entry)

    def test_missing_dispatch_identity_rejected(self):
        r = copy.deepcopy(self.rec); r.pop("dispatch_code_identity")
        with self.assertRaises(d5.DispatchError):
            d5.verify_dispatch_binding(r, self.entry)

    def test_v4_record_on_v5_path_rejected(self):
        r = copy.deepcopy(self.rec); r["dispatch_policy_id"] = "n2e-qualification-dispatch-v4"
        with self.assertRaises(d5.DispatchError):
            d5.verify_dispatch_binding(r, self.entry)

    def test_manifest_not_routed_to_v5_rejected(self):
        e = copy.deepcopy(self.entry); e["dispatch_policy_id"] = None
        with self.assertRaises(d5.DispatchError):
            d5.verify_dispatch_binding(self.rec, e)


class TestDrift(unittest.TestCase):
    def setUp(self):
        self.entry = _entry(); self.rec = _rec(self.entry)

    def _drift(self, key):
        r = copy.deepcopy(self.rec)
        r["dispatch_code_identity"] = dict(r["dispatch_code_identity"]); r["dispatch_code_identity"][key] = "0" * 64
        with self.assertRaises(d5.DispatchError):
            d5.verify_dispatch_binding(r, self.entry)

    def test_registry_drift(self): self._drift("registry_sha256")
    def test_oracle_module_drift(self): self._drift("oracle_module_sha256")
    def test_dispatch_module_drift(self): self._drift("dispatch_module_sha256")
    def test_rtk_source_drift(self): self._drift("rtk_source_identity_sha256")
    def test_execution_policy_drift(self): self._drift("execution_policy_sha256")

    def test_canon_drift(self):
        r = copy.deepcopy(self.rec)
        r["dispatch_code_identity"] = dict(r["dispatch_code_identity"])
        r["dispatch_code_identity"]["canonicalization_policy_id"] = "docker-v2"
        with self.assertRaises(d5.DispatchError):
            d5.verify_dispatch_binding(r, self.entry)


class TestRegistryScoping(unittest.TestCase):
    def setUp(self):
        self.reg = d5.load_registry()

    def test_wrong_case_no_match(self):
        with self.assertRaises(d5.DispatchError):
            d5._registry_entry(self.reg, "rtk-docker-images-oracle-v1", "other::case::x")

    def test_unknown_policy_no_match(self):
        with self.assertRaises(d5.DispatchError):
            d5._registry_entry(self.reg, "rtk-nonexistent-v9", REDIS)

    def test_family_level_barred(self):
        reg = copy.deepcopy(self.reg); reg["entries"][0]["allowed_case_ids"] = ["redis"]
        with self.assertRaises(d5.DispatchError):
            d5._registry_entry(reg, "rtk-docker-images-oracle-v1", "redis")

    def test_duplicate_not_exactly_one(self):
        reg = copy.deepcopy(self.reg); reg["entries"].append(copy.deepcopy(reg["entries"][0]))
        with self.assertRaises(d5.DispatchError):
            d5._registry_entry(reg, "rtk-docker-images-oracle-v1", REDIS)


class TestNoDiscoveryNoFallback(unittest.TestCase):
    def setUp(self):
        self.entry = _entry(); self.rec = _rec(self.entry)

    def test_dynamic_import_path_barred(self):
        for k in ("oracle_module_path", "oracle_import", "module_path", "import_path", "entry_point"):
            r = copy.deepcopy(self.rec); r[k] = "tools/evil.py"
            with self.assertRaises(d5.DispatchError):
                d5.verify_dispatch_binding(r, self.entry)

    def test_unregistered_policy_has_no_module(self):
        e = copy.deepcopy(self.entry); e["command_semantic_oracle_policy_id"] = "rtk-unregistered-v1"
        with self.assertRaises(d5.DispatchError):
            d5.dispatch_code_identity(e)

    def test_test_dialect_id_present_rejected(self):
        e = copy.deepcopy(self.entry); e["rtk_test_dialect_policy_id"] = "rtk-x"
        with self.assertRaises(d5.DispatchError):
            d5.verify_dispatch_binding(self.rec, e)


class TestRecomputeFailClosed(unittest.TestCase):
    def setUp(self):
        self.entry = _entry(); self.rec = _rec(self.entry)

    def test_diagnostic_kind_rejected(self):
        r = copy.deepcopy(self.rec); r["record_kind"] = "redis_docker_images_diagnostic_capture"
        with self.assertRaises(d5.DispatchError):
            d5.recompute_dispatch_v5(r, self.entry)

    def test_barred_flag_rejected(self):
        r = copy.deepcopy(self.rec); r["barred_from_qualification"] = True
        with self.assertRaises(d5.DispatchError):
            d5.recompute_dispatch_v5(r, self.entry)

    def test_tampered_evidence_sha_rejected(self):
        r = copy.deepcopy(self.rec)
        r["docker_evidence"]["rtk_stdout"] = dict(r["docker_evidence"]["rtk_stdout"])
        r["docker_evidence"]["rtk_stdout"]["sha256"] = "0" * 64
        with self.assertRaises(d5.DispatchError):
            d5.recompute_dispatch_v5(r, self.entry)

    def test_missing_evidence_rejected(self):
        r = copy.deepcopy(self.rec); r["docker_evidence"].pop("raw_inspect")
        with self.assertRaises(d5.DispatchError):
            d5.recompute_dispatch_v5(r, self.entry)

    def _swap_evidence(self, tmpname, changes):
        """Copy the frozen fixtures into a tmp dir, apply {filename: new_bytes}, rebind evidence."""
        tmp = N2E_DIR / "evidence" / tmpname
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        tmp.mkdir(parents=True, exist_ok=True)
        src = N2E_DIR / FX
        for k, fn in _FILES.items():
            (tmp / fn).write_bytes(changes.get(fn, (src / fn).read_bytes()))
        r = copy.deepcopy(self.rec)
        rel = f"evidence/{tmpname}"
        r["docker_evidence"] = {k: {"evidence_path": f"{rel}/{fn}",
                                    "sha256": hashlib.sha256((tmp / fn).read_bytes()).hexdigest(),
                                    "bytes": (tmp / fn).stat().st_size}
                                for k, fn in _FILES.items()}
        return r

    def test_recompute_false_when_passthrough(self):
        # RTK echoed the raw table (never_worse fallback): no compact projection -> recompute False
        raw_table = (N2E_DIR / FX / "raw.stdout.bin").read_bytes()
        r = self._swap_evidence("_dispatchv5_red_pt", {"rtk.stdout.bin": raw_table})
        self.assertFalse(d5.recompute_dispatch_v5(r, self.entry))

    def test_recompute_false_when_multiset_differs(self):
        # RTK lists a different tag than the raw --format projection -> equivalence False
        rtk_wrong = b"[docker] 1 images (47MB)\n  redis:WRONG [46.7MB]\n"
        r = self._swap_evidence("_dispatchv5_red_ms", {"rtk.stdout.bin": rtk_wrong})
        self.assertFalse(d5.recompute_dispatch_v5(r, self.entry))

    def test_recompute_false_when_wrong_image_identity(self):
        # inspect shows a DIFFERENT config Id / RepoDigest than the pinned execution policy -> False
        wrong = (b'[{"Id":"sha256:deadbeef","RepoDigests":["redis@sha256:0000"],'
                 b'"RepoTags":["redis:n2e"],"Architecture":"amd64","Os":"linux","Size":1}]')
        r = self._swap_evidence("_dispatchv5_red_id",
                                {"raw.inspect.json": wrong, "rtk.inspect.json": wrong})
        self.assertFalse(d5.recompute_dispatch_v5(r, self.entry))


if __name__ == "__main__":
    unittest.main()
