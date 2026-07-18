"""Phase 1 acceptance for the additive resolved-ENVIRONMENT overlay (Model B frozen dependency
snapshot). The overlay is contract-anchored (pins base_execution_contract_sha256 + materializes
the resolved execution contract's stable-logical dependency_environment_identity_ref) and carries
the frozen Run 29654373144 determinants. The loader validates EVERY pinned determinant against the
committed frozen artifacts (not schema shape), requires exactly one snapshot for the replacement
case, re-derives the closure size from the committed graph, and bars diagnostic-only provenance.

Acceptance:
  GREEN: the frozen Run 29654373144 evidence closes through the loader.
  RED:   missing fifth overlay; overlay on the wrong execution contract; one changed lock
         byte/hash/count/scope/case identifier; a 345- or 347-node closure; duplicate snapshots;
         barred diagnostic-only provenance; an overlay that does not materialize the contract ref.
  Regression: the four existing overlays rebuild byte-identically (unchanged digests).
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
import build_n2e_resolved_overlays as B  # noqa: E402


def _real_inputs():
    ds = c.load_record(L.OV_DEPSNAP)
    ec = c.load_record(L.OV_CONTRACT)
    dep_ref = ec["overlay_contracts"][0]["dependency_environment_identity_ref"]
    rm_sha = c.sha256_json_file(L.RESOLVED_MEMBERSHIP)
    base_sha = c.sha256_json_file(L.CONTRACT)
    return ds, dep_ref, rm_sha, base_sha


class TestDependencySnapshotOverlay(unittest.TestCase):
    def setUp(self):
        self.ds, self.dep_ref, self.rm_sha, self.base_sha = _real_inputs()
        self.ev = Path(tempfile.mkdtemp())
        shutil.copy(L.DEPSNAP_DIR / "Cargo.lock", self.ev / "Cargo.lock")
        shutil.copy(L.DEPSNAP_DIR / "resolved-graph.json", self.ev / "resolved-graph.json")

    def _v(self, ds=None, dep_ref=None, rm_sha=None, base_sha=None, ev=None):
        return L.validate_dependency_snapshot_overlay(
            self.ds if ds is None else ds,
            self.dep_ref if dep_ref is None else dep_ref,
            self.rm_sha if rm_sha is None else rm_sha,
            self.base_sha if base_sha is None else base_sha,
            self.ev if ev is None else ev)

    def _mut(self, **snap_fields):
        ds = copy.deepcopy(self.ds)
        ds["overlay_dependency_snapshots"][0].update(snap_fields)
        return ds

    # ---------- GREEN ----------
    def test_green_frozen_evidence_validates(self):
        snap = self._v()
        self.assertEqual(snap["host_resolved_package_count"], 346)
        self.assertEqual(snap["cargo_lock_bytes"], 85805)

    def test_green_full_closure_loads(self):
        cl = L.validate_resolved_closure()
        self.assertIn("dependency_snapshot", cl["overlays"])
        self.assertEqual(cl["effective_record_hash_map"]["frozen_dependency_snapshot"]
                         ["host_resolved_package_count"], 346)
        b = L.load_case_bundle(L.REPLACEMENT_CASE_ID, "resolved")
        self.assertEqual(b["resolved_dependency_snapshot"]["host_resolved_package_count"], 346)

    # ---------- RED ----------
    def test_red_missing_fifth_overlay(self):
        with self.assertRaises(L.ResolvedScopeError):
            L._load_snapshot_overlay(self.ev / "does-not-exist.json")

    def test_red_wrong_execution_contract(self):
        with self.assertRaises(L.ResolvedScopeError):
            self._v(base_sha="sha256:" + "0" * 64)

    def test_red_lock_byte_changed_in_evidence(self):
        (self.ev / "Cargo.lock").write_bytes((self.ev / "Cargo.lock").read_bytes() + b"# tampered\n")
        with self.assertRaises(L.ResolvedScopeError):
            self._v()

    def test_red_lock_hash_pin_changed(self):
        with self.assertRaises(L.ResolvedScopeError):
            self._v(ds=self._mut(cargo_lock_sha256="0" * 64))

    def test_red_scope_changed(self):
        with self.assertRaises(L.ResolvedScopeError):
            self._v(ds=self._mut(cargo_lock_scope="host-filtered"))

    def test_red_case_identifier_changed(self):
        with self.assertRaises(L.ResolvedScopeError):
            self._v(ds=self._mut(case_id="uutils__coreutils-6731::rust_cargo::test::evil"))

    def test_red_count_345_pin_mismatch(self):
        with self.assertRaises(L.ResolvedScopeError):
            self._v(ds=self._mut(host_resolved_package_count=345))

    def test_red_count_347_self_consistent_closure(self):
        # build a self-consistent 347-node closure (add an isolated ghost root) with a recomputed
        # graph hash + pin, so the ONLY failing invariant is "not the proven 346-node closure".
        g = c.load_record(self.ev / "resolved-graph.json")
        hg = g["host_resolve_graph"]
        hg["resolve_nodes"] = sorted(hg["resolve_nodes"] + [{"id": "ghost 9.9.9", "features": [], "deps": []}],
                                     key=lambda n: n["id"])
        hg["resolve_roots"] = sorted(hg["resolve_roots"] + ["ghost 9.9.9"])
        hg["reachable_package_ids"] = sorted(hg["reachable_package_ids"] + ["ghost 9.9.9"])
        new_graph_sha = L._manifest_hash(hg)
        g["host_resolve_graph_sha256"] = new_graph_sha
        g["host_resolved_package_count"] = 347
        (self.ev / "resolved-graph.json").write_text(json.dumps(g))
        ds = self._mut(host_resolve_graph_sha256=new_graph_sha, host_resolved_package_count=347)
        with self.assertRaises(L.ResolvedScopeError):
            self._v(ds=ds)

    def test_red_duplicate_snapshots(self):
        ds = copy.deepcopy(self.ds)
        s = ds["overlay_dependency_snapshots"][0]
        ds["overlay_dependency_snapshots"] = [s, copy.deepcopy(s)]
        with self.assertRaises(L.ResolvedScopeError):
            self._v(ds=ds)

    def test_red_wrong_materialized_ref(self):
        ds = copy.deepcopy(self.ds)
        ds["materializes_dependency_environment_identity_ref"] = {"where": "elsewhere", "protected_files": []}
        with self.assertRaises(L.ResolvedScopeError):
            self._v(ds=ds)

    def test_red_barred_diagnostic_run_provenance(self):
        # 29652684349 == run for impl 3dbbf2b (diagnostic-only)
        ds = copy.deepcopy(self.ds)
        ds["overlay_dependency_snapshots"][0]["provenance"]["run_id"] = "29652684349"
        with self.assertRaises(L.ResolvedScopeError):
            self._v(ds=ds)

    def test_red_barred_diagnostic_impl_provenance(self):
        ds = copy.deepcopy(self.ds)
        ds["overlay_dependency_snapshots"][0]["provenance"]["verifier_implementation"] = "bcd4164"
        with self.assertRaises(L.ResolvedScopeError):
            self._v(ds=ds)

    # ---------- Regression ----------
    def test_regression_existing_four_overlays_byte_identical(self):
        builders = {
            "n2e-resolved-publisher-env-overlay-v1.json": B.build_publisher_env_overlay,
            "n2e-resolved-toolchain-overlay-v1.json": B.build_toolchain_overlay,
            "n2e-resolved-command-scenario-overlay-v1.json": B.build_command_scenario_overlay,
            "n2e-resolved-execution-contract-v1.json": B.build_execution_contract_overlay,
        }
        for fname, fn in builders.items():
            body = fn()
            c.finalize(body)
            rebuilt = json.dumps(body, indent=2, sort_keys=True) + "\n"
            on_disk = (N2E_DIR / fname).read_text()
            self.assertEqual(rebuilt, on_disk, f"{fname} digest changed")


if __name__ == "__main__":
    unittest.main()
