"""Genuinely-independent, fail-closed DISQUALIFIED_RTK_SEMANTIC_LOSS derivation
(corrections 3/4). A terminal entry requires: exact toolchain-lock identity match (not
bool(toolchain_pin)), acquisition-order verification, and INDEPENDENT re-hash + re-parse
of the uploaded primary per-rep streams (RAW + measured RTK + tee sidecar). Missing
evidence files, a hash mismatch, a preserved identity in the measured RTK stream, or any
failed precondition downgrades to insufficient_evidence."""
import hashlib
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import build_n2e_canary_rejection_ledger as L  # noqa: E402
import n2e_common as c  # noqa: E402

CADDY = "caddyserver__caddy-5870::go::test::buggy"
INSTANCE = "caddyserver__caddy-5870"
GO_SHA = "0cdc4480040b5ef62eb17ba283ab92eca991794a937620604a2b5772201c2b59"  # matches the lock
RTK = L.RTK_BINARY_SHA256
BASE = "b" * 40
FAILLINE = b"=== RUN   TestUnsyncedConfigAccess\n--- FAIL: TestUnsyncedConfigAccess (0.01s)\nFAIL\nexit 1\n"
# RTK measured stream: summary preserved (1 failed) but the per-test FAIL id diverted to tee
RTK_MEASURED = b"1 failed\n[full output: /tmp/n2e/rtk/tee/1737_caddy.log]\nFAIL\nexit 1\n"


def _order():
    GM = {"go.mod": "m", "go.sum": "s"}
    def b(label, **x): return {"label": label, "protected": GM, "worktree_diff_sha256": "d",
                               "worktree_diff_bytes": 1, "tracked_status": [], **x}
    return {
        "policy_id": "publisher-acquisition-order-v1", "snapshot_variant": "buggy",
        "base_commit": BASE, "gold_files": [],
        "canonical_sequence": ["base", "pre_install", "install_warm", "test_files_reset", "test_patch"],
        "boundaries": [
            b("base"), b("pre_install"), b("install_warm"),
            b("test_files_reset", test_patch_files=["caddytest/x_test.go"], gold_files=[],
              test_patch_files_existing_at_base=["caddytest/x_test.go"],
              reset_paths=["caddytest/x_test.go"], reset_failed=[], reset_from_commit=BASE,
              base_commit=BASE),
            b("test_patch", tracked_status=[" M caddytest/x_test.go"], applied=True, patch_sha256="t"),
        ],
        "install": {"ran": True, "locked": False, "steps": [{"exit": 0}]},
        "applied_patches": [{"name": "test_patch", "apply_exit": 0}],
        "gold_applied": False, "test_applied": True,
    }


def _ev(dirp, role, rep, data):
    comp = zlib.compress(data, 9)
    (dirp / f"{role}.rep{rep}.zst").write_bytes(comp)
    return {"role": role, "rep": rep, "case_id": CADDY, "file": f"{role}.rep{rep}.zst",
            "compression": "zlib", "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "policy_id": "caddy-go-test-v1"}


def make_case(td, raw_streams, rtk_streams, tee_streams, **over):
    safe = CADDY.replace("::", "__")
    evdir = td / "evidence" / safe
    evdir.mkdir(parents=True)
    raw_files = [_ev(evdir, "raw", i, s) for i, s in enumerate(raw_streams)]
    rtk_files = [_ev(evdir, "rtk", i, s) for i, s in enumerate(rtk_streams)]
    tee_files = [_ev(evdir, "rtk_tee", i, s) for i, s in enumerate(tee_streams)]

    def runs(streams):
        return [{"exit_code": 1, "canonical_sha256": hashlib.sha256(s).hexdigest(),
                 "canonical_bytes": len(s)} for s in streams]
    rec = c.envelope(
        record_type="n2e-canary-case", generated_by="test", case_id=CADDY,
        command_family="go", command_subfamily="test", status="RTK_REJECTED",
        rtk_binary_sha256=RTK,
        acquisition={
            "identity_verified": True, "publisher_recipe": "GO_SPECS[caddy]",
            "publisher_case_id": CADDY, "instance_id": INSTANCE,
            "environment_identity": {
                "toolchain_pin": {"kind": "go", "version": "1.23.8"},
                "toolchain": {"go": {"present": True, "sha256": GO_SHA,
                                     "version": "go version go1.23.8 linux/amd64"}},
                "dependencies": {"mutation_guard_ok": True},
                "acquisition_order": _order()}},
        isolation={"denial_probe": {"denied": True}},
        raw_arm={"reps_completed": 3, "exit_code": 1, "exit_code_stable": True,
                 "canonical_deterministic": True, "runs": runs(raw_streams),
                 "primary_evidence_files": raw_files},
        rtk_arm={"reps_completed": 3, "exit_code": 1, "exit_code_stable": True,
                 "canonical_deterministic": True, "runs": runs(rtk_streams),
                 "primary_evidence_files": rtk_files + tee_files,
                 "rtk_sidecar_proof": {"identity_only_in_unmeasured_sidecar": True}},
        raw_semantic_oracle={"oracle": "test_outcome", "verdict": True,
                             "evidence": {"required_targets": ["TestUnsyncedConfigAccess"],
                                          "observed_failing": ["TestUnsyncedConfigAccess"]}},
        rtk_semantic_oracle={"oracle": "test_agreement", "verdict": False, "evidence": {}},
    )
    for k, v in over.items():
        rec[k] = v
    rec = c.finalize(rec)
    rec["_impl_sha"], rec["_run_id"] = "i" * 40, "run-1"
    return rec


class TestIndependentSemanticLoss(unittest.TestCase):
    def test_full_evidence_yields_terminal(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            rec = make_case(td, [FAILLINE] * 3, [RTK_MEASURED] * 3, [FAILLINE] * 3)
            entry, unmet, truth = L.derive_rtk_semantic_loss(rec, td)
            self.assertEqual(unmet, [], unmet)
            self.assertIsNotNone(entry)
            self.assertTrue(entry["terminal"])
            self.assertEqual(entry["required_failing_ids"], ["TestUnsyncedConfigAccess"])
            self.assertEqual(entry["missing_identity_set"], ["TestUnsyncedConfigAccess"])
            self.assertTrue(entry["primary_evidence_reverified"])
            self.assertTrue(all(truth.values()), [k for k, v in truth.items() if not v])

    def test_missing_evidence_files_is_insufficient(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            rec = make_case(td, [FAILLINE] * 3, [RTK_MEASURED] * 3, [FAILLINE] * 3)
            # delete one tee file -> independent re-derivation cannot confirm
            (td / "evidence" / CADDY.replace("::", "__") / "rtk_tee.rep1.zst").unlink()
            entry, unmet, _ = L.derive_rtk_semantic_loss(rec, td)
            self.assertIsNone(entry)
            self.assertIn("primary_streams_reverified", unmet)

    def test_identity_present_in_measured_rtk_is_insufficient(self):
        # RTK actually preserved the failing id in the measured stream -> NOT semantic loss
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            rec = make_case(td, [FAILLINE] * 3, [FAILLINE] * 3, [FAILLINE] * 3)
            entry, unmet, _ = L.derive_rtk_semantic_loss(rec, td)
            self.assertIsNone(entry)
            self.assertIn("rtk_required_missing_from_measured", unmet)

    def test_evidence_hash_tamper_is_insufficient(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            rec = make_case(td, [FAILLINE] * 3, [RTK_MEASURED] * 3, [FAILLINE] * 3)
            # tamper a raw evidence file so its sha no longer matches the manifest
            f = td / "evidence" / CADDY.replace("::", "__") / "raw.rep0.zst"
            f.write_bytes(zlib.compress(FAILLINE + b"tampered\n", 9))
            entry, unmet, _ = L.derive_rtk_semantic_loss(rec, td)
            self.assertIsNone(entry)
            self.assertIn("primary_streams_reverified", unmet)

    def test_wrong_toolchain_hash_is_insufficient(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            rec = make_case(td, [FAILLINE] * 3, [RTK_MEASURED] * 3, [FAILLINE] * 3)
            rec["acquisition"]["environment_identity"]["toolchain"]["go"]["sha256"] = "f00d"
            entry, unmet, _ = L.derive_rtk_semantic_loss(rec, td)
            self.assertIsNone(entry)
            self.assertIn("toolchain_identity_matches_lock", unmet)

    def test_network_not_denied_is_insufficient(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            rec = make_case(td, [FAILLINE] * 3, [RTK_MEASURED] * 3, [FAILLINE] * 3)
            rec["acquisition"]  # keep
            rec["isolation"] = {"denial_probe": {"denied": False}}
            rec = c.finalize({k: v for k, v in rec.items() if not k.startswith("record_")})
            rec["_impl_sha"], rec["_run_id"] = "i" * 40, "run-1"
            entry, unmet, _ = L.derive_rtk_semantic_loss(rec, td)
            self.assertIsNone(entry)
            self.assertIn("network_denied", unmet)

    def test_build_emits_terminal_over_dir(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            rec = make_case(td, [FAILLINE] * 3, [RTK_MEASURED] * 3, [FAILLINE] * 3)
            on_disk = {k: v for k, v in rec.items() if not k.startswith("_")}
            (td / f"n2e-canary-case-{CADDY.replace('::', '__')}.json").write_text(
                __import__("json").dumps(on_disk, indent=2, sort_keys=True) + "\n")

            class A:
                run_id, impl_sha = "run-1", "i" * 40
            body = L.build(td, A())
            self.assertEqual(body["terminal_rejection_count"], 1)
            self.assertEqual(body["terminal_rejections"][0]["case_id"], CADDY)


if __name__ == "__main__":
    unittest.main()
