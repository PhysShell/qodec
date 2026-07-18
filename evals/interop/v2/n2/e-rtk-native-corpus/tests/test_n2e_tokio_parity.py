"""Independent Tokio parity classification (items 5/7): DISQUALIFIED_ENVIRONMENT_
UNREPRODUCIBLE only when every identity equality holds AND both reach the same cargo
locked-resolution refusal; else HARNESS_DEFECT / SOURCE_PROVENANCE_DEFECT / insufficient."""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import verify_n2e_tokio_parity as V  # noqa: E402

REFUSE = {"class": "cargo_locked_resolution_refusal", "locked_resolution_refusal": True}


def ident(exit_code, fclass=None, **over):
    d = {"base_commit": "b", "head_matches_base": True, "workspace_manifests": {"Cargo.toml": "m"},
         "fixture_evidence": {"upstream_fixture_sha256": "fx", "materialized_cargo_lock_sha256": "ml"},
         "cargo_binary_identity": {"real_cargo_binary_sha256": "cargo"}, "cargo_version_verbose": "cargo 1.83",
         "target_platform": "x86_64", "effective_env": {"RUSTUP_TOOLCHAIN": "1.83.0", "HOME": "/tmp/x"},
         "install": {"exit": exit_code, "command": "RUSTFLAGS=-Awarnings cargo test --locked ..."},
         "failure_class": fclass or REFUSE}
    d.update(over)
    return d


def rec(part_d, prov=True, n2e=None):
    return {"n2e_identity": n2e or ident(101), "part_d_upstream": part_d,
            "harness_dataset_provenance": {"compatible_pair_proven": prov}}


class TestTokioParity(unittest.TestCase):
    def test_reproduction_defect_insufficient(self):
        r = V.classify(rec({"status": "TOKIO_UPSTREAM_REPRODUCTION_DEFECT", "reasons": ["x"]}))
        self.assertEqual(r["outcome"], "insufficient_evidence")
        self.assertFalse(r["terminal"])

    def test_upstream_success_is_harness_defect(self):
        r = V.classify(rec({"status": "upstream_install_ran", "identity": ident(0)}))
        self.assertEqual(r["classification"], "HARNESS_DEFECT")
        self.assertFalse(r["terminal"])

    def test_both_fail_with_pair_proof_unreproducible(self):
        r = V.classify(rec({"status": "upstream_install_ran", "identity": ident(101)}))
        self.assertEqual(r["classification"], "DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE")
        self.assertTrue(r["terminal"])

    def test_no_pair_proof_is_provenance_defect(self):
        r = V.classify(rec({"status": "upstream_install_ran", "identity": ident(101)}, prov=False))
        self.assertEqual(r["classification"], "SOURCE_PROVENANCE_DEFECT")

    def test_manifest_mismatch_insufficient(self):
        up = ident(101); up["workspace_manifests"] = {"Cargo.toml": "DIFFERENT"}
        r = V.classify(rec({"status": "upstream_install_ran", "identity": up}))
        self.assertEqual(r["outcome"], "insufficient_evidence")

    def test_failure_class_mismatch_insufficient(self):
        up = ident(101, fclass={"class": "cargo_other_error"})
        r = V.classify(rec({"status": "upstream_install_ran", "identity": up}))
        self.assertEqual(r["outcome"], "insufficient_evidence")

    def test_exit_101_alone_does_not_classify_without_failure_class(self):
        # both exit 101 but neither is the parsed locked-resolution refusal -> insufficient
        up = ident(101, fclass={"class": "cargo_other_error"})
        n = ident(101, fclass={"class": "cargo_other_error"})
        r = V.classify(rec({"status": "upstream_install_ran", "identity": up}, n2e=n))
        self.assertEqual(r["outcome"], "insufficient_evidence")


if __name__ == "__main__":
    unittest.main()
