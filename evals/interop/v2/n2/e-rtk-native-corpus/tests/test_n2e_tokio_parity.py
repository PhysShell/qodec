"""Corrected Tokio parity classification (ruling steps 2/3).

DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE (terminal candidate outcome) is emitted only when
substrate_status == PROVEN (instance-level recipe applicability) AND every identity
equality holds AND both N2-E and upstream reach the same cargo locked-resolution refusal.
The withdrawn global cross-pin gate is a VERIFIER_DEFECT_PROVENANCE_GATE_PRECEDENCE:
SOURCE_PROVENANCE_DEFECT is never terminal for a candidate and never invokes fallback.
"""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import verify_n2e_tokio_parity as V  # noqa: E402
import n2e_classification as cls  # noqa: E402

REFUSE = {"class": "cargo_locked_resolution_refusal", "locked_resolution_refusal": True,
          "requested_lock_mutation": True, "updating_crates_io_index": True}
STDERR = ("    Updating crates.io index\nerror: the lock file /x/Cargo.lock needs to be "
          "updated but --locked was passed to prevent this\n")
ARGV = ["cargo", "+1.83.0", "test", "--locked", "--package", "tokio", "--no-run"]
APPLIC_OK = {"instance_recipe_applicable": True}


def ident(exit_code, fclass=None, stderr=STDERR, argv=None, **over):
    d = {"base_commit": "b", "head_matches_base": True, "workspace_manifests": {"Cargo.toml": "m"},
         "fixture_evidence": {"upstream_fixture_sha256": "fx", "materialized_cargo_lock_sha256": "ml"},
         "cargo_binary_identity": {"real_cargo_binary_sha256": "cargo"}, "cargo_version_verbose": "cargo 1.83",
         "target_platform": "x86_64", "effective_env": {"RUSTUP_TOOLCHAIN": "1.83.0", "HOME": "/tmp/x"},
         "install": {"exit": exit_code, "command": "RUSTFLAGS=-Awarnings cargo test --locked ...",
                     "argv": argv if argv is not None else list(ARGV), "stderr": stderr},
         "failure_class": fclass if fclass is not None else dict(REFUSE)}
    d.update(over)
    return d


def rec(part_d, n2e=None):
    return {"n2e_identity": n2e or ident(101), "part_d_upstream": part_d}


class TestTokioParity(unittest.TestCase):
    def test_reproduction_defect_insufficient(self):
        r = V.classify(rec({"status": "TOKIO_UPSTREAM_REPRODUCTION_DEFECT", "reasons": ["x"]}), APPLIC_OK)
        self.assertEqual(r["outcome"], "insufficient_evidence")
        self.assertFalse(r["terminal_candidate_outcome"])

    def test_upstream_success_is_harness_defect(self):
        r = V.classify(rec({"status": "upstream_install_ran", "identity": ident(0)}), APPLIC_OK)
        self.assertEqual(r["candidate_classification"], cls.HARNESS_DEFECT)
        self.assertFalse(r["terminal_candidate_outcome"])

    def test_both_fail_applicability_proven_unreproducible(self):
        r = V.classify(rec({"status": "upstream_install_ran", "identity": ident(101)}), APPLIC_OK)
        self.assertEqual(r["candidate_classification"], cls.DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE)
        self.assertTrue(r["terminal_candidate_outcome"])
        self.assertEqual(r["substrate_status"], cls.SUBSTRATE_PROVEN)

    def test_provenance_defect_never_terminal_no_fallback(self):
        # applicability NOT proven -> SOURCE_PROVENANCE_DEFECT substrate, NON-terminal
        r = V.classify(rec({"status": "upstream_install_ran", "identity": ident(101)}), None)
        self.assertEqual(r["substrate_status"], cls.SUBSTRATE_SOURCE_PROVENANCE_DEFECT)
        self.assertIsNone(r["candidate_classification"])
        self.assertFalse(r["terminal_candidate_outcome"])
        self.assertEqual(r["withdrawn_gate"], cls.VERIFIER_DEFECT_PROVENANCE_GATE_PRECEDENCE)

    def test_manifest_mismatch_insufficient(self):
        up = ident(101); up["workspace_manifests"] = {"Cargo.toml": "DIFFERENT"}
        r = V.classify(rec({"status": "upstream_install_ran", "identity": up}), APPLIC_OK)
        self.assertEqual(r["outcome"], "insufficient_evidence")
        self.assertFalse(r["terminal_candidate_outcome"])

    def test_failure_class_mismatch_insufficient(self):
        up = ident(101, fclass={"class": "cargo_other_error"})
        r = V.classify(rec({"status": "upstream_install_ran", "identity": up}), APPLIC_OK)
        self.assertEqual(r["outcome"], "insufficient_evidence")

    def test_argv_mismatch_insufficient(self):
        up = ident(101, argv=["cargo", "test", "--offline"])
        r = V.classify(rec({"status": "upstream_install_ran", "identity": up}), APPLIC_OK)
        self.assertEqual(r["outcome"], "insufficient_evidence")

    def test_missing_refusal_message_insufficient(self):
        up = ident(101, stderr="    Updating crates.io index\nerror: something else\n")
        r = V.classify(rec({"status": "upstream_install_ran", "identity": up}), APPLIC_OK)
        self.assertEqual(r["outcome"], "insufficient_evidence")


if __name__ == "__main__":
    unittest.main()
