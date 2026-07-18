"""The publisher acquisition ORDER verifier (item 4): the `--locked` install must warm
the frozen lockfile on the pristine manifest BEFORE the gold patch mutates Cargo.toml;
a swapped or premature patch order must FAIL. Also covers the gradle-offline-isolation
policy flags (item 5)."""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import verify_n2e_acquisition_order as V  # noqa: E402
import n2e_execution_control as xctl  # noqa: E402

# manifest hash maps: pristine vs gold-mutated (gold patch changes Cargo.toml)
PRISTINE = {"Cargo.toml": "aaa", "Cargo.lock": "lockhash"}
GOLD_MUT = {"Cargo.toml": "bbb", "Cargo.lock": "lockhash"}


def _b(label, protected, diff, status, **extra):
    return {"label": label, "protected": protected, "worktree_diff_sha256": diff,
            "worktree_diff_bytes": len(diff), "tracked_status": status, **extra}


def good_fixed_rust():
    return {
        "policy_id": "publisher-acquisition-order-v1",
        "snapshot_variant": "fixed",
        "canonical_sequence": ["base", "pre_install", "install_warm", "gold_patch", "test_patch"],
        "boundaries": [
            _b("base", PRISTINE, "d0", []),
            _b("pre_install", PRISTINE, "d0", []),          # lockfile heredoc already present
            _b("install_warm", PRISTINE, "d0", []),         # --locked ran on pristine manifest
            _b("gold_patch", GOLD_MUT, "d1", [" M src/lib.rs"], applied=True, patch_sha256="g"),
            _b("test_patch", GOLD_MUT, "d2", [" M src/lib.rs", " M tests/t.rs"],
               applied=True, patch_sha256="t"),
        ],
        "install": {"ran": True, "locked": True, "steps": [{"exit": 0, "locked": True}]},
        "applied_patches": [{"name": "patch", "apply_exit": 0, "sha256": "g"},
                            {"name": "test_patch", "apply_exit": 0, "sha256": "t"}],
        "gold_applied": True, "test_applied": True,
    }


class TestAcquisitionOrder(unittest.TestCase):
    def test_good_fixed_rust_passes(self):
        ok, reasons = V.verify_acquisition_order(good_fixed_rust(), "rust_cargo")
        self.assertTrue(ok, reasons)

    def test_gold_applied_before_locked_install_fails(self):
        # gold patch mutated Cargo.toml BEFORE install_warm -> manifest differs -> FAIL
        o = good_fixed_rust()
        o["boundaries"][2]["protected"] = GOLD_MUT  # install_warm sees mutated manifest
        ok, reasons = V.verify_acquisition_order(o, "rust_cargo")
        self.assertFalse(ok)
        self.assertTrue(any("before the locked install" in r for r in reasons), reasons)

    def test_swapped_gold_and_test_order_fails(self):
        o = good_fixed_rust()
        # swap the two patch boundaries in the recorded sequence
        o["boundaries"][3], o["boundaries"][4] = o["boundaries"][4], o["boundaries"][3]
        ok, reasons = V.verify_acquisition_order(o, "rust_cargo")
        self.assertFalse(ok)
        self.assertTrue(any("sequence" in r for r in reasons), reasons)

    def test_install_without_locked_fails(self):
        o = good_fixed_rust()
        o["install"]["locked"] = False
        o["install"]["steps"] = [{"exit": 0, "locked": False}]
        ok, reasons = V.verify_acquisition_order(o, "rust_cargo")
        self.assertFalse(ok)
        self.assertTrue(any("--locked" in r for r in reasons), reasons)

    def test_install_nonzero_exit_fails(self):
        o = good_fixed_rust()
        o["install"]["steps"] = [{"exit": 101, "locked": True}]
        ok, reasons = V.verify_acquisition_order(o, "rust_cargo")
        self.assertFalse(ok)
        self.assertTrue(any("exited 101" in r for r in reasons), reasons)

    def test_gold_that_did_not_change_tree_fails(self):
        o = good_fixed_rust()
        o["boundaries"][3]["worktree_diff_sha256"] = "d0"  # same as install_warm
        ok, reasons = V.verify_acquisition_order(o, "rust_cargo")
        self.assertFalse(ok)
        self.assertTrue(any("did not change the worktree" in r for r in reasons), reasons)

    def test_buggy_no_gold_boundary_passes(self):
        o = {
            "snapshot_variant": "buggy",
            "canonical_sequence": ["base", "pre_install", "install_warm", "test_patch"],
            "boundaries": [
                _b("base", {"go.mod": "m"}, "d0", []),
                _b("pre_install", {"go.mod": "m"}, "d0", []),
                _b("install_warm", {"go.mod": "m"}, "d0", []),
                _b("test_patch", {"go.mod": "m"}, "d1", [" M x_test.go"],
                   applied=True, patch_sha256="t"),
            ],
            "install": {"ran": True, "locked": False, "steps": [{"exit": 0}]},
            "applied_patches": [{"name": "test_patch", "apply_exit": 0}],
            "gold_applied": False, "test_applied": True,
        }
        ok, reasons = V.verify_acquisition_order(o, "go")
        self.assertTrue(ok, reasons)

    def test_buggy_with_gold_boundary_fails(self):
        o = {
            "snapshot_variant": "buggy",
            "canonical_sequence": ["base", "pre_install", "install_warm", "test_patch"],
            "boundaries": [
                _b("base", {"go.mod": "m"}, "d0", []),
                _b("pre_install", {"go.mod": "m"}, "d0", []),
                _b("install_warm", {"go.mod": "m"}, "d0", []),
                _b("gold_patch", {"go.mod": "m"}, "d1", [], applied=True),
                _b("test_patch", {"go.mod": "m"}, "d2", [], applied=True),
            ],
            "install": {"ran": True, "locked": False, "steps": []},
            "applied_patches": [], "gold_applied": True, "test_applied": True,
        }
        ok, reasons = V.verify_acquisition_order(o, "go")
        self.assertFalse(ok)
        self.assertTrue(any("must not have a gold_patch" in r for r in reasons), reasons)

    def test_non_monotonic_tracked_state_fails(self):
        o = good_fixed_rust()
        # test_patch boundary drops the src/lib.rs change that gold_patch introduced
        o["boundaries"][4]["tracked_status"] = [" M tests/t.rs"]
        ok, reasons = V.verify_acquisition_order(o, "rust_cargo")
        self.assertFalse(ok)
        self.assertTrue(any("non-monotonic" in r for r in reasons), reasons)


class TestGradleOfflinePolicy(unittest.TestCase):
    def test_flags_exact(self):
        self.assertEqual(xctl.gradle_offline_args(),
                         ["--offline", "--no-daemon", "-Dorg.gradle.vfs.watch=false"])

    def test_policy_id_and_fields(self):
        p = xctl.gradle_offline_policy()
        self.assertEqual(p["policy_id"], "gradle-offline-isolation-v1")
        self.assertIn("--offline", p["args"])
        self.assertIn("per-repetition", p["gradle_user_home_isolation"])
        self.assertIn("DISQUALIFIED_OFFLINE_EXECUTION", p["per_rep_execution_proof"])


if __name__ == "__main__":
    unittest.main()
