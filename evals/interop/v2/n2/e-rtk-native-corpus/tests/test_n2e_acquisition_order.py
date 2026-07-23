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


BASE = "b" * 40


def _reset_b(**over):
    d = {"test_patch_files": ["tests/t.rs"], "gold_files": ["src/lib.rs"],
         "test_patch_files_existing_at_base": ["tests/t.rs"],
         "reset_paths": ["tests/t.rs"], "reset_failed": [],
         "reset_from_commit": BASE, "base_commit": BASE}
    d.update(over)
    return _b("test_files_reset", GOLD_MUT, "d1", [" M src/lib.rs"], **d)


def good_fixed_rust():
    return {
        "policy_id": "publisher-acquisition-order-v1",
        "snapshot_variant": "fixed", "base_commit": BASE,
        "canonical_sequence": ["base", "pre_install", "install_warm", "gold_patch",
                               "test_files_reset", "test_patch"],
        "gold_files": ["src/lib.rs"],
        "boundaries": [
            _b("base", PRISTINE, "d0", []),
            _b("pre_install", PRISTINE, "d0", []),          # lockfile heredoc already present
            _b("install_warm", PRISTINE, "d0", []),         # --locked ran on pristine manifest
            _b("gold_patch", GOLD_MUT, "d1", [" M src/lib.rs"], applied=True, patch_sha256="g"),
            _reset_b(),
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
        # swap gold_patch (idx 3) and test_patch (idx 5) in the recorded sequence
        o["boundaries"][3], o["boundaries"][5] = o["boundaries"][5], o["boundaries"][3]
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

    def _buggy_go(self):
        GM = {"go.mod": "m"}
        return {
            "snapshot_variant": "buggy", "base_commit": BASE, "gold_files": [],
            "canonical_sequence": ["base", "pre_install", "install_warm",
                                   "test_files_reset", "test_patch"],
            "boundaries": [
                _b("base", GM, "d0", []),
                _b("pre_install", GM, "d0", []),
                _b("install_warm", GM, "d0", []),
                _b("test_files_reset", GM, "d0", [], test_patch_files=["x_test.go"],
                   gold_files=[], test_patch_files_existing_at_base=["x_test.go"],
                   reset_paths=["x_test.go"], reset_failed=[], reset_from_commit=BASE,
                   base_commit=BASE),
                _b("test_patch", GM, "d1", [" M x_test.go"], applied=True, patch_sha256="t"),
            ],
            "install": {"ran": True, "locked": False, "steps": [{"exit": 0}]},
            "applied_patches": [{"name": "test_patch", "apply_exit": 0}],
            "gold_applied": False, "test_applied": True,
        }

    def test_buggy_no_gold_boundary_passes(self):
        ok, reasons = V.verify_acquisition_order(self._buggy_go(), "go")
        self.assertTrue(ok, reasons)

    def test_buggy_with_gold_boundary_fails(self):
        o = self._buggy_go()
        o["boundaries"].insert(3, _b("gold_patch", {"go.mod": "m"}, "dg", [], applied=True))
        ok, reasons = V.verify_acquisition_order(o, "go")
        self.assertFalse(ok)
        self.assertTrue(any("must not have a gold_patch" in r for r in reasons), reasons)

    def test_missing_test_files_reset_fails(self):
        o = good_fixed_rust()
        o["boundaries"] = [b for b in o["boundaries"] if b["label"] != "test_files_reset"]
        ok, reasons = V.verify_acquisition_order(o, "rust_cargo")
        self.assertFalse(ok)
        self.assertTrue(any("test_files_reset" in r for r in reasons), reasons)

    def test_reset_from_non_base_fails(self):
        o = good_fixed_rust()
        o["boundaries"][4]["reset_from_commit"] = "f" * 40
        ok, reasons = V.verify_acquisition_order(o, "rust_cargo")
        self.assertFalse(ok)
        self.assertTrue(any("!= base_commit" in r for r in reasons), reasons)

    def test_reset_of_undeclared_file_fails(self):
        o = good_fixed_rust()
        o["boundaries"][4]["reset_paths"] = ["tests/t.rs", "src/lib.rs"]  # src not a test file
        ok, reasons = V.verify_acquisition_order(o, "rust_cargo")
        self.assertFalse(ok)
        self.assertTrue(any("not declared by test_patch" in r for r in reasons), reasons)

    def test_gold_edit_surviving_in_test_file_fails(self):
        # gold ALSO modified the publisher test file, and it was NOT reset -> gold survives
        o = good_fixed_rust()
        o["gold_files"] = ["src/lib.rs", "tests/t.rs"]
        o["boundaries"][4]["gold_files"] = ["src/lib.rs", "tests/t.rs"]
        o["boundaries"][4]["reset_paths"] = []        # nothing reset
        o["boundaries"][4]["test_patch_files_existing_at_base"] = ["tests/t.rs"]
        ok, reasons = V.verify_acquisition_order(o, "rust_cargo")
        self.assertFalse(ok)
        self.assertTrue(any("gold edits could survive" in r for r in reasons), reasons)

    def test_non_monotonic_tracked_state_fails(self):
        o = good_fixed_rust()
        # test_patch boundary (idx 5) drops the src/lib.rs change gold_patch introduced
        o["boundaries"][5]["tracked_status"] = [" M tests/t.rs"]
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


class TestTestFileResetMechanism(unittest.TestCase):
    """Functional proof (correction 1): when the gold patch modifies a publisher-owned
    test file, the evaluation-time reset + test_patch re-apply makes the FINAL measured
    file the base+test_patch version, NOT the gold-patch version."""
    def _git(self, d, *a):
        import subprocess
        return subprocess.run(["git", "-C", str(d), *a], capture_output=True, text=True, env=self.ge)

    def setUp(self):
        import tempfile, subprocess
        sys.path.insert(0, str(N2E_DIR / "tools"))
        import run_canary_case as rc
        self.rc = rc
        self.ge = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                   "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_GLOBAL": "/dev/null",
                   "GIT_CONFIG_SYSTEM": "/dev/null", "PATH": __import__("os").environ.get("PATH", "/usr/bin:/bin")}
        self.d = Path(tempfile.mkdtemp())
        self._git(self.d, "init", "-q")
        (self.d / "t_test.go").write_text("BASE_TEST\n")
        self._git(self.d, "add", "-A"); self._git(self.d, "commit", "-qm", "base")
        self.base = self._git(self.d, "rev-parse", "HEAD").stdout.strip()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.d, ignore_errors=True)

    def test_gold_edit_to_test_file_does_not_survive(self):
        # gold patch modifies the test file (should be discarded by the reset)
        (self.d / "t_test.go").write_text("GOLD_MUTATED_TEST\n")
        # the publisher test_patch (as a real diff base->PUBLISHER_TEST)
        (self.d / "t_test.go").write_text("PUBLISHER_TEST\n")
        tp = self._git(self.d, "diff").stdout.encode()
        # reset the working tree to the gold state, then run the reset+apply sequence
        (self.d / "t_test.go").write_text("GOLD_MUTATED_TEST\n")
        files = self.rc._diff_modified_files(tp)
        self.assertEqual(files, ["t_test.go"])
        existing, reset_paths, failed = self.rc._reset_test_files(self.d, self.ge, self.base, files)
        self.assertEqual(reset_paths, ["t_test.go"]); self.assertEqual(failed, [])
        # after reset the file is back to BASE; now apply the publisher test_patch
        pf = self.d / "tp.diff"; pf.write_bytes(tp)
        self.assertEqual(self._git(self.d, "apply", str(pf)).returncode, 0)
        self.assertEqual((self.d / "t_test.go").read_text(), "PUBLISHER_TEST\n")
