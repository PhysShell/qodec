"""CARGO_HOME ephemeral exclusion: cargo's global GC tracker (.global-cache) and other
bookkeeping files carry no dependency content and must not count toward acquisition parity.
Run 29648282170 surfaced .global-cache as the SOLE full-manifest difference between two
otherwise byte-identical acquisitions."""
import sys
import tempfile
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import probe_coreutils_diagnostic as probe  # noqa: E402


class TestGlobalCacheRootExact(unittest.TestCase):
    """Root-relative exact exclusion: only $CARGO_HOME/.global-cache is ephemeral. A file
    literally named .global-cache anywhere deeper is real content and must be retained."""

    def test_root_global_cache_excluded(self):
        self.assertTrue(probe._is_ephemeral_cargo_home_path((".global-cache",)))

    def test_registry_src_global_cache_retained(self):
        self.assertFalse(probe._is_ephemeral_cargo_home_path(
            ("registry", "src", "x", "crate", ".global-cache")))

    def test_registry_cache_global_cache_retained(self):
        self.assertFalse(probe._is_ephemeral_cargo_home_path(("registry", "cache", "x", ".global-cache")))

    def test_git_checkouts_global_cache_retained(self):
        self.assertFalse(probe._is_ephemeral_cargo_home_path(("git", "checkouts", "x", ".global-cache")))

    def test_nested_global_cache_retained(self):
        self.assertFalse(probe._is_ephemeral_cargo_home_path(("some", "nested", ".global-cache")))

    def test_locks_and_package_cache_still_excluded(self):
        # existing lock/bookkeeping scope retained (documented)
        self.assertTrue(probe._is_ephemeral_cargo_home_path(("registry", "index", "x", ".cache", "config.json.lock")))
        self.assertTrue(probe._is_ephemeral_cargo_home_path((".package-cache",)))
        self.assertTrue(probe._is_ephemeral_cargo_home_path((".crates2.json.lock",)))


class TestLockPathScoping(unittest.TestCase):
    """The blanket *.lock exclusion is removed: only enumerated cargo advisory-lock paths are
    bookkeeping. Any .lock under a dependency-content root, and any unknown lock-shaped path,
    is RETAINED (never silently classified as bookkeeping)."""

    def test_registry_src_lock_retained(self):
        self.assertFalse(probe._is_ephemeral_cargo_home_path(
            ("registry", "src", "x", "crate", "fixtures", "example.lock")))

    def test_registry_cache_lock_retained(self):
        self.assertFalse(probe._is_ephemeral_cargo_home_path(("registry", "cache", "x", "dependency.lock")))

    def test_git_checkouts_lock_retained(self):
        self.assertFalse(probe._is_ephemeral_cargo_home_path(
            ("git", "checkouts", "x", "repo", "testdata", "state.lock")))

    def test_git_db_lock_retained(self):
        self.assertFalse(probe._is_ephemeral_cargo_home_path(("git", "db", "x", "somefile.lock")))

    def test_unknown_nested_lock_retained(self):
        self.assertFalse(probe._is_ephemeral_cargo_home_path(("some", "nested", "file.lock")))

    def test_unknown_root_lock_retained(self):
        # a lock-shaped file at root that is NOT an enumerated cargo advisory lock -> retained
        self.assertFalse(probe._is_ephemeral_cargo_home_path(("mystery.lock",)))

    # separate positive tests: every EXACT cargo advisory-lock / bookkeeping path excluded
    def test_exact_global_cache_excluded(self):
        self.assertTrue(probe._is_ephemeral_cargo_home_path((".global-cache",)))

    def test_exact_package_cache_excluded(self):
        self.assertTrue(probe._is_ephemeral_cargo_home_path((".package-cache",)))

    def test_exact_package_cache_mutate_excluded(self):
        self.assertTrue(probe._is_ephemeral_cargo_home_path((".package-cache-mutate",)))

    def test_exact_crates2_json_lock_excluded(self):
        self.assertTrue(probe._is_ephemeral_cargo_home_path((".crates2.json.lock",)))

    def test_exact_crates_toml_lock_excluded(self):
        self.assertTrue(probe._is_ephemeral_cargo_home_path((".crates.toml.lock",)))

    def test_sparse_index_config_lock_bounded_excluded(self):
        self.assertTrue(probe._is_ephemeral_cargo_home_path(("registry", "index", "id", "config.json.lock")))
        self.assertTrue(probe._is_ephemeral_cargo_home_path(("registry", "index", "id", ".cache", "config.json.lock")))

    def test_config_lock_wrong_depth_retained(self):
        # config.json.lock outside the exact sparse-index shape is retained
        self.assertFalse(probe._is_ephemeral_cargo_home_path(("registry", "index", "config.json.lock")))
        self.assertFalse(probe._is_ephemeral_cargo_home_path(("elsewhere", "config.json.lock")))


class TestCargoHomeEphemeral(unittest.TestCase):
    def setUp(self):
        self.ch = Path(tempfile.mkdtemp())
        # a real dependency artifact (must be retained) + ephemeral bookkeeping (must be dropped)
        crate = self.ch / "registry" / "cache" / "idx"
        crate.mkdir(parents=True)
        (crate / "libc-0.2.159.crate").write_bytes(b"tarball")
        (self.ch / ".global-cache").write_bytes(b"gc-timestamps-vary")
        (self.ch / ".package-cache").write_bytes(b"advisory-lock")            # root advisory lock
        (self.ch / ".package-cache-mutate").write_bytes(b"mutate-lock")       # root advisory lock

    def test_stable_manifest_excludes_global_cache(self):
        man = probe._stable_manifest(self.ch)
        self.assertIn("registry/cache/idx/libc-0.2.159.crate", man)
        self.assertNotIn(".global-cache", man)
        self.assertNotIn(".package-cache", man)

    def test_cargo_cache_manifests_exclude_global_cache(self):
        m = probe._cargo_cache_manifests(self.ch)
        self.assertIn("registry/cache/idx/libc-0.2.159.crate", m["full"])
        self.assertNotIn(".global-cache", m["full"])
        self.assertNotIn(".global-cache", m["semantic"])

    def test_global_cache_difference_does_not_break_parity(self):
        # two cargo homes identical except .global-cache -> full manifests equal after exclusion
        ch2 = Path(tempfile.mkdtemp())
        (ch2 / "registry" / "cache" / "idx").mkdir(parents=True)
        (ch2 / "registry" / "cache" / "idx" / "libc-0.2.159.crate").write_bytes(b"tarball")
        (ch2 / ".global-cache").write_bytes(b"DIFFERENT-gc-timestamps")
        (ch2 / ".package-cache").write_bytes(b"advisory-lock")
        (ch2 / ".package-cache-mutate").write_bytes(b"mutate-lock")
        a = probe._cargo_cache_manifests(self.ch)
        b = probe._cargo_cache_manifests(ch2)
        diff = probe._cargo_cache_full_diff_summary(a, b)
        self.assertEqual(diff["semantic_diff_count"], 0)
        self.assertEqual(diff["full_diff_counts"], {"only_in_A": 0, "only_in_B": 0, "changed": 0})


if __name__ == "__main__":
    unittest.main()
