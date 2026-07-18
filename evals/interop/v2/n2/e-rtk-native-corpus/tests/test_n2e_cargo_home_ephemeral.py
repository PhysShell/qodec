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


class TestCargoHomeEphemeral(unittest.TestCase):
    def setUp(self):
        self.ch = Path(tempfile.mkdtemp())
        # a real dependency artifact (must be retained) + ephemeral bookkeeping (must be dropped)
        crate = self.ch / "registry" / "cache" / "idx"
        crate.mkdir(parents=True)
        (crate / "libc-0.2.159.crate").write_bytes(b"tarball")
        (self.ch / ".global-cache").write_bytes(b"gc-timestamps-vary")
        (self.ch / ".package-cache").write_bytes(b"advisory-lock")
        (self.ch / "registry" / ".package-cache-mutate").write_bytes(b"x")

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
        (ch2 / "registry" / ".package-cache-mutate").write_bytes(b"y")
        a = probe._cargo_cache_manifests(self.ch)
        b = probe._cargo_cache_manifests(ch2)
        diff = probe._cargo_cache_full_diff_summary(a, b)
        self.assertEqual(diff["semantic_diff_count"], 0)
        self.assertEqual(diff["full_diff_counts"], {"only_in_A": 0, "only_in_B": 0, "changed": 0})


if __name__ == "__main__":
    unittest.main()
