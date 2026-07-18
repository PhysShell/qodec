"""cargo-cache seed determinant narrowing (run 29645805079 diagnosis).

Run 29645805079 reached COREUTILS_ACQUISITION_NONDETERMINISTIC with EVERY parity field true
except cargo_cache_seed_equal: the two independent acquisitions produced a byte-identical
repository dependency closure (Cargo.lock, manifests, `cargo metadata` members) but a
different CARGO_HOME stable-manifest hash. The sole non-semantic source is cargo's sparse
registry HTTP response cache (registry/index/<host-hash>/.cache/**), which embeds per-fetch
etag/last-modified metadata. The seed determinant now excludes that HTTP-cache zone while
retaining the content-addressed registry/cache/*.crate tarballs + extracted sources; a
transparent A/B diff (computed on the FULL manifest) surfaces any residual semantic diff."""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import probe_coreutils_diagnostic as probe  # noqa: E402


class TestIsHttpCache(unittest.TestCase):
    def test_sparse_index_cache_flagged(self):
        p = ("registry", "index", "index.crates.io-6f17d22bba15001f", ".cache", "l", "i", "libc")
        self.assertTrue(probe._is_http_cache(p))

    def test_crate_tarball_not_flagged(self):
        self.assertFalse(probe._is_http_cache(("registry", "cache", "index.crates.io-6f17d22bba15001f", "libc-0.2.159.crate")))

    def test_extracted_src_not_flagged(self):
        self.assertFalse(probe._is_http_cache(("registry", "src", "index.crates.io-6f17d22bba15001f", "libc-0.2.159", "src", "lib.rs")))

    def test_non_registry_cache_not_flagged(self):
        self.assertFalse(probe._is_http_cache(("some", ".cache", "x")))


class TestStableManifestExcludesHttpCache(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.root = Path(tempfile.mkdtemp())
        crate = self.root / "registry" / "cache" / "idx"
        crate.mkdir(parents=True)
        (crate / "libc-0.2.159.crate").write_bytes(b"tarball-bytes")
        cache = self.root / "registry" / "index" / "idx" / ".cache" / "l" / "i"
        cache.mkdir(parents=True)
        # two "fetches" would differ only in the embedded etag line
        (cache / "libc").write_bytes(b"3\netag:\"aaa\"\n{\"vers\":\"0.2.159\"}")

    def test_default_excludes_http_cache(self):
        man = probe._stable_manifest(self.root)
        self.assertIn("registry/cache/idx/libc-0.2.159.crate", man)
        self.assertNotIn("registry/index/idx/.cache/l/i/libc", man)

    def test_full_includes_http_cache(self):
        man = probe._stable_manifest(self.root, exclude_http_cache=False)
        self.assertIn("registry/index/idx/.cache/l/i/libc", man)


class TestManifestDiff(unittest.TestCase):
    def test_http_only_diff_has_zero_residual(self):
        a = {"registry/cache/idx/libc.crate": "h1", "registry/index/idx/.cache/l/i/libc": "etagA"}
        b = {"registry/cache/idx/libc.crate": "h1", "registry/index/idx/.cache/l/i/libc": "etagB"}
        d = probe._manifest_diff(a, b)
        self.assertEqual(d["residual_non_http_cache_diff_count"], 0)
        self.assertEqual(d["residual_non_http_cache_paths"], [])
        self.assertEqual(len(d["changed"]), 1)
        self.assertTrue(d["changed"][0]["http_cache"])

    def test_semantic_diff_surfaces_residual(self):
        a = {"registry/cache/idx/libc-0.2.159.crate": "h1"}
        b = {"registry/cache/idx/libc-0.2.160.crate": "h2"}
        d = probe._manifest_diff(a, b)
        self.assertEqual(d["residual_non_http_cache_diff_count"], 2)  # one only_in_A + one only_in_B
        self.assertTrue(all(not e["http_cache"] for e in d["only_in_A"] + d["only_in_B"]))


if __name__ == "__main__":
    unittest.main()
