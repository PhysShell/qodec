"""Pinned Cargo-1.81.0 sparse-index cache canonicalizer: exact path recognizer, fail-closed
binary parse, and transport-validator vs semantic separation."""
import json
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_cargo_index_cache as cic  # noqa: E402

PKG = {"name": "libc", "vers": "0.2.159", "deps": [],
       "cksum": "a" * 64, "features": {}, "yanked": False, "v": 2}


def _cache_bytes(revision=b"etag-A", versions=((("0.2.159"), PKG),), cache_ver=3, index_v=2):
    body = bytes([cache_ver]) + int(index_v).to_bytes(4, "little")
    body += revision + b"\x00"
    for ver, pkg in versions:
        body += ver.encode() + b"\x00" + json.dumps(pkg).encode() + b"\x00"
    return body


class TestExactRecognizer(unittest.TestCase):
    def test_pinned_layout_matches(self):
        self.assertTrue(cic.is_sparse_index_cache_path(
            ("registry", "index", "index.crates.io-6f17d22bba15001f", ".cache", "li", "bc", "libc")))

    def test_registry_src_cache_rejected(self):
        self.assertFalse(cic.is_sparse_index_cache_path(
            ("registry", "src", "index.crates.io-6f17d22bba15001f", "libc-0.2.159", ".cache", "file")))

    def test_registry_other_cache_rejected(self):
        self.assertFalse(cic.is_sparse_index_cache_path(("registry", "other", ".cache", "file")))

    def test_registry_index_not_at_root_rejected(self):
        self.assertFalse(cic.is_sparse_index_cache_path(
            ("foo", "registry", "index", "x", ".cache", "file")))

    def test_registry_index_without_id_segment_rejected(self):
        # registry/index/.cache/file -- no <registry-id> between index and .cache
        self.assertFalse(cic.is_sparse_index_cache_path(("registry", "index", ".cache", "file")))

    def test_content_addressed_crate_not_matched(self):
        self.assertFalse(cic.is_sparse_index_cache_path(
            ("registry", "cache", "index.crates.io-6f17d22bba15001f", "libc-0.2.159.crate")))


class TestFailClosedParse(unittest.TestCase):
    def test_valid_entry_parses(self):
        e = cic.parse_entry(_cache_bytes())
        self.assertEqual(e["cache_version"], 3)
        self.assertEqual(e["index_schema_version"], 2)
        self.assertEqual(e["transport_revision"], "etag-A")
        self.assertEqual(len(e["versions"]), 1)
        self.assertEqual(e["versions"][0]["package"]["cksum"], "a" * 64)

    def test_wrong_cache_version_byte_fails(self):
        with self.assertRaises(cic.CargoIndexCacheUnparseable):
            cic.parse_entry(_cache_bytes(cache_ver=2))

    def test_wrong_index_schema_version_fails(self):
        with self.assertRaises(cic.CargoIndexCacheUnparseable):
            cic.parse_entry(_cache_bytes(index_v=3))

    def test_missing_null_terminator_fails(self):
        with self.assertRaises(cic.CargoIndexCacheUnparseable):
            cic.parse_entry(_cache_bytes()[:-1])  # drop the final \0

    def test_odd_field_count_fails(self):
        # revision + a lone version with no json blob
        body = bytes([3]) + (2).to_bytes(4, "little") + b"etag\x00" + b"0.2.159\x00"
        with self.assertRaises(cic.CargoIndexCacheUnparseable):
            cic.parse_entry(body)

    def test_non_json_package_fails(self):
        body = bytes([3]) + (2).to_bytes(4, "little") + b"etag\x00" + b"0.2.159\x00not-json\x00"
        with self.assertRaises(cic.CargoIndexCacheUnparseable):
            cic.parse_entry(body)

    def test_too_short_fails(self):
        with self.assertRaises(cic.CargoIndexCacheUnparseable):
            cic.parse_entry(b"\x03\x02")


class TestValidatorVsSemantic(unittest.TestCase):
    def test_validator_differs_semantic_equal(self):
        a = _cache_bytes(revision=b"etag-A")
        b = _cache_bytes(revision=b"etag-B")   # only the HTTP validator differs
        sa, va = cic.digests_for_bytes(a)
        sb, vb = cic.digests_for_bytes(b)
        self.assertEqual(sa, sb, "semantic digest must ignore the transport validator")
        self.assertNotEqual(va, vb, "validator digest must reflect the etag difference")

    def test_semantic_differs_on_checksum_change(self):
        p2 = dict(PKG); p2["cksum"] = "b" * 64
        a = _cache_bytes(versions=(("0.2.159", PKG),))
        b = _cache_bytes(versions=(("0.2.159", p2),))
        sa, _ = cic.digests_for_bytes(a)
        sb, _ = cic.digests_for_bytes(b)
        self.assertNotEqual(sa, sb, "a checksum change is a semantic difference")

    def test_semantic_differs_on_new_version(self):
        p3 = dict(PKG); p3["vers"] = "0.2.160"
        a = _cache_bytes(versions=(("0.2.159", PKG),))
        b = _cache_bytes(versions=(("0.2.159", PKG), ("0.2.160", p3)))
        sa, _ = cic.digests_for_bytes(a)
        sb, _ = cic.digests_for_bytes(b)
        self.assertNotEqual(sa, sb, "an added cached crate version is a semantic difference")

    def test_version_order_independent(self):
        p3 = dict(PKG); p3["vers"] = "0.2.160"
        a = _cache_bytes(versions=(("0.2.159", PKG), ("0.2.160", p3)))
        b = _cache_bytes(versions=(("0.2.160", p3), ("0.2.159", PKG)))
        sa, _ = cic.digests_for_bytes(a)
        sb, _ = cic.digests_for_bytes(b)
        self.assertEqual(sa, sb, "semantic digest is independent of cached-version ordering")


if __name__ == "__main__":
    unittest.main()
