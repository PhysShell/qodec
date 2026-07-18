"""Pinned Cargo 1.81.0 sparse-index cache (`SummariesCache`) semantic canonicalizer.

SOURCE IDENTITY (pinned): rust-lang/cargo @ tag `rust-1.81.0`
  - src/cargo/sources/registry/index/cache.rs : `const CURRENT_CACHE_VERSION: u8 = 3;`
  - src/cargo/sources/registry/index/mod.rs   : `const INDEX_V_MAX: u32 = 2;`

On-disk format of each `registry/index/<registry-id>/.cache/**` entry, exactly as
`SummariesCache::serialize` writes it and `parse` reads it:

    byte 0            : CURRENT_CACHE_VERSION (u8)            == 3
    bytes 1..5        : INDEX_V_MAX (u32, little-endian)      == 2   (index schema version)
    <revision>\0      : the index "revision". For a SPARSE registry this is the HTTP
                        validator returned by the server (ETag / Last-Modified) -- pure
                        transport-freshness state that varies between two independent
                        fetches of the SAME crate versions.
    ( <semver>\0 <json-package-blob>\0 )*   : one pair per cached crate version. SEMANTIC.

Only `<revision>` is transport metadata. The cache-format byte, the index-schema version,
and every (version, package-json) pair -- name, vers, deps, features, features2, cksum,
yanked, links, v -- are SEMANTIC and retained/hashed. Parsing is FAIL-CLOSED: any entry that
does not conform to the pinned format raises CargoIndexCacheUnparseable so the producer can
classify COREUTILS_CARGO_INDEX_CACHE_UNPARSEABLE and stop before measurement. This is NOT a
generic newline/substring strip -- the exact binary framing is parsed byte-for-byte."""
from __future__ import annotations

import hashlib
import json

# pinned Cargo 1.81.0 constants (see SOURCE IDENTITY above)
CURRENT_CACHE_VERSION = 3
INDEX_V_MAX = 2
CARGO_SOURCE_IDENTITY = {
    "toolchain": "1.81.0",
    "repo": "rust-lang/cargo",
    "ref": "rust-1.81.0",
    "current_cache_version": CURRENT_CACHE_VERSION,
    "index_v_max": INDEX_V_MAX,
    "files": [
        "src/cargo/sources/registry/index/cache.rs",
        "src/cargo/sources/registry/index/mod.rs",
    ],
}


class CargoIndexCacheUnparseable(Exception):
    """Raised when a sparse-index cache entry does not conform to the pinned Cargo-1.81 format."""


def is_sparse_index_cache_path(parts) -> bool:
    """Exact Cargo sparse-index cache layout ONLY: registry/index/<registry-id>/.cache/**.

    parts is the path split relative to CARGO_HOME. Classification only -- a True result must
    not by itself cause the file to be dropped from semantic comparison; the caller replaces
    the raw-byte hash with a semantic digest.

    Rejects (see tests): registry/src/<id>/<crate>/.cache/file (parts[1]!='index'),
    registry/other/.cache/file, foo/registry/index/x/.cache/file (registry not at root),
    registry/index/.cache/file (no <registry-id> segment before .cache)."""
    p = tuple(parts)
    return (len(p) >= 5 and p[0] == "registry" and p[1] == "index" and p[3] == ".cache")


def parse_entry(data: bytes) -> dict:
    """Fail-closed parse of one SummariesCache file into transport-validator + semantic parts.

    Returns {cache_version, index_schema_version, transport_revision, versions:[{version,
    package}]}. Raises CargoIndexCacheUnparseable on any deviation from the pinned format."""
    if len(data) < 5:
        raise CargoIndexCacheUnparseable("shorter than the 5-byte pinned header")
    if data[0] != CURRENT_CACHE_VERSION:
        raise CargoIndexCacheUnparseable(
            f"cache-format byte {data[0]} != pinned CURRENT_CACHE_VERSION {CURRENT_CACHE_VERSION}")
    index_v = int.from_bytes(data[1:5], "little")
    if index_v != INDEX_V_MAX:
        raise CargoIndexCacheUnparseable(
            f"index schema version {index_v} != pinned INDEX_V_MAX {INDEX_V_MAX}")
    rest = data[5:]
    # cargo terminates EVERY field (revision, each version, each json) with a trailing \0, so
    # splitting yields a final empty element that must be present (fail-closed otherwise).
    fields = rest.split(b"\x00")
    if not fields or fields[-1] != b"":
        raise CargoIndexCacheUnparseable("cache body is not null-terminated as pinned format requires")
    fields = fields[:-1]
    if not fields:
        raise CargoIndexCacheUnparseable("missing revision field")
    revision = fields[0]                      # TRANSPORT validator (etag / last-modified)
    pairs = fields[1:]
    if len(pairs) % 2 != 0:
        raise CargoIndexCacheUnparseable(f"odd version/json field count {len(pairs)} (must pair)")
    versions = []
    for i in range(0, len(pairs), 2):
        ver_b, json_b = pairs[i], pairs[i + 1]
        try:
            ver = ver_b.decode("utf-8")
        except UnicodeDecodeError as e:
            raise CargoIndexCacheUnparseable(f"version field {i // 2} not utf-8: {e}")
        try:
            obj = json.loads(json_b)
        except Exception as e:  # noqa: BLE001
            raise CargoIndexCacheUnparseable(f"package json {i // 2} not valid json: {e}")
        if not isinstance(obj, dict) or "name" not in obj or "vers" not in obj:
            raise CargoIndexCacheUnparseable(f"package json {i // 2} missing name/vers")
        versions.append({"version": ver, "package": obj})
    return {"cache_version": data[0], "index_schema_version": index_v,
            "transport_revision": revision.decode("utf-8", "replace"),
            "versions": versions}


def _semantic_payload(entry: dict) -> dict:
    """The semantic content ONLY (schema versions + every (version, package) pair sorted by
    version); transport_revision is EXCLUDED. Package JSON is retained whole -- name, vers,
    deps, features, features2, cksum, yanked, links, v -- so any dependency/checksum/yanked
    change is a semantic difference."""
    return {
        "cache_version": entry["cache_version"],
        "index_schema_version": entry["index_schema_version"],
        "versions": sorted(
            ({"version": v["version"], "package": v["package"]} for v in entry["versions"]),
            key=lambda v: v["version"]),
    }


def semantic_digest(entry: dict) -> str:
    return hashlib.sha256(
        json.dumps(_semantic_payload(entry), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validator_digest(entry: dict) -> str:
    return hashlib.sha256(entry["transport_revision"].encode("utf-8")).hexdigest()


def digests_for_bytes(data: bytes) -> tuple:
    """(semantic_digest, validator_digest) for one raw cache file; fail-closed via parse_entry."""
    e = parse_entry(data)
    return semantic_digest(e), validator_digest(e)
