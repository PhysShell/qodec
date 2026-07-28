#!/usr/bin/env python3
"""Independent reference implementation of the qodec canonical identity format.

The golden vectors in `tests/canon.rs` are pasted literals. Literals are only
trustworthy if someone can regenerate them without running the code under test,
so this script exists as the second implementation: written from the normative
description in `docs/proposals/qodec-query-harness.md` and `src/canon.rs`'s
module docs, in a different language, using the standard library's SHA-256.

It is deliberately NOT wired into the Rust test run. A reference that executes
inside the same process it validates would drift together with the thing it is
supposed to cross-check, which is the failure this file exists to prevent.

    python3 tests/reference/canon_reference.py            # print the vectors
    python3 tests/reference/canon_reference.py --check    # diff against tests/canon.rs

`--check` re-derives every vector and compares it against the constants
currently committed in `tests/canon.rs`, so a drift between the two
implementations is a hard failure rather than a note someone reads later.
"""

import argparse
import hashlib
import re
import struct
import sys
from pathlib import Path

SCHEMA_V1 = "qodec.query.v1"
DOMAIN_CANONICAL_QUERY = "qodec.canonical-query.v1"
DOMAIN_COMPLETE_RESULT = "qodec.complete-result.v1"
DOMAIN_QUERY_RESULT_ID = "qodec.query-result-id.v1"


def domain_header(domain: str) -> bytes:
    """`u16be(len) || utf8` — the length-delimited domain tag."""
    b = domain.encode("utf-8")
    return struct.pack(">H", len(b)) + b


def framed_field(tag: str, value: bytes) -> bytes:
    """`u16be(tag) || tag || u64be(val) || val` — both sides delimited."""
    t = tag.encode("utf-8")
    return struct.pack(">H", len(t)) + t + struct.pack(">Q", len(value)) + value


def length_prefixed(b: bytes) -> bytes:
    """`u64be(len) || bytes`."""
    return struct.pack(">Q", len(b)) + b


def enc_str(s: str) -> bytes:
    """`u64be(len) || utf8`, with no normalization and no escaping."""
    if "﻿" in s:
        raise ValueError("canonical string must not contain U+FEFF")
    b = s.encode("utf-8")
    return struct.pack(">Q", len(b)) + b


def enc_seq(items) -> bytes:
    """`u32be(count) || enc_str(e)…` in the order given."""
    return struct.pack(">I", len(items)) + b"".join(enc_str(i) for i in items)


def query_bytes_lookup(field: str, value: str) -> bytes:
    """Canonical bytes of a `Lookup`; discriminant 1."""
    return b"\x01" + enc_str(field) + enc_str(value)


def query_bytes_intersect(key: str, sets) -> bytes:
    """Canonical bytes of an `Intersect`; discriminant 2, sets sorted+deduped."""
    return b"\x02" + enc_str(key) + enc_seq(sorted(set(sets)))


def result_bytes(candidates) -> bytes:
    """Canonical bytes of a complete result; total order, deduplicated."""
    return enc_seq(sorted(set(candidates)))


def canonical_query_digest(b: bytes) -> bytes:
    """Digest canonical query bytes under the query domain."""
    return hashlib.sha256(domain_header(DOMAIN_CANONICAL_QUERY) + length_prefixed(b)).digest()


def complete_result_digest(b: bytes) -> bytes:
    """Digest complete result bytes under the result domain."""
    return hashlib.sha256(domain_header(DOMAIN_COMPLETE_RESULT) + length_prefixed(b)).digest()


def query_result_id(schema: str, artifact: bytes, qd: bytes, rd: bytes) -> bytes:
    """The content-addressed identity, every component framed."""
    p = domain_header(DOMAIN_QUERY_RESULT_ID)
    p += framed_field("schema", schema.encode("utf-8"))
    p += framed_field("artifact", artifact)
    p += framed_field("query", qd)
    p += framed_field("result", rd)
    return hashlib.sha256(p).digest()


def vectors() -> dict:
    """Derive every golden vector the Rust contract tests assert against."""
    artifact = bytes.fromhex(
        "3b1f8a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8"
    )
    qb1 = query_bytes_lookup("suite", "cli::reader_17")
    qb2 = query_bytes_intersect("test_id", ["attempt_3", "attempt_1", "attempt_2"])
    rb = result_bytes(["cli::reader_17"])
    qd1, qd2, rd = canonical_query_digest(qb1), canonical_query_digest(qb2), complete_result_digest(rb)
    subst = b"identical-payload-bytes"
    return {
        "GOLDEN_ARTIFACT": "sha256:" + artifact.hex(),
        "GOLDEN_QUERY_BYTES_1": qb1.hex(),
        "GOLDEN_QUERY_DIGEST_1": "sha256:" + qd1.hex(),
        "GOLDEN_QUERY_BYTES_2": qb2.hex(),
        "GOLDEN_QUERY_DIGEST_2": "sha256:" + qd2.hex(),
        "GOLDEN_RESULT_BYTES": rb.hex(),
        "GOLDEN_RESULT_DIGEST": "sha256:" + rd.hex(),
        "GOLDEN_QRID_1": "sha256:" + query_result_id(SCHEMA_V1, artifact, qd1, rd).hex(),
        "GOLDEN_QRID_2": "sha256:" + query_result_id(SCHEMA_V1, artifact, qd2, rd).hex(),
        "GOLDEN_QRID_V2SCHEMA": "sha256:"
        + query_result_id("qodec.query.v2", artifact, qd1, rd).hex(),
        "SUBST_AS_QUERY": "sha256:" + canonical_query_digest(subst).hex(),
        "SUBST_AS_RESULT": "sha256:" + complete_result_digest(subst).hex(),
    }


def check() -> int:
    """Compare derived vectors against the constants committed in tests/canon.rs."""
    src = (Path(__file__).resolve().parents[1] / "canon.rs").read_text(encoding="utf-8")
    bad = 0
    for name, want in vectors().items():
        m = re.search(rf'const {name}: &str =\s*"([^"]+)"', src)
        if not m:
            print(f"MISSING in tests/canon.rs: {name}")
            bad += 1
            continue
        if m.group(1) != want:
            print(f"DRIFT {name}\n  rust      {m.group(1)}\n  reference {want}")
            bad += 1
    print("reference and tests/canon.rs agree" if not bad else f"{bad} mismatch(es)")
    return 1 if bad else 0


def main() -> None:
    """Print the vectors, or verify the committed ones against this reference."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="verify tests/canon.rs constants")
    args = ap.parse_args()
    if args.check:
        sys.exit(check())
    for name, value in vectors().items():
        print(f"{name:22s} {value}")


if __name__ == "__main__":
    main()
