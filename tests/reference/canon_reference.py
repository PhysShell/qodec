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
DOMAIN_ARTIFACT = "qodec.artifact.v1"
DOMAIN_STORE_PLAN = "qodec.store-plan.v1"
DOMAIN_STORE_ID = "qodec.store-id.v1"
DOMAIN_RESULT_SUPPORT = "qodec.result-support.v1"


def domain_header(domain: str) -> bytes:
    """`u16be(len) || utf8` — the length-delimited domain tag."""
    b = domain.encode("utf-8")
    return struct.pack(">H", len(b)) + b


def framed_field(tag: str, value: bytes) -> bytes:
    """`u16be(len(tag)) || tag || u64be(len(value)) || value` — both delimited."""
    t = tag.encode("utf-8")
    return struct.pack(">H", len(t)) + t + struct.pack(">Q", len(value)) + value


def length_prefixed(b: bytes) -> bytes:
    """`u64be(len) || bytes`."""
    return struct.pack(">Q", len(b)) + b


def enc_bytes(b: bytes) -> bytes:
    """`u64be(len) || raw` — the framing for any value, name or key alike."""
    return struct.pack(">Q", len(b)) + b


def enc_name(s: str) -> bytes:
    """A protocol name enters as its UTF-8 bytes; empty and BOM are rejected."""
    if not s:
        raise ValueError("protocol name must not be empty")
    if "﻿" in s:
        raise ValueError("protocol name must not contain U+FEFF")
    return enc_bytes(s.encode("utf-8"))


def enc_name_seq(items) -> bytes:
    """`u32be(count) || enc_name(e)…` in the order given."""
    return struct.pack(">I", len(items)) + b"".join(enc_name(i) for i in items)


def enc_key_seq(items) -> bytes:
    """`u32be(count) || enc_bytes(e)…` in the order given."""
    return struct.pack(">I", len(items)) + b"".join(enc_bytes(i) for i in items)


def query_bytes_lookup(field: str, value: bytes) -> bytes:
    """Canonical bytes of a `Lookup`; discriminant 1, value is raw bytes."""
    return b"\x01" + enc_name(field) + enc_bytes(value)


def query_bytes_intersect(key: str, sets) -> bytes:
    """Canonical bytes of an `Intersect`; discriminant 2, sets sorted+deduped."""
    return b"\x02" + enc_name(key) + enc_name_seq(sorted(set(sets)))


def result_bytes(candidates) -> bytes:
    """Canonical bytes of a complete result; unsigned byte order, deduplicated."""
    return enc_key_seq(sorted(set(candidates)))


def canonical_query_digest(b: bytes) -> bytes:
    """Digest canonical query bytes under the query domain."""
    return hashlib.sha256(domain_header(DOMAIN_CANONICAL_QUERY) + length_prefixed(b)).digest()


def complete_result_digest(b: bytes) -> bytes:
    """Digest complete result bytes under the result domain."""
    return hashlib.sha256(domain_header(DOMAIN_COMPLETE_RESULT) + length_prefixed(b)).digest()


def artifact_digest(artifact_bytes: bytes) -> bytes:
    """Digest an artifact's own bytes under the artifact domain."""
    return hashlib.sha256(domain_header(DOMAIN_ARTIFACT) + length_prefixed(artifact_bytes)).digest()


def plan_bytes(segmentation: bytes, specs) -> bytes:
    """Canonical bytes of an open plan; specs sorted by index name."""
    out = segmentation + struct.pack(">I", len(specs))
    for name, extractor in sorted(specs, key=lambda s: s[0]):
        out += enc_name(name) + extractor
    return out


def seg_lines(section: str) -> bytes:
    """`Segmentation::Lines`; discriminant 1."""
    return b"\x01" + enc_name(section)


def seg_marked(prefix: str, suffix: str, preamble: str) -> bytes:
    """`Segmentation::MarkedSections`; discriminant 2, markers are data."""
    return (
        b"\x02"
        + enc_bytes(prefix.encode("utf-8"))
        + enc_bytes(suffix.encode("utf-8"))
        + enc_name(preamble)
    )


def extractor_whole() -> bytes:
    """`KeyExtractor::WholeRecord`; discriminant 1."""
    return b"\x01"


def extractor_field(separator: int, index: int) -> bytes:
    """`KeyExtractor::Field`; discriminant 2, then the separator byte and index."""
    return b"\x02" + bytes([separator]) + struct.pack(">I", index)


def store_plan_digest(b: bytes) -> bytes:
    """Digest canonical plan bytes under the store-plan domain."""
    return hashlib.sha256(domain_header(DOMAIN_STORE_PLAN) + length_prefixed(b)).digest()


def store_id(artifact: bytes, plan: bytes) -> bytes:
    """One artifact opened one way — the space where coordinates are unambiguous."""
    p = domain_header(DOMAIN_STORE_ID)
    p += framed_field("artifact", artifact)
    p += framed_field("plan", plan)
    return hashlib.sha256(p).digest()


def support_bytes(completion, support) -> bytes:
    """Canonical support: completion state, then each candidate's record ids.

    `completion` is `None` for Exhausted or an int limit for LimitReached.
    Record ids enter as coordinates only; the store is already bound by the
    identity, so repeating it per record would restate a known fact.
    """
    out = b"\x01" if completion is None else b"\x02" + struct.pack(">Q", completion)
    out += struct.pack(">I", len(support))
    for candidate, ids in sorted(support.items()):
        out += enc_bytes(candidate) + struct.pack(">I", len(ids))
        for section, ordinal in ids:
            out += enc_name(section) + struct.pack(">Q", ordinal)
    return out


def result_support_digest(b: bytes) -> bytes:
    """Digest canonical support bytes under the result-support domain."""
    return hashlib.sha256(domain_header(DOMAIN_RESULT_SUPPORT) + length_prefixed(b)).digest()


def query_result_id(schema: str, store: bytes, qd: bytes, rd: bytes, sd: bytes) -> bytes:
    """The content-addressed identity: store, question, result, and support."""
    p = domain_header(DOMAIN_QUERY_RESULT_ID)
    p += framed_field("schema", schema.encode("utf-8"))
    p += framed_field("store", store)
    p += framed_field("query", qd)
    p += framed_field("result", rd)
    p += framed_field("support", sd)
    return hashlib.sha256(p).digest()


def vectors() -> dict:
    """Derive every golden vector the Rust contract tests assert against."""
    artifact = bytes.fromhex(
        "3b1f8a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8"
    )
    qb1 = query_bytes_lookup("suite", b"cli::reader_17")
    qb2 = query_bytes_intersect("test_id", ["attempt_3", "attempt_1", "attempt_2"])
    rb = result_bytes([b"cli::reader_17"])
    qd1, qd2, rd = canonical_query_digest(qb1), canonical_query_digest(qb2), complete_result_digest(rb)
    subst = b"identical-payload-bytes"
    # A key that is not valid UTF-8 and carries an interior NUL. Nothing in
    # the pipeline may decode, replace, or truncate it.
    raw_key = bytes([0xFF, 0x00, 0xFE, 0x80])
    qb3 = query_bytes_lookup("suite", raw_key)
    rb3 = result_bytes([raw_key, bytes([0xFF, 0x00, 0xFE, 0x81])])
    # A store plan: one section of lines, one whole-record index.
    pb = plan_bytes(seg_lines("s"), [("line", extractor_whole())])
    pd = store_plan_digest(pb)
    sid = store_id(artifact, pd)
    # The same artifact opened a different way is a different store.
    pb_marked = plan_bytes(
        seg_marked("--- ", " ---", "preamble"), [("line", extractor_whole())]
    )
    sid_marked = store_id(artifact, store_plan_digest(pb_marked))
    # One candidate backed by one record, from an execution that finished.
    sb = support_bytes(None, {b"cli::reader_17": [("s", 0)]})
    sd = result_support_digest(sb)
    # The same candidate set, but the search stopped at a bound.
    sb_limited = support_bytes(7, {b"cli::reader_17": [("s", 0)]})
    # The retry-store fixture used by tests/query.rs: one candidate backed by
    # one record per attempt block. Derived here so the constants that exist to
    # prove the completion state is inside the digest are not merely pasted.
    retry = {b"alpha": [("attempt_1", 0), ("attempt_2", 0), ("attempt_3", 0)]}
    retry_limited = {b"alpha": [("attempt_1", 0), ("attempt_2", 0)]}
    return {
        "GOLDEN_ARTIFACT": "sha256:" + artifact.hex(),
        "GOLDEN_QUERY_BYTES_1": qb1.hex(),
        "GOLDEN_QUERY_DIGEST_1": "sha256:" + qd1.hex(),
        "GOLDEN_QUERY_BYTES_2": qb2.hex(),
        "GOLDEN_QUERY_DIGEST_2": "sha256:" + qd2.hex(),
        "GOLDEN_RESULT_BYTES": rb.hex(),
        "GOLDEN_RESULT_DIGEST": "sha256:" + rd.hex(),
        "GOLDEN_PLAN_BYTES": pb.hex(),
        "GOLDEN_PLAN_DIGEST": "sha256:" + pd.hex(),
        "GOLDEN_STORE_ID": "sha256:" + sid.hex(),
        "GOLDEN_STORE_ID_MARKED": "sha256:" + sid_marked.hex(),
        "GOLDEN_SUPPORT_BYTES": sb.hex(),
        "GOLDEN_SUPPORT_DIGEST": "sha256:" + sd.hex(),
        "GOLDEN_SUPPORT_DIGEST_LIMITED": "sha256:" + result_support_digest(sb_limited).hex(),
        "GOLDEN_QRID_1": "sha256:" + query_result_id(SCHEMA_V1, sid, qd1, rd, sd).hex(),
        "GOLDEN_QRID_2": "sha256:" + query_result_id(SCHEMA_V1, sid, qd2, rd, sd).hex(),
        "GOLDEN_QRID_V2SCHEMA": "sha256:"
        + query_result_id("qodec.query.v2", sid, qd1, rd, sd).hex(),
        "SUBST_AS_QUERY": "sha256:" + canonical_query_digest(subst).hex(),
        "SUBST_AS_RESULT": "sha256:" + complete_result_digest(subst).hex(),
        "GOLDEN_RAW_KEY_QUERY_BYTES": qb3.hex(),
        "GOLDEN_RAW_KEY_QUERY_DIGEST": "sha256:" + canonical_query_digest(qb3).hex(),
        "GOLDEN_RAW_KEY_RESULT_BYTES": rb3.hex(),
        "GOLDEN_RAW_KEY_RESULT_DIGEST": "sha256:" + complete_result_digest(rb3).hex(),
        "GOLDEN_RETRY_SUPPORT_EXHAUSTED": "sha256:"
        + result_support_digest(support_bytes(None, retry)).hex(),
        "GOLDEN_RETRY_SUPPORT_LIMITED": "sha256:"
        + result_support_digest(support_bytes(2, retry_limited)).hex(),
    }


def check() -> int:
    """Compare derived vectors against the constants committed in the Rust tests.

    Scans every Rust test file that holds golden constants, not just one. A
    constant the reference never derives is self-attested: it proves only that
    someone pasted it, which is exactly the state the reference exists to
    prevent.
    """
    tests = Path(__file__).resolve().parents[1]
    sources = {p.name: p.read_text(encoding="utf-8") for p in sorted(tests.glob("*.rs"))}
    bad = 0
    for name, want in vectors().items():
        pattern = re.compile(rf'const {re.escape(name)}: &str =\s*"([^"]+)"')
        found = {f: m.group(1) for f, src in sources.items() if (m := pattern.search(src))}
        if not found:
            print(f"MISSING from every Rust test file: {name}")
            bad += 1
            continue
        for where, got in found.items():
            if got != want:
                print(f"DRIFT {name} in {where}\n  rust      {got}\n  reference {want}")
                bad += 1
    print("reference and the Rust golden constants agree" if not bad else f"{bad} mismatch(es)")
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
