#!/usr/bin/env python3
"""Independent verifier replay for a log-evidence-capsule-v1. Fail-closed: given the capsule + the
source stream (a Path or bytes), it RE-STREAMS the whole stream to EOF and re-derives every
attestation, trusting nothing the capsule asserts about itself.

Confirms:
  * the pinned canon module matches the CURRENT code (frozen-code drift is fail-closed);
  * read_to_eof AND the re-streamed byte count == stream.bytes;
  * stream.sha256 == streaming re-hash; chunk_count + Merkle root re-derive;
  * summary == re-extraction through the pinned log-hdfs-v1 canon (the whole semantic summary,
    including the fail-closed DISQUALIFIED_TEMPLATE_CARDINALITY outcome);
  * each excerpt's content == the bytes at [byte_start,byte_end), its sha256 matches, its
    chunk_sha256 re-hashes the containing chunk, and its Merkle proof re-roots to merkle_root.

A capsule that claims read_to_eof but under-counts bytes, a tampered digest, a summary that does
not re-derive, or an excerpt that does not belong to the stream is REJECTED here -- this is the
answer to "nobody will independently check a 300 MB proof": the proof is the bounded capsule plus
this replay over the checksum-pinned source, not a committed multi-GB blob.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import n2e_log_evidence_capsule as cap  # noqa: E402


class LogCapsuleVerifyError(Exception):
    pass


def _reroot(leaf_hex: str, proof: list[dict]) -> str:
    h = bytes.fromhex(leaf_hex)
    for step in proof:
        sib = bytes.fromhex(step["hash"])
        h = hashlib.sha256((h + sib) if step["side"] == "right" else (sib + h)).digest()
    return h.hex()


def verify(capsule: dict, source) -> dict:
    if capsule.get("record_type") != "n2e-log-evidence-capsule":
        raise LogCapsuleVerifyError("wrong record_type")
    canon = capsule.get("canon") or {}
    if canon.get("dialect") != cap.CAPSULE_DIALECT:
        raise LogCapsuleVerifyError("unexpected canon dialect")
    # frozen-code drift: the pinned canon module MUST equal the current code
    if canon.get("module_sha256") != cap.canon_module_sha256():
        raise LogCapsuleVerifyError("canon module drift (log-hdfs-v1 changed since the capsule was frozen)")

    stream = capsule.get("stream") or {}
    chunk_bytes = ((stream.get("chunking") or {}).get("chunk_bytes")) or cap.CHUNK_BYTES

    # ---- re-stream the WHOLE source to EOF; re-derive hash, byte count, chunk leaves, semantics ----
    col = cap._Collector()
    if isinstance(source, (str, Path)):
        path = Path(source)
        for chunk in _iter_fixed(path, chunk_bytes):
            col.feed(chunk)
        col.finish()

        def reader(off, n):
            with open(path, "rb") as f:
                f.seek(off)
                return f.read(n)
    elif isinstance(source, (bytes, bytearray)):
        data = bytes(source)
        for i in range(0, len(data), chunk_bytes):
            col.feed(data[i:i + chunk_bytes])
        col.finish()

        def reader(off, n):
            return data[off:off + n]
    else:
        raise LogCapsuleVerifyError(f"unsupported source {type(source)!r}")

    if stream.get("read_to_eof") is not True:
        raise LogCapsuleVerifyError("capsule does not claim read_to_eof")
    if stream.get("bytes") != col.total_bytes:
        raise LogCapsuleVerifyError(f"byte count mismatch: capsule {stream.get('bytes')} != {col.total_bytes}")
    if stream.get("sha256") != col.stream_sha256:
        raise LogCapsuleVerifyError("full-stream sha256 mismatch")
    ck = stream.get("chunking") or {}
    if ck.get("chunk_count") != len(col.chunk_hashes):
        raise LogCapsuleVerifyError("chunk_count mismatch")
    if ck.get("merkle_root") != col.merkle_root():
        raise LogCapsuleVerifyError("Merkle root mismatch")

    # summary re-derivation (whole semantic summary, incl. the fail-closed outcome)
    if capsule.get("summary") != col.summary():
        raise LogCapsuleVerifyError("semantic summary != independent re-extraction")

    # excerpts: each must belong to the stream and re-root
    root = ck.get("merkle_root")
    for ex in capsule.get("excerpts") or []:
        bs, be = ex["byte_start"], ex["byte_end"]
        if be - bs > cap.MAX_EXCERPT_BYTES or be < bs:
            raise LogCapsuleVerifyError("excerpt window out of bounds")
        window = reader(bs, be - bs)
        if ex["content"] != window.decode("utf-8", "replace"):
            raise LogCapsuleVerifyError("excerpt content != stream bytes at [start,end)")
        if ex["sha256"] != hashlib.sha256(window).hexdigest():
            raise LogCapsuleVerifyError("excerpt sha256 mismatch")
        ci = ex["chunk_index"]
        if ci != bs // chunk_bytes:
            raise LogCapsuleVerifyError("excerpt chunk_index inconsistent with byte_start")
        if ci >= len(col.chunk_hashes) or ex["chunk_sha256"] != col.chunk_hashes[ci].hex():
            raise LogCapsuleVerifyError("excerpt chunk_sha256 != re-hashed chunk")
        if _reroot(ex["chunk_sha256"], ex["merkle_proof"]) != root:
            raise LogCapsuleVerifyError("excerpt Merkle proof does not re-root")

    return {"role": stream.get("role"), "bytes": col.total_bytes,
            "outcome": col.summary()["outcome"], "unique_templates": col.summary()["unique_template_count"]}


def _iter_fixed(path: Path, chunk_bytes: int):
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_bytes)
            if not b:
                break
            yield b
