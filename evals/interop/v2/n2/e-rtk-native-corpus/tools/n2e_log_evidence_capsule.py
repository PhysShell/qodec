#!/usr/bin/env python3
"""log-evidence-capsule-v1: a compact, deterministic, independently-verifiable representation of a
large log stream (Loghub HDFS: `cat HDFS.log` is ~1.5 GB). The full stream is NEVER held in memory
or committed; it is consumed ONCE in fixed chunks through two paths that BOTH reach EOF:

  1. full-byte hash: every byte -> sha256 + a running byte count + a per-chunk hash whose Merkle
     root is pinned (capsule size is independent of stream size);
  2. bounded semantic extractor: line-framed (newline; residual buffer across chunk boundaries),
     each line parsed by the declared `log-hdfs-v1` canon into (severity, template_id); a severity
     counter + a per-template {count, first, last} table CAPPED at TEMPLATE_CAP -- overflow fails
     closed (DISQUALIFIED_TEMPLATE_CARDINALITY), never a silent pass.

Bounded means the MEMORY and the RECORD are bounded, never the verified data region: the stream is
always read to EOF and fully hashed. See docs/n2e-log-evidence-model-v1.md for the frozen contract.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

CAPSULE_DIALECT = "log-hdfs-v1"
CHUNK_BYTES = 1 << 20          # 1 MiB fixed chunk for hashing + Merkle leaves
TEMPLATE_CAP = 4096            # max distinct templates before fail-closed
MAX_EXCERPTS = 16             # bounded excerpt count
MAX_EXCERPT_BYTES = 4096      # bounded excerpt window


class LogCapsuleError(Exception):
    pass


# ---- declared, ordered HDFS masking canon (exact grammar only; a real message diff survives) ----
_MASKS: list[tuple[re.Pattern[bytes], bytes]] = [
    (re.compile(rb"blk_-?\d+"), b"blk_<*>"),                       # HDFS block ids
    (re.compile(rb"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), b"<ip>"),  # IPv4[:port]
    (re.compile(rb"/[\w./:-]+"), b"<path>"),                      # rooted paths / uris
    (re.compile(rb"\b\d+\b"), b"<num>"),                          # standalone integers
]
_LEVELS = {b"INFO": "INFO", b"WARN": "WARN", b"WARNING": "WARN", b"ERROR": "ERROR",
           b"FATAL": "FATAL", b"DEBUG": "DEBUG"}
# HDFS: "YYMMDD HHMMSS PID LEVEL COMPONENT: MESSAGE"
_HDFS = re.compile(rb"^\d{6} \d{6} \d+ ([A-Z]+) ([^:]+):[ ]?(.*)$", re.DOTALL)


def masking_rules_declared() -> list[dict]:
    return [{"pattern": p.pattern.decode(), "replacement": r.decode()} for p, r in _MASKS]


def canon_module_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def parse_line(line: bytes) -> tuple[str, str, str]:
    """(severity, template_id, template_text). A line that does not match the HDFS grammar is
    severity='unparsed', template='<unparsed>' -- counted, NEVER dropped."""
    body = line[:-1] if line.endswith(b"\n") else line
    m = _HDFS.match(body)
    if not m:
        tid = hashlib.sha256(b"<unparsed>").hexdigest()[:16]
        return "unparsed", tid, "<unparsed>"
    level_b, comp_b, msg_b = m.group(1), m.group(2).strip(), m.group(3)
    severity = _LEVELS.get(level_b, "other")
    masked = msg_b
    for pat, repl in _MASKS:
        masked = pat.sub(repl, masked)
    template_text = comp_b + b"\x00" + masked
    tid = hashlib.sha256(template_text).hexdigest()[:16]
    return severity, tid, template_text.decode("utf-8", "replace")


def _merkle_root(leaves: list[bytes]) -> str:
    if not leaves:
        return hashlib.sha256(b"n2e-log-merkle-empty").hexdigest()
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            a = level[i]
            b = level[i + 1] if i + 1 < len(level) else level[i]  # duplicate last if odd
            nxt.append(hashlib.sha256(a + b).digest())
        level = nxt
    return level[0].hex()


def _merkle_proof(leaves: list[bytes], index: int) -> list[dict]:
    """Inclusion proof: the sibling hash at each level + its side, re-rooting to _merkle_root."""
    proof: list[dict] = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            a = level[i]
            b = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(hashlib.sha256(a + b).digest())
        sib = idx ^ 1
        if sib >= len(level):
            sib = idx  # odd tail duplicated
        proof.append({"side": "right" if idx % 2 == 0 else "left", "hash": level[sib].hex()})
        idx //= 2
        level = nxt
    return proof


class _Collector:
    """Single-pass streaming collector. Feed fixed CHUNK_BYTES chunks; call finish() at EOF."""

    def __init__(self) -> None:
        self._h = hashlib.sha256()
        self.total_bytes = 0
        self.chunk_hashes: list[bytes] = []
        self._buf = b""
        self._buf_offset = 0
        self.total_lines = 0
        self.severity: dict[str, int] = {}
        self.templates: dict[str, dict] = {}
        self.overflow = False

    def feed(self, chunk: bytes) -> None:
        self._h.update(chunk)
        self.total_bytes += len(chunk)
        self.chunk_hashes.append(hashlib.sha256(chunk).digest())
        self._buf += chunk
        s = 0
        while True:
            nl = self._buf.find(b"\n", s)
            if nl < 0:
                break
            self._emit(self._buf[s:nl + 1], self._buf_offset + s)
            s = nl + 1
        if s:
            self._buf = self._buf[s:]
            self._buf_offset += s

    def finish(self) -> None:
        if self._buf:  # final unterminated line is a real line
            self._emit(self._buf, self._buf_offset)
            self._buf_offset += len(self._buf)
            self._buf = b""

    def _emit(self, line: bytes, byte_start: int) -> None:
        byte_end = byte_start + len(line)
        self.total_lines += 1
        sev, tid, template = parse_line(line)
        self.severity[sev] = self.severity.get(sev, 0) + 1
        ent = self.templates.get(tid)
        occ = {"line": self.total_lines, "byte_start": byte_start, "byte_end": byte_end}
        if ent is None:
            if len(self.templates) >= TEMPLATE_CAP:
                self.overflow = True  # stop registering NEW templates; keep hashing to EOF
                return
            self.templates[tid] = {"template": template, "count": 1,
                                   "first": dict(occ), "last": dict(occ)}
        else:
            ent["count"] += 1
            ent["last"] = dict(occ)

    # ---- derived ----
    @property
    def stream_sha256(self) -> str:
        return self._h.hexdigest()

    def merkle_root(self) -> str:
        return _merkle_root(self.chunk_hashes)

    def summary(self) -> dict:
        tids = sorted(self.templates)
        occ = {t: self.templates[t]["count"] for t in tids}
        fl = {t: {"first": {k: self.templates[t]["first"][k] for k in ("line", "byte_start", "byte_end")},
                  "last": {k: self.templates[t]["last"][k] for k in ("line", "byte_start", "byte_end")}}
              for t in tids}
        body = {
            "outcome": "DISQUALIFIED_TEMPLATE_CARDINALITY" if self.overflow else "parsed",
            "total_lines": self.total_lines,
            "severity_counts": {k: self.severity[k] for k in sorted(self.severity)},
            "unique_template_count": len(tids),
            "unique_template_ids": tids,
            "occurrence_counts": occ,
            "first_last_occurrence": fl,
            "overflow": self.overflow,
        }
        body["summary_sha256"] = hashlib.sha256(
            _canon_json(body).encode()).hexdigest()
        return body


def _canon_json(obj) -> str:
    import json
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _iter_chunks(path: Path):
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_BYTES)
            if not chunk:
                break
            yield chunk


def _excerpts_from(col: _Collector, reader) -> list[dict]:
    """Bounded second read: for the first MAX_EXCERPTS templates (sorted by id), read only that
    template's first-occurrence window (<= MAX_EXCERPT_BYTES) via random access, and anchor it to
    its chunk hash + Merkle inclusion proof. Total bytes re-read <= MAX_EXCERPTS*MAX_EXCERPT_BYTES."""
    out: list[dict] = []
    for tid in sorted(col.templates)[:MAX_EXCERPTS]:
        first = col.templates[tid]["first"]
        bs = first["byte_start"]
        be = min(first["byte_end"], bs + MAX_EXCERPT_BYTES)
        content = reader(bs, be - bs)
        ci = bs // CHUNK_BYTES
        out.append({
            "template_id": tid, "byte_start": bs, "byte_end": be,
            "chunk_index": ci,
            "chunk_sha256": col.chunk_hashes[ci].hex() if ci < len(col.chunk_hashes) else None,
            "merkle_proof": _merkle_proof(col.chunk_hashes, ci) if col.chunk_hashes else [],
            "sha256": hashlib.sha256(content).hexdigest(),
            "content": content.decode("utf-8", "replace"),
        })
    return out


def build_capsule(source, role: str, invoked_argv: list[str], exit_status: int,
                  identities: dict | None = None) -> dict:
    """Build the capsule from `source` (a Path to a file, or a bytes object). Streaming for a Path
    (bounded memory); bytes for the small RTK summary + tests."""
    col = _Collector()
    if isinstance(source, (str, Path)):
        path = Path(source)
        for chunk in _iter_chunks(path):
            col.feed(chunk)
        col.finish()

        def reader(off, n):
            with open(path, "rb") as f:
                f.seek(off)
                return f.read(n)
    elif isinstance(source, (bytes, bytearray)):
        data = bytes(source)
        for i in range(0, len(data), CHUNK_BYTES):
            col.feed(data[i:i + CHUNK_BYTES])
        col.finish()  # empty data -> no chunks, empty Merkle root, bytes=0, read_to_eof True

        def reader(off, n):
            return data[off:off + n]
    else:
        raise LogCapsuleError(f"unsupported source type {type(source)!r}")

    summary = col.summary()
    return {
        "record_type": "n2e-log-evidence-capsule",
        "capsule_version": "v1",
        "stream": {
            "role": role, "invoked_argv": list(invoked_argv), "exit_status": exit_status,
            "bytes": col.total_bytes, "sha256": col.stream_sha256, "read_to_eof": True,
            "chunking": {"chunk_bytes": CHUNK_BYTES, "chunk_count": len(col.chunk_hashes),
                         "merkle_root": col.merkle_root()},
        },
        "canon": {
            "dialect": CAPSULE_DIALECT, "module_sha256": canon_module_sha256(),
            "framing": "split on \\n; residual buffer across chunks; final unterminated line kept",
            "encoding": "raw bytes hashed; per-line utf-8/replace for template derivation only",
            "masking_rules": masking_rules_declared(),
            "template_cap": TEMPLATE_CAP, "truncation_policy": "none-for-hashing",
        },
        "summary": summary,
        "excerpts": _excerpts_from(col, reader),
        "identities": identities or {},
    }
