#!/usr/bin/env python3
"""log-evidence-capsule-v1: a compact, deterministic, independently-verifiable representation of a
large log stream (Loghub HDFS: `cat HDFS.log` is ~1.5 GB, 11 167 740 lines). The full stream is
NEVER held in memory or committed; it is consumed ONCE in fixed chunks through two paths that BOTH
reach EOF:

  1. full-byte hash: every byte -> sha256 + a running byte count + a per-chunk hash whose Merkle
     root is pinned (capsule size is independent of stream size);
  2. bounded semantic extractor: line-framed (newline; residual buffer across chunk boundaries),
     each line's Content assigned an EventId from the PUBLISHED Loghub HDFS template set
     (n2e-loghub-hdfs-reference-v1) by EXACTLY-ONE-MATCH -- zero matches or more than one is a
     fail-closed reject, never a silent pass. Aggregates a severity counter + a per-EventId
     {count, first, last} table (bounded by the 46 published templates).

The published set DEFINES identity (unique_template_ids) and the ground-truth per-template
occurrence_counts; the streamed counts must EQUAL the published Occurrences for the full stream (a
mismatch is a reject). Our own masking is retained ONLY as a diagnostic cross-check, never as the
authority. Bounded means MEMORY + RECORD, never a truncated data region: the stream is always read
to EOF and fully hashed. See docs/n2e-log-evidence-model-v1.md.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from pathlib import Path

import n2e_rtk_log_hdfs_oracle as _rtk_oracle

CAPSULE_DIALECT = "log-hdfs-v1"
CHUNK_BYTES = 1 << 20          # 1 MiB fixed chunk for hashing + Merkle leaves
MAX_EXCERPTS = 16             # bounded excerpt count
MAX_EXCERPT_BYTES = 4096      # bounded excerpt window

_HERE = Path(__file__).resolve().parent
_N2E = _HERE.parent
REFERENCE_RECORD = _N2E / "n2e-loghub-hdfs-reference-v1.json"
TEMPLATES_CSV = _N2E / "n2e-loghub-hdfs-templates.csv"


class LogCapsuleError(Exception):
    pass


# ---- diagnostic-only masking cross-check (NEVER the authority for identity) ----
_MASKS: list[tuple[re.Pattern[bytes], bytes]] = [
    (re.compile(rb"blk_-?\d+"), b"blk_<*>"),
    (re.compile(rb"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), b"<ip>"),
    (re.compile(rb"/[\w./:-]+"), b"<path>"),
    (re.compile(rb"\b\d+\b"), b"<num>"),
]
_LEVELS = {b"INFO": "INFO", b"WARN": "WARN", b"WARNING": "WARN", b"ERROR": "ERROR",
           b"FATAL": "FATAL", b"DEBUG": "DEBUG"}
# HDFS: "YYMMDD HHMMSS PID LEVEL COMPONENT: MESSAGE"
_HDFS = re.compile(rb"^\d{6} \d{6} \d+ ([A-Z]+) ([^:]+):[ ]?(.*)$", re.DOTALL)


def canon_module_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _template_to_regex(template: str) -> re.Pattern[str]:
    """Compile a published Loghub EventTemplate (with `<*>` wildcards) to an anchored full-match
    regex. Literal text is escaped; each `<*>` becomes a non-greedy `.*?`."""
    parts = template.split("<*>")
    return re.compile("^" + "(?:.*?)".join(re.escape(p) for p in parts) + "$", re.DOTALL)


def load_reference() -> dict:
    """Load + self-check the pinned published HDFS reference. The committed CSV's sha256 MUST equal
    the digest the reference record pins (fail-closed); returns compiled matchers + published counts."""
    rec = json.loads(REFERENCE_RECORD.read_text())
    if rec.get("record_type") != "n2e-loghub-hdfs-reference":
        raise LogCapsuleError("reference record_type wrong")
    csv_bytes = TEMPLATES_CSV.read_bytes()
    ref_sha = hashlib.sha256(csv_bytes).hexdigest()
    if ref_sha != rec["reference_file"]["sha256"] or len(csv_bytes) != rec["reference_file"]["bytes"]:
        raise LogCapsuleError("published templates CSV sha256/bytes != pinned reference")
    rows = list(csv.DictReader(io.StringIO(csv_bytes.decode())))
    templates = {r["EventId"]: r["EventTemplate"] for r in rows}
    published = {r["EventId"]: int(r["Occurrences"]) for r in rows}
    matchers = {eid: _template_to_regex(t) for eid, t in templates.items()}
    # leading literal (template text before the first `<*>`) -- a NECESSARY prefix for a match, so a
    # cheap `content.startswith(lead)` prefilters most templates before the anchored regex (sound for
    # exactly-one-match: a template whose leading literal is not a prefix of the line cannot match).
    leads = {eid: t.split("<*>")[0] for eid, t in templates.items()}
    return {"sha256": ref_sha, "event_ids": sorted(templates), "published": published,
            "templates": templates, "matchers": matchers, "leads": leads, "record": rec}


def assign_event_id(content: str, matchers: dict, leads: dict | None = None) -> tuple[str, int]:
    """Exactly-one-match against the published templates. Returns (EventId, 1) for a unique match;
    ('<unmatched>', 0) for zero; ('<ambiguous>', n) for >1 -- both are fail-closed rejects. `leads`
    (leading literals) is an OPTIONAL prefilter that changes speed only, never the result."""
    if leads is not None:
        hits = [eid for eid, rx in matchers.items() if content.startswith(leads[eid]) and rx.match(content)]
    else:
        hits = [eid for eid, rx in matchers.items() if rx.match(content)]
    if len(hits) == 1:
        return hits[0], 1
    if not hits:
        return "<unmatched>", 0
    return "<ambiguous>", len(hits)


def _merkle_root(leaves: list[bytes]) -> str:
    if not leaves:
        return hashlib.sha256(b"n2e-log-merkle-empty").hexdigest()
    level = list(leaves)
    while len(level) > 1:
        level = [hashlib.sha256(level[i] + (level[i + 1] if i + 1 < len(level) else level[i])).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def _merkle_proof(leaves: list[bytes], index: int) -> list[dict]:
    proof: list[dict] = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        sib = idx ^ 1
        if sib >= len(level):
            sib = idx
        proof.append({"side": "right" if idx % 2 == 0 else "left", "hash": level[sib].hex()})
        level = [hashlib.sha256(level[i] + (level[i + 1] if i + 1 < len(level) else level[i])).digest()
                 for i in range(0, len(level), 2)]
        idx //= 2
    return proof


class _Collector:
    """Single-pass streaming collector. Feed fixed CHUNK_BYTES chunks; call finish() at EOF."""

    def __init__(self, reference: dict) -> None:
        self._h = hashlib.sha256()
        self.total_bytes = 0
        self.chunk_hashes: list[bytes] = []
        self._buf = b""
        self._buf_offset = 0
        self.total_lines = 0
        self.severity: dict[str, int] = {}
        self.events: dict[str, dict] = {}     # EventId -> {count, first, last}
        self.unmatched = 0
        self.ambiguous = 0
        self._masks: set[bytes] = set()       # diagnostic masking cross-check (distinct masked)
        self._ref = reference
        self.rtk_sev = {"error": 0, "warn": 0, "info": 0, "other": 0}  # RTK-semantic severity totals

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
        if self._buf:
            self._emit(self._buf, self._buf_offset)
            self._buf_offset += len(self._buf)
            self._buf = b""

    def _emit(self, line: bytes, byte_start: int) -> None:
        byte_end = byte_start + len(line)
        self.total_lines += 1
        body = line[:-1] if line.endswith(b"\n") else line
        # RAW-side reference for the RTK oracle: RTK categorizes the WHOLE line by substring severity
        # (source-grounded in n2e_rtk_log_hdfs_oracle). Computed for EVERY line, even unparsed ones.
        self.rtk_sev[_rtk_oracle.rtk_categorize(body.decode("utf-8", "replace"))] += 1
        m = _HDFS.match(body)
        if not m:
            self.severity["unparsed"] = self.severity.get("unparsed", 0) + 1
            self.unmatched += 1
            return
        level_b, _comp, msg_b = m.group(1), m.group(2).strip(), m.group(3)
        sev = _LEVELS.get(level_b, "other")
        self.severity[sev] = self.severity.get(sev, 0) + 1
        # diagnostic masking cross-check (never authority)
        masked = msg_b
        for pat, repl in _MASKS:
            masked = pat.sub(repl, masked)
        self._masks.add(masked)
        # AUTHORITY: published EventId by exactly-one-match (prefiltered by leading literal for speed)
        eid, n = assign_event_id(msg_b.decode("utf-8", "replace"),
                                 self._ref["matchers"], self._ref.get("leads"))
        if eid == "<unmatched>":
            self.unmatched += 1
            return
        if eid == "<ambiguous>":
            self.ambiguous += 1
            return
        occ = {"line": self.total_lines, "byte_start": byte_start, "byte_end": byte_end}
        ent = self.events.get(eid)
        if ent is None:
            self.events[eid] = {"count": 1, "first": dict(occ), "last": dict(occ)}
        else:
            ent["count"] += 1
            ent["last"] = dict(occ)

    @property
    def stream_sha256(self) -> str:
        return self._h.hexdigest()

    def merkle_root(self) -> str:
        return _merkle_root(self.chunk_hashes)

    def summary(self) -> dict:
        obs = sorted(self.events)
        streamed = {e: self.events[e]["count"] for e in obs}
        published = {e: self._ref["published"][e] for e in obs}
        fl = {e: {"first": self.events[e]["first"], "last": self.events[e]["last"]} for e in obs}
        match_pub = streamed == published
        if self.unmatched or self.ambiguous:
            outcome = "DISQUALIFIED_UNMATCHED_OR_AMBIGUOUS"
        elif not match_pub:
            outcome = "streamed_partial"   # a partial/sub stream: valid but not the full published log
        else:
            outcome = "parsed"
        body = {
            "reference_sha256": self._ref["sha256"],
            "reference_template_count": len(self._ref["event_ids"]),
            "outcome": outcome,
            "total_lines": self.total_lines,
            "severity_counts": {k: self.severity[k] for k in sorted(self.severity)},
            "observed_event_ids": obs,
            "unique_template_count": len(obs),
            "streamed_occurrence_counts": streamed,
            "published_occurrence_counts": published,
            "occurrence_counts_match_published": match_pub,
            "first_last_occurrence": fl,
            "unmatched_lines": self.unmatched,
            "ambiguous_lines": self.ambiguous,
            "masking_cross_check": {"canon": "log-hdfs-masking-diagnostic-v1",
                                    "distinct_masked": len(self._masks), "authority": False},
            # RAW-side reference for the RTK oracle: RTK's severity totals re-derived over the full
            # stream (the only overlap `rtk log` actually reports). Bounded (4 counters).
            "rtk_semantic_projection": dict(self.rtk_sev),
        }
        body["summary_sha256"] = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return body


def _iter_chunks(path: Path):
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_BYTES)
            if not chunk:
                break
            yield chunk


def stream_digest(path, chunk_bytes: int = CHUNK_BYTES) -> dict:
    """Bounded streaming digest of a file: full sha256 + byte count + line count (a final
    unterminated line counts, exactly as the collector frames lines). No semantic matching -- for
    the acquisition-time INPUT IDENTITY both arms share."""
    h = hashlib.sha256()
    total = 0
    lines = 0
    tail_nl = True
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_bytes)
            if not b:
                break
            h.update(b)
            total += len(b)
            lines += b.count(b"\n")
            tail_nl = b.endswith(b"\n")
    if total > 0 and not tail_nl:
        lines += 1
    return {"sha256": h.hexdigest(), "bytes": total, "line_count": lines}


def extract_member_streaming(zip_path, member: str, dest, expected_bytes: int | None = None,
                             chunk_bytes: int = CHUNK_BYTES) -> int:
    """Extract ONE zip member to `dest` in bounded memory (no whole-file read). Rejects an unsafe
    member path and, when given, an uncompressed size that does not match the pinned expectation."""
    import zipfile
    mp = Path(member)
    if member.startswith("/") or ".." in mp.parts:
        raise LogCapsuleError(f"unsafe member path {member!r}")
    n = 0
    with zipfile.ZipFile(zip_path) as z, z.open(z.getinfo(member)) as src, open(dest, "wb") as out:
        while True:
            b = src.read(chunk_bytes)
            if not b:
                break
            out.write(b)
            n += len(b)
    if expected_bytes is not None and n != expected_bytes:
        raise LogCapsuleError(f"member {member} uncompressed bytes {n} != pinned {expected_bytes}")
    return n


def _excerpts_from(col: _Collector, reader) -> list[dict]:
    """Bounded second read: the first MAX_EXCERPTS observed EventIds (sorted), each anchored to its
    first-occurrence window (<= MAX_EXCERPT_BYTES) by byte range + chunk hash + Merkle proof."""
    out: list[dict] = []
    for eid in sorted(col.events)[:MAX_EXCERPTS]:
        first = col.events[eid]["first"]
        bs = first["byte_start"]
        be = min(first["byte_end"], bs + MAX_EXCERPT_BYTES)
        content = reader(bs, be - bs)
        ci = bs // CHUNK_BYTES
        out.append({
            "event_id": eid, "byte_start": bs, "byte_end": be, "chunk_index": ci,
            "chunk_sha256": col.chunk_hashes[ci].hex() if ci < len(col.chunk_hashes) else None,
            "merkle_proof": _merkle_proof(col.chunk_hashes, ci) if col.chunk_hashes else [],
            "sha256": hashlib.sha256(content).hexdigest(),
            "content": content.decode("utf-8", "replace"),
        })
    return out


def build_capsule(source, role: str, invoked_argv: list[str], exit_status: int,
                  identities: dict | None = None, reference: dict | None = None) -> dict:
    """Build the capsule from `source` (a Path -> streamed, bounded memory; or bytes -> small/RTK/tests)."""
    ref = reference or load_reference()
    col = _Collector(ref)
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
        col.finish()

        def reader(off, n):
            return data[off:off + n]
    else:
        raise LogCapsuleError(f"unsupported source type {type(source)!r}")

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
            "identity_authority": "n2e-loghub-hdfs-reference-v1 (published EventId set; exactly-one-match)",
            "reference_sha256": ref["sha256"],
            "framing": "split on \\n; residual buffer across chunks; final unterminated line kept",
            "encoding": "raw bytes hashed; per-line utf-8/replace for template matching only",
            "masking_cross_check": "log-hdfs-masking-diagnostic-v1 (diagnostic only; never authority)",
            "truncation_policy": "none-for-hashing",
        },
        "summary": col.summary(),
        "excerpts": _excerpts_from(col, reader),
        "identities": identities or {},
    }
