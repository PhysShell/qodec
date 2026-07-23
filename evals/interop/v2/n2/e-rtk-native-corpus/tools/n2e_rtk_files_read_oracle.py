#!/usr/bin/env python3
"""rtk-files-read-oracle-v1: the `rtk read` file-read command-semantic oracle, defined FROM the pinned
RTK implementation (rtk-ai/rtk @5d32d07), then validated. This is a rtk_command_oracle (NOT a
test-summary dialect): `rtk read` has no pass/fail counts. Case-scoped to preact + lombok as TWO
independent case bindings of this ONE policy -- never family-level files_search::read.

Source-grounded semantics -- what `rtk read FILE` (the frozen argv, no flags) preserves / drops /
synthesizes, traced end to end through the pinned source:

  1. DEFAULT FILTER LEVEL IS `none`. main.rs `Commands::Read`:
         #[arg(short, long, default_value = "none")] level: core::filter::FilterLevel
     and max_lines / tail_lines / line_numbers all default to None/false. The frozen contract argv is
     exactly `rtk read README.md` (no --level, no window, no -n), so level == FilterLevel::None.
  2. `none` -> NoFilter, which is the IDENTITY transform. filter.rs:
         impl FilterStrategy for NoFilter { fn filter(&self, content, _lang) -> String { content.to_string() } }
     (Language detection is computed but irrelevant under NoFilter. Note also `.md` -> Language::Data,
     whose comment patterns are all None, so even Minimal/Aggressive would only collapse >=3 blank
     lines + trim -- a line-subsequence-preserving transform. This oracle grounds the DEFAULT `none`
     path, and its equivalence predicate is deliberately robust to that blank-collapse too.)
  3. No line window: read.rs `apply_line_window(&filtered, None, None, &lang)` returns the content
     unchanged; line_numbers=false so no renumbering.
  4. never_worse guard (guard.rs): `never_worse(&raw, &rtk_output)` returns `filtered` unless it would
     emit MORE tokens than raw; for the identity path filtered == raw (equal tokens) -> filtered kept.
  5. safety fallback (read.rs 44-51): only fires if the filter EMPTIED a non-empty file; NoFilter
     never empties, so it never fires here.
  6. tracking (tracking.rs `TimedExecution::track`): records to a SQLite history DB under HOME; it
     writes NOTHING to stdout/stderr and emits NO tee-log envelope on the measured stream. At
     verbose=0 read.rs prints only `print!("{}", shown)` to stdout and nothing to stderr.

  => `rtk read README.md` stdout is BYTE-IDENTICAL to `cat README.md` for a valid-UTF-8 Markdown file:
     RTK preserves 100% of the file content, drops nothing, synthesizes nothing. This is the strongest
     fidelity class -- the oracle asserts CONTENT FIDELITY, not the internal filter rules (which is the
     version-robust semantic predicate: it verifies the invariant `read.rs` guarantees rather than
     reimplementing a filter that could change between RTK versions).

Three structurally distinct layers (never conflated): captured bytes -> execution binding -> semantic
projection. This module is the SEMANTIC PROJECTION + the RAW<->RTK equivalence predicate. RAW is
`cat FILE`; RTK is `rtk read FILE` (a DIFFERENT command RTK reimplements -- not `rtk`-wrapping cat).
Allowed non-semantic normalizations, enumerated: ANSI escapes, CRLF, and a trailing newline
difference (the gin lesson: RTK presentation may differ by a trailing newline; content is semantic).
The ordered sequence of non-blank content lines is the semantic invariant.
"""
from __future__ import annotations

import hashlib
import re

ORACLE_ID = "rtk-files-read-oracle-v1"
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
# primary source (the read command flow); supporting refs pinned via RTK_SOURCE_REFS below.
RTK_SOURCE_FILE = "src/cmds/system/read.rs"
RTK_SOURCE_FUNCTION = "run"
# every pinned source location this oracle is grounded in (file + the exact item), each frozen and
# re-hashed by the source-proof builder/verifier.
RTK_SOURCE_REFS = [
    {"source_file": "src/cmds/system/read.rs", "source_function": "run"},
    {"source_file": "src/core/filter.rs",
     "source_function": "NoFilter::filter / get_filter / Language::from_extension"},
    {"source_file": "src/core/guard.rs", "source_function": "never_worse"},
    {"source_file": "src/main.rs", "source_function": "Commands::Read (default_value=\"none\")"},
]

_ANSI = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")


def _strip_presentation(data: bytes) -> bytes:
    data = _ANSI.sub(b"", data)
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return data


def _project(data: bytes) -> dict:
    """Project a file-read stream (cat OR rtk read) to a content-fidelity fingerprint. The semantic
    core is the ORDERED sequence of non-blank content lines (byte-preserving within each line);
    blank-line runs and a trailing newline are non-semantic presentation."""
    n = _strip_presentation(data)
    text = n.decode("utf-8", "replace")
    lines = text.split("\n")
    # a "blank" line is empty or whitespace-only (read.rs Minimal treats whitespace-only as blank; at
    # level none they are preserved, but they are never the SEMANTIC payload of a file read)
    nonblank = [ln for ln in lines if ln.strip()]
    empty = not text.strip()
    nb_joined = "\n".join(nonblank).encode("utf-8")
    return {
        "outcome": "empty" if empty else "text",
        "byte_count": len(n),
        "content_sha256": hashlib.sha256(n).hexdigest(),
        "nonblank_line_count": len(nonblank),
        "nonblank_sha256": hashlib.sha256(nb_joined).hexdigest(),
        "trailing_newline": n.endswith(b"\n"),
    }


def parse_raw(data: bytes) -> dict:
    """Project the RAW `cat FILE` output. `read` is an identity-class command, so RAW and RTK share
    the same projection shape; the equivalence predicate carries the fidelity requirement."""
    return _project(data)


def parse_rtk(data: bytes) -> dict:
    """Project the RTK `rtk read FILE` output (default level none -> identity of the file content)."""
    return _project(data)


def equivalence(raw: dict, rtk: dict) -> dict:
    """RAW<->RTK file-read fidelity: RTK must reproduce EVERY non-blank content line of RAW, unchanged
    and in order (retained_line_coverage == 1.0), must not empty a non-empty file (read.rs safety
    fallback), and must agree on the empty/text outcome. Blank-line runs and a trailing newline are
    non-semantic. A dropped, altered, reordered, fabricated, or truncated content line breaks
    equivalence."""
    mismatches = []
    if raw.get("outcome") != rtk.get("outcome"):
        mismatches.append("outcome")
    # content fidelity: identical ordered non-blank line sequence
    if raw.get("nonblank_sha256") != rtk.get("nonblank_sha256"):
        mismatches.append("content")
    # safety-fallback invariant: a non-empty RAW must not project to an empty RTK
    if (raw.get("nonblank_line_count") or 0) > 0 and (rtk.get("nonblank_line_count") or 0) == 0:
        mismatches.append("emptied_nonempty")
    coverage = 1.0 if raw.get("nonblank_sha256") == rtk.get("nonblank_sha256") else 0.0
    return {"equivalent": not mismatches, "mismatches": mismatches,
            "retained_line_coverage": coverage}
