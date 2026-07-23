#!/usr/bin/env python3
"""rtk-jvm-test-summary-v1: the JVM (Gradle) test-summary RTK dialect, defined FROM the pinned RTK
implementation (rtk-ai/rtk @5d32d07, src/cmds/jvm/gradlew_cmd.rs: filter_test), then validated
against that filter's own real sample I/O. NOT inferred from one success fixture. Lucene builds with
Gradle, so this dialect grounds in the gradle branch (mvn_cmd.rs is a separate, unproven policy).

Source-grounded semantics (each rule maps to a line of the pinned filter_test):
  * BUILD status: `^BUILD (SUCCESSFUL|FAILED)` (BUILD_STATUS) is always kept -> process outcome.
  * Summary lines kept (SUMMARY_LINE): `\\d+ tests? completed`, `\\d+ tests? failed`,
    `There were failing tests`, `See the report at` -> the completed/failed COUNTS.
  * FAILED per-test lines kept (`FAILED$| FAILED `) -> the failing test identities; each opens a
    failure block whose exception class (java./kotlin.) + FIRST user-code stack frame are kept while
    org.junit/junit/java.lang.reflect/sun.reflect/org.gradle framework frames are dropped.
  * PASSED/SKIPPED per-test lines (` PASSED$| SKIPPED$`) are STRIPPED -- the gradle filter surfaces
    NO per-test passed enumeration, so this dialect is source-faithful and does NOT invent one.
  * Empty-guarantee: when nothing survives, `BUILD SUCCESSFUL` present -> synthetic
    `ok ✓ (no test output ...)`; else the trimmed raw. It NEVER manufactures a PASS.

Three structurally distinct layers (never conflated): captured bytes -> execution binding ->
semantic projection. This module is the SEMANTIC PROJECTION + the RAW<->RTK equivalence predicate.

Allowed normalizations (the ONLY presentation noise treated as non-semantic), enumerated: ANSI SGR
escapes, CR in CRLF, and the gradle elapsed duration (`BUILD ... in 1m 23s`). Counts, BUILD status,
failing ids, and terminal-summary presence are all semantic.
"""
from __future__ import annotations

import re

DIALECT_ID = "rtk-jvm-test-summary-v1"
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
RTK_SOURCE_FILE = "src/cmds/jvm/gradlew_cmd.rs"

# ---- pinned filter regexes (mirrored from gradlew_cmd.rs) ----
_BUILD_STATUS = re.compile(r"^BUILD (SUCCESSFUL|FAILED)")
_FAILED_LINE = re.compile(r"FAILED$| FAILED ")
_PASSED_SKIPPED = re.compile(r" PASSED$| SKIPPED$")
_COMPLETED = re.compile(r"(\d+) tests? completed")
_FAILED_COUNT = re.compile(r"(\d+) tests? failed")
_FAILING_TESTS_NOTE = re.compile(r"There were failing tests|See the report at")
# a FAILED per-test identity: strip a trailing " FAILED" (with optional surrounding text)
_FAILED_ID = re.compile(r"^(?P<id>.*?)\s+FAILED\s*$")
_SYNTHETIC_OK = "ok ✓ (no test output"

# ---- enumerated allowed (non-semantic) normalizations ----
_ANSI = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")
_BUILD_DUR = re.compile(rb"^(BUILD (?:SUCCESSFUL|FAILED)) in .*$", re.MULTILINE)


def _strip_presentation(data: bytes) -> bytes:
    """Remove ONLY enumerated presentation noise: ANSI escapes, CR of CRLF, and the BUILD duration
    tail. Everything else (BUILD status word, counts, ids) is preserved."""
    data = _ANSI.sub(b"", data)
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    data = _BUILD_DUR.sub(rb"\1 in <dur>", data)
    return data


def _proj(outcome, tests_completed=None, tests_failed=None, failing_ids=None,
          terminal_summary_present=False, truncated=False):
    return {"outcome": outcome, "tests_completed": tests_completed, "tests_failed": tests_failed,
            "failing_ids": sorted(failing_ids or []),
            "terminal_summary_present": terminal_summary_present, "truncated": truncated}


def _parse(text: str) -> dict:
    """Shared projection over decoded text. RAW and the RTK-filtered stream both project through this
    -- the RTK filter only removes lines this projection already ignores (PASSED/SKIPPED, framework
    frames, task noise), so the two projections must agree."""
    build_status = None
    completed = None
    failed_count = None
    failing_ids = set()
    failing_note = False
    truncated = "output truncated" in text.lower() or "✂" in text

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        m = _BUILD_STATUS.match(line)
        if m:
            build_status = m.group(1)
            continue
        cm = _COMPLETED.search(line)
        if cm:
            completed = int(cm.group(1))
        fm = _FAILED_COUNT.search(line)
        if fm:
            failed_count = int(fm.group(1))
        if _FAILING_TESTS_NOTE.search(line):
            failing_note = True
        # PASSED/SKIPPED are non-semantic (stripped by the filter) -> ignore
        if _PASSED_SKIPPED.search(line):
            continue
        if _FAILED_LINE.search(line):
            idm = _FAILED_ID.match(line.strip())
            if idm:
                failing_ids.add(idm.group("id").strip())

    # source-faithful: tests_failed prefers the explicit summary count, else the failing-id count
    tests_failed = failed_count if failed_count is not None else (len(failing_ids) or None)
    if failed_count is None and failing_ids:
        tests_failed = len(failing_ids)

    # outcome: BUILD status is authoritative; else derive from failures / completion
    if _SYNTHETIC_OK in text:
        outcome = "success"
    elif build_status == "FAILED":
        outcome = "failure"
    elif (tests_failed or 0) > 0 or failing_note or failing_ids:
        outcome = "failure"
    elif build_status == "SUCCESSFUL":
        outcome = "success"
    elif completed is not None:
        outcome = "success"
    else:
        outcome = "indeterminate"

    terminal = (build_status is not None or completed is not None or failing_note
                or _SYNTHETIC_OK in text)
    return _proj(outcome, tests_completed=completed, tests_failed=(tests_failed or 0),
                 failing_ids=failing_ids, terminal_summary_present=terminal, truncated=truncated)


def parse_raw(data: bytes) -> dict:
    return _parse(_strip_presentation(data).decode("utf-8", "replace"))


def parse_rtk(data: bytes) -> dict:
    return _parse(_strip_presentation(data).decode("utf-8", "replace"))


_EQUIV_KEYS = ("outcome", "tests_completed", "tests_failed", "failing_ids",
               "terminal_summary_present")


def equivalence(raw: dict, rtk: dict) -> dict:
    """RAW<->RTK semantic equivalence: the projections must agree on outcome, counts, failing ids,
    and terminal-summary presence. Presentation (PASSED/SKIPPED lines, framework frames, task noise,
    duration) is not compared."""
    mismatches = [k for k in _EQUIV_KEYS if raw.get(k) != rtk.get(k)]
    return {"equivalent": not mismatches, "mismatches": mismatches}
