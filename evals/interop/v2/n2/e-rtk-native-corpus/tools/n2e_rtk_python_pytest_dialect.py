#!/usr/bin/env python3
"""rtk-python-pytest-summary-v1: the Python (pytest) test-summary RTK dialect, defined FROM the pinned
RTK implementation (rtk-ai/rtk @5d32d07, src/cmds/python/pytest_cmd.rs: filter_pytest_output +
parse_summary_line + build_pytest_summary), then validated against that filter's own real sample I/O.
NOT inferred from one success fixture. Scrapy runs pytest (canon pytest-v1); ruff is a separate,
unproven policy. Case-scoped to scrapy.

Source-grounded semantics:
  * SUMMARY COUNTS from the pytest summary line, both `=== N passed, M failed, ... in T ===` and the
    quiet form `5 failed, 1698 passed, 2 skipped in 108.89s`. Word order matters: xpassed/xfailed
    contain passed/failed, so they are matched FIRST (mirrors parse_summary_line). Counts: passed,
    failed, skipped, xfailed, xpassed.
  * build_pytest_summary compact form is also parsed: `Pytest: N passed[, M failed[, K skipped ...]]`.
  * FAILING IDENTITIES from the `=== short test summary info ===` section: `FAILED <id> - <msg>` and
    `ERROR <id> ...` lines -> <id> (up to ` - `).
  * `no tests ran` / `collected 0 items` -> no_tests (NEVER a manufactured PASS).

Three structurally distinct layers (never conflated): captured bytes -> execution binding ->
semantic projection. This module is the SEMANTIC PROJECTION + the RAW<->RTK equivalence predicate.

Allowed normalizations enumerated: ANSI SGR, CRLF, and the trailing ` in <T>s` duration of the
summary line. Counts, outcome, failing ids, terminal-summary presence are semantic.
"""
from __future__ import annotations

import re

DIALECT_ID = "rtk-python-pytest-summary-v1"
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
RTK_SOURCE_FILE = "src/cmds/python/pytest_cmd.rs"

_ANSI = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")
_SUMMARY_DUR = re.compile(rb" in \d+(?:\.\d+)?s")
# a "<n> <word>" count token in a summary line
_COUNT_TOKEN = re.compile(r"(\d+)\s+(xpassed|xfailed|passed|failed|skipped|error|errors|deselected|warnings?)")
_SUMMARY_HINT = re.compile(r"(passed|failed|skipped|error|no tests ran)", re.IGNORECASE)
_FAILED_ID = re.compile(r"^(?:FAILED|ERROR)\s+(?P<id>\S+)")


def _strip_presentation(data: bytes) -> bytes:
    data = _ANSI.sub(b"", data)
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    data = _SUMMARY_DUR.sub(b" in <dur>", data)
    return data


def _proj(outcome, passed=0, failed=0, skipped=0, xfailed=0, xpassed=0, errors=0,
          failing_ids=None, terminal_summary_present=False, truncated=False):
    return {"outcome": outcome, "passed": passed, "failed": failed, "skipped": skipped,
            "xfailed": xfailed, "xpassed": xpassed, "errors": errors,
            "failing_ids": sorted(failing_ids or []),
            "terminal_summary_present": terminal_summary_present, "truncated": truncated}


def _summary_line(text: str):
    """Return the pytest summary line, if any: a `=== ... in <dur> ===` line, a bare quiet-mode count
    line, or the compact `Pytest: ...` form."""
    for line in text.splitlines():
        t = line.strip()
        if not t:
            continue
        if t.startswith("Pytest:"):
            return t
        if (t.startswith("===") and t.endswith("===") and _SUMMARY_HINT.search(t)):
            return t
        # quiet mode: a line that is only counts + ` in <dur>` (no leading FAILED/collected)
        if (_COUNT_TOKEN.search(t) and " in <dur>" in t
                and not t.startswith(("FAILED", "ERROR", "collected"))):
            return t
        if "no tests ran" in t:
            return t
    return None


def _parse(text: str) -> dict:
    truncated = "output truncated" in text.lower() or "✂" in text
    summary = _summary_line(text)
    failing_ids = []
    for line in text.splitlines():
        m = _FAILED_ID.match(line.strip())
        if m:
            failing_ids.append(m.group("id"))

    if summary is None:
        return _proj("indeterminate", failing_ids=failing_ids, terminal_summary_present=False,
                     truncated=truncated)
    if "no tests ran" in summary or "collected 0 items" in text:
        return _proj("no_tests", failing_ids=failing_ids, terminal_summary_present=True,
                     truncated=truncated)

    counts = {"passed": 0, "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0, "errors": 0}
    for n, word in _COUNT_TOKEN.findall(summary):
        n = int(n)
        if word == "xpassed":
            counts["xpassed"] = n
        elif word == "xfailed":
            counts["xfailed"] = n
        elif word == "passed":
            counts["passed"] = n
        elif word == "failed":
            counts["failed"] = n
        elif word == "skipped":
            counts["skipped"] = n
        elif word.startswith("error"):
            counts["errors"] = n

    outcome = ("failure" if (counts["failed"] > 0 or counts["errors"] > 0)
               else "success" if counts["passed"] > 0 or counts["skipped"] > 0 or counts["xfailed"] > 0
               else "no_tests")
    return _proj(outcome, failing_ids=failing_ids, terminal_summary_present=True,
                 truncated=truncated, **counts)


def parse_raw(data: bytes) -> dict:
    return _parse(_strip_presentation(data).decode("utf-8", "replace"))


def parse_rtk(data: bytes) -> dict:
    return _parse(_strip_presentation(data).decode("utf-8", "replace"))


_EQUIV_KEYS = ("outcome", "passed", "failed", "skipped", "xfailed", "xpassed", "errors",
               "failing_ids", "terminal_summary_present")


def equivalence(raw: dict, rtk: dict) -> dict:
    mismatches = [k for k in _EQUIV_KEYS if raw.get(k) != rtk.get(k)]
    return {"equivalent": not mismatches, "mismatches": mismatches}
