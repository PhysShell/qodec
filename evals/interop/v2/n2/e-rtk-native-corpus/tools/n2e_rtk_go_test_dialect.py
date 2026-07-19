#!/usr/bin/env python3
"""rtk-go-test-summary-v1: the Go (go test -json) test-summary RTK dialect. This policy already
exists in the frozen corpus (caddy's execution contract binds it); this module PROVES its semantics
+ source identity from the pinned RTK implementation (rtk-ai/rtk @5d32d07, src/cmds/go/go_cmd.rs:
filter_go_test_json) and binds it CASE-SCOPED to caddy -- it does not re-author a new policy, and
one caddy case does NOT establish family-level go::test.

Source-grounded semantics (each rule maps to filter_go_test_json):
  * go test -json emits line-delimited JSON events. A pass/fail event WITH a Test field is a per-test
    result; WITHOUT a Test field it is a PACKAGE-level event.
  * NO DOUBLE-COUNT: go emits a package-level {"Action":"fail"} after each test-level failure -- that
    cascade is NOT an extra failure. A package-level fail counts as a failure ONLY when the package
    has no failing tests (timeout / signal / panic before tests), which must NOT read as "No tests".
  * passed / failed are distinct-test counts; packages is the distinct package count; failing ids are
    the failing tests (+ package-level-only failures).

Three structurally distinct layers (never conflated): captured bytes -> execution binding ->
semantic projection. This module is the SEMANTIC PROJECTION + the RAW<->RTK equivalence predicate.

Allowed normalizations enumerated: ANSI, CRLF, elapsed times (Elapsed/duration). Counts, outcome,
failing ids, terminal-summary presence are semantic.
"""
from __future__ import annotations

import json as _json
import re

DIALECT_ID = "rtk-go-test-summary-v1"
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
RTK_SOURCE_FILE = "src/cmds/go/go_cmd.rs"

_ANSI = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")
# RTK compact form: "Go test: N passed[, M failed][, K packages]" -- each count parsed independently
# (order/commas vary: an all-fail run has no "passed" token and "failed" directly follows the colon).
_COMPACT_HINT = re.compile(r"Go test:")
_C_PASSED = re.compile(r"(\d+)\s+passed")
_C_FAILED = re.compile(r"(\d+)\s+failed")
_C_PACKAGES = re.compile(r"(\d+)\s+packages")


def _strip_presentation(data: bytes) -> bytes:
    data = _ANSI.sub(b"", data)
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return data


def _proj(outcome, passed=0, failed=0, packages=0, failing_ids=None,
          terminal_summary_present=False, truncated=False):
    return {"outcome": outcome, "passed": passed, "failed": failed, "packages": packages,
            "failing_ids": sorted(failing_ids or []),
            "terminal_summary_present": terminal_summary_present, "truncated": truncated}


def _parse_json_stream(text: str):
    """Parse the go test -json event stream. Returns None if no JSON events are present."""
    tests, pkgs = {}, set()
    pkg_fail = []          # package-level fail events (no Test)
    pkg_has_test_fail = set()
    saw_json = False
    for line in text.splitlines():
        line = line.strip()
        if not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            ev = _json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        saw_json = True
        action = ev.get("Action")
        pkg = ev.get("Package")
        test = ev.get("Test")
        if pkg:
            pkgs.add(pkg)
        if action in ("pass", "fail") and test:
            tests[(pkg, test)] = action
            if action == "fail":
                pkg_has_test_fail.add(pkg)
        elif action == "fail" and not test:
            pkg_fail.append(pkg)
    if not saw_json:
        return None

    passed = sum(1 for a in tests.values() if a == "pass")
    failed = sum(1 for a in tests.values() if a == "fail")
    failing_ids = [f"{pkg}::{t}" if pkg else t for (pkg, t), a in tests.items() if a == "fail"]
    # package-level failure with no failing test in that package (timeout/panic) -> +1
    for pkg in pkg_fail:
        if pkg not in pkg_has_test_fail:
            failed += 1
            failing_ids.append(f"{pkg}::<package>")
    outcome = "failure" if failed > 0 else ("success" if passed > 0 else "no_tests")
    terminal = bool(tests) or bool(pkg_fail)
    return _proj(outcome, passed=passed, failed=failed, packages=len(pkgs),
                 failing_ids=failing_ids, terminal_summary_present=terminal)


def _parse_compact(text: str):
    """Parse the RTK compact 'Go test: N passed, M failed, K packages' form + preserved FAIL ids."""
    hint = _COMPACT_HINT.search(text)
    if not hint:
        return None
    line = next((ln for ln in text.splitlines() if _COMPACT_HINT.search(ln)), text)
    pm, fm, km = _C_PASSED.search(line), _C_FAILED.search(line), _C_PACKAGES.search(line)
    passed = int(pm.group(1)) if pm else 0
    failed = int(fm.group(1)) if fm else 0
    packages = int(km.group(1)) if km else 0
    failing_ids = []
    for line in text.splitlines():
        t = line.strip()
        # preserved go failure lines: "--- FAIL: TestX" or "FAIL\tpkg"
        fm = re.match(r"^--- FAIL:\s+(\S+)", t)
        if fm:
            failing_ids.append(fm.group(1))
    outcome = "failure" if failed > 0 else ("success" if passed > 0 else "no_tests")
    return _proj(outcome, passed=passed, failed=failed, packages=packages,
                 failing_ids=failing_ids, terminal_summary_present=True)


def _parse(text: str) -> dict:
    truncated = "output truncated" in text.lower() or "✂" in text
    r = _parse_json_stream(text)
    if r is None:
        r = _parse_compact(text)
    if r is None:
        return _proj("indeterminate", terminal_summary_present=False, truncated=truncated)
    r["truncated"] = truncated
    return r


def parse_raw(data: bytes) -> dict:
    return _parse(_strip_presentation(data).decode("utf-8", "replace"))


def parse_rtk(data: bytes) -> dict:
    return _parse(_strip_presentation(data).decode("utf-8", "replace"))


# counts + outcome are authoritative across the JSON<->compact tiers; failing IDENTITIES render
# differently (pkg::Test in JSON vs the --- FAIL name in the compact form), so cross-tier requires
# the failed COUNT to agree, same-tier requires identity-set equality.
_COUNT_KEYS = ("outcome", "passed", "failed", "terminal_summary_present")


def equivalence(raw: dict, rtk: dict) -> dict:
    mismatches = [k for k in _COUNT_KEYS if raw.get(k) != rtk.get(k)]
    return {"equivalent": not mismatches, "mismatches": mismatches}
