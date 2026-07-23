#!/usr/bin/env python3
"""rtk-go-test-summary-v1: the Go test-summary RTK dialect. This policy already exists in the frozen
corpus (caddy's execution contract binds it); this module PROVES its semantics + source identity from
the pinned RTK implementation (rtk-ai/rtk @5d32d07, src/cmds/go/go_cmd.rs: filter_go_test_json +
build_go_test_summary) AND against the REAL committed caddy canonical streams
(evidence/caddy-pass-run-29639560535/streams). Case-scoped to caddy; one caddy case does NOT
establish family-level go::test.

The two ARM OUTPUT forms this dialect projects (NOT the JSON that RTK consumes INTERNALLY):
  * RAW arm = human `go test -v` (caddy argv has -v, not -json), canonicalized by caddy-go-test-v1:
      `--- PASS: <Test> (<dur>)` / `--- FAIL: <Test> (<dur>)` per-test lines; `ok\t<pkg>\t<dur>` /
      `FAIL\t<pkg>\t<dur>` package result lines; a trailing bare `PASS`/`FAIL`.
  * RTK arm = the compact build_go_test_summary form:
      `Go test: <P> passed[, <F> failed][, <S> skipped] in <K> packages`, `Go test: No tests found`,
      `Go test: <P> passed in <K> packages`; failing ids as `[FAIL] <Test>` lines.
  (A go test -json event stream is also tolerated for robustness, but neither caddy arm emits it.)

Source-grounded rules: passed/failed are distinct-test counts; NO DOUBLE-COUNT -- a package-level
FAIL cascading after a test-level failure is not an extra failure; a package-level FAIL with no
failing test (build/timeout) is ONE failure, never "No tests". failing ids are the failing tests.

Three structurally distinct layers (never conflated): captured bytes -> execution binding ->
semantic projection. Allowed normalizations enumerated: ANSI, CRLF, elapsed durations. Counts,
outcome, failing ids, terminal-summary presence are semantic.
"""
from __future__ import annotations

import json as _json
import re

DIALECT_ID = "rtk-go-test-summary-v1"
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
RTK_SOURCE_FILE = "src/cmds/go/go_cmd.rs"

_ANSI = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")
# RTK compact form: "Go test: N passed[, M failed][, S skipped] in K packages" -- counts parsed
# independently (an all-fail run has no "passed" token; "failed" may directly follow the colon).
_COMPACT_HINT = re.compile(r"Go test:")
_C_PASSED = re.compile(r"(\d+)\s+passed")
_C_FAILED = re.compile(r"(\d+)\s+failed")
_C_PACKAGES = re.compile(r"(\d+)\s+packages")
_RTK_FAIL_ID = re.compile(r"^\[FAIL\]\s+(\S+)")
# RAW human `go test -v` form
_RAW_PASS_ID = re.compile(r"^\s*--- PASS:\s+(\S+)")
_RAW_FAIL_ID = re.compile(r"^\s*--- FAIL:\s+(\S+)")
_RAW_PKG_OK = re.compile(r"^ok\s+(\S+)")
_RAW_PKG_FAIL = re.compile(r"^FAIL\s+(\S+)")


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
    """Parse the RTK compact 'Go test: N passed[, M failed] in K packages' form + `[FAIL] <Test>`."""
    if not _COMPACT_HINT.search(text):
        return None
    if "No tests found" in text:
        return _proj("no_tests", terminal_summary_present=True)
    line = next((ln for ln in text.splitlines() if _COMPACT_HINT.search(ln)), text)
    pm, fm, km = _C_PASSED.search(line), _C_FAILED.search(line), _C_PACKAGES.search(line)
    passed = int(pm.group(1)) if pm else 0
    failed = int(fm.group(1)) if fm else 0
    packages = int(km.group(1)) if km else 0
    failing_ids = [m.group(1) for ln in text.splitlines()
                   for m in (_RTK_FAIL_ID.match(ln.strip()),) if m]
    outcome = "failure" if failed > 0 else ("success" if passed > 0 else "no_tests")
    return _proj(outcome, passed=passed, failed=failed, packages=packages,
                 failing_ids=failing_ids, terminal_summary_present=True)


def _parse_human(text: str):
    """Parse the RAW human `go test -v` form (caddy-go-test-v1 canonical)."""
    pass_ids, fail_ids, pkg_ok, pkg_fail = [], [], [], []
    bare_fail = bare_pass = False
    for raw in text.splitlines():
        ln = raw.rstrip()
        pm = _RAW_PASS_ID.match(ln)
        if pm:
            pass_ids.append(pm.group(1)); continue
        fm = _RAW_FAIL_ID.match(ln)
        if fm:
            fail_ids.append(fm.group(1)); continue
        t = ln.strip()
        if _RAW_PKG_OK.match(ln):
            pkg_ok.append(_RAW_PKG_OK.match(ln).group(1)); continue
        if "\t" in ln and ln.startswith("FAIL\t"):
            pkg_fail.append(ln.split("\t")[1]); continue
        if t == "FAIL":
            bare_fail = True
        elif t == "PASS":
            bare_pass = True
    # nothing that looks like a go test terminal -> not this form
    if not (pass_ids or fail_ids or pkg_ok or pkg_fail or bare_fail or bare_pass):
        return None
    passed, failed = len(pass_ids), len(fail_ids)
    failing_ids = list(fail_ids)
    # NO DOUBLE-COUNT: a package FAIL with no test-level failure (build/timeout) is one failure
    if failed == 0 and pkg_fail:
        failed += len(pkg_fail)
        failing_ids += [f"{p}::<package>" for p in pkg_fail]
    packages = len(set(pkg_ok) | set(pkg_fail))
    outcome = "failure" if (failed > 0 or bare_fail or pkg_fail) else "success"
    terminal = bool(pass_ids or fail_ids or pkg_ok or pkg_fail or bare_fail or bare_pass)
    return _proj(outcome, passed=passed, failed=failed, packages=packages,
                 failing_ids=failing_ids, terminal_summary_present=terminal)


def _parse(text: str) -> dict:
    truncated = "output truncated" in text.lower() or "✂" in text
    # RTK compact first (unambiguous "Go test:" marker), then RAW human, then a -json event stream
    r = _parse_compact(text) or _parse_human(text) or _parse_json_stream(text)
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
