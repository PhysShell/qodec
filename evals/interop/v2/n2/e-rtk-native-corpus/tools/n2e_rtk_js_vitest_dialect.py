#!/usr/bin/env python3
"""rtk-js-vitest-summary-v1: the JS/TS (vitest) test-summary RTK dialect, defined FROM the pinned RTK
implementation (rtk-ai/rtk @5d32d07, src/cmds/js/vitest_cmd.rs), then validated against that parser's
own real sample I/O. NOT inferred from one success fixture. Vue builds with vitest (canon vitest-v1);
jest/tsc/eslint are separate, unproven policies. Case-scoped to vue.

Source-grounded semantics (each rule maps to a tier of the pinned VitestParser):
  * TIER 1 (JSON): a `{ ... "numTotalTests" ... "numPassedTests" ... "numFailedTests" ... }` object
    (vitest --reporter=json, injected by default) -> total / passed / failed; failing ids are the
    testResults[].assertionResults[] with status=="failed" (fullName).
  * TIER 2 (regex fallback): `Tests\\s+(?:(\\d+)\\s+failed\\s+\\|\\s+)?(\\d+)\\s+passed` -> failed
    (optional) + passed, total = passed + failed; failing ids are `[x]`/`FAIL` lines. Returns a
    result ONLY when total > 0.
  * TIER 3 (passthrough): neither tier parses -> no structured result; NEVER a manufactured PASS.

Three structurally distinct layers (never conflated): captured bytes -> execution binding ->
semantic projection. This module is the SEMANTIC PROJECTION + the RAW<->RTK equivalence predicate.

Allowed normalizations enumerated: ANSI SGR escapes (strip_ansi in the pinned source), CRLF, and the
`Duration <n>ms|s` line. Counts, pass/fail outcome, failing ids, and terminal-summary presence are
semantic.
"""
from __future__ import annotations

import json as _json
import re

DIALECT_ID = "rtk-js-vitest-summary-v1"
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
RTK_SOURCE_FILE = "src/cmds/js/vitest_cmd.rs"

_ANSI = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")
_DURATION = re.compile(rb"^\s*Duration\s+[\d.]+(?:ms|s)\s*$", re.MULTILINE)
# TIER 2 regex mirrored from extract_stats_regex
_TESTS_RE = re.compile(r"Tests\s+(?:(\d+)\s+failed\s+\|\s+)?(\d+)\s+passed")
# a JSON object carrying the vitest totals (tier 1). Non-greedy up to the closing brace of the object
_JSON_OBJ = re.compile(r"\{[^{}]*\"numTotalTests\"[^{}]*\}")
_JSON_NESTED = re.compile(r"\{.*\"numTotalTests\".*\}", re.DOTALL)


def _strip_presentation(data: bytes) -> bytes:
    data = _ANSI.sub(b"", data)
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    data = _DURATION.sub(b"Duration <dur>", data)
    return data


def _proj(outcome, total=None, passed=None, failed=None, failing_ids=None,
          tier=None, terminal_summary_present=False, truncated=False):
    return {"outcome": outcome, "total": total, "passed": passed, "failed": failed,
            "failing_ids": sorted(failing_ids or []), "tier": tier,
            "terminal_summary_present": terminal_summary_present, "truncated": truncated}


def _json_failing_ids(obj: dict) -> list:
    ids = []
    for tr in obj.get("testResults") or []:
        for ar in tr.get("assertionResults") or []:
            if ar.get("status") == "failed":
                ids.append(ar.get("fullName") or ar.get("title") or "<unnamed>")
    return ids


def _try_json(text: str):
    for rx in (_JSON_OBJ, _JSON_NESTED):
        for m in rx.finditer(text):
            try:
                obj = _json.loads(m.group(0))
            except Exception:  # noqa: BLE001
                continue
            if "numTotalTests" in obj:
                return obj
    return None


def _parse(text: str) -> dict:
    truncated = "output truncated" in text.lower() or "✂" in text
    # TIER 1: JSON
    obj = _try_json(text)
    if obj is not None:
        total = obj.get("numTotalTests")
        passed = obj.get("numPassedTests")
        failed = obj.get("numFailedTests")
        fids = _json_failing_ids(obj)
        outcome = "failure" if (failed or 0) > 0 else "success"
        return _proj(outcome, total=total, passed=passed, failed=failed, failing_ids=fids,
                     tier=1, terminal_summary_present=True, truncated=truncated)
    # TIER 2: regex fallback (only counts when total > 0)
    m = _TESTS_RE.search(text)
    if m:
        failed = int(m.group(1)) if m.group(1) else 0
        passed = int(m.group(2)) if m.group(2) else 0
        total = passed + failed
        if total > 0:
            fids = [ln.strip() for ln in text.splitlines() if "[x]" in ln or "FAIL" in ln]
            outcome = "failure" if failed > 0 else "success"
            return _proj(outcome, total=total, passed=passed, failed=failed, failing_ids=fids,
                         tier=2, terminal_summary_present=True, truncated=truncated)
    # TIER 3: passthrough -> no structured verdict
    return _proj("passthrough", tier=3, terminal_summary_present=False, truncated=truncated)


def parse_raw(data: bytes) -> dict:
    return _parse(_strip_presentation(data).decode("utf-8", "replace"))


def parse_rtk(data: bytes) -> dict:
    return _parse(_strip_presentation(data).decode("utf-8", "replace"))


# equivalence compares the semantic totals + outcome + failing count; the failing IDENTITIES may be
# rendered differently across tiers (JSON fullName vs a `[x]` line), so identity SET equality is
# required only when both sides parsed the same tier; across tiers the failed COUNT is authoritative.
_COUNT_KEYS = ("outcome", "total", "passed", "failed", "terminal_summary_present")


def equivalence(raw: dict, rtk: dict) -> dict:
    mismatches = [k for k in _COUNT_KEYS if raw.get(k) != rtk.get(k)]
    same_tier = raw.get("tier") == rtk.get("tier")
    if same_tier and raw.get("failing_ids") != rtk.get("failing_ids"):
        mismatches.append("failing_ids")
    elif not same_tier and len(raw.get("failing_ids") or []) != len(rtk.get("failing_ids") or []):
        # cross-tier: at least the number of failing identities must agree
        if (raw.get("failed") or 0) != (rtk.get("failed") or 0):
            mismatches.append("failing_count")
    return {"equivalent": not mismatches, "mismatches": mismatches, "same_tier": same_tier}
