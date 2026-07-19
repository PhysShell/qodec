#!/usr/bin/env python3
"""rtk-go-vet-oracle-v1: the Go `go vet` command-semantic oracle, defined FROM the pinned RTK
implementation (rtk-ai/rtk @5d32d07, src/cmds/go/go_cmd.rs: filter_go_vet), then validated. This is
a rtk_command_oracle (NOT a test-summary dialect): go vet has no pass/fail test counts. Case-scoped
to gin; one gin case does NOT establish family-level go::vet.

Source-grounded semantics -- EXACTLY what filter_go_vet preserves / drops / synthesizes:
  * an ISSUE line = a non-empty, non-`#`-prefixed line CONTAINING `.go:` (vet's file:line:col form).
  * DROPS: empty lines, `#`-prefixed package headers, and any line without `.go:`.
  * SYNTHESIZES: `Go vet: No issues found` when there are zero issue lines; otherwise a
    `Go vet: {N} issues` header (N = the FULL issue count) + a numbered list, each issue truncated to
    120 chars and CAPPED (with `… +K more issues`). The header count N is lossless even when the list
    is capped.
  * EXIT-AGNOSTIC on purpose: the filter never inspects the exit code, so a nonzero exit with no
    `.go:` line is projected as clean -- this oracle FAITHFULLY represents that (it does NOT invent an
    exit/severity/category/error-count field the filter drops). Qualification is RAW<->RTK fidelity,
    not a judgement of whether the filter is complete.
  * EMPTY output = CLEAN. A clean `go vet` emits NOTHING (exit 0, no issues). RTK's run_filtered
    token guard (core/runner.rs: "never emit more tokens than the command") then SUPPRESSES the
    synthetic `Go vet: No issues found` back to empty, so the real RTK clean stream is empty
    (observed: RAW 0 bytes <-> RTK 1 byte newline for gin, exit 0, deterministic across 3 reps).
    Whitespace-only output on BOTH sides therefore projects to clean/0-issues. If instead RTK is
    empty while RAW carries a `.go:` issue, the projections disagree (issues vs clean) and the
    mismatch is caught -- the token guard only empties RTK when RAW was already empty.

Three structurally distinct layers (never conflated): captured bytes -> execution binding ->
semantic projection. This module is the SEMANTIC PROJECTION + the RAW<->RTK equivalence predicate.
Allowed normalizations enumerated: ANSI, CRLF. Issue lines, issue count, and the clean/issues
outcome are semantic.
"""
from __future__ import annotations

import re

ORACLE_ID = "rtk-go-vet-oracle-v1"
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
RTK_SOURCE_FILE = "src/cmds/go/go_cmd.rs"
RTK_SOURCE_FUNCTION = "filter_go_vet"
_ISSUE_TRUNCATE = 120  # matches truncate(issue, 120) in filter_go_vet

_ANSI = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")
_RTK_NO_ISSUES = "Go vet: No issues found"
_RTK_HEADER = re.compile(r"Go vet:\s+(\d+)\s+issues")
_RTK_NUMBERED = re.compile(r"^\d+\.\s+(.*)$")
_RTK_MORE = re.compile(r"\+(\d+)\s+more issues")


def _strip_presentation(data: bytes) -> bytes:
    data = _ANSI.sub(b"", data)
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return data


def _proj(outcome, issue_count=0, issues=None, synthetic_no_issues=False,
          capped=False, truncated=False):
    return {"outcome": outcome, "issue_count": issue_count, "issues": list(issues or []),
            "synthetic_no_issues": synthetic_no_issues, "capped": capped, "truncated": truncated}


def _is_issue_line(line: str) -> bool:
    t = line.strip()
    return bool(t) and not t.startswith("#") and ".go:" in t


def parse_raw(data: bytes) -> dict:
    """Project the RAW `go vet` output through the filter_go_vet issue-line rule. Empty (a clean
    vet emits nothing) -> clean/0-issues."""
    text = _strip_presentation(data).decode("utf-8", "replace")
    truncated = "output truncated" in text.lower() or "✂" in text
    issues = [ln.strip() for ln in text.splitlines() if _is_issue_line(ln)]
    outcome = "issues" if issues else "clean"
    return _proj(outcome, issue_count=len(issues), issues=issues, truncated=truncated)


def parse_rtk(data: bytes) -> dict:
    """Project the RTK compact `Go vet: ...` form; EMPTY (token-guard-suppressed clean) -> clean."""
    text = _strip_presentation(data).decode("utf-8", "replace")
    truncated = "output truncated" in text.lower() or "✂" in text
    if not text.strip():
        # clean vet: the token guard suppressed the synthetic marker back to empty
        return _proj("clean", issue_count=0, issues=[], synthetic_no_issues=True, truncated=truncated)
    if _RTK_NO_ISSUES in text:
        return _proj("clean", issue_count=0, issues=[], synthetic_no_issues=True, truncated=truncated)
    m = _RTK_HEADER.search(text)
    if not m:
        return _proj("indeterminate", truncated=truncated)
    count = int(m.group(1))
    issues = [nm.group(1).strip() for ln in text.splitlines()
              for nm in (_RTK_NUMBERED.match(ln.strip()),) if nm]
    capped = bool(_RTK_MORE.search(text)) or len(issues) < count
    return _proj("issues", issue_count=count, issues=issues, capped=capped, truncated=truncated)


def _truncate(s: str) -> str:
    return s if len(s) <= _ISSUE_TRUNCATE else s[:_ISSUE_TRUNCATE]


def equivalence(raw: dict, rtk: dict) -> dict:
    """RAW<->RTK go-vet fidelity: same outcome + same FULL issue count; and every issue RTK actually
    displays must equal the corresponding RAW issue (truncated to 120) in order -- a dropped or
    altered displayed diagnostic breaks equivalence. When RTK capped the list, only the displayed
    prefix is compared (the header count already carried the full total)."""
    mismatches = []
    if raw.get("outcome") != rtk.get("outcome"):
        mismatches.append("outcome")
    if raw.get("issue_count") != rtk.get("issue_count"):
        mismatches.append("issue_count")
    raw_disp = [_truncate(x) for x in (raw.get("issues") or [])]
    rtk_disp = list(rtk.get("issues") or [])
    n = min(len(raw_disp), len(rtk_disp))
    if raw_disp[:n] != rtk_disp[:n]:
        mismatches.append("issues")
    # if RTK was NOT capped, it must display every issue RAW has
    if not rtk.get("capped") and rtk.get("outcome") == "issues" and len(rtk_disp) != len(raw_disp):
        mismatches.append("issue_display_count")
    return {"equivalent": not mismatches, "mismatches": mismatches}
