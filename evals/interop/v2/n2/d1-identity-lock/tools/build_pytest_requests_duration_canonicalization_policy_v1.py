#!/usr/bin/env python3
"""Builds the immutable, self-hash-locked
pytest-requests-duration-capture-canonicalization-policy-v1.json.

N2-D1b Stage 2 remediation round 2 (2026-07-17): the first ever genuinely
successful repo-requests capture pair (focused diagnostic probe run
29549403465, commit c75c60d -- diagnostic only, not itself Stage 2
evidence) showed capture-a and capture-b differ in EXACTLY one line: the
pytest final summary's own wall-clock duration ("78.47s" vs "78.71s").
See pytest_requests_duration_canonicalizer_v1.py's own module docstring
for the full grammar derivation from the real, installed _pytest/
terminal.py (pytest 9.1.1) source.

This is a NEW, separate policy identity from the retired pytest_requests_
canonicalizer.py (v1, rejected -- built from run 29544801640's invalid,
error-heavy bytes; see pytest-requests-canonicalization-v1-rejection-
record.json). No object-address or thread-ident rule is carried forward.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest_requests_duration_canonicalizer_v1 as prdc

OUT_PATH = Path(__file__).resolve().parents[1] / "pytest-requests-duration-capture-canonicalization-policy-v1.json"

APPROVING_DECISION_IDENTITY = "n2d1b-repo-requests-duration-canonicalization-v1-authorization-2026-07-17"

PYTEST_SOURCE_DERIVATION = {
    "installed_package": "pytest",
    "installed_version": "9.1.1",
    "source_file": "_pytest/terminal.py",
    "function": "format_session_duration(seconds: float) -> str",
    "source_locator": (
        "if seconds < 60: return f'{seconds:.2f}s'; else: dt = datetime.timedelta("
        "seconds=int(seconds)); return f'{seconds:.2f}s ({dt})'. Called from "
        "TerminalReporter.summary_stats() as f' in {format_session_duration(...)}', "
        "appended after the comma-joined KNOWN_TYPES stat parts (built by "
        "build_summary_stats_line / _build_normal_summary_stats_line), the whole "
        "message then wrapped in '=' padding via TerminalWriter.sep()."
    ),
    "grammar_derivation": (
        "Two disjoint branches, both derived directly from the source above, never "
        "guessed: seconds < 60 -> '{seconds:.2f}s' (no parenthetical); seconds >= 60 -> "
        "'{seconds:.2f}s ({dt})' where dt = timedelta(seconds=int(seconds)) and "
        "str(timedelta(...)) for durations under one day renders exactly 'H:MM:SS' "
        "(H unbounded/unpadded, MM and SS always exactly two digits -- Python's own "
        "timedelta.__str__). The real observed pair ('78.47s (0:01:18)' vs "
        "'78.71s (0:01:18)') exercises the second branch. The >=1-day 'D day(s), "
        "H:MM:SS' form is excluded -- never observed for this test suite, and any "
        "occurrence must fail closed, not be guessed at."
    ),
}

PROHIBITED_TRANSFORMATIONS = [
    "faking, freezing, or otherwise altering wall-clock time during the real capture",
    "altering the frozen ['pytest'] execution argv",
    "canonicalizing the passed/skipped/xfailed/warnings (or any other KNOWN_TYPES) counts -- "
    "a difference there is a genuine outcome difference, never timing noise",
    "canonicalizing anything other than the exact duration token this rule's anchored regex "
    "matches -- the '=' padding length and every stat-count part are re-emitted verbatim, "
    "captured from the match groups, never hardcoded or reconstructed",
    "reviving, reusing, or importing any rule from the retired pytest_requests_canonicalizer.py "
    "(v1) -- especially its object-repr-address and thread-repr-ident rules, which must not be "
    "carried forward without separate D1b review of genuinely successful evidence exhibiting them",
    "applying this rule to a case_id outside applicable_case_ids",
    "reusing the general-purpose canary sanitizer (sanitizer.sanitize) as the canonical-input "
    "transformer",
    "importing, modifying, broadening, or depending on maven_canonicalizer.py, "
    "vstest_canonicalizer.py, gradle_canonicalizer.py (v1), gradle_canonicalizer_v2.py, "
    "gradle_canonicalizer_helm_values_v1.py, cargo_test_canonicalizer.py, or their policy files",
    "treating this policy's authorization as evidence that Stage 2 is accepted -- it documents "
    "a canonicalization rule only, not final acceptance",
]

UTF8_AND_LINE_ENDING_POLICY = (
    "Input must be valid UTF-8 (strict decode); invalid UTF-8 is a hard failure, never a lossy "
    "replace. Line order, line count, and each line's own original line-ending sequence (or "
    "absence of one, for a final line with no trailing newline) are preserved exactly. Only a "
    "line that BOTH starts and ends with '=' padding AND contains ' in ' is even considered a "
    "candidate (real evidence: a bare ' in ' substring also appears inside repo-requests' own "
    "DeprecationWarning text -- 4 such lines in the captured stdout -- and must never be "
    "flagged); a candidate line whose duration does not match the derived grammar raises, "
    "rather than silently passing through."
)


def canonicalize_and_hash(body: dict) -> tuple[str, str]:
    text = json.dumps(body, indent=2, sort_keys=True) + "\n"
    return text, hashlib.sha256(text.encode()).hexdigest()


def build_policy() -> dict:
    rule = {
        "rule_name": prdc.RULE_NAME,
        "trigger_substring": " in ",
        "anchored_regex": prdc._LINE_RE.pattern,
        "placeholder": prdc.PLACEHOLDER,
        "evidence_justification": (
            "Independently derived from pytest 9.1.1's own installed _pytest/terminal.py "
            "source -- see pytest_source_derivation."
        ),
    }
    body = {
        "policy_type": "n2d1b-pytest-requests-duration-capture-canonicalization-policy-v1",
        "policy_version": 1,
        "applicable_case_ids": ["repo-requests"],
        "selected_source_stream": "stdout",
        "canonicalizer_module": "pytest_requests_duration_canonicalizer_v1.py",
        "rules": [rule],
        "pytest_source_derivation": PYTEST_SOURCE_DERIVATION,
        "prohibited_transformations": PROHIBITED_TRANSFORMATIONS,
        "utf8_and_line_ending_policy": UTF8_AND_LINE_ENDING_POLICY,
        "approving_decision_identity": APPROVING_DECISION_IDENTITY,
        "derived_from_evidence": {
            "workflow_run_id": 29549403465,
            "note": (
                "Diagnostic-only focused probe (repo-requests only, disposable branch "
                "ci-probe/n2d1b-repo-requests-focused-c75c60d) -- the first genuinely "
                "successful repo-requests capture pair observed. This policy's own "
                "authorization is independent of and does not itself constitute Stage 2 "
                "acceptance evidence; a fresh full nine-case matrix run is still required."
            ),
        },
        "scope_statement": (
            "This policy applies ONLY to repo-requests. Any other case found to need "
            "additional canonicalization rules must stop for separate D1b review -- this "
            "policy is not extended silently, and is never merged with any other "
            "ecosystem's canonicalization policy file."
        ),
    }
    _, digest = canonicalize_and_hash(body)
    body["policy_sha256"] = digest
    return body


def main() -> int:
    body = build_policy()
    without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
    _, recomputed = canonicalize_and_hash(without_hash)
    assert recomputed == body["policy_sha256"], "self-hash did not verify stable"
    OUT_PATH.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT_PATH} (policy_sha256={body['policy_sha256']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
