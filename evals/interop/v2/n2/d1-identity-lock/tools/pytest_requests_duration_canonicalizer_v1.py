#!/usr/bin/env python3
"""N2-D1b: pytest final-summary-duration canonicalizer v1, for repo-requests'
raw pytest stdout.

D1b-authorized (2026-07-17) after real CI evidence (focused diagnostic
probe run 29549403465, commit c75c60d, artifacts n2d1b-pilot-repo-requests-
capture-a/-b) showed the first ever genuinely successful repo-requests
capture pair (`619 passed, 15 skipped, 1 xfailed, 18 warnings`, exit_code 0,
zero failed, zero errors on both sides) differ in EXACTLY one line -- the
pytest final summary's own wall-clock duration ("78.47s" vs "78.71s") --
and nowhere else (independently confirmed: 68 lines each, only line 66
differs; every other receipt semantic field, including sanitized_stdout_
sha256, is identical between the two captures).

This is a SEPARATE, NEW policy identity from the retired pytest_requests_
canonicalizer.py (v1, rejected -- see pytest-requests-canonicalization-v1-
rejection-record.json): that module was derived from run 29544801640's
INVALID, error-heavy bytes (30 failed, 205 errors) and its three rules
(object-repr address, session-summary duration, threading.Thread native
ident) existed mainly to canonicalize repeated traceback material those
205 fixture errors produced. This module is built from a genuinely
successful capture pair and canonicalizes ONLY the duration -- no object-
address or thread-ident rule is carried forward (the D1b decision record's
explicit prohibition); if a future run shows any other raw difference,
that must stop and be reported, never silently absorbed into this policy.

The duration grammar is derived directly from the real, installed
_pytest/terminal.py (pytest 9.1.1) source, not guessed:

    def format_session_duration(seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.2f}s"
        else:
            dt = datetime.timedelta(seconds=int(seconds))
            return f"{seconds:.2f}s ({dt})"

`str(timedelta(seconds=N))` for N < 86400 (one day) renders exactly
"H:MM:SS" (H unbounded/unpadded, MM and SS always exactly two digits --
Python's own timedelta.__str__). The >=1-day "D day(s), H:MM:SS" form is
excluded: never observed for this test suite, and any occurrence must fail
closed here, not be guessed at.

Does NOT reuse maven_canonicalizer.py's per-line `Rule.trigger` (single
substring pre-check) convention: a plain " in " substring also appears
inside repo-requests' own DeprecationWarning text (real evidence: 4 such
lines in the captured stdout), which would incorrectly be flagged as a
malformed summary line if a bare substring were the only gate. Instead,
`_is_candidate_line` requires a line to BOTH start and end with pytest's
own "=" padding AND contain " in " -- a combination only pytest's own
final summary-stats line ever has (the other two "="-decorated separator
lines, "test session starts" and "warnings summary", contain no " in ").
"""
from __future__ import annotations

import re
from pathlib import Path

from maven_canonicalizer import (  # noqa: F401 -- re-exported for callers
    CanonicalizerError,
    PolicyIntegrityError,
    _sha256,
    _split_line_ending,
)

RULE_NAME = "pytest_final_summary_duration"
PLACEHOLDER = "<DURATION>"

_DURATION_RE = r"\d+\.\d{2}s(?: \(\d+:\d{2}:\d{2}\))?"
_LINE_RE = re.compile(
    r"^(?P<lead>=+) (?P<prefix>.+) in (?P<duration>" + _DURATION_RE + r"|" + re.escape(PLACEHOLDER)
    + r") (?P<trail>=+)$"
)


def _is_candidate_line(line: str) -> bool:
    return line.startswith("=") and line.endswith("=") and " in " in line


def canonicalize_stream(raw_bytes: bytes) -> tuple[bytes, dict]:
    """Returns (canonicalized_bytes, report). Raises CanonicalizerError if
    `raw_bytes` is not valid UTF-8, or if a line structurally looks like
    pytest's own final summary line (starts and ends with "=", contains
    " in ") but its duration does not conform to the exactly-derived
    grammar above."""
    try:
        text = raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        raise CanonicalizerError(f"input is not valid UTF-8: {e}") from e

    lines = text.splitlines(keepends=True)
    replacements: list[dict] = []
    match_count = 0
    out_lines: list[str] = []

    for line_number, line in enumerate(lines, start=1):
        content, ending = _split_line_ending(line)
        if _is_candidate_line(content):
            m = _LINE_RE.match(content)
            if not m:
                raise CanonicalizerError(
                    f"line {line_number}: looks like pytest's final summary line (starts/ends "
                    f"with '=', contains ' in ') but does not match the anchored expected "
                    f"grammar: {content!r}"
                )
            match_count += 1
            replaced = f"{m.group('lead')} {m.group('prefix')} in {PLACEHOLDER} {m.group('trail')}"
            if replaced != content:
                replacements.append({
                    "rule_name": RULE_NAME,
                    "line_number": line_number,
                    "before_line_sha256": _sha256(content.encode("utf-8")),
                    "after_line_sha256": _sha256(replaced.encode("utf-8")),
                })
            content = replaced
        out_lines.append(content + ending)

    canonical_text = "".join(out_lines)
    canonical_bytes = canonical_text.encode("utf-8")
    report = {
        "report_type": "n2d1b-pytest-requests-duration-canonicalization-report-v1",
        "line_count_in": len(lines),
        "line_count_out": len(out_lines),
        "trailing_newline_preserved": raw_bytes.endswith(b"\n") == canonical_bytes.endswith(b"\n"),
        "rule_match_counts": {RULE_NAME: match_count},
        "replacement_count": len(replacements),
        "replacements": replacements,
    }
    return canonical_bytes, report


def load_and_verify_policy(policy_path: Path) -> dict:
    """Loads pytest-requests-duration-capture-canonicalization-policy-v1.json
    and verifies it against the ACTUAL running code before returning it --
    never merely trusts the `policy_sha256` field embedded in the file
    itself. Raises PolicyIntegrityError (fail closed) if the file's own
    self-hash does not verify, its documented rule does not match this
    module's own RULE_NAME/regex/placeholder, or `applicable_case_ids` is
    empty or missing."""
    import hashlib
    import json

    body = json.loads(policy_path.read_text())
    if "policy_sha256" not in body:
        raise PolicyIntegrityError(f"{policy_path}: missing policy_sha256 -- not a self-hash-locked policy record")
    recorded = body["policy_sha256"]
    without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
    canonical_text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
    recomputed = hashlib.sha256(canonical_text.encode("utf-8")).hexdigest()
    if recomputed != recorded:
        raise PolicyIntegrityError(
            f"{policy_path}: policy_sha256 {recorded} does not match recomputed {recomputed} "
            "-- refusing to trust a tampered or corrupted canonicalization policy"
        )
    if not body.get("applicable_case_ids"):
        raise PolicyIntegrityError(f"{policy_path}: applicable_case_ids is empty or missing")

    documented_rules = {r["rule_name"]: r for r in body.get("rules", [])}
    if set(documented_rules) != {RULE_NAME}:
        raise PolicyIntegrityError(
            f"{policy_path}: documented rule set {sorted(documented_rules)} does not match "
            f"the code's own {{{RULE_NAME!r}}} -- policy and code have drifted"
        )
    documented = documented_rules[RULE_NAME]
    if (
        documented["anchored_regex"] != _LINE_RE.pattern
        or documented["placeholder"] != PLACEHOLDER
    ):
        raise PolicyIntegrityError(
            f"{policy_path}: rule {RULE_NAME!r} in the policy file does not match the actual "
            "pytest_requests_duration_canonicalizer_v1.py rule it is supposed to document"
        )
    return body
