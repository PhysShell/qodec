#!/usr/bin/env python3
"""N2-D1b Stage 2: canonicalizer for repo-requests' raw pytest stdout.

Real CI evidence (Stage 2, fourth full run, after the editable-install
exposure fix let pytest actually run its full 635-item suite): capture-a and
capture-b produced IDENTICAL outcomes (byte-for-byte identical "30 failed,
384 passed, 15 skipped, 1 xfailed, 32 warnings, 205 errors" counts -- the
many ERRORs are pytest-httpbin's own local WSGI test server genuinely
failing to bind under this sandbox's permanent network denial, identically
and reproducibly on both sides, not something this task authorizes loosening
confinement for), differing ONLY in:

  1. CPython's own default object repr address (`<module.Class object at
     0x7f...>`, or a custom repr ending the same way, e.g. urllib3's
     `HTTPConnection(host=..., port=...) at 0x7f...`) -- pytest's own
     assertion-introspection machinery prints local-variable reprs at
     failure/error sites, and any live Python object's memory address varies
     run to run. 17 distinct real shapes were found in the actual captured
     pair (WSGIServer, HTTPConnectionPool, HTTPSConnectionPool, traceback,
     list_iterator, HTTPConnection, HTTPSConnection, HTTPAdapter, several
     test-class instances, and one exception-during-repr fallback case) --
     the arbitrary PREFIX before each "<...>" (pytest chooses which local
     variable to show) is never enumerable, so this rule is deliberately
     substring-scoped (not a Rule.pattern.match(whole_line) rule like every
     other canonicalizer in this codebase) to the closed, well-documented
     CPython convention that a default object repr always ends
     "... at 0x<lowercase hex digits>>" -- verified against the two real
     captures: every single occurrence of the substring " at 0x" (400 in
     each) was immediately followed by that exact closed grammar, with zero
     exceptions.
  2. pytest's own session-summary banner's trailing duration ("... in
     14.49s ="), independently derived from pytest's own source (tag
     v9.1.1, format_session_duration: `f"{seconds:.2f}s"` for the (here
     applicable) under-60-second case) -- same class of fix as Gradle's and
     cargo test's own build/test-duration canonicalization, never the
     passed/failed/skipped/xfailed/warnings/errors counts themselves, which
     remain a genuine outcome signal.
  3. `threading.Thread`'s own custom `__repr__` (used by urllib3/pytest-
     httpbin's background WSGI server threads), which prints the native
     thread ident as a large DECIMAL integer instead of a hex address --
     `<Server(Thread-N, stopped <ident>)>` / `<TLSServer(Thread-N, stopped
     <ident>)>` -- 25 distinct occurrences in the real captured pair,
     verified computationally: every single "Thread-" occurrence in both
     files (25 in each) matches the exact closed grammar
     `<(?:Server|TLSServer)\(Thread-\d+, stopped \d+\)>` with zero
     exceptions, and the Thread-N ordinals themselves (1-24, 26) are
     IDENTICAL between capture-a and capture-b -- only the raw thread
     ident varies, confirming this is the same class of nondeterminism as
     the object-repr address above, not a genuine outcome difference.

Deliberately NOT the general-purpose canary sanitizer (sanitizer.sanitize).
Never imports/modifies maven_canonicalizer.py, vstest_canonicalizer.py,
gradle_canonicalizer.py (v1), gradle_canonicalizer_v2.py,
gradle_canonicalizer_helm_values_v1.py, or cargo_test_canonicalizer.py --
reuses only their shared _sha256/_split_line_ending plumbing (this module's
own two rules do not fit maven_canonicalizer.Rule's "fully anchored
pattern.match(whole_line)" contract, so it defines its own, narrower
substring-scoped rule shape instead of stretching that contract to fit).
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from maven_canonicalizer import (  # noqa: F401 -- re-exported for callers
    CanonicalizerError,
    PolicyIntegrityError,
    _sha256,
    _split_line_ending,
)


@dataclass
class SubstringRule:
    """Unlike maven_canonicalizer.Rule (fully anchored ^...$ against the
    WHOLE line), this rule scopes to an exact, closed pattern that may
    appear anywhere within an otherwise-arbitrary line -- required here
    because pytest's own local-variable-repr prefix (which variable, at
    which failure site) is never enumerable. `detect` is a deliberately
    LOOSE regex used only to count candidate occurrences (never itself the
    replacement); if `detect`'s occurrence count differs from `pattern`'s
    (the strict, closed grammar) match count on the same line, that is a
    hard error -- some occurrence didn't conform to the expected grammar,
    never a silent partial replacement. `trigger` is a plain substring
    fast pre-check (avoids running `detect` against every line)."""

    name: str
    trigger: str
    detect: "re.Pattern[str]"
    pattern: "re.Pattern[str]"
    placeholder: str
    replacement: str

    def to_policy_dict(self) -> dict:
        return {
            "rule_name": self.name,
            "trigger_substring": self.trigger,
            "anchored_regex": self.pattern.pattern,
            "placeholder": self.placeholder,
        }


# --- Rule 1: any CPython default object repr's memory address -------------
# Trigger is deliberately narrow (" at 0x", the literal substring immediately
# preceding every real address observed) -- detect and pattern coincide here
# since the grammar itself (hex digits then '>') is already unambiguous; no
# separate loose/strict distinction is needed, unlike Rule 2 below.
_ADDR_TRIGGER = " at 0x"
_ADDR_PATTERN = re.compile(r"at 0x(?:[0-9a-f]+|ADDR)>")
_ADDR_PLACEHOLDER = "0xADDR"

RULE_OBJECT_REPR_ADDRESS = SubstringRule(
    name="python_object_repr_address",
    trigger=_ADDR_TRIGGER,
    detect=re.compile(re.escape(_ADDR_TRIGGER)),
    pattern=_ADDR_PATTERN,
    placeholder=_ADDR_PLACEHOLDER,
    replacement="at 0xADDR>",
)

# --- Rule 2: pytest's own session-summary trailing duration ---------------
# The literal substring "s =" is NOT a safe trigger on its own -- the
# session-open banner "===== test session starts =====" contains it too
# (the "s" of "starts" immediately followed by " ="), a real false positive
# caught while testing this rule against the actual captured pair. `detect`
# is deliberately loose (any "in <digits-and-dots>s =") so it never matches
# that banner (no digits there) while still catching any malformed/
# unexpected duration variant for the strict grammar to reject.
_DURATION_TRIGGER = "s ="
_DURATION_DETECT = re.compile(r"in [\d.]+s =")
_DURATION_PATTERN = re.compile(r"in (?:\d+\.\d{2}|ELAPSED)s =")
_DURATION_PLACEHOLDER = "ELAPSED"

RULE_SESSION_SUMMARY_DURATION = SubstringRule(
    name="pytest_session_summary_duration",
    trigger=_DURATION_TRIGGER,
    detect=_DURATION_DETECT,
    pattern=_DURATION_PATTERN,
    placeholder=_DURATION_PLACEHOLDER,
    replacement="in ELAPSEDs =",
)

# --- Rule 3: threading.Thread's own repr's decimal native thread ident ----
# Trigger is deliberately narrow (", stopped ", the literal substring
# immediately preceding every real ident observed) -- detect and pattern
# coincide here since the grammar itself (digits then ')>') is already
# unambiguous, same as Rule 1. The class name and "Thread-N" ordinal are
# preserved verbatim (captured via groups) since they are IDENTICAL between
# capture-a and capture-b -- only the raw native ident is masked.
_THREAD_TRIGGER = ", stopped "
_THREAD_DETECT = re.compile(re.escape(_THREAD_TRIGGER))
_THREAD_PATTERN = re.compile(r"<(Server|TLSServer)\((Thread-\d+), stopped (?:\d+|IDENT)\)>")
_THREAD_PLACEHOLDER = "IDENT"

RULE_THREAD_REPR_IDENT = SubstringRule(
    name="python_thread_repr_ident",
    trigger=_THREAD_TRIGGER,
    detect=_THREAD_DETECT,
    pattern=_THREAD_PATTERN,
    placeholder=_THREAD_PLACEHOLDER,
    replacement=r"<\1(\2, stopped IDENT)>",
)

RULES: list[SubstringRule] = [
    RULE_OBJECT_REPR_ADDRESS,
    RULE_SESSION_SUMMARY_DURATION,
    RULE_THREAD_REPR_IDENT,
]


def _apply_rule_to_line(rule: SubstringRule, current: str, line_number: int) -> tuple[str, int]:
    """Returns (new_line, match_count). Raises CanonicalizerError if the
    loose detect count doesn't match the strict pattern's match count --
    some occurrence didn't conform to the expected closed grammar."""
    if rule.trigger not in current:
        return current, 0
    detect_count = len(rule.detect.findall(current))
    if detect_count == 0:
        return current, 0
    matches = rule.pattern.findall(current)
    if len(matches) != detect_count:
        raise CanonicalizerError(
            f"line {line_number}: rule {rule.name!r} detected {detect_count} candidate "
            f"occurrence(s) via {rule.detect.pattern!r} but its anchored expected grammar "
            f"{rule.pattern.pattern!r} matched only {len(matches)} time(s) -- refusing a "
            f"partial/ambiguous replacement: {current!r}"
        )
    return rule.pattern.sub(rule.replacement, current), detect_count


def canonicalize_stream(raw_bytes: bytes) -> tuple[bytes, dict]:
    """Returns (canonicalized_bytes, report). Raises CanonicalizerError if
    `raw_bytes` is not valid UTF-8, or if any line contains a rule's trigger
    substring more times than its anchored expected grammar matches."""
    try:
        text = raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        raise CanonicalizerError(f"input is not valid UTF-8: {e}") from e

    lines = text.splitlines(keepends=True)
    replacements: list[dict] = []
    rule_match_counts = {rule.name: 0 for rule in RULES}
    out_lines: list[str] = []

    for line_number, line in enumerate(lines, start=1):
        content, ending = _split_line_ending(line)
        current = content
        for rule in RULES:
            replaced, count = _apply_rule_to_line(rule, current, line_number)
            if count:
                rule_match_counts[rule.name] += count
                if replaced != current:
                    replacements.append({
                        "rule_name": rule.name,
                        "line_number": line_number,
                        "before_line_sha256": _sha256(current.encode("utf-8")),
                        "after_line_sha256": _sha256(replaced.encode("utf-8")),
                    })
            current = replaced
        out_lines.append(current + ending)

    canonical_text = "".join(out_lines)
    canonical_bytes = canonical_text.encode("utf-8")
    report = {
        "report_type": "n2d1b-pytest-requests-canonicalization-report-v1",
        "canonicalizer_version": 1,
        "line_count_in": len(lines),
        "line_count_out": len(out_lines),
        "trailing_newline_preserved": raw_bytes.endswith(b"\n") == canonical_bytes.endswith(b"\n"),
        "rule_match_counts": rule_match_counts,
        "replacement_count": len(replacements),
        "replacements": replacements,
    }
    return canonical_bytes, report


def load_and_verify_policy(policy_path: Path) -> dict:
    """Same integrity discipline as gradle_canonicalizer_v2.load_and_verify_policy
    -- verified against THIS module's own RULES, never merely trusting the
    policy file's embedded hash."""
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

    if body.get("policy_type") != "n2d1b-pytest-requests-capture-canonicalization-policy-v1":
        raise PolicyIntegrityError(
            f"{policy_path}: policy_type {body.get('policy_type')!r} is not the expected "
            "'n2d1b-pytest-requests-capture-canonicalization-policy-v1'"
        )
    if body.get("policy_version") != 1:
        raise PolicyIntegrityError(
            f"{policy_path}: policy_version {body.get('policy_version')!r} is not the expected 1"
        )

    documented_rules = {r["rule_name"]: r for r in body.get("rules", [])}
    code_rule_names = {rule.name for rule in RULES}
    if set(documented_rules) != code_rule_names:
        raise PolicyIntegrityError(
            f"{policy_path}: documented rule set {sorted(documented_rules)} does not match "
            f"pytest_requests_canonicalizer.RULES {sorted(code_rule_names)} -- policy and code have drifted"
        )
    for rule in RULES:
        documented = documented_rules[rule.name]
        if (
            documented["anchored_regex"] != rule.pattern.pattern
            or documented["trigger_substring"] != rule.trigger
            or documented["placeholder"] != rule.placeholder
        ):
            raise PolicyIntegrityError(
                f"{policy_path}: rule {rule.name!r} in the policy file does not match the "
                "actual pytest_requests_canonicalizer.py rule it is supposed to document"
            )

    if body.get("applicable_case_ids") != ["repo-requests"]:
        raise PolicyIntegrityError(
            f"{policy_path}: applicable_case_ids {body.get('applicable_case_ids')} is not exactly "
            "['repo-requests'] -- this policy is not authorized for any other case"
        )

    return body
