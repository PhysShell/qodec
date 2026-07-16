#!/usr/bin/env python3
"""N2-D1b: Gradle build-duration canonicalizer v2, for repo-moshi's raw
Gradle stdout.

Independent of and NOT a silent upgrade of gradle_canonicalizer.py (v1),
which remains byte-for-byte historical evidence -- see
gradle-capture-canonicalization-policy.json (v1) vs
gradle-capture-canonicalization-policy-v2.json (v2) for the full
authorization trail of each.

v1's grammar (`(?:\\d+h )?(?:\\d+m )?\\d+s`) required a mandatory trailing
seconds component, because the only real evidence available at the time
(run 29474204715) was a "BUILD SUCCESSFUL in 1m 50s" / "1m 11s" pair. A
later real run produced "BUILD SUCCESSFUL in 2m" -- a genuine Gradle output
with a ZERO-valued (hence omitted) seconds component -- which v1's grammar
correctly rejected as unrecognized (fail-closed, not a bug) rather than
silently pass through or guess.

v2 replaces v1 (for repo-moshi only; v1's own files are untouched and
unused by any active capture/verification path) with the exact closed
grammar independently derived from Gradle 9.5.1's own duration formatter --
see gradle-capture-canonicalization-policy-v2.json's `gradle_source_derivation`
for the full citation (repository, tag, commit, file, method). The
grammar is NOT a generic "number plus time unit" pattern: it is the exact
production set TimeFormatting.formatDurationTerse(long) can emit --
hours (when present) are a positive integer with no upper bound; minutes
and seconds (when present) are always in [1, 59] (Gradle's own modulo
arithmetic against MILLIS_PER_HOUR/MILLIS_PER_MINUTE bounds them there, and
each is omitted -- never printed as "0m"/"0s" -- exactly when its own
computed value is zero); milliseconds (only when the whole elapsed time is
under 1000ms) are an integer in [0, 999]. "1000ms" can never be emitted by
the real formatter (1000ms hits the ">= 1 second" branch and prints "1s"
instead), so it is correctly unrepresentable here too.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from maven_canonicalizer import (  # noqa: F401 -- re-exported for callers
    CanonicalizerError,
    PolicyIntegrityError,
    Rule,
    _sha256,
    _split_line_ending,
)

# --- Rule: Gradle build-completion banner's wall-clock duration (v2) --------
_PREFIX = "BUILD SUCCESSFUL in "
# Deliberately looser than _PREFIX (no trailing space): a bare
# "BUILD SUCCESSFUL in" with nothing following it still must not silently
# pass through as an unrelated line -- it is exactly the kind of malformed/
# truncated banner this canonicalizer must fail closed on, not skip.
_TRIGGER = "BUILD SUCCESSFUL in"

# Hours: a positive integer, no leading zero, no upper bound (Gradle's own
# `elapsedTimeInMs / MILLIS_PER_HOUR` -- an unbounded integer division).
_HOUR = r"[1-9]\d*"
# Minutes and seconds: 1 through 59, no leading zero. Both are Gradle's own
# `(x % larger_unit) / smaller_unit`, an integer division that can never
# reach 60, and the source omits the component entirely (never prints "0m"
# or "0s") whenever that computed value is exactly zero -- so 0 is never a
# valid printed value for either, only 1-59.
_MINSEC = r"[1-9]|[1-5][0-9]"
# Milliseconds: 0 through 999, no leading zero (except the bare literal
# "0" itself). Only ever printed when the WHOLE elapsed time is < 1000ms
# (Gradle's `elapsedTimeInMs >= MILLIS_PER_SECOND` branch), so this is also
# never itself accompanied by an "s"/"m"/"h" component.
_MS = r"0|[1-9]\d{0,2}"

# The closed production set, matching TimeFormatting.formatDurationTerse's
# own branching exactly (see the policy's gradle_source_derivation for the
# line-by-line justification of each production):
#   Nh Nm Ns | Nh Nm | Nh Ns | Nh   (hours present; minutes/seconds each
#                                    independently optional -- not nested,
#                                    since Gradle's own code computes and
#                                    conditionally appends each separately)
#   Nm Ns | Nm                     (minutes present, no hours)
#   Ns                              (seconds only)
#   Nms                             (milliseconds only, elapsed < 1s)
#   <ELAPSED>                       (already-canonicalized placeholder, for
#                                    idempotence on a second pass)
_GRAMMAR = (
    rf"(?:{_HOUR})h(?: (?:{_MINSEC})m)?(?: (?:{_MINSEC})s)?"
    rf"|(?:{_MINSEC})m(?: (?:{_MINSEC})s)?"
    rf"|(?:{_MINSEC})s"
    rf"|(?:{_MS})ms"
    r"|<ELAPSED>"
)
_PATTERN = re.compile("^" + re.escape(_PREFIX) + "(" + _GRAMMAR + ")$")


def _apply_rule(m: "re.Match[str]") -> str:
    return _PREFIX + "<ELAPSED>"


RULE_GRADLE_BUILD_DURATION_V2 = Rule(
    name="gradle_build_duration_v2",
    trigger=_TRIGGER,
    pattern=_PATTERN,
    placeholder="<ELAPSED>",
    apply=_apply_rule,
)

# Only one rule -- a changed task count, a genuine BUILD FAILED, or a
# malformed/truncated banner must never be silently canonicalized away; the
# loop below fails closed on any line containing the trigger substring that
# doesn't match this exact anchored grammar.
RULES: list[Rule] = [RULE_GRADLE_BUILD_DURATION_V2]


def canonicalize_stream(raw_bytes: bytes) -> tuple[bytes, dict]:
    """Returns (canonicalized_bytes, report). Raises CanonicalizerError if
    `raw_bytes` is not valid UTF-8, or if any line contains the rule's
    trigger substring but does not conform to its anchored expected
    grammar."""
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
            if rule.trigger not in current:
                continue
            m = rule.pattern.match(current)
            if not m:
                raise CanonicalizerError(
                    f"line {line_number}: contains trigger {rule.trigger!r} for rule "
                    f"{rule.name!r} but does not match its anchored expected grammar: {current!r}"
                )
            rule_match_counts[rule.name] += 1
            replaced = rule.apply(m)
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
        "report_type": "n2d1b-gradle-canonicalization-report-v2",
        "canonicalizer_version": 2,
        "line_count_in": len(lines),
        "line_count_out": len(out_lines),
        "trailing_newline_preserved": raw_bytes.endswith(b"\n") == canonical_bytes.endswith(b"\n"),
        "rule_match_counts": rule_match_counts,
        "replacement_count": len(replacements),
        "replacements": replacements,
    }
    return canonical_bytes, report


def load_and_verify_policy(policy_path: Path) -> dict:
    """Same integrity discipline as gradle_canonicalizer.load_and_verify_policy
    (v1) and maven_canonicalizer's -- verified against THIS module's own
    RULES, never merely trusting the policy file's embedded hash. Also
    checks policy_type/policy_version are the v2 identities -- a v1 policy
    file (or a policy claiming to be neither v1 nor v2) must never be
    silently accepted here."""
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

    if body.get("policy_type") != "n2d1b-gradle-capture-canonicalization-policy-v2":
        raise PolicyIntegrityError(
            f"{policy_path}: policy_type {body.get('policy_type')!r} is not the expected "
            "'n2d1b-gradle-capture-canonicalization-policy-v2'"
        )
    if body.get("policy_version") != 2:
        raise PolicyIntegrityError(
            f"{policy_path}: policy_version {body.get('policy_version')!r} is not the expected 2"
        )

    documented_rules = {r["rule_name"]: r for r in body.get("rules", [])}
    code_rule_names = {rule.name for rule in RULES}
    if set(documented_rules) != code_rule_names:
        raise PolicyIntegrityError(
            f"{policy_path}: documented rule set {sorted(documented_rules)} does not match "
            f"gradle_canonicalizer_v2.RULES {sorted(code_rule_names)} -- policy and code have drifted"
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
                "actual gradle_canonicalizer_v2.py rule it is supposed to document"
            )

    if not body.get("applicable_case_ids"):
        raise PolicyIntegrityError(f"{policy_path}: applicable_case_ids is empty or missing")
    if body["applicable_case_ids"] != ["repo-moshi"]:
        raise PolicyIntegrityError(
            f"{policy_path}: applicable_case_ids {body['applicable_case_ids']} is not exactly "
            "['repo-moshi'] -- v2 is not authorized for any other case"
        )

    return body
