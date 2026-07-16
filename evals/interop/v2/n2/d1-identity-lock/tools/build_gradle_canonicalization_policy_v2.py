#!/usr/bin/env python3
"""Builds the immutable, self-hash-locked
gradle-capture-canonicalization-policy-v2.json.

N2-D1b Stage 1 reacceptance (2026-07-16): v1's grammar
(`(?:\\d+h )?(?:\\d+m )?\\d+s`) required a mandatory trailing seconds
component. A real Gradle build genuinely produced "BUILD SUCCESSFUL in 2m"
(a zero-valued, hence omitted, seconds component) -- v1 correctly rejected
this as unrecognized (fail-closed, not a bug), but it means Stage 1 cannot
be reaccepted on v1's grammar for any repo-moshi run whose build happens to
complete on an exact whole minute (or hour). v2 replaces v1 for repo-moshi
ONLY (v1's own files remain untouched, historical evidence -- see
gradle_canonicalizer.py / gradle-capture-canonicalization-policy.json) with
the exact closed grammar independently derived from Gradle 9.5.1's own
duration formatter -- see GRADLE_SOURCE_DERIVATION below for the full
citation. This builder only packages that same logic (implemented in
gradle_canonicalizer_v2.py, the single source of truth for the actual
regex/replacement logic) plus the evidence and policy metadata into one
durable, self-hash-locked record; it never hand-duplicates the regex text.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import gradle_canonicalizer_v2 as gcz2

OUT_PATH = Path(__file__).resolve().parents[1] / "gradle-capture-canonicalization-policy-v2.json"

APPROVING_DECISION_IDENTITY = "n2d1b-gradle-duration-grammar-v2-authorization-2026-07-16"

HISTORICAL_V1_POLICY_PATH = "evals/interop/v2/n2/d1-identity-lock/gradle-capture-canonicalization-policy.json"
HISTORICAL_V1_POLICY_SHA256 = "c968245e3837e2155873a8c8a3623bad9b2522ef163ee79cfbf2461eb8ef3b7c"

OBSERVED_UNSUPPORTED_V1_FORM = "BUILD SUCCESSFUL in 2m"

REASON_V1_SUPERSEDED = (
    "v1's anchored grammar `(?:\\d+h )?(?:\\d+m )?\\d+s` requires a mandatory "
    "trailing seconds component in every accepted form. A real repo-moshi "
    "Gradle build genuinely completed with a zero-valued (hence, per "
    "Gradle's own formatter, omitted) seconds component, producing the raw "
    f"line {OBSERVED_UNSUPPORTED_V1_FORM!r} -- v1 correctly rejected this "
    "as not matching its grammar (fail-closed, not a defect in v1's logic), "
    "but it means Stage 1 cannot be reaccepted against v1's grammar for any "
    "repo-moshi run whose real build duration happens to land on an exact "
    "whole minute or hour. v2 is not a loosening of v1's strictness -- it "
    "is the exact, independently-derived closed production set Gradle's "
    "own formatter can emit, no broader and no narrower."
)

# Independently derived (not assumed from any task prompt) by fetching the
# real Gradle source at the exact v9.5.1 tag and manually tracing
# formatDurationTerse's branches against every value in the required
# grammar's closed set -- see gradle_canonicalizer_v2.py's own module
# docstring and RULE comments for the full walkthrough.
GRADLE_SOURCE_DERIVATION = {
    "repository_url": "https://github.com/gradle/gradle",
    "tag": "v9.5.1",
    "commit_sha": "fd78213f09782e62ca4957f9cfd3d90c6c3f1767",
    "formatter_file": (
        "platforms/core-runtime/time/src/main/java/org/gradle/internal/time/TimeFormatting.java"
    ),
    "formatter_method": "TimeFormatting.formatDurationTerse(long elapsedTimeInMs)",
    "wrapper_file": (
        "platforms/core-runtime/logging/src/main/java/org/gradle/internal/logging/format/"
        "TersePrettyDurationFormatter.java"
    ),
    "wrapper_class": "TersePrettyDurationFormatter implements DurationFormatter",
    "caller_file": "subprojects/core/src/main/java/org/gradle/internal/buildevents/BuildLogger.java",
    "caller_class": "BuildResultLogger",
    "source_locator": (
        "formatDurationTerse's method body (constants MILLIS_PER_SECOND=1000, "
        "MILLIS_PER_MINUTE=60_000, MILLIS_PER_HOUR=3_600_000 declared near the "
        "top of the same class)"
    ),
    "grammar_derivation": (
        "formatDurationTerse builds its result left to right: (1) if "
        "elapsedTimeInMs >= MILLIS_PER_HOUR, appends "
        "`elapsedTimeInMs / MILLIS_PER_HOUR` + \"h \" -- an unbounded positive "
        "integer division, so hours has no upper bound and is only ever "
        "present (and only ever >= 1) when this branch fires; "
        "(2) if elapsedTimeInMs >= MILLIS_PER_MINUTE, computes "
        "`(elapsedTimeInMs % MILLIS_PER_HOUR) / MILLIS_PER_MINUTE` (bounded "
        "0-59 by the modulo) and appends it + \"m \" ONLY if that value is > 0 "
        "-- a zero-valued minutes component is silently omitted, never "
        "printed as \"0m\"; (3) if elapsedTimeInMs >= MILLIS_PER_SECOND, "
        "computes `(elapsedTimeInMs % MILLIS_PER_MINUTE) / 1000` (bounded "
        "0-59) and appends it + \"s\" ONLY if > 0, same omission rule; "
        "otherwise (elapsedTimeInMs < 1000) appends the raw millisecond "
        "value (0-999) + \"ms\". The final `.trim()` removes the single "
        "trailing space left when an hour and/or minute component was "
        "appended but the following optional component was omitted. Because "
        "steps (2) and (3) are independently gated (each only checks its OWN "
        "computed value, not whether the OTHER was printed), \"Nh Ns\" "
        "(hours present, minutes omitted because minutes computed to zero, "
        "seconds present) is a real, directly reachable production -- "
        "confirmed by manual trace: elapsedTimeInMs=3601000 (1h 0m 1s) "
        "yields exactly \"1h 1s\". \"1000ms\" can never be emitted: at "
        "elapsedTimeInMs=1000 the `>= MILLIS_PER_SECOND` branch fires "
        "instead, printing \"1s\", never the millisecond branch."
    ),
}

PROHIBITED_TRANSFORMATIONS = [
    "faking, freezing, or otherwise altering wall-clock time during the real build",
    "altering the frozen/authorized ./gradlew test execution argv",
    "trimming leading/trailing whitespace beyond the rule's own anchored match",
    "deduplicating lines",
    "removing lines",
    "reordering lines",
    "a generic 'number followed by seconds/minutes' replacement across arbitrary diagnostic lines",
    "accepting a generic number-plus-unit pattern broader than Gradle's own exact closed production set",
    "accepting ISO-8601 durations, decimal seconds, comma decimals, plural unit words, uppercase units, "
    "arbitrary whitespace, or any other unobserved future variant without separate D1b review",
    "replacing the actionable-tasks count, task names, or any other build output",
    "applying this rule to a case_id outside applicable_case_ids",
    "reusing the general-purpose canary sanitizer (sanitizer.sanitize) as the canonical-input transformer",
    "adding this rule to maven_canonicalizer.py/vstest_canonicalizer.py or gradle_canonicalizer.py (v1), "
    "or broadening any of their own scopes",
    "using this rule as a substitute for the deterministic scheduling profile -- it does not mask "
    "task-log ordering",
    "overwriting, renaming, reinterpreting, or silently upgrading gradle_canonicalizer.py (v1) or "
    "gradle-capture-canonicalization-policy.json (v1)",
    "making the historical v1 policy, module, or builder depend on any v2 code",
]

UTF8_AND_LINE_ENDING_POLICY = (
    "Input must be valid UTF-8 (strict decode); invalid UTF-8 is a hard "
    "failure, never a lossy replace. Line order, line count, and each "
    "line's own original line-ending sequence (or absence of one, for a "
    "final line with no trailing newline) are preserved exactly -- the "
    "canonicalizer only ever substitutes the rule-matched duration value "
    "within a line's own content, never its terminator. Only the duration "
    "payload after \"BUILD SUCCESSFUL in \" is ever replaced; task names, "
    "task ordering, task counts, the build result itself, and all other "
    "output remain byte-for-byte untouched."
)


def canonicalize_and_hash(body: dict) -> tuple[str, str]:
    text = json.dumps(body, indent=2, sort_keys=True) + "\n"
    return text, hashlib.sha256(text.encode()).hexdigest()


def build_policy() -> dict:
    rules = []
    for rule in gcz2.RULES:
        d = rule.to_policy_dict()
        d["evidence_justification"] = (
            "Independently derived from Gradle 9.5.1's own TimeFormatting.formatDurationTerse "
            "source (see gradle_source_derivation) -- not from any single observed capture pair. "
            f"The gap this closes was surfaced by a real, previously-unsupported raw line: "
            f"{OBSERVED_UNSUPPORTED_V1_FORM!r} (v1's grammar requires a mandatory seconds "
            "component that this line's build genuinely did not have)."
        )
        rules.append(d)

    body = {
        "policy_type": "n2d1b-gradle-capture-canonicalization-policy-v2",
        "policy_version": 2,
        "applicable_case_ids": ["repo-moshi"],
        "selected_source_stream": "stdout",
        "canonicalizer_module": "gradle_canonicalizer_v2.py",
        "rules": rules,
        "requires_deterministic_scheduling_profile": True,
        "gradle_source_derivation": GRADLE_SOURCE_DERIVATION,
        "reason_v1_superseded": REASON_V1_SUPERSEDED,
        "observed_unsupported_v1_form": OBSERVED_UNSUPPORTED_V1_FORM,
        "historical_gradle_policy_v1": {
            "path": HISTORICAL_V1_POLICY_PATH,
            "sha256": HISTORICAL_V1_POLICY_SHA256,
            "superseded": True,
        },
        "prohibited_transformations": PROHIBITED_TRANSFORMATIONS,
        "utf8_and_line_ending_policy": UTF8_AND_LINE_ENDING_POLICY,
        "approving_decision_identity": APPROVING_DECISION_IDENTITY,
        "scope_statement": (
            "This policy applies ONLY to the case_id(s) listed in "
            "applicable_case_ids (repo-moshi, and only repo-moshi). Any "
            "other case found to need additional canonicalization rules "
            "must stop for separate D1b review -- this policy is not "
            "extended silently, and is never merged with "
            "capture-canonicalization-policy.json (Maven), "
            "vstest-capture-canonicalization-policy.json (VSTest), or "
            "gradle-capture-canonicalization-policy.json (Gradle v1, "
            "historical, no longer used by any active capture/verification "
            "path)."
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
