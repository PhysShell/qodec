#!/usr/bin/env python3
"""Builds the immutable, self-hash-locked
gradle-capture-canonicalization-policy-helm-values-v1.json.

N2-D1b Stage 2: repo-helm-values (the deterministically selected jvm-gradle
repository-miner replacement for the permanently-rejected repo-spotless --
see stage2-replacement-selection-v1.json) runs Gradle 9.5.0 (tag v9.5.0,
commit 3fe117d68f3907790f3809f121aa36303a9151f8). Its
platforms/core-runtime/time/src/main/java/org/gradle/internal/time/
TimeFormatting.java was independently fetched and diffed byte-for-byte
against v9.5.1's (repo-moshi's own authorized version) and found IDENTICAL
-- see GRADLE_SOURCE_DERIVATION below. Per this task's explicit
requirement, an identical grammar does not license broadening or importing
repo-moshi's own case-scoped policy (gradle-capture-canonicalization-
policy-v2.json / gradle_canonicalizer_v2.py) -- this is a wholly separate
policy, module, and approval identity, scoped to repo-helm-values only.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import gradle_canonicalizer_helm_values_v1 as gcz_hv

OUT_PATH = Path(__file__).resolve().parents[1] / "gradle-capture-canonicalization-policy-helm-values-v1.json"

APPROVING_DECISION_IDENTITY = "n2d1b-stage2-gradle-duration-grammar-helm-values-v1-authorization-2026-07-16"

GRADLE_SOURCE_DERIVATION = {
    "repository_url": "https://github.com/gradle/gradle",
    "tag": "v9.5.0",
    "commit_sha": "3fe117d68f3907790f3809f121aa36303a9151f8",
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
    "cross_version_identity_check": (
        "platforms/core-runtime/time/.../TimeFormatting.java fetched at both "
        "v9.5.0 (commit 3fe117d68f3907790f3809f121aa36303a9151f8, repo-helm-"
        "values's actual pinned Gradle wrapper version per its gradle-wrapper."
        "properties distributionUrl=gradle-9.5.0-bin.zip) and v9.5.1 (commit "
        "fd78213f09782e62ca4957f9cfd3d90c6c3f1767, repo-moshi's authorized "
        "version) via independent raw fetches and diffed byte-for-byte -- "
        "IDENTICAL. This is the basis for reusing the same closed grammar "
        "while keeping the two cases' policy identities, modules, and "
        "approval records entirely separate, per this task's explicit "
        "requirement never to broaden or import repo-moshi's own case-"
        "scoped policy."
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
        "appended but the following optional component was omitted. \"1000ms\" "
        "can never be emitted: at elapsedTimeInMs=1000 the "
        "`>= MILLIS_PER_SECOND` branch fires instead, printing \"1s\", never "
        "the millisecond branch."
    ),
}

PROHIBITED_TRANSFORMATIONS = [
    "faking, freezing, or otherwise altering wall-clock time during the real build",
    "altering the frozen/authorized ./gradlew :helm-values-shared:test execution argv",
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
    "importing, modifying, broadening, or depending on gradle_canonicalizer.py (v1), "
    "gradle_canonicalizer_v2.py (repo-moshi), or their policy files",
    "using this rule as a substitute for the deterministic scheduling profile -- it does not mask "
    "task-log ordering",
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
    for rule in gcz_hv.RULES:
        d = rule.to_policy_dict()
        d["evidence_justification"] = (
            "Independently derived by fetching repo-helm-values's actual pinned "
            "Gradle wrapper version's own TimeFormatting.java source (v9.5.0) and "
            "confirming it is byte-for-byte identical to repo-moshi's already-"
            "authorized v9.5.1 version -- see gradle_source_derivation."
        )
        rules.append(d)

    body = {
        "policy_type": "n2d1b-gradle-capture-canonicalization-policy-helm-values-v1",
        "policy_version": 1,
        "applicable_case_ids": ["repo-helm-values"],
        "selected_source_stream": "stdout",
        "canonicalizer_module": "gradle_canonicalizer_helm_values_v1.py",
        "rules": rules,
        "requires_deterministic_scheduling_profile": True,
        "gradle_source_derivation": GRADLE_SOURCE_DERIVATION,
        "prohibited_transformations": PROHIBITED_TRANSFORMATIONS,
        "utf8_and_line_ending_policy": UTF8_AND_LINE_ENDING_POLICY,
        "approving_decision_identity": APPROVING_DECISION_IDENTITY,
        "scope_statement": (
            "This policy applies ONLY to the case_id(s) listed in "
            "applicable_case_ids (repo-helm-values, and only repo-helm-values). "
            "Any other case found to need additional canonicalization rules "
            "must stop for separate D1b review -- this policy is not extended "
            "silently, and is never merged with capture-canonicalization-"
            "policy.json (Maven), vstest-capture-canonicalization-policy.json "
            "(VSTest), gradle-capture-canonicalization-policy.json (Gradle v1, "
            "historical), or gradle-capture-canonicalization-policy-v2.json "
            "(repo-moshi)."
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
