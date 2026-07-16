#!/usr/bin/env python3
"""N2-D1b Stage 2: Gradle build-duration canonicalizer for repo-helm-values's
raw Gradle stdout.

Independent of gradle_canonicalizer.py (v1, repo-spotless's historical
grammar) and gradle_canonicalizer_v2.py (repo-moshi's Stage 1 grammar) --
NOT a broadening of either, and neither of those two modules is imported,
modified, or referenced by applicable_case_ids here. repo-helm-values is
Gradle 9.5.0 (tag v9.5.0, commit 3fe117d68f3907790f3809f121aa36303a9151f8);
its platforms/core-runtime/time/src/main/java/org/gradle/internal/time/
TimeFormatting.java is independently confirmed BYTE-FOR-BYTE IDENTICAL to
v9.5.1's (repo-moshi's version) -- see
gradle-capture-canonicalization-policy-helm-values-v1.json's
gradle_source_derivation for the full diff-confirmed citation. Because the
formatter semantics are identical, this module's grammar is the same closed
production set as gradle_canonicalizer_v2.py's -- reimplemented here
independently (not imported) with its own rule name, policy type, and
applicable_case_ids gate, per this task's explicit requirement that the
selected replacement case have its own policy identity, never sharing or
broadening repo-moshi's.
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

# --- Rule: Gradle build-completion banner's wall-clock duration -------------
_PREFIX = "BUILD SUCCESSFUL in "
_TRIGGER = "BUILD SUCCESSFUL in"

_HOUR = r"[1-9]\d*"
_MINSEC = r"[1-9]|[1-5][0-9]"
_MS = r"0|[1-9]\d{0,2}"

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


RULE_GRADLE_BUILD_DURATION_HELM_VALUES_V1 = Rule(
    name="gradle_build_duration_helm_values_v1",
    trigger=_TRIGGER,
    pattern=_PATTERN,
    placeholder="<ELAPSED>",
    apply=_apply_rule,
)

RULES: list[Rule] = [RULE_GRADLE_BUILD_DURATION_HELM_VALUES_V1]


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
        "report_type": "n2d1b-gradle-canonicalization-report-helm-values-v1",
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

    if body.get("policy_type") != "n2d1b-gradle-capture-canonicalization-policy-helm-values-v1":
        raise PolicyIntegrityError(
            f"{policy_path}: policy_type {body.get('policy_type')!r} is not the expected "
            "'n2d1b-gradle-capture-canonicalization-policy-helm-values-v1'"
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
            f"gradle_canonicalizer_helm_values_v1.RULES {sorted(code_rule_names)} -- policy and code have drifted"
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
                "actual gradle_canonicalizer_helm_values_v1.py rule it is supposed to document"
            )

    if not body.get("applicable_case_ids"):
        raise PolicyIntegrityError(f"{policy_path}: applicable_case_ids is empty or missing")
    if body["applicable_case_ids"] != ["repo-helm-values"]:
        raise PolicyIntegrityError(
            f"{policy_path}: applicable_case_ids {body['applicable_case_ids']} is not exactly "
            "['repo-helm-values'] -- this policy is not authorized for any other case"
        )

    return body
