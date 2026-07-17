#!/usr/bin/env python3
"""N2-D1b Stage 2: Gradle-precedent-style canonicalizer for cargo test's own
build-completion line, shared by repo-rustlings and repo-dockerfile-parser-rs
(both invoke the identical frozen ["cargo", "test"] argv, and both run
against the same rustup-resolved "stable" toolchain -- unlike the Gradle
9.5.0/9.5.1 replacement scenario, there is no separate replacement-selection
identity here to keep isolated).

Real CI evidence (Stage 2, second full 9-case run, after the deterministic
RUST_TEST_THREADS=1 scheduling profile made every individual test-result
line byte-identical and same-order): the SOLE remaining raw difference
between capture-a and capture-b for both cases was libtest's own summary
line's trailing wall-clock duration, e.g.:

    test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.85s

Independently derived from Rust's own libtest source (tag v1.97.0, commit
2d8144b7880597b6e6d3dfd63a9a9efae3f533d3, matching this session's own
installed rustc 1.97.0):
  - library/test/src/formatters/pretty.rs's write_run_finish (identical
    logic in formatters/terse.rs) emits
    ". {passed} passed; {failed} failed; {ignored} ignored; {measured}
    measured; {filtered_out} filtered out", then, if state.exec_time is
    Some, appends "; finished in {exec_time}".
  - library/test/src/time.rs's TestSuiteExecTime Display impl formats the
    duration as `write!(f, "{:.2}s", self.0.as_secs_f64())` -- always
    exactly 2 digits after the decimal point, an unbounded number of
    digits before it (Duration::as_secs_f64() is always non-negative).
  - console.rs sets `st.exec_time = start_time.map(|t|
    TestSuiteExecTime(t.elapsed()))` -- exec_time is Some whenever the
    suite runs to completion under a normal (no --no-run) `cargo test`
    invocation, i.e. always present for this frozen argv.

Deliberately NOT the general-purpose canary sanitizer (sanitizer.sanitize).
Never imports/modifies maven_canonicalizer.py, vstest_canonicalizer.py,
gradle_canonicalizer_v2.py, or gradle_canonicalizer_helm_values_v1.py --
reuses only their shared Rule/error plumbing, mirroring
gradle_canonicalizer_helm_values_v1.py's own precedent.
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

_PREFIX = "test result: "
_TRIGGER = "test result: "

_COUNTS = r"\d+ passed; \d+ failed; \d+ ignored; \d+ measured; \d+ filtered out"
_DURATION = r"\d+\.\d{2}s"

_GRAMMAR = rf"(?:ok|FAILED)\. {_COUNTS}; finished in (?:{_DURATION}|<ELAPSED>)"
_PATTERN = re.compile("^" + re.escape(_PREFIX) + "(" + _GRAMMAR + ")$")
_DURATION_PATTERN = re.compile(_DURATION + "$")


def _apply_rule(m: "re.Match[str]") -> str:
    body = m.group(1)
    if body.endswith("<ELAPSED>"):
        return _PREFIX + body
    prefix, _, duration = body.rpartition(" ")
    if not _DURATION_PATTERN.match(duration):
        raise CanonicalizerError(f"unexpected duration token in cargo test summary line: {duration!r}")
    return _PREFIX + prefix + " <ELAPSED>"


RULE_CARGO_TEST_SUMMARY_DURATION = Rule(
    name="cargo_test_summary_duration",
    trigger=_TRIGGER,
    pattern=_PATTERN,
    placeholder="<ELAPSED>",
    apply=_apply_rule,
)

RULES: list[Rule] = [RULE_CARGO_TEST_SUMMARY_DURATION]


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
        "report_type": "n2d1b-cargo-test-canonicalization-report-v1",
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

    if body.get("policy_type") != "n2d1b-cargo-test-capture-canonicalization-policy-v1":
        raise PolicyIntegrityError(
            f"{policy_path}: policy_type {body.get('policy_type')!r} is not the expected "
            "'n2d1b-cargo-test-capture-canonicalization-policy-v1'"
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
            f"cargo_test_canonicalizer.RULES {sorted(code_rule_names)} -- policy and code have drifted"
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
                "actual cargo_test_canonicalizer.py rule it is supposed to document"
            )

    if not body.get("applicable_case_ids"):
        raise PolicyIntegrityError(f"{policy_path}: applicable_case_ids is empty or missing")
    if set(body["applicable_case_ids"]) != {"repo-rustlings", "repo-dockerfile-parser-rs"}:
        raise PolicyIntegrityError(
            f"{policy_path}: applicable_case_ids {body['applicable_case_ids']} is not exactly "
            "{'repo-rustlings', 'repo-dockerfile-parser-rs'} -- this policy is not authorized for any other case"
        )

    return body
