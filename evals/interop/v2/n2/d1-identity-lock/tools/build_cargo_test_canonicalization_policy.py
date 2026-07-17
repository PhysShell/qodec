#!/usr/bin/env python3
"""Builds the immutable, self-hash-locked
cargo-test-capture-canonicalization-policy.json.

N2-D1b Stage 2: repo-rustlings and repo-dockerfile-parser-rs both invoke the
identical frozen ["cargo", "test"] argv against the same rustup-resolved
"stable" toolchain -- after the deterministic RUST_TEST_THREADS=1 scheduling
profile made every individual test-result line byte-identical and
same-order (real CI evidence, Stage 2 second full run), the sole remaining
raw difference was libtest's own summary line's trailing wall-clock
duration. See cargo_test_canonicalizer.py's own module docstring for the
full derivation from Rust's actual libtest source (tag v1.97.0, commit
2d8144b7880597b6e6d3dfd63a9a9efae3f533d3).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import cargo_test_canonicalizer as ctc

OUT_PATH = Path(__file__).resolve().parents[1] / "cargo-test-capture-canonicalization-policy.json"

APPROVING_DECISION_IDENTITY = "n2d1b-stage2-cargo-test-duration-grammar-v1-authorization-2026-07-16"

LIBTEST_SOURCE_DERIVATION = {
    "repository_url": "https://github.com/rust-lang/rust",
    "tag": "1.97.0",
    "commit_sha": "2d8144b7880597b6e6d3dfd63a9a9efae3f533d3",
    "formatter_files": [
        "library/test/src/formatters/pretty.rs",
        "library/test/src/formatters/terse.rs",
        "library/test/src/time.rs",
        "library/test/src/console.rs",
    ],
    "formatter_method": "PrettyFormatter::write_run_finish / TerseFormatter::write_run_finish",
    "source_locator": (
        "write_run_finish builds '. {passed} passed; {failed} failed; {ignored} ignored; "
        "{measured} measured; {filtered_out} filtered out', then, if state.exec_time is "
        "Some, appends '; finished in {exec_time}'. time.rs's TestSuiteExecTime Display "
        "impl formats the duration as write!(f, \"{:.2}s\", self.0.as_secs_f64()) -- "
        "always exactly 2 digits after the decimal point. console.rs sets "
        "st.exec_time = start_time.map(|t| TestSuiteExecTime(t.elapsed())), which is "
        "Some whenever the suite runs to completion under a normal (no --no-run) "
        "`cargo test` invocation -- i.e. always present for this frozen argv."
    ),
    "grammar_derivation": (
        "The summary line is always exactly "
        "'test result: (ok|FAILED). N passed; M failed; K ignored; L measured; "
        "J filtered out; finished in D.DDs' -- N/M/K/L/J are unbounded non-negative "
        "integers (never canonicalized: a difference in any of these means a genuinely "
        "different test outcome, not mere timing noise), and D.DDs is an unbounded "
        "number of digits before the decimal point, always exactly 2 after, always "
        "non-negative (Duration::as_secs_f64() cannot be negative). Only the D.DDs "
        "duration token is ever replaced; the 'ok'/'FAILED' outcome word and every "
        "count are preserved byte-for-byte."
    ),
}

PROHIBITED_TRANSFORMATIONS = [
    "faking, freezing, or otherwise altering wall-clock time during the real build",
    "altering the frozen ['cargo', 'test'] execution argv",
    "trimming leading/trailing whitespace beyond the rule's own anchored match",
    "deduplicating lines",
    "removing lines",
    "reordering lines",
    "canonicalizing the passed/failed/ignored/measured/filtered-out counts -- a difference "
    "there is a genuine outcome difference, never timing noise",
    "a generic 'number followed by s' replacement across arbitrary diagnostic lines",
    "accepting per-test #[test] timing lines (TestExecTime, {:.3}s, 3 decimals) under this "
    "same rule -- this policy applies ONLY to the suite-level summary line's {:.2}s "
    "(TestSuiteExecTime), a distinct, separately-formatted duration type in libtest's own "
    "source; a per-test timing line appearing in captured output would need separate D1b "
    "review, never silently folded into this rule",
    "applying this rule to a case_id outside applicable_case_ids",
    "reusing the general-purpose canary sanitizer (sanitizer.sanitize) as the canonical-input "
    "transformer",
    "importing, modifying, broadening, or depending on maven_canonicalizer.py, "
    "vstest_canonicalizer.py, gradle_canonicalizer.py (v1), gradle_canonicalizer_v2.py, "
    "gradle_canonicalizer_helm_values_v1.py, or their policy files",
    "using this rule as a substitute for the deterministic RUST_TEST_THREADS=1 scheduling "
    "profile -- it does not mask test-ordering nondeterminism, only the suite-level duration",
]

UTF8_AND_LINE_ENDING_POLICY = (
    "Input must be valid UTF-8 (strict decode); invalid UTF-8 is a hard "
    "failure, never a lossy replace. Line order, line count, and each "
    "line's own original line-ending sequence (or absence of one, for a "
    "final line with no trailing newline) are preserved exactly -- the "
    "canonicalizer only ever substitutes the rule-matched duration value "
    "within a line's own content, never its terminator. Only the duration "
    "payload after 'finished in ' is ever replaced; the outcome word, every "
    "count, test names, and all other output remain byte-for-byte untouched."
)


def canonicalize_and_hash(body: dict) -> tuple[str, str]:
    text = json.dumps(body, indent=2, sort_keys=True) + "\n"
    return text, hashlib.sha256(text.encode()).hexdigest()


def build_policy() -> dict:
    rules = []
    for rule in ctc.RULES:
        d = rule.to_policy_dict()
        d["evidence_justification"] = (
            "Independently derived from Rust's own libtest source (tag v1.97.0, matching "
            "this session's installed rustc) -- see libtest_source_derivation."
        )
        rules.append(d)

    body = {
        "policy_type": "n2d1b-cargo-test-capture-canonicalization-policy-v1",
        "policy_version": 1,
        "applicable_case_ids": ["repo-dockerfile-parser-rs", "repo-rustlings"],
        "selected_source_stream": "stdout",
        "canonicalizer_module": "cargo_test_canonicalizer.py",
        "rules": rules,
        "requires_deterministic_scheduling_profile": True,
        "libtest_source_derivation": LIBTEST_SOURCE_DERIVATION,
        "prohibited_transformations": PROHIBITED_TRANSFORMATIONS,
        "utf8_and_line_ending_policy": UTF8_AND_LINE_ENDING_POLICY,
        "approving_decision_identity": APPROVING_DECISION_IDENTITY,
        "scope_statement": (
            "This policy applies ONLY to the case_id(s) listed in "
            "applicable_case_ids (repo-dockerfile-parser-rs and repo-rustlings, and "
            "only those two -- both invoke the identical frozen ['cargo', 'test'] "
            "argv against the identical rustup 'stable' toolchain, so this is a "
            "single shared identity, not a per-case duplication). Any other case "
            "found to need additional canonicalization rules must stop for separate "
            "D1b review -- this policy is not extended silently, and is never "
            "merged with capture-canonicalization-policy.json (Maven), "
            "vstest-capture-canonicalization-policy.json (VSTest), "
            "gradle-capture-canonicalization-policy.json (Gradle v1, historical), "
            "gradle-capture-canonicalization-policy-v2.json (repo-moshi), or "
            "gradle-capture-canonicalization-policy-helm-values-v1.json (repo-helm-values)."
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
