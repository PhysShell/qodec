#!/usr/bin/env python3
"""Builds the immutable, self-hash-locked
pytest-requests-capture-canonicalization-policy.json.

N2-D1b Stage 2: repo-requests invokes pytest against the frozen argv under
full network denial (repo-requests is NOT in
NETWORK_ENFORCEMENT_AUTHORIZED_CASES). After the argv0-resolution,
TMPDIR/tmp-fs-rw, and editable-install-source-dir fixes let pytest actually
run its full suite, capture-a and capture-b produced byte-for-byte-identical
outcome counts (30 failed, 384 passed, 15 skipped, 1 xfailed, 32 warnings,
205 errors -- the errors are pytest-httpbin's own local WSGI test server
genuinely, deterministically failing to bind under permanent network denial,
identically on both sides), differing only in three independently-derived,
evidence-verified nondeterminism classes. See
pytest_requests_canonicalizer.py's own module docstring for the full
derivation of each rule from CPython's own object-repr convention,
pytest's own source (tag v9.1.1), and threading.Thread's own repr format.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest_requests_canonicalizer as prc

OUT_PATH = Path(__file__).resolve().parents[1] / "pytest-requests-capture-canonicalization-policy.json"

APPROVING_DECISION_IDENTITY = "n2d1b-stage2-pytest-requests-nondeterminism-grammar-v1-authorization-2026-07-17"

PYTEST_SOURCE_DERIVATION = {
    "repository_url": "https://github.com/pytest-dev/pytest",
    "tag": "9.1.1",
    "commit_sha": "cf470ec0bf7eb89cd97dd56df4859eae5db46447",
    "formatter_file": "src/_pytest/terminal.py",
    "formatter_method": "TerminalReporter.summary_stats / format_session_duration",
    "source_locator": (
        "The session-summary banner's trailing '(...) in D.DDs =' is built from "
        "format_session_duration(session_duration), which for a duration under 60 "
        "seconds renders f'{seconds:.2f}s' -- always exactly 2 digits after the "
        "decimal point, never negative (a monotonic wall-clock elapsed measurement)."
    ),
    "grammar_derivation": (
        "The trailing duration token is always 'D.DDs' immediately followed by ' =' "
        "and the banner's closing '=' fill characters; only this duration token is "
        "ever replaced, never the passed/failed/skipped/xfailed/warnings/errors "
        "counts themselves, which remain a genuine outcome signal."
    ),
}

CPYTHON_SOURCE_DERIVATION = {
    "convention": "object.__repr__ default format",
    "source_locator": (
        "CPython's default object.__repr__ (Objects/typeobject.c, object_repr) always "
        "renders '<module.qualname object at 0x%p>', where %p is the C pointer address "
        "formatted as lowercase hex with no leading zero-padding requirement. Many "
        "stdlib/third-party classes (urllib3's HTTPConnection/HTTPConnectionPool, "
        "traceback objects, list_iterator, etc.) implement a custom __repr__ that still "
        "ends with the identical '... at 0x<hex>>' suffix -- this rule matches only "
        "that closed, well-documented suffix grammar, never the arbitrary, "
        "non-enumerable prefix pytest's own assertion-introspection machinery chooses "
        "to print (whichever local variable is relevant at a given failure/error site)."
    ),
    "grammar_derivation": (
        "17 distinct real object-repr shapes were found in the actual captured pair "
        "(WSGIServer, HTTPConnectionPool, HTTPSConnectionPool, traceback, "
        "list_iterator, HTTPConnection, HTTPSConnection, HTTPAdapter, several "
        "test-class instances, and one exception-during-repr fallback case). Every "
        "single occurrence of the substring ' at 0x' (400 in each of the two real "
        "captured files) was verified computationally to be immediately followed by "
        "the exact grammar '[0-9a-f]+>' with zero exceptions."
    ),
}

THREADING_SOURCE_DERIVATION = {
    "convention": "threading.Thread.__repr__",
    "source_locator": (
        "CPython's threading.Thread.__repr__ (Lib/threading.py) renders "
        "'<ClassName(Thread-N, <status> <native_id-or-ident>)>', where the trailing "
        "integer is the OS-level native thread identifier or ident -- both are "
        "process/run-specific and vary run to run even for an otherwise identical "
        "thread. pytest-httpbin's background WSGI/TLS server threads are named "
        "Server/TLSServer subclasses of threading.Thread."
    ),
    "grammar_derivation": (
        "25 distinct 'Thread-' occurrences were found in each of the two real "
        "captured files. Every single occurrence was verified computationally to "
        "match the exact closed grammar '<(?:Server|TLSServer)\\(Thread-\\d+, "
        "stopped \\d+\\)>' with zero exceptions, and the Thread-N ordinals themselves "
        "(1 through 24, and 26) are IDENTICAL, in the same order, between capture-a "
        "and capture-b -- only the trailing native ident varies, confirming this is "
        "the same class of nondeterminism as the object-repr address above, not a "
        "genuine outcome difference. Only the trailing ident is replaced; the class "
        "name and 'Thread-N' ordinal are preserved byte-for-byte via capture groups."
    ),
}

PROHIBITED_TRANSFORMATIONS = [
    "faking, freezing, or otherwise altering wall-clock time during the real test run",
    "altering the frozen pytest execution argv",
    "loosening or disabling this sandbox's network-denial confinement for repo-requests "
    "in order to make pytest-httpbin's local server bind -- the resulting ERRORs are "
    "genuine, deterministic, and identical between capture-a and capture-b, and are not "
    "in scope for this canonicalization pass",
    "trimming leading/trailing whitespace beyond a rule's own anchored match",
    "deduplicating lines",
    "removing lines",
    "reordering lines",
    "canonicalizing the passed/failed/skipped/xfailed/warnings/errors counts -- a "
    "difference there is a genuine outcome difference, never timing or identity noise",
    "a generic 'any hex number' or 'any large decimal number' replacement across "
    "arbitrary diagnostic lines -- each rule is scoped to its own independently-derived, "
    "closed grammar and its own verified trigger substring",
    "applying any rule in this policy to a case_id outside applicable_case_ids",
    "reusing the general-purpose canary sanitizer (sanitizer.sanitize) as the "
    "canonical-input transformer",
    "importing, modifying, broadening, or depending on maven_canonicalizer.py, "
    "vstest_canonicalizer.py, gradle_canonicalizer.py (v1), gradle_canonicalizer_v2.py, "
    "gradle_canonicalizer_helm_values_v1.py, cargo_test_canonicalizer.py, or their "
    "policy files -- this module defines its own SubstringRule shape and reuses only "
    "their shared _sha256/_split_line_ending plumbing",
]

UTF8_AND_LINE_ENDING_POLICY = (
    "Input must be valid UTF-8 (strict decode); invalid UTF-8 is a hard "
    "failure, never a lossy replace. Line order, line count, and each "
    "line's own original line-ending sequence (or absence of one, for a "
    "final line with no trailing newline) are preserved exactly -- each rule "
    "only ever substitutes its own rule-matched substring within a line's "
    "own content, never its terminator, and never any other rule's payload."
)


def canonicalize_and_hash(body: dict) -> tuple[str, str]:
    text = json.dumps(body, indent=2, sort_keys=True) + "\n"
    return text, hashlib.sha256(text.encode()).hexdigest()


def build_policy() -> dict:
    rules = []
    for rule in prc.RULES:
        d = rule.to_policy_dict()
        d["evidence_justification"] = (
            "Independently derived and computationally verified against the real "
            "Stage 2 fourth-run captured pair -- see pytest_source_derivation / "
            "cpython_source_derivation / threading_source_derivation."
        )
        rules.append(d)

    body = {
        "policy_type": "n2d1b-pytest-requests-capture-canonicalization-policy-v1",
        "policy_version": 1,
        "applicable_case_ids": ["repo-requests"],
        "selected_source_stream": "stdout",
        "canonicalizer_module": "pytest_requests_canonicalizer.py",
        "rules": rules,
        "pytest_source_derivation": PYTEST_SOURCE_DERIVATION,
        "cpython_source_derivation": CPYTHON_SOURCE_DERIVATION,
        "threading_source_derivation": THREADING_SOURCE_DERIVATION,
        "prohibited_transformations": PROHIBITED_TRANSFORMATIONS,
        "utf8_and_line_ending_policy": UTF8_AND_LINE_ENDING_POLICY,
        "approving_decision_identity": APPROVING_DECISION_IDENTITY,
        "scope_statement": (
            "This policy applies ONLY to the case_id(s) listed in "
            "applicable_case_ids (repo-requests, and only that one). Any other case "
            "found to need additional canonicalization rules must stop for separate "
            "D1b review -- this policy is not extended silently, and is never merged "
            "with capture-canonicalization-policy.json (Maven), "
            "vstest-capture-canonicalization-policy.json (VSTest), "
            "gradle-capture-canonicalization-policy.json (Gradle v1, historical), "
            "gradle-capture-canonicalization-policy-v2.json (repo-moshi), "
            "gradle-capture-canonicalization-policy-helm-values-v1.json "
            "(repo-helm-values), or cargo-test-capture-canonicalization-policy.json "
            "(repo-rustlings, repo-dockerfile-parser-rs)."
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
