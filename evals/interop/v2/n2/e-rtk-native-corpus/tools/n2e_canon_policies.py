"""Per-tool, versioned output canonicalization policies (§15).

Each policy is identified by an IMMUTABLE id and matches ONLY the exact known
nondeterministic grammar for one tool's output — elapsed durations, and nothing
else. Policies never touch diagnostic text, paths, test names, error messages,
counts, or any semantic value. `identity-v1` is the default and changes nothing.

A policy is resolved deterministically from a frozen scenario's (command_family,
command_subfamily) via `policy_for`, and the resolved id is recorded in the
per-case evidence. Mutation tests (test_n2e_canon_policies.py) prove that a
semantic change to the bytes always survives canonicalization (i.e. the policy
cannot mask a real difference).
"""
from __future__ import annotations

import re

# Each policy: id -> list of (compiled_pattern, replacement). Patterns must be
# anchored to the tool's exact duration grammar. Replacements are fixed tokens.
_POLICIES: dict[str, list[tuple[re.Pattern, bytes]]] = {
    "identity-v1": [],
    # cargo test: "test result: ok. 5 passed; 0 failed; ... finished in 0.12s"
    #             "   Running unittests src/lib.rs (target/debug/deps/...-<hash>)"
    "cargo-test-v1": [
        (re.compile(rb"finished in \d+\.\d+s"), b"finished in <dur>"),
        (re.compile(rb"\(target/[^)]*-[0-9a-f]{8,}\)"), b"(target/<artifact>)"),
    ],
    # cargo build/check/clippy: "Finished `dev` profile ... in 1.23s"; "Compiling x v1 ..."
    "cargo-build-v1": [
        (re.compile(rb"in \d+\.\d+s\b"), b"in <dur>"),
        (re.compile(rb"in \d+m \d+\.\d+s\b"), b"in <dur>"),
    ],
    # go test: "ok  \tpkg\t0.123s" ; "--- FAIL: TestX (0.00s)"
    "go-test-v1": [
        (re.compile(rb"\t\d+\.\d+s\b"), b"\t<dur>"),
        (re.compile(rb"\(\d+\.\d+s\)"), b"(<dur>)"),
        (re.compile(rb"\(cached\)"), b"(<dur>)"),
    ],
    # go vet: diagnostics only; no durations expected -> identity but declared for clarity
    "go-vet-v1": [],
    # pytest: "===== 3 passed in 0.12s =====" ; "0.12s call     test_x"
    "pytest-v1": [
        (re.compile(rb"in \d+\.\d+s\b"), b"in <dur>"),
        (re.compile(rb"\bin \d+\.\d+s "), b"in <dur> "),
        (re.compile(rb"^\d+\.\d+s\b", re.MULTILINE), b"<dur>"),
    ],
    # vitest/jest: "Duration  1.23s" ; "Time:        1.234 s"
    "vitest-v1": [
        (re.compile(rb"Duration\s+\d+\.\d+m?s"), b"Duration <dur>"),
        (re.compile(rb"Time:\s+\d+\.\d+\s*s"), b"Time: <dur>"),
        (re.compile(rb"\bin \d+ms\b"), b"in <dur>"),
    ],
    # gradle test: "BUILD SUCCESSFUL in 12s" ; "> Task :test"
    "gradle-test-v1": [
        (re.compile(rb"BUILD (SUCCESSFUL|FAILED) in \d+m? ?\d*s"), b"BUILD \\1 in <dur>"),
    ],
    # maven test: "Total time:  01:23 min" ; "Tests run: 5, ... Time elapsed: 0.123 s"
    "maven-test-v1": [
        (re.compile(rb"Total time:\s+[0-9:]+ ?\w*"), b"Total time: <dur>"),
        (re.compile(rb"Time elapsed: \d+\.\d+ s"), b"Time elapsed: <dur>"),
    ],
    # git: no duration nondeterminism; identity (state must be repo-local + fixed)
    "git-v1": [],
    # docker: identity (created/uptime handled by choosing stable subcommands/formatting)
    "docker-v1": [],
    # logs / files: static input -> identity
    "log-v1": [],
    "files-v1": [],
}

# deterministic resolution from the frozen scenario
_FAMILY_SUB_POLICY = {
    ("rust_cargo", "test"): "cargo-test-v1",
    ("rust_cargo", "build"): "cargo-build-v1",
    ("rust_cargo", "check"): "cargo-build-v1",
    ("rust_cargo", "clippy"): "cargo-build-v1",
    ("go", "test"): "go-test-v1",
    ("go", "build"): "go-test-v1",
    ("go", "vet"): "go-vet-v1",
    ("python", "pytest"): "pytest-v1",
    ("python", "ruff"): "identity-v1",
    ("js_ts", "test"): "vitest-v1",
    ("js_ts", "tsc"): "identity-v1",
    ("js_ts", "lint"): "identity-v1",
    ("jvm", "test"): "gradle-test-v1",   # overridden to maven-test-v1 by the adapter when pom.xml
    ("logs", "log"): "log-v1",
    ("files_search", "grep"): "files-v1",
    ("files_search", "read"): "files-v1",
    ("files_search", "ls"): "files-v1",
    ("files_search", "tree"): "files-v1",
    ("containers", "ps"): "docker-v1",
    ("containers", "images"): "docker-v1",
    ("containers", "logs"): "docker-v1",
}


def policy_for(family: str, subfamily: str, git: bool = False, jvm_build: str | None = None) -> str:
    if git:
        return "git-v1"
    if family == "jvm" and subfamily == "test":
        return "maven-test-v1" if jvm_build == "maven" else "gradle-test-v1"
    if family == "git":
        return "git-v1"
    return _FAMILY_SUB_POLICY.get((family, subfamily), "identity-v1")


def canonicalize(data: bytes, policy_id: str) -> bytes:
    if policy_id not in _POLICIES:
        raise KeyError(f"unknown canonicalization policy {policy_id!r}")
    out = data
    for pat, repl in _POLICIES[policy_id]:
        out = pat.sub(repl, out)
    return out


def all_policy_ids() -> list[str]:
    return sorted(_POLICIES)
