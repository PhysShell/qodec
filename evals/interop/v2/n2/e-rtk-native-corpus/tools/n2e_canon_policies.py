"""Per-tool, versioned output canonicalization policies (§15).

Each policy is identified by an IMMUTABLE id. There are two DISTINCT classes:

  1. Tool-level duration/cache policies (e.g. cargo-test-v1, go-test-v1, pytest-v1,
     vitest-v1, gradle-test-v1). These match ONLY the exact known nondeterministic
     grammar of a single tool's OWN output — elapsed durations, cache markers, and
     the tool's own wall-clock summary lines — and nothing else. They are selected
     by (command_family, command_subfamily). They never touch diagnostic text,
     paths, test names, error messages, counts, or any semantic value.

  2. Explicitly case-scoped, PARSER-BOUNDED structural policies (e.g.
     caddy-go-test-v1). These handle a structured artifact that a SPECIFIC case's
     tested program emits (here: Caddy's zap JSON admin logs). They parse the full
     structure with a real parser, require the exact schema/context before touching
     anything, normalize only proven wall-clock fields, and canonicalize declared
     unordered sets while preserving their exact multiset. A case-scoped policy is
     selected ONLY by the exact immutable case_id (via _CASE_POLICY / the execution
     contract) — NEVER from family/subfamily — and must never be substituted by the
     family-generic policy.

`policy_for` resolves the id (honouring the case-scoped binding first); the id is
recorded in the per-case evidence AND in the self-hash-locked execution contract,
which is the normative source the verifier checks. Mutation tests
(test_n2e_canon_policies.py) prove that a semantic change to the bytes always
survives canonicalization (i.e. the policy cannot mask a real difference).
"""
from __future__ import annotations

import json as _json
import re

# --------------------------------------------------------------------------
# Scoped, parser-bounded Caddy policy (caddy-go-test-v1).
#
# Bound ONLY to the exact Caddy scenario (never selected from family/subfamily).
# For every candidate line it: parses the FULL JSON object with a real parser;
# requires the exact zap schema/context (level, numeric ts, logger, msg) before
# touching anything; replaces only the proven wall-clock `ts`; sorts the parsed
# `origins` string array preserving its EXACT multiset; serializes through ONE
# declared canonical JSON encoding. Malformed JSON, unexpected types, duplicate
# keys, and unrelated objects (even ones that merely contain `ts`/`origins`) are
# left byte-identical. It never sorts or reorders whole lines, so residual
# goroutine line-interleaving stays observable (i.e. remains nondeterministic).
# --------------------------------------------------------------------------

def _reject_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key")  # duplicate-key ambiguity -> reject
        d[k] = v
    return d


def _is_caddy_zap(obj: dict) -> bool:
    return (isinstance(obj.get("level"), str) and isinstance(obj.get("ts"), (int, float))
            and not isinstance(obj.get("ts"), bool)
            and isinstance(obj.get("logger"), str) and isinstance(obj.get("msg"), str))


def _caddy_line(line: bytes) -> bytes:
    # only a whole-line JSON object (no surrounding whitespace) is a candidate
    if not (line[:1] == b"{" and line[-1:] == b"}"):
        return line
    try:
        obj = _json.loads(line.decode("utf-8"), object_pairs_hook=_reject_dupes)
    except Exception:
        return line  # malformed / non-utf8 / duplicate key -> byte-identical
    if not isinstance(obj, dict) or not _is_caddy_zap(obj):
        return line  # unrelated object (even if it has ts/origins) -> byte-identical
    obj = dict(obj)
    obj["ts"] = "<ts>"  # schema proved ts is a wall-clock number
    if "origins" in obj:
        og = obj["origins"]
        if not (isinstance(og, list) and all(isinstance(x, str) for x in og)):
            return line  # unexpected type -> leave unchanged
        obj["origins"] = sorted(og)  # preserve exact multiset
    return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8")


def _caddy_go_test_canon(data: bytes) -> bytes:
    # tool-level go-test duration/cache normalization first (the case is still
    # `go test ./...`), THEN the scoped per-line zap-log JSON canon.
    for pat, repl in _GO_TEST_RULES:
        data = pat.sub(repl, data)
    return b"\n".join(_caddy_line(ln) for ln in data.split(b"\n"))


# go test tool-level grammar (durations + cache marker) -- shared by go-test-v1
# and the Caddy scoped policy; NOTHING case-specific lives here.
_GO_TEST_RULES = [
    (re.compile(rb"\t\d+\.\d+s\b"), b"\t<dur>"),
    (re.compile(rb"\(\d+\.\d+s\)"), b"(<dur>)"),
    (re.compile(rb"\(cached\)"), b"(<dur>)"),
]

# Each policy: id -> list of (compiled_pattern, replacement) OR a callable
# (bytes)->bytes. Regex patterns are anchored to the tool's exact duration
# grammar; replacements are fixed tokens.
_POLICIES: dict[str, object] = {
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
    # go test (tool-level ONLY): "ok  \tpkg\t0.123s" ; "--- FAIL: TestX (0.00s)" ;
    # "(cached)". No case-specific (app-log) rules live here.
    "go-test-v1": _GO_TEST_RULES,
    # Caddy-only scoped policy: go-test durations + real-JSON zap-log canon.
    "caddy-go-test-v1": _caddy_go_test_canon,
    # go vet: diagnostics only; no durations expected -> identity but declared for clarity
    "go-vet-v1": [],
    # pytest: "===== 3 passed in 0.12s =====" ; "0.12s call     test_x"
    "pytest-v1": [
        (re.compile(rb"in \d+\.\d+s\b"), b"in <dur>"),
        (re.compile(rb"\bin \d+\.\d+s "), b"in <dur> "),
        (re.compile(rb"^\d+\.\d+s\b", re.MULTILINE), b"<dur>"),
    ],
    # vitest/jest: "Duration  1.23s" ; "Time: 1.234 s" ; per-file/test trailing
    # elapsed such as "(150 tests) 110ms" and "... 1.2s" (all pure duration grammar).
    "vitest-v1": [
        (re.compile(rb"Duration\s+\d+\.\d+m?s"), b"Duration <dur>"),
        (re.compile(rb"Time:\s+\d+\.\d+\s*s"), b"Time: <dur>"),
        (re.compile(rb"\bin \d+ms\b"), b"in <dur>"),
        # trailing per-file/per-suite elapsed after a "(N tests[...]) 110ms" or " 1.2s"
        (re.compile(rb"(\)\s*)\d+ms\b"), rb"\1<dur>"),
        (re.compile(rb"(\)\s*)\d+\.\d+s\b"), rb"\1<dur>"),
        (re.compile(rb"(\btests?\b.*?\s)\d+ms\b"), rb"\1<dur>"),
        # vitest summary "Start at  HH:MM:SS" (wall-clock) and the per-phase Duration
        # breakdown "(transform 5.92s, setup 643ms, collect .., tests .., ..)" -- these
        # are vitest's OWN summary grammar (tool-level). Case-specific cross-tool noise
        # (e.g. a puppeteer/chromium crash from a browser-backed test) is NOT normalized
        # here; such a case is classified on its merits, not masked by a generic policy.
        (re.compile(rb"Start at\s+\d{1,2}:\d{2}:\d{2}"), b"Start at <time>"),
        (re.compile(rb"\b(transform|setup|collect|tests|environment|prepare)\s+\d+(?:\.\d+)?\s?m?s\b"),
         rb"\1 <dur>"),
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


# Case-SCOPED policy bindings: an exact case_id explicitly references a distinct
# policy that must NOT be selected from family/subfamily alone. This is the
# per-case canonicalization contract, keyed on the immutable frozen case_id.
_CASE_POLICY = {
    "caddyserver__caddy-5870::go::test::buggy": "caddy-go-test-v1",
}


def policy_for(family: str, subfamily: str, git: bool = False,
               jvm_build: str | None = None, case_id: str | None = None) -> str:
    if case_id and case_id in _CASE_POLICY:
        return _CASE_POLICY[case_id]
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
    spec = _POLICIES[policy_id]
    if callable(spec):
        return spec(data)
    out = data
    for pat, repl in spec:
        out = pat.sub(repl, out)  # repl may be bytes or a callable(match)->bytes
    return out


# --------------------------------------------------------------------------
# rtk-envelope-v1: a versioned, RTK-ARM-ONLY policy that normalizes ONLY the
# wall-clock epoch inside RTK's own tee-log diagnostic line, whose exact grammar is
#     [full output: <path>/rtk/tee/<epoch>_<name>.log]
# It is anchored to that whole "[full output: ... .log]" envelope, so it normalizes
# only the <epoch> digits and NOTHING else: an arbitrary command that merely prints
# a lookalike path (e.g. "rtk/tee/123_x.log" without the envelope) is untouched, a
# changed <name> suffix stays observable, and unrelated numeric paths are untouched.
# Applied ONLY to the RTK arm; the policy id is recorded in the per-rep evidence.
# --------------------------------------------------------------------------
RTK_ENVELOPE_POLICY_ID = "rtk-envelope-v1"
_RTK_ENVELOPE = re.compile(rb"(\[full output:[^\]\n]*?rtk/tee/)\d+(_[^\]\n]*?\.log\])")


def rtk_envelope(data: bytes) -> bytes:
    """Normalize ONLY the epoch in RTK's tee-log envelope line. RTK-arm only."""
    return _RTK_ENVELOPE.sub(rb"\1<ts>\2", data)


def all_policy_ids() -> list[str]:
    return sorted(_POLICIES)
