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

import hashlib
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
    # cargo test (HISTORICAL, unchanged): "test result: ok. 5 passed; ... finished in
    # 0.12s"; "   Running unittests src/lib.rs (target/debug/deps/...-<hash>)". Bound to the
    # frozen tokio contract; its meaning must never broaden (see cargo-test-v2 for the
    # bounded build-progress-stripping variant used by the resolved coreutils replacement).
    "cargo-test-v1": [
        (re.compile(rb"finished in \d+\.\d+s"), b"finished in <dur>"),
        (re.compile(rb"\(target/[^)]*-[0-9a-f]{8,}\)"), b"(target/<artifact>)"),
    ],
    # cargo test v2 (resolved coreutils): a measurement rep that must COMPILE the patched
    # crate emits cargo build-progress lines whose ORDER is nondeterministic under parallel
    # compilation -- pure progress, NOT test semantics. A BOUNDED line-by-line callable
    # removes ONLY exact Cargo status grammar (Compiling/Checking/Documenting/Fresh package
    # records; the `<profile>` profile completion record; registry index/download/lock
    # activity), then normalizes the test-result duration. Every `test <id> ... ok/FAILED`,
    # `running N tests`, `test result:`, and `Running .../deps/<bin>-<hash>` line is kept
    # (deps hashes are path-stable and deterministic). See _cargo_test_v2_canon.
    "cargo-test-v2": None,  # filled below with the callable
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
        # Bugfix (completeness): the vitest TOTAL "Duration  828ms" is emitted as INTEGER ms with no
        # decimal, but the original pattern required "\d+\.\d+" and so left the total un-normalized --
        # the sole per-rep nondeterminism observed for vue (run 29865050045: 1 line of 112 differed,
        # only the total Duration). The optional-decimal class here matches the intent stated in the
        # comment above ("Duration 1.23s") and the per-phase breakdown below, which already used it.
        # No qualification artifact was ever derived under vitest-v1, so nothing derived is invalidated.
        (re.compile(rb"Duration\s+\d+(?:\.\d+)?m?s"), b"Duration <dur>"),
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

# --------------------------------------------------------------------------
# cargo-test-v2: BOUNDED, line-by-line removal of EXACT Cargo status grammar only. Cargo
# right-aligns each status verb so the word ENDS at column 12; we require that EXACT prefix
# (12 - len(verb) leading spaces) plus the verb's full shape. A line is removed ONLY if it
# matches one of these exact Cargo status forms -- an arbitrary indented line that merely
# begins with "Finished"/"Checking"/"Fresh"/"Documenting"/"Compiling"/"Updating"/... (wrong
# indentation, missing version, or a non-Cargo tail) is PRESERVED byte-for-byte.
_CRATE = rb"[A-Za-z0-9_+-]+"
_SEMVER = rb"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?"
_CARGO_DUR = rb"(?:\d+m )?\d+(?:\.\d+)?s"    # "0.05s", "40.21s", "2m 38s"


def _prefix(verb: bytes) -> bytes:
    return b" " * (12 - len(verb))


# package records: <exact prefix>{verb} <crate> v<semver> [ (<source>)]  -- version REQUIRED
_V2_PKG = [re.compile(rb"^" + _prefix(v) + v + rb" " + _CRATE + rb" v" + _SEMVER + rb"(?: \(.+\))?$")
           for v in (b"Compiling", b"Checking", b"Documenting", b"Fresh")]
# completion record: "    Finished `<profile>` profile [<qualifiers>] target(s) in <dur>"
# 'profile' is REQUIRED and the tail must be an exact Cargo duration (no arbitrary tail).
_V2_FINISHED = re.compile(
    rb"^" + _prefix(b"Finished") + rb"Finished `[\w.+-]+` profile(?: \[[^\]]*\])? target\(s\) in "
    + _CARGO_DUR + rb"$")
# source-defined registry/package activity, each with its exact right-aligned prefix
_V2_REGISTRY = [
    re.compile(rb"^" + _prefix(b"Updating") + rb"Updating crates\.io index$"),
    re.compile(rb"^" + _prefix(b"Updating") + rb"Updating git repository `.+`$"),
    re.compile(rb"^" + _prefix(b"Downloading") + rb"Downloading(?: \d+)? crates ?\.\.\.$"),
    re.compile(rb"^" + _prefix(b"Downloaded") + rb"Downloaded " + _CRATE + rb" v" + _SEMVER + rb".*$"),
    re.compile(rb"^" + _prefix(b"Downloaded") + rb"Downloaded \d+ crates?.*$"),
    re.compile(rb"^" + _prefix(b"Locking") + rb"Locking \d+ packages? to latest.*$"),
    re.compile(rb"^" + _prefix(b"Blocking") + rb"Blocking waiting for file lock on .+$"),
]
_V2_KILL = tuple(_V2_PKG) + (_V2_FINISHED,) + tuple(_V2_REGISTRY)
_V2_FINISHED_IN = re.compile(rb"finished in \d+\.\d+s")


def _is_cargo_status_line(line_no_nl: bytes) -> bool:
    return any(p.match(line_no_nl) for p in _V2_KILL)


def _cargo_test_v2_canon(data: bytes) -> bytes:
    """Remove exact Cargo build-status lines (build progress, not test semantics); keep
    everything else; normalize the test-result duration on kept lines. Line-by-line."""
    out = []
    for line in data.splitlines(keepends=True):
        body = line.rstrip(b"\r\n")
        if _is_cargo_status_line(body):
            continue
        out.append(_V2_FINISHED_IN.sub(b"finished in <dur>", line))
    return b"".join(out)


def cargo_test_v2_removed_diag(data: bytes) -> dict:
    """Diagnostic evidence: number + SHA-256 of the removed Cargo-status lines (the
    removed bytes remain available in the primary raw capture)."""
    removed = [line for line in data.splitlines(keepends=True)
               if _is_cargo_status_line(line.rstrip(b"\r\n"))]
    joined = b"".join(removed)
    return {"removed_line_count": len(removed),
            "removed_sha256": hashlib.sha256(joined).hexdigest(),
            "removed_bytes": len(joined)}


_POLICIES["cargo-test-v2"] = _cargo_test_v2_canon


# --------------------------------------------------------------------------
# cargo-test-v3: cargo-test-v2 UNCHANGED, plus EXACTLY ONE additional rule. cargo-test-v2 is
# left byte-for-byte intact (a separate immutable callable) so every existing v2 record keeps
# its exact meaning -- v3 is a NEW policy id, never an in-place mutation of v2.
#
# The one added rule normalizes the wall-clock duration inside RTK's cargo-test COMPACT ALL-PASS
# summary, whose exact source grammar (rust RTK @5d32d07 AggregatedTestResult::format_compact) is:
#     cargo test: {N} passed[, {I} ignored][, {F} filtered out} (<K> suite(s), <D.DD>s)
# The rule is anchored to that COMPLETE line (counts + suite clause + trailing "<D.DD>s)$"); it
# rewrites ONLY the duration to <dur>. It is NOT a generic "\d+\.\d+s" replacement: an out-of-grammar
# duration, a failure/build/no-summary line, a trailing tail after ")", or the no-duration compact
# form "(K suites)" are all left byte-identical. Suite count and every test count are preserved.
_V3_RTK_COMPACT_ALLPASS_DUR = re.compile(
    rb"^(cargo test: \d+ passed(?:, \d+ ignored)?(?:, \d+ filtered out)? "
    rb"\(\d+ suites?, )\d+\.\d+s(\))$", re.MULTILINE)


def _cargo_test_v3_canon(data: bytes) -> bytes:
    """cargo-test-v2 canon, then normalize ONLY the RTK compact all-pass summary duration."""
    data = _cargo_test_v2_canon(data)
    return _V3_RTK_COMPACT_ALLPASS_DUR.sub(rb"\1<dur>\2", data)


_POLICIES["cargo-test-v3"] = _cargo_test_v3_canon


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


def policy_definition_sha256(policy_id: str) -> str:
    """Deterministic hash of a canonicalization policy's DEFINITION (its exact rule set), so a frozen
    qualification record can pin the policy BYTES -- not just the id string -- and any later change to
    that policy (even in place, keeping the same id) is DETECTED as drift rather than silently changing
    the record's meaning. A callable policy is pinned by its qualified name; a rule list is pinned by
    each (pattern-bytes, flags, replacement) triple in order (replacement callables by qualified name)."""
    import hashlib
    if policy_id not in _POLICIES:
        raise KeyError(f"unknown canonicalization policy {policy_id!r}")
    spec = _POLICIES[policy_id]
    parts: list[bytes] = [policy_id.encode()]
    if callable(spec):
        parts.append(b"callable:" + f"{spec.__module__}.{spec.__qualname__}".encode())
    else:
        for pat, repl in spec:
            parts.append(b"pat:" + pat.pattern if isinstance(pat.pattern, bytes)
                         else b"pat:" + pat.pattern.encode())
            parts.append(b"flags:" + str(int(pat.flags)).encode())
            if isinstance(repl, bytes):
                parts.append(b"repl:" + repl)
            elif isinstance(repl, str):
                parts.append(b"repl:" + repl.encode())
            else:  # callable replacement
                parts.append(b"repl-callable:" + f"{repl.__module__}.{repl.__qualname__}".encode())
    return hashlib.sha256(b"\x00".join(parts)).hexdigest()
