#!/usr/bin/env python3
"""rtk-rust-cargo-test-summary-v1: the Rust cargo-test RTK dialect, defined FROM the pinned RTK
implementation (rtk-ai/rtk @5d32d07, src/cmds/rust/cargo_cmd.rs: filter_cargo_test +
AggregatedTestResult), then validated against the real captured streams. NOT inferred from one
success fixture.

Source-grounded semantics (each rule maps to a line of the pinned filter_cargo_test):
  * ALL-PASS compact summary is produced ONLY by aggregating `test result: ok.` lines
    (AggregatedTestResult::parse_line returns None for a non-`ok` status), so a FAILED suite can
    NEVER enter the all-pass path. Counts are SUMMED across suites; the suite count is counted;
    has_duration is CONJUNCTIVE across suites. format_compact emits:
        cargo test: {passed} passed[, {ignored} ignored][, {filtered_out} filtered out]
                    ({K} suite(s)[, {D.DD}s])
    It NEVER emits `failed` or `measured` (all-pass => failed 0; measured is dropped).
  * FAILURE form: `FAILURES ({n}):` numbered failure blocks (each `---- <id> stdout ----` ...),
    then the raw `test result: FAILED. ...` summary lines. Failing identities are preserved.
  * COMPILE-ERROR form: routed through the build projection (`cargo test (... crates compiled)` /
    `cargo test: failed (exit N)` with `error[..]`/`error:` diagnostics) -- DISTINCT from a test
    failure.
  * NO terminal summary => fallback to the last meaningful lines; it NEVER manufactures a PASS.

Three structurally distinct layers (never conflated): captured bytes -> execution binding ->
semantic projection. This module is the SEMANTIC PROJECTION + the RAW<->RTK equivalence predicate.

Allowed normalizations (the ONLY presentation noise treated as non-semantic), enumerated
explicitly: elapsed DURATION (RTK compact `<dur>` / native `finished in <dur>`), ANSI SGR escape
sequences, CR in CRLF line endings, and cargo build-PROGRESS lines (Compiling/Finished/... handled
by cargo-test-v3). NOTHING else is normalized -- counts, statuses, failing ids, suite counts, and
terminal-summary presence are all semantic.
"""
from __future__ import annotations

import re

DIALECT_ID = "rtk-rust-cargo-test-summary-v1"
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
RTK_SOURCE_FILE = "src/cmds/rust/cargo_cmd.rs"

# ---- explicitly enumerated allowed (non-semantic) normalizations ----
_ANSI = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")            # ANSI SGR / cursor escapes
_DUR_NATIVE = re.compile(rb"finished in \d+\.\d+s")      # native cargo test-result duration


def _strip_presentation(data: bytes) -> bytes:
    """Remove ONLY the enumerated presentation noise: ANSI escapes, CR of CRLF, and durations.
    Everything else (counts, statuses, ids, suite counts) is preserved byte-for-byte."""
    data = _ANSI.sub(b"", data)
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    data = _DUR_NATIVE.sub(b"finished in <dur>", data)
    data = re.sub(rb"(\(\d+ suites?, )(?:<dur>|\d+\.\d+s)(\))", rb"\1<dur>\2", data)
    return data


def _proj(outcome, passed=None, failed=None, ignored=None, measured=None, filtered_out=None,
          suites=None, failing_ids=None, terminal_summary_present=False, compile_failure=False,
          truncated=False):
    return {"outcome": outcome, "passed": passed, "failed": failed, "ignored": ignored,
            "measured": measured, "filtered_out": filtered_out, "suites": suites,
            "failing_ids": sorted(failing_ids or []),
            "terminal_summary_present": terminal_summary_present,
            "compile_failure": compile_failure, "truncated": truncated}


# ============================ RTK dialect parser ============================
# ALL-PASS compact form (exact format_compact grammar; duration already <dur> after normalization).
_RTK_COMPACT = re.compile(
    rb"^cargo test: (\d+) passed(?:, (\d+) ignored)?(?:, (\d+) filtered out)? "
    rb"\((\d+) suites?(?:, <dur>)?\)$", re.MULTILINE)
_RTK_FAILURES_HDR = re.compile(rb"^FAILURES \((\d+)\):$", re.MULTILINE)
_RTK_FAILED_SUMMARY = re.compile(
    rb"test result: FAILED\.\s+(\d+) passed;\s+(\d+) failed;\s+(\d+) ignored;\s+(\d+) measured;"
    rb"\s+(\d+) filtered out")
# a failing identity as it survives in RTK's preserved failure block: "---- <id> stdout ----"
_FAIL_BLOCK_ID = re.compile(rb"----\s+(\S+)\s+stdout\s+----")
# compile-error build projection (filter_cargo_build_labeled): "cargo test (N crates compiled)"
# / "cargo test: failed (exit N)" accompanied by rustc diagnostics
_RTK_BUILD = re.compile(rb"^cargo test(?: \(\d+ crates? compiled\)| \(\d+ errors?[^)]*\)|: failed \(exit \d+\))",
                        re.MULTILINE)
_RUSTC_ERR = re.compile(rb"(?m)^\s*error(?:\[[A-Z]\d+\])?:")


def parse_rtk(data: bytes) -> dict:
    """Semantic projection of an RTK-filtered cargo-test stream (raw or v3-canonical)."""
    d = _strip_presentation(data)
    # truncation: a non-empty stream that ends without a newline is a truncated capture
    truncated = bool(d) and not d.endswith(b"\n")

    compact = _RTK_COMPACT.search(d)
    failures = _RTK_FAILURES_HDR.search(d)
    # RTK's failure output preserves the RAW `test result:` summary lines verbatim (one per suite)
    result_lines = _RAW_RESULT.findall(d)
    build = _RTK_BUILD.search(d)

    # compile failure is DISTINCT and takes precedence over a (missing) test summary. It carries
    # NO test terminal summary.
    if build or (_RUSTC_ERR.search(d) and not compact and not result_lines):
        return _proj("compile_failure", compile_failure=True, terminal_summary_present=False,
                     truncated=truncated,
                     failing_ids=[i.decode("utf-8", "replace") for i in _FAIL_BLOCK_ID.findall(d)])

    if failures or any(s == b"FAILED" for s, *_ in result_lines):
        # aggregate the preserved `test result:` lines exactly as the native stream would
        ids = sorted(set(i.decode("utf-8", "replace") for i in _FAIL_BLOCK_ID.findall(d)))
        p = f = ig = me = fi = 0
        for _st, pp, ff, gg, mm, oo in result_lines:
            p += int(pp); f += int(ff); ig += int(gg); me += int(mm); fi += int(oo)
        suites = len(result_lines) or None
        return _proj("failure", passed=(p if result_lines else None),
                     failed=(f if result_lines else None), ignored=(ig if result_lines else None),
                     measured=(me if result_lines else None), filtered_out=(fi if result_lines else None),
                     suites=suites, failing_ids=ids, terminal_summary_present=bool(result_lines),
                     truncated=truncated)

    if compact:
        # exactly ONE compact summary is the valid all-pass terminal; more than one is malformed
        if len(_RTK_COMPACT.findall(d)) != 1:
            return _proj("incomplete", terminal_summary_present=False, truncated=truncated)
        passed = int(compact.group(1))
        ignored = int(compact.group(2)) if compact.group(2) else 0
        filtered = int(compact.group(3)) if compact.group(3) else 0
        suites = int(compact.group(4))
        # all-pass => failed 0; format_compact drops measured (measured None = "not presented")
        return _proj("success", passed=passed, failed=0, ignored=ignored, measured=None,
                     filtered_out=filtered, suites=suites, failing_ids=[],
                     terminal_summary_present=True, truncated=truncated)

    # no compact, no failure, no build projection -> incomplete; NEVER success
    return _proj("incomplete", terminal_summary_present=False, truncated=truncated)


# ============================ native cargo (RAW) parser ============================
_RAW_RESULT = re.compile(
    rb"test result: (ok|FAILED)\.\s+(\d+) passed;\s+(\d+) failed;\s+(\d+) ignored;"
    rb"\s+(\d+) measured;\s+(\d+) filtered out")
_RAW_FAIL_LINE = re.compile(rb"(?m)^test (\S+) \.\.\. FAILED$")
_RAW_FAILURES_SECTION = re.compile(rb"(?ms)^failures:\n(.*?)(?:\n\ntest result:|\Z)")
_RAW_FAILSEC_ID = re.compile(rb"(?m)^    (\S+)$")


def parse_raw(data: bytes) -> dict:
    """Semantic projection of a native cargo-test stream (raw or canonical)."""
    d = _strip_presentation(data)
    truncated = bool(d) and not d.endswith(b"\n")
    results = _RAW_RESULT.findall(d)
    has_compile_err = bool(_RUSTC_ERR.search(d))

    if not results:
        if has_compile_err:
            return _proj("compile_failure", compile_failure=True, terminal_summary_present=False,
                         truncated=truncated)
        return _proj("incomplete", terminal_summary_present=False, truncated=truncated)

    passed = failed = ignored = measured = filtered = 0
    all_ok = True
    for status, p, f, ig, me, fi in results:
        if status != b"ok":
            all_ok = False
        passed += int(p); failed += int(f); ignored += int(ig)
        measured += int(me); filtered += int(fi)
    suites = len(results)

    ids = set(i.decode("utf-8", "replace") for i in _RAW_FAIL_LINE.findall(d))
    for sec in _RAW_FAILURES_SECTION.findall(d):
        for i in _RAW_FAILSEC_ID.findall(sec):
            ids.add(i.decode("utf-8", "replace"))

    outcome = "success" if (all_ok and failed == 0) else "failure"
    # a compile error alongside a partial result still classifies as compile_failure only when
    # there is NO test result at all (handled above); with results present it is a test outcome.
    return _proj(outcome, passed=passed, failed=failed, ignored=ignored, measured=measured,
                 filtered_out=filtered, suites=suites, failing_ids=sorted(ids),
                 terminal_summary_present=True, truncated=truncated)


# ============================ RAW <-> RTK equivalence ============================
def equivalence(raw: dict, rtk: dict) -> dict:
    """Narrow, source-grounded equivalence: RTK compression may drop presentation noise but must
    preserve process success/failure, compile-vs-test failure, totals (where present), every
    failing identity, terminal-summary presence, and truncation state. Returns
    {equivalent: bool, mismatches: [...]}. Duration is presentation metadata (never compared)."""
    m = []

    def eq(field, a, b, allow_rtk_none_when_zero=False):
        if allow_rtk_none_when_zero and b is None:
            if a not in (0, None):
                m.append(f"{field}: RTK omitted but RAW={a} (>0 loss)")
            return
        if a != b:
            m.append(f"{field}: RAW={a} RTK={b}")

    # process success/failure + compile-vs-test distinction
    if raw["outcome"] != rtk["outcome"]:
        m.append(f"outcome: RAW={raw['outcome']} RTK={rtk['outcome']}")
    if raw["compile_failure"] != rtk["compile_failure"]:
        m.append(f"compile_failure: RAW={raw['compile_failure']} RTK={rtk['compile_failure']}")
    # totals where present in BOTH (RTK all-pass omits measured -> allowed only when RAW measured==0)
    eq("passed", raw["passed"], rtk["passed"])
    eq("failed", raw["failed"], rtk["failed"])
    eq("ignored", raw["ignored"], rtk["ignored"])
    eq("filtered_out", raw["filtered_out"], rtk["filtered_out"])
    eq("measured", raw["measured"], rtk["measured"], allow_rtk_none_when_zero=True)
    eq("suites", raw["suites"], rtk["suites"])
    # every failing identity preserved
    if raw["failing_ids"] != rtk["failing_ids"]:
        m.append(f"failing_ids: RAW={raw['failing_ids']} RTK={rtk['failing_ids']}")
    # a valid terminal summary must be present/absent identically (no manufactured summary)
    if raw["terminal_summary_present"] != rtk["terminal_summary_present"]:
        m.append(f"terminal_summary_present: RAW={raw['terminal_summary_present']} "
                 f"RTK={rtk['terminal_summary_present']}")
    if raw["truncated"] != rtk["truncated"]:
        m.append(f"truncated: RAW={raw['truncated']} RTK={rtk['truncated']}")
    return {"equivalent": not m, "mismatches": m}
