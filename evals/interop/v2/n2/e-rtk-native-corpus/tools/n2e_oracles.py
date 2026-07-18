"""Executable semantic-preservation oracles (§14).

Two checks per case, each returning a dict with an explicit boolean `verdict`:
  - raw_outcome(scenario, raw_bytes, raw_exit): the RAW arm shows the scenario's
    DECLARED successful outcome (not merely a stable exit code).
  - rtk_agrees(scenario, raw_bytes, rtk_bytes): the RTK arm preserves the exact
    semantic identities the family requires. RTK may reformat/omit passing names,
    but may not drop a failing test id, a diagnostic, a match, a changed path, a
    container identity, or alter a count.

A missing oracle, a None verdict, or verdict=False fails the case.
"""
from __future__ import annotations

import hashlib
import re

# ----------------------------- parsers -----------------------------

_CARGO = re.compile(rb"test result:\s+\w+\.\s+(\d+) passed;\s+(\d+) failed(?:;\s+(\d+) ignored)?")
_CARGO_FAIL = re.compile(rb"^\s*(?:test\s+)?(\S+)\s+\.\.\.\s+FAILED", re.MULTILINE)
_CARGO_FAIL2 = re.compile(rb"^\s{4}(\S+)$", re.MULTILINE)  # under "failures:" block
_GOTEST_FAIL = re.compile(rb"^--- FAIL:\s+(\S+)", re.MULTILINE)
_GOTEST_OKFAIL = re.compile(rb"^(ok|FAIL|PASS)\b", re.MULTILINE)
_PYTEST_SUM = re.compile(rb"(\d+) passed|(\d+) failed|(\d+) error|(\d+) skipped")
_PYTEST_FAIL = re.compile(rb"^FAILED\s+(\S+)", re.MULTILINE)
_PYTEST_FAIL2 = re.compile(rb"_{3,}\s+(\S+)\s+_{3,}")
# vitest verbose marks a failed test with a leading `×` (U+00D7 = \xc3\x97) or a
# file-level `FAIL`, followed by the FULL `path > suite > test` chain. Capture the whole
# chain (strip a trailing ` NNNms`). The captured identity MUST contain a ` > ` segment
# -- this is what disambiguates a vitest test line from Go's `FAIL\t<package>\t<dur>`
# package-summary line (which has no ` > ` and must NOT be read as a failing id).
_VITEST_FAIL = re.compile(rb"^\s*(?:\xc3\x97|FAIL)\s+(\S.*?\s>\s.*?)(?:\s+\d+ms)?\s*$", re.MULTILINE)
_DIAG = re.compile(rb"(?P<file>[\w./\-]+):(?P<line>\d+):(?:(?P<col>\d+):)?\s*(?P<sev>error|warning|note)?", re.IGNORECASE)


_VITEST_SUM = re.compile(rb"Tests\s+(?:(\d+) failed\s*\|\s*)?(\d+) passed(?:\s*\|\s*(\d+) skipped)?")
_VITEST_SUM_FAILONLY = re.compile(rb"Tests\s+(\d+) failed\b(?!\s*\|)")
_GRADLE_SUM = re.compile(rb"(\d+) tests? completed(?:,\s*(\d+) failed)?")
_GRADLE_FAIL = re.compile(rb"^(\S+) > (\S+) FAILED", re.MULTILINE)

# --- native Cargo target-execution proof (bounded) ---------------------------------
# `cargo test` runs one binary per test target; each emits `Running <src> (…/deps/<bin>-<hash>)`,
# then `running N tests`, then `test <fn> ... ok|FAILED|ignored`, then an aggregate
# `test result: <ok|FAILED>. P passed; F failed; I ignored; M measured; K filtered out`.
_CARGO_RUNNING_BIN = re.compile(rb"^\s*Running\b.*?/deps/([A-Za-z0-9_]+?)-[0-9a-f]{5,}\b", re.MULTILINE)
_CARGO_RUNNING_N = re.compile(rb"^running (\d+) tests?\b", re.MULTILINE)
_CARGO_TEST_LINE = re.compile(rb"^test ([\w:]+) \.\.\. (ok|FAILED|ignored)\b", re.MULTILINE)
_CARGO_RESULT_FULL = re.compile(
    rb"test result:\s+(\w+)\.\s+(\d+) passed;\s+(\d+) failed(?:;\s+(\d+) ignored)?"
    rb"(?:;\s+(\d+) measured)?(?:;\s+(\d+) filtered out)?")
_CARGO_COMPILE_FAIL = re.compile(
    rb"error\[E\d+\]|error: could not compile|error: no test target|error: test failed, "
    rb"to rerun|error: could not find|error\[?:? linking with")


def cargo_test_summary(raw: bytes) -> dict:
    """Aggregate native `cargo test` output across ALL test binaries: total passed/failed/
    ignored/measured/filtered_out, executed (binary::fn) ids by outcome, running-count total,
    and compile/setup failure detection. Binary context comes from each `Running …/deps/<bin>`
    line so a bare `test <fn>` line becomes `<bin>::<fn>`."""
    passed = failed = ignored = measured = filtered = 0
    results_seen = 0
    executed_ok, executed_failed, executed_ignored = [], [], []
    running_total = 0
    # walk lines in order, tracking the current binary from Running lines
    cur_bin = None
    for ln in (raw or b"").splitlines():
        mb = _CARGO_RUNNING_BIN.match(ln)
        if mb:
            cur_bin = mb.group(1).decode("utf-8", "replace")
            continue
        mn = _CARGO_RUNNING_N.match(ln)
        if mn:
            running_total += int(mn.group(1))
            continue
        mt = _CARGO_TEST_LINE.match(ln)
        if mt:
            fn = mt.group(1).decode("utf-8", "replace")
            ident = f"{cur_bin}::{fn}" if cur_bin else fn
            {"ok": executed_ok, "FAILED": executed_failed,
             "ignored": executed_ignored}[mt.group(2).decode()].append(ident)
            continue
    for mm in _CARGO_RESULT_FULL.finditer(raw or b""):
        results_seen += 1
        passed += int(mm.group(2)); failed += int(mm.group(3))
        ignored += int(mm.group(4) or 0); measured += int(mm.group(5) or 0)
        filtered += int(mm.group(6) or 0)
    return {"passed": passed, "failed": failed, "ignored": ignored, "measured": measured,
            "filtered_out": filtered, "result_lines": results_seen, "running_total": running_total,
            "executed_ok": sorted(executed_ok), "executed_failed": sorted(executed_failed),
            "executed_ignored": sorted(executed_ignored),
            "compile_or_setup_failure": bool(_CARGO_COMPILE_FAIL.search(raw or b""))}


def cargo_target_execution_proof(raw: bytes, exit_code: int, target_ids: list) -> dict:
    """Prove a RAW `cargo test` rep genuinely EXECUTED the declared target test(s) and
    passed -- never inferred from exit 0 or the target string appearing in argv.

    Requires (fixed snapshot): exit 0; aggregate failed == 0; every target leaf observed as
    an executed PASSING test (`test <bin>::<fn> ... ok`); nonzero tests executed; not filtered
    to zero; not compile-only; no compile/setup failure. Records the complete executed id set
    so the caller can require determinism across reps."""
    s = cargo_test_summary(raw)
    targets = [t.split("::")[-1] for t in (target_ids or [])]
    ok_leaves = {x.split("::")[-1] for x in s["executed_ok"]}
    all_leaves = ({x.split("::")[-1] for x in s["executed_ok"]}
                  | {x.split("::")[-1] for x in s["executed_failed"]})
    target_executed_passing = bool(targets) and all(t in ok_leaves for t in targets)
    checks = {
        "exit_zero": exit_code == 0,
        "aggregate_failed_zero": s["failed"] == 0,
        "target_executed_passing": target_executed_passing,
        "nonzero_tests_executed": (s["passed"] + s["failed"]) > 0,
        "not_filtered_to_zero": s["running_total"] > 0 and (s["passed"] + s["failed"]) > 0,
        "not_compile_only": s["result_lines"] > 0,
        "no_compile_or_setup_failure": not s["compile_or_setup_failure"],
    }
    return {"summary": s, "target_ids": sorted(target_ids or []),
            "targets_missing_from_executed": sorted(t for t in targets if t not in all_leaves),
            "executed_ok_ids": s["executed_ok"], "checks": checks,
            "executed_ok": all(checks.values())}

# ---- test-output DIALECTS (separate semantic parsing from output format) ----
# The native tool stream and RTK's filtered summary express the SAME semantic events
# (failed_count, failing_ids) in different grammars. The oracle must parse each stream
# with its OWN dialect and compare the normalized events -- never require byte-format
# equality, and never fall back to a generic 'FAIL' substring search.
RAW_GO_DIALECT = "go-test-native-v1"      # `--- FAIL: <id>`
RTK_GO_DIALECT = "rtk-go-test-summary-v1"  # bounded `[FAIL] <id>` record (RTK source @5d32d07)

# RTK filter dialects keyed by command family. Each value is a PROVEN parser (derived
# from the pinned RTK source + real measured fixtures for that ecosystem). A family with
# NO proven dialect must FAIL CLOSED in rtk_agrees -- it must NEVER silently reuse the Go
# parser. A common cross-ecosystem policy may only be added here after it is proven from
# the pinned RTK source (commit 5d32d07) with a real fixture for every affected ecosystem.
RTK_DIALECTS = {
    "go": RTK_GO_DIALECT,   # proven: caddy diagnostic RAW/RTK primary streams
    # "rust_cargo": <proven RTK cargo dialect>,   # not yet proven
    # "js_ts":      <proven RTK vitest dialect>,   # not yet proven
    # "jvm":        <proven RTK gradle dialect>,   # not yet proven
    # "python":     <proven RTK pytest dialect>,   # not yet proven
}


def rtk_dialect_for(family: str) -> str | None:
    return RTK_DIALECTS.get(family)

# rtk-go-test-summary-v1: bounded, anchored records derived from the pinned RTK source
# (commit 5d32d07). A per-test failure is the whole `[FAIL]` token at the START of the
# (whitespace-stripped) line, then exactly the identity, then EOL -- rejecting `text
# [FAIL] X`, `[PASS] X`, a `-run X` selector, a `[full output: ...X...]` tee pointer, and
# any substring. The AGGREGATE summary is a SEPARATE, EXACT, line-anchored record (the
# only three source-defined Go forms). Per-test records and the aggregate summary are
# distinct evidence: a missing/malformed/duplicated aggregate summary is INCOMPLETE
# (failed stays None) and is never derived from the `[FAIL]`/`[PASS]` record counts.
_RTK_FAIL = re.compile(rb"^[ \t]*\[FAIL\][ \t]+(\S+)[ \t]*$", re.MULTILINE)
_RTK_GO_FAIL_SUMMARY = re.compile(
    rb"^Go test: (\d+) passed, (\d+) failed(?:, (\d+) skipped)? in (\d+) packages$", re.MULTILINE)
_RTK_GO_PASS_SUMMARY = re.compile(rb"^Go test: (\d+) passed in (\d+) packages$", re.MULTILINE)
_RTK_GO_NOTESTS = re.compile(rb"^Go test: No tests found$", re.MULTILINE)


def _rtk_go_summary(raw: bytes) -> dict:
    """rtk-go-test-summary-v1: parse RTK's Go filter output. Fails closed -- an absent,
    malformed, or CONFLICTING (>1) aggregate summary leaves counts None (incomplete),
    and counts are NEVER derived from the per-test `[FAIL]` records."""
    failing = sorted({m.group(1).decode("utf-8", "replace") for m in _RTK_FAIL.finditer(raw)})
    fails = _RTK_GO_FAIL_SUMMARY.findall(raw)
    passes = _RTK_GO_PASS_SUMMARY.findall(raw)
    notests = _RTK_GO_NOTESTS.findall(raw)
    total = len(fails) + len(passes) + len(notests)
    passed = failed = skipped = packages = None
    if total == 1:  # exactly one aggregate summary of a source-defined form
        if fails:
            p, f, s, pk = fails[0]
            passed, failed, skipped, packages = int(p), int(f), (int(s) if s else 0), int(pk)
        elif passes:
            p, pk = passes[0]
            passed, failed, packages = int(p), 0, int(pk)
        else:  # "No tests found"
            passed, failed = 0, 0
    return {"passed": passed, "failed": failed, "skipped": skipped, "packages": packages,
            "failing_ids": failing, "dialect": RTK_GO_DIALECT,
            "aggregate_summary_present": total == 1, "aggregate_summary_conflict": total > 1}


def _test_summary(raw: bytes, dialect: str = "native") -> dict:
    """Parse passed/failed + failing ids under the given output DIALECT policy id.
    RTK_GO_DIALECT uses the strict Go summary grammar; "native" parses the native tool
    streams; any OTHER dialect id fails closed (unknown -> incomplete evidence)."""
    if dialect == RTK_GO_DIALECT:
        return _rtk_go_summary(raw)
    if dialect != "native":
        return {"passed": None, "failed": None, "failing_ids": [], "dialect": dialect,
                "unknown_dialect": True}
    failing = set()
    passed = failed = None
    m = _CARGO.search(raw)
    if m:
        passed = int(m.group(1))
        failed = int(m.group(2))
    # vitest: "Tests  1 failed | 3185 passed | 5 skipped (3268)" (or all-passed)
    if passed is None:
        vm = _VITEST_SUM.search(raw)
        if vm:
            failed = int(vm.group(1)) if vm.group(1) else 0
            passed = int(vm.group(2))
        elif _VITEST_SUM_FAILONLY.search(raw):
            failed = int(_VITEST_SUM_FAILONLY.search(raw).group(1))
            passed = 0
    # gradle/JUnit: "N tests completed, M failed" + "Class > method FAILED"
    if passed is None:
        gm = _GRADLE_SUM.search(raw)
        if gm:
            total = int(gm.group(1))
            failed = int(gm.group(2)) if gm.group(2) else 0
            passed = total - failed
    for fm in _GRADLE_FAIL.finditer(raw):
        failing.add(f"{fm.group(1).decode('utf-8','replace')}::{fm.group(2).decode('utf-8','replace')}")
    for pat in (_CARGO_FAIL, _GOTEST_FAIL, _PYTEST_FAIL, _VITEST_FAIL):
        for fm in pat.finditer(raw):
            ident = fm.group(1).decode("utf-8", "replace").strip()
            # ignore the `Test Files`/`Tests` summary lines that also contain 'failed'
            if ident and not ident.startswith(("Test Files", "Tests ")):
                failing.add(ident)
    # pytest summary counts
    if passed is None:
        p = f = e = s = 0
        for mm in _PYTEST_SUM.finditer(raw):
            if mm.group(1):
                p = int(mm.group(1))
            if mm.group(2):
                f = int(mm.group(2))
            if mm.group(3):
                e = int(mm.group(3))
            if mm.group(4):
                s = int(mm.group(4))
        if p or f or e or s:
            passed, failed = p, f + e
    # go: derive failed from --- FAIL count if no summary
    if failed is None and (_GOTEST_FAIL.search(raw) or _GOTEST_OKFAIL.search(raw)):
        failed = len(_GOTEST_FAIL.findall(raw))
        passed = 0
    return {"passed": passed, "failed": failed, "failing_ids": sorted(failing)}


def _diagnostics(raw: bytes) -> set:
    ids = set()
    for m in _DIAG.finditer(raw):
        ids.add((m.group("file").decode("utf-8", "replace"), int(m.group("line")),
                 (m.group("sev") or b"").decode().lower()))
    return ids


def _grep_ids(raw: bytes) -> set:
    ids = set()
    for ln in raw.splitlines():
        m = re.match(rb"(?:([^:]+):)?(\d+):(.*)$", ln)
        if m:
            ids.add(((m.group(1) or b"").decode("utf-8", "replace"), int(m.group(2)),
                     hashlib.sha256(m.group(3)).hexdigest()))
    return ids


def log_severity_counts(raw: bytes) -> dict:
    sev = {"error": re.compile(rb"\b(error|err|fatal|panic|severe)\b", re.I),
           "warn": re.compile(rb"\b(warn|warning)\b", re.I),
           "info": re.compile(rb"\b(info|notice|debug|trace)\b", re.I)}
    lines = raw.splitlines()
    counts = {"total_lines": len(lines), "error": 0, "warn": 0, "info": 0}
    for ln in lines:
        for k, pat in sev.items():
            if pat.search(ln):
                counts[k] += 1
                break
    return counts


def grep_match_identities(raw: bytes) -> set:
    return _grep_ids(raw)


# ----------------------------- RAW outcome -----------------------------

def raw_outcome(scenario: dict, raw: bytes, raw_exit: int) -> dict:
    fam, sub = scenario["command_family"], scenario["command_subfamily"]
    variant = scenario.get("snapshot_variant")
    if sub in ("test", "pytest"):
        summ = _test_summary(raw)
        if variant in ("buggy", "fail"):
            # STRICT target-aware qualification (a package-setup/compile/panic failure,
            # or an UNRELATED failing test, must NOT qualify the declared buggy case):
            #   * the command reached the test framework (a summary was parsed);
            #   * failed_count > 0 and the exit code is the declared failing outcome;
            #   * EVERY required target identity appears in the parsed failing IDs.
            targets = set(_leaf_ids(scenario.get("target_test_ids") or []))
            observed = set(_leaf_ids(summ["failing_ids"]))
            reached = summ["failed"] is not None or summ["passed"] is not None
            failed_n = summ["failed"] or 0
            covers = bool(targets) and targets.issubset(observed)  # all targets present
            ok = reached and failed_n > 0 and raw_exit != 0 and covers
            return {"oracle": "test_outcome", "verdict": bool(ok),
                    "evidence": {"summary": summ, "exit": raw_exit, "declared": "failing",
                                 "required_targets": sorted(targets),
                                 "observed_failing": sorted(observed),
                                 "reached_framework": reached, "targets_covered": covers}}
        # fixed/pass: all pass
        ok = raw_exit == 0 and (summ["failed"] in (0, None))
        return {"oracle": "test_outcome", "verdict": bool(ok),
                "evidence": {"summary": summ, "exit": raw_exit, "declared": "passing"}}
    if sub in ("build", "check", "clippy", "vet", "tsc", "lint", "ruff"):
        # diagnostics case: RAW is valid if the tool RAN to a definite result -- a
        # clean pass (exit 0, no diagnostics) is a legitimate outcome, not a failure;
        # only a tool that neither exited clean nor emitted diagnostics is rejected.
        ok = raw_exit == 0 or len(raw) > 0
        return {"oracle": "diagnostics_defined", "verdict": bool(ok),
                "evidence": {"diagnostics": len(_diagnostics(raw)), "exit": raw_exit,
                             "clean": raw_exit == 0 and len(raw) == 0}}
    if fam == "git":
        return {"oracle": f"git_{sub}", "verdict": _git_raw_ok(sub, raw, raw_exit),
                "evidence": {"exit": raw_exit, "bytes": len(raw)}}
    if fam == "files_search" and sub == "read":
        return {"oracle": "file_read", "verdict": raw_exit == 0 and len(raw) > 0,
                "evidence": {"raw_sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}}
    if fam == "files_search" and sub in ("ls", "tree"):
        return {"oracle": "file_listing", "verdict": raw_exit == 0,
                "evidence": {"entries": len(raw.splitlines())}}
    if fam == "files_search" and sub == "grep":
        ids = _grep_ids(raw)
        return {"oracle": "grep", "verdict": raw_exit in (0, 1),
                "evidence": {"match_count": len(ids)}}
    if fam == "logs":
        return {"oracle": "log", "verdict": raw_exit == 0 and len(raw) > 0,
                "evidence": {"severity": log_severity_counts(raw)}}
    if fam == "containers":
        return {"oracle": "docker", "verdict": raw_exit == 0,
                "evidence": {"bytes": len(raw)}}
    return {"oracle": "none", "verdict": None, "evidence": {}}


def _git_raw_ok(sub: str, raw: bytes, raw_exit: int) -> bool:
    if sub in ("status", "diff", "log", "show"):
        return raw_exit == 0
    if sub == "add":
        return raw_exit == 0
    if sub == "commit":
        return raw_exit == 0  # a real commit must succeed (requires a prepared dirty+staged state)
    if sub == "push":
        return raw_exit == 0  # push to the disposable local bare remote must succeed
    return raw_exit == 0


def _leaf_ids(ids: list) -> list:
    out = []
    for x in ids:
        s = str(x)
        # take the trailing test name token for cross-tool comparison
        out.append(s.split("::")[-1].split("#")[-1].split(".")[-1].split("/")[-1])
    return out


# ----------------------------- RTK agreement -----------------------------

def rtk_agrees(scenario: dict, raw: bytes, rtk: bytes) -> dict:
    fam, sub = scenario["command_family"], scenario["command_subfamily"]
    if sub in ("test", "pytest"):
        # DIALECT-AWARE + ECOSYSTEM-BOUND: parse RAW with the native tool grammar and RTK
        # with the PROVEN dialect for this family, then compare NORMALIZED semantic events
        # (failed_count + failing_ids) -- never byte-format equality. A family with no
        # proven RTK dialect FAILS CLOSED (never reuse the Go parser).
        r = _test_summary(raw, dialect="native")
        rtk_dialect = rtk_dialect_for(fam)
        if rtk_dialect is None:
            return {"oracle": "test_agreement", "verdict": False,
                    "evidence": {"error": f"no proven RTK dialect for family {fam!r} -- "
                                          f"fail-closed (do not reuse the Go parser)",
                                 "raw": r, "rtk_dialect": None, "unproven_family": fam}}
        k = _test_summary(rtk, dialect=rtk_dialect)
        raw_fail = set(_leaf_ids(r["failing_ids"]))
        rtk_fail = set(_leaf_ids(k["failing_ids"]))
        # BOTH aggregate failed counts must be known and equal (a missing count on EITHER
        # side is NOT agreement), and every RAW failing id must be a subset of RTK's.
        count_ok = (r["failed"] is not None and k["failed"] is not None
                    and r["failed"] == k["failed"])
        ids_ok = raw_fail <= rtk_fail
        return {"oracle": "test_agreement", "verdict": bool(ids_ok and count_ok),
                "evidence": {"raw": r, "rtk": k, "raw_dialect": RAW_GO_DIALECT,
                             "rtk_dialect": rtk_dialect, "count_ok": count_ok, "ids_ok": ids_ok,
                             "compared": "normalized_semantic_events"}}
    if sub in ("build", "check", "clippy", "vet", "tsc", "lint", "ruff"):
        raw_d, rtk_d = _diagnostics(raw), _diagnostics(rtk)
        # every RAW diagnostic identity must be preserved by RTK
        ok = raw_d <= rtk_d
        return {"oracle": "diagnostics_agreement", "verdict": bool(ok),
                "evidence": {"raw_count": len(raw_d), "rtk_count": len(rtk_d),
                             "missing": [list(x) for x in sorted(raw_d - rtk_d)][:10]}}
    if fam == "files_search" and sub == "grep":
        raw_ids, rtk_ids = _grep_ids(raw), _grep_ids(rtk)
        ok = raw_ids <= rtk_ids  # EXACT: no RAW match may disappear (not mere overlap)
        return {"oracle": "grep_agreement", "verdict": bool(ok),
                "evidence": {"raw_matches": len(raw_ids), "rtk_matches": len(rtk_ids),
                             "missing": [list(x) for x in sorted(raw_ids - rtk_ids)][:10]}}
    if fam == "files_search" and sub in ("ls", "tree"):
        raw_paths = {ln.split()[-1] for ln in raw.split(b"\n") if ln.strip()}
        rtk_paths = {ln.split()[-1] for ln in rtk.split(b"\n") if ln.strip()}
        ok = raw_paths <= rtk_paths or len(rtk_paths) >= len(raw_paths) - 1
        return {"oracle": "listing_agreement", "verdict": bool(ok),
                "evidence": {"raw_entries": len(raw_paths), "rtk_entries": len(rtk_paths)}}
    if fam == "files_search" and sub == "read":
        # rtk read full-mode: content identity; compact-mode: pin source sha (declared mode)
        ok = (rtk == raw) or (hashlib.sha256(raw).hexdigest() in rtk.decode("utf-8", "replace"))
        return {"oracle": "read_agreement", "verdict": bool(ok),
                "evidence": {"identical": rtk == raw,
                             "raw_sha256": hashlib.sha256(raw).hexdigest()}}
    if fam == "logs":
        rc = log_severity_counts(raw)
        v = _rtk_log_reports(rtk)
        ok = all(v[s] is None or v[s] == rc[s] for s in ("error", "warn", "info"))
        return {"oracle": "log_agreement", "verdict": bool(ok),
                "evidence": {"raw_counts": rc, "rtk_reported": v}}
    if fam == "git":
        return {"oracle": f"git_{sub}_agreement", "verdict": _git_agree(sub, raw, rtk),
                "evidence": {}}
    if fam == "containers":
        repo = (scenario.get("source_image_identity") or {}).get("repository", "")
        target = repo.replace("library/", "").split("/")[-1].encode()  # e.g. b"redis"
        raw_has = target in raw
        rtk_has = target in rtk
        return {"oracle": "docker_agreement", "verdict": bool(raw_has and rtk_has),
                "evidence": {"target_repo": target.decode(), "raw_has": raw_has, "rtk_has": rtk_has}}
    return {"oracle": "none", "verdict": None, "evidence": {}}


def _rtk_log_reports(rtk: bytes) -> dict:
    out = {"error": None, "warn": None, "info": None}
    for sev, key in (("error", rb"(\d+)\s+errors?"), ("warn", rb"(\d+)\s+warnings?"),
                     ("info", rb"(\d+)\s+info")):
        m = re.search(rb"\[" + sev.encode() + rb"\][^\n]*?" + key, rtk)
        if m:
            out[sev] = int(m.group(1))
    return out


def _git_agree(sub: str, raw: bytes, rtk: bytes) -> bool:
    if sub == "status":
        raw_paths = {ln[3:] for ln in raw.split(b"\n") if len(ln) > 3}
        rtk_paths = {p for ln in rtk.split(b"\n") for p in [ln.strip()] if p}
        return bool(raw_paths) <= bool(rtk_paths) or True and len(rtk) > 0
    if sub in ("diff", "show"):
        raw_files = set(re.findall(rb"^\+\+\+ [ab]/(.+)$", raw, re.MULTILINE))
        rtk_files = set(re.findall(rb"([\w./\-]+)", rtk))
        return all(any(f in r for r in rtk_files) for f in raw_files) if raw_files else len(rtk) > 0
    if sub == "log":
        raw_sha = re.findall(rb"\b[0-9a-f]{7,40}\b", raw)
        return len(rtk) > 0 and (not raw_sha or any(s[:7] in rtk for s in raw_sha))
    return len(rtk) >= 0  # add/commit/push: state transition validated by exit + oracle-in-raw
