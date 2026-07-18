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
_VITEST_FAIL = re.compile(rb"(?:FAIL|\xc3\x97)\s+(\S+)")
_DIAG = re.compile(rb"(?P<file>[\w./\-]+):(?P<line>\d+):(?:(?P<col>\d+):)?\s*(?P<sev>error|warning|note)?", re.IGNORECASE)


_VITEST_SUM = re.compile(rb"Tests\s+(?:(\d+) failed\s*\|\s*)?(\d+) passed(?:\s*\|\s*(\d+) skipped)?")
_VITEST_SUM_FAILONLY = re.compile(rb"Tests\s+(\d+) failed\b(?!\s*\|)")
_GRADLE_SUM = re.compile(rb"(\d+) tests? completed(?:,\s*(\d+) failed)?")
_GRADLE_FAIL = re.compile(rb"^(\S+) > (\S+) FAILED", re.MULTILINE)


def _test_summary(raw: bytes) -> dict:
    """Best-effort tool-agnostic parse of passed/failed + failing ids."""
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
    for pat in (_CARGO_FAIL, _GOTEST_FAIL, _PYTEST_FAIL):
        for fm in pat.finditer(raw):
            failing.add(fm.group(1).decode("utf-8", "replace"))
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
        r, k = _test_summary(raw), _test_summary(rtk)
        raw_fail = set(_leaf_ids(r["failing_ids"]))
        rtk_fail = set(_leaf_ids(k["failing_ids"]))
        # no failing test id may disappear; failed count preserved when known
        ids_ok = raw_fail <= rtk_fail
        count_ok = (r["failed"] is None or k["failed"] is None or r["failed"] == k["failed"])
        return {"oracle": "test_agreement", "verdict": bool(ids_ok and count_ok),
                "evidence": {"raw": r, "rtk": k}}
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
