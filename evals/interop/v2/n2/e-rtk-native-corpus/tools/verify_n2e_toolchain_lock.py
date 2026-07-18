#!/usr/bin/env python3
"""Fail-closed toolchain-lock verification against per-case evidence.

Derives the EXPECTED publisher case set from the registry and proves, structurally
(never by substring): every expected publisher case appears exactly once; no extra
publisher-bound case appears; each record carries publisher_recipe and a
publisher_case_id equal to its evidence case_id; the toolchain kind is present and
expected; every required executable identity exists; the parsed release of each
executable equals the lock exactly; and, where the lock pins an executable
SHA-256, the observed binary hash equals it. Unknown/missing kinds FAIL (never
skip). For js_ts, pnpm must be present and match. A canonical run additionally
requires lock_state == COMPLETE.

Usage: verify_n2e_toolchain_lock.py <evidence-dir> [--canonical] | --self-hash-only
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_publisher_registry as pub  # noqa: E402

LOCK = N2E_DIR / "n2e-toolchain-lock-v1.json"

# publisher toolchain kind (docker_specs) -> lock kind + observed executables to check
_KIND = {"go": "go", "rust": "rust", "node": "node", "java": "java"}
_EXES = {"go": ["go"], "rust": ["rustc", "cargo"], "node": ["node"], "java": ["java"]}


def _parse_release(kind: str, exe: str, ver: str) -> str | None:
    """Extract the exact release token from a `--version` string, structurally."""
    if kind == "go":
        m = re.search(r"\bgo(\d+\.\d+(?:\.\d+)?)\b", ver);  return f"go{m.group(1)}" if m else None
    if kind == "rust":
        m = re.match(rf"{exe} (\d+\.\d+\.\d+)", ver);       return m.group(1) if m else None
    if kind == "node":
        m = re.search(r"\bv(\d+\.\d+\.\d+)\b", ver);        return f"v{m.group(1)}" if m else None
    if kind == "java":
        m = re.search(r'version "(\d+\.\d+\.\d+)', ver);    return m.group(1) if m else None
    return None


def _expected_release(kind: str, exe: str, spec: dict) -> str:
    if kind == "java":
        return spec["openjdk_version"].split("+")[0].split("-")[0]  # 21.0.11+10-LTS -> 21.0.11
    return spec["release"]  # go1.23.8 / 1.83.0 / v20.20.2


def verify_record_identity(rec: dict, require_complete: bool = True) -> tuple[bool, str]:
    """Exact toolchain-identity check for ONE publisher-recipe evidence record: kind
    present + expected, every required executable's parsed release equals the lock, and
    (where pinned) the observed binary SHA-256 equals the lock. Used by the rejection-
    ledger builder so a terminal entry never relies on bool(toolchain_pin)."""
    lock = c.load_record(LOCK)
    ok, msg = c.verify_self_hash(lock)
    if not ok:
        return False, f"lock self-hash: {msg}"
    if require_complete and lock.get("lock_state") != "COMPLETE":
        return False, f"lock_state != COMPLETE ({lock.get('lock_state')!r})"
    tls = lock["toolchains"]
    acq = rec.get("acquisition") or {}
    if "publisher_recipe" not in acq:
        return False, "record has no publisher_recipe"
    env = acq.get("environment_identity") or {}
    pin = env.get("toolchain_pin") or {}
    kind = _KIND.get(pin.get("kind"))
    if not kind or kind not in tls:
        return False, f"unknown/missing toolchain kind {pin.get('kind')!r}"
    spec = tls[kind]
    observed = env.get("toolchain") or {}
    for exe in _EXES[kind]:
        t = observed.get(exe) or {}
        if not t.get("version") or not t.get("sha256"):
            return False, f"missing {kind} executable identity for '{exe}'"
        if _parse_release(kind, exe, t["version"]) != _expected_release(kind, exe, spec):
            return False, f"{exe} wrong release vs lock"
        exp_hash = (spec.get("executables", {}).get(exe) or {}).get("expected_sha256")
        if exp_hash is not None and t.get("sha256") != exp_hash:
            return False, f"{exe} binary sha256 != locked"
    if kind == "node":
        pn = observed.get("pnpm") or {}
        if not pn.get("version") or not pn.get("sha256"):
            return False, "missing pnpm identity"
        pn_rel = (re.match(r"(\d+\.\d+\.\d+)", pn["version"]) or [None, None])[1]
        if pn_rel != spec["pnpm"]["release"]:
            return False, "pnpm wrong release vs lock"
    return True, f"{kind} identity matches lock exactly"


def verify(evidence_dir: Path, canonical: bool = False) -> tuple[bool, str]:
    lock = c.load_record(LOCK)
    ok, msg = c.verify_self_hash(lock)
    if not ok:
        return False, f"toolchain-lock self-hash: {msg}"
    if canonical and lock.get("lock_state") != "COMPLETE":
        return False, (f"canonical run requires lock_state==COMPLETE (is {lock.get('lock_state')!r}; "
                       f"missing {lock.get('missing_expected_identities')})")
    tls = lock["toolchains"]
    expected_cases = {r["case_id"] for r in pub.load()["recipes"]}
    seen: dict = {}
    for p in sorted(evidence_dir.rglob("n2e-canary-case-*.json")):
        r = c.load_record(p)
        cid = r.get("case_id")
        acq = r.get("acquisition") or {}
        if "publisher_recipe" not in acq:
            continue
        if cid not in expected_cases:
            return False, f"{cid}: publisher-bound evidence for a case with no registry recipe"
        if cid in seen:
            return False, f"{cid}: duplicate publisher evidence record"
        seen[cid] = True
        if acq.get("publisher_case_id") != cid:
            return False, f"{cid}: publisher_case_id {acq.get('publisher_case_id')!r} != evidence case_id"
        env = acq.get("environment_identity") or {}
        pin = env.get("toolchain_pin") or {}
        kind = _KIND.get(pin.get("kind"))
        if not kind or kind not in tls:
            return False, f"{cid}: unknown/missing toolchain kind {pin.get('kind')!r}"
        spec = tls[kind]
        observed = env.get("toolchain") or {}
        for exe in _EXES[kind]:
            t = observed.get(exe) or {}
            if not t.get("version") or not t.get("sha256"):
                return False, f"{cid}: missing {kind} executable identity for '{exe}'"
            got = _parse_release(kind, exe, t["version"])
            want = _expected_release(kind, exe, spec)
            if got != want:
                return False, f"{cid}: {exe} release {got!r} != locked {want!r} (wrong toolchain)"
            exp_hash = (spec.get("executables", {}).get(exe) or {}).get("expected_sha256")
            if exp_hash is not None and t.get("sha256") != exp_hash:
                return False, f"{cid}: {exe} binary sha256 {t.get('sha256')} != locked {exp_hash}"
        if kind == "node":  # pnpm must be present + match (it executes acquisition + measurement)
            pn = observed.get("pnpm") or {}
            if not pn.get("version") or not pn.get("sha256"):
                return False, f"{cid}: missing pnpm executable identity"
            pn_rel = (re.match(r"(\d+\.\d+\.\d+)", pn["version"]) or [None, None])[1]
            if pn_rel != spec["pnpm"]["release"]:
                return False, f"{cid}: pnpm release {pn_rel!r} != locked {spec['pnpm']['release']!r}"
    missing_cases = expected_cases - set(seen)
    if missing_cases:
        return False, f"missing publisher evidence for expected case(s): {sorted(missing_cases)}"
    return True, (f"OK; lock_state={lock['lock_state']}; {len(seen)}/{len(expected_cases)} "
                  f"publisher cases matched the lock exactly")


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-hash-only":
        ok, msg = c.verify_self_hash(c.load_record(LOCK))
        print(f"toolchain-lock self-hash: {'OK' if ok else msg}")
        return 0 if ok else 1
    if len(sys.argv) < 2:
        print("usage: verify_n2e_toolchain_lock.py <evidence-dir> [--canonical] | --self-hash-only",
              file=sys.stderr)
        return 2
    ok, msg = verify(Path(sys.argv[1]), canonical=("--canonical" in sys.argv))
    if not ok:
        print(f"::error::toolchain-lock verification FAILED: {msg}", file=sys.stderr)
        return 1
    print(f"toolchain-lock: {msg}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
