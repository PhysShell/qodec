#!/usr/bin/env python3
"""Verify per-case toolchain evidence against the self-hash-locked toolchain lock.

For every canary per-case record that used a publisher recipe, the observed
toolchain identity must match the lock EXACTLY:
  * the reported version string must contain the lock's expected version (this alone
    rejects wrong-toolchain substitution: rustc 1.97.1 for 1.83.0, Node 22 for 20);
  * where the lock pins a per-executable binary SHA-256 (from a clean probe), the
    observed binary SHA-256 must equal it.

Usage: verify_n2e_toolchain_lock.py <per-case-evidence-dir>
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

LOCK = N2E_DIR / "n2e-toolchain-lock-v1.json"

# recipe language -> toolchain-lock kind + which observed toolchain keys to check
_LANG_KIND = {"rust_cargo": "rust", "go": "go", "js_ts": "node", "jvm": "java"}
_OBSERVED_KEYS = {"rust": ["rustc", "cargo"], "go": ["go"], "node": ["node"], "java": ["java"]}


def verify(evidence_dir: Path) -> tuple[bool, str]:
    lock = c.load_record(LOCK)
    ok, msg = c.verify_self_hash(lock)
    if not ok:
        return False, f"toolchain-lock self-hash: {msg}"
    tls = lock["toolchains"]
    checked = 0
    for p in sorted(evidence_dir.rglob("n2e-canary-case-*.json")):
        r = c.load_record(p)
        acq = r.get("acquisition") or {}
        if "publisher_recipe" not in acq:
            continue
        env = acq.get("environment_identity") or {}
        pin = env.get("toolchain_pin") or {}
        # toolchain_pin.kind is the publisher kind (go/rust/node/java) -> lock kind
        kind = {"go": "go", "rust": "rust", "node": "node", "java": "java"}.get(pin.get("kind"))
        if not kind or kind not in tls:
            continue
        spec = tls[kind]
        observed = env.get("toolchain") or {}
        want = spec["expected_version_contains"]
        for key in _OBSERVED_KEYS[kind]:
            t = observed.get(key) or {}
            ver = t.get("version") or ""
            if want not in ver:
                return False, (f"{r.get('case_id')}: toolchain '{key}' version {ver!r} does not "
                               f"match lock expected {want!r} (wrong toolchain -> HARNESS_DEFECT)")
            exp_hash = (spec.get("executables", {}).get(key) or {}).get("expected_binary_sha256")
            if exp_hash and t.get("sha256") != exp_hash:
                return False, (f"{r.get('case_id')}: toolchain '{key}' binary sha256 "
                               f"{t.get('sha256')} != locked {exp_hash}")
        checked += 1
    return True, f"OK; toolchain lock satisfied for {checked} publisher-recipe record(s)"


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-hash-only":
        ok, msg = c.verify_self_hash(c.load_record(LOCK))
        print(f"toolchain-lock self-hash: {'OK' if ok else msg}")
        return 0 if ok else 1
    if len(sys.argv) < 2:
        print("usage: verify_n2e_toolchain_lock.py <evidence-dir> | --self-hash-only", file=sys.stderr)
        return 2
    ok, msg = verify(Path(sys.argv[1]))
    if not ok:
        print(f"::error::toolchain-lock verification FAILED: {msg}", file=sys.stderr)
        return 1
    print(f"toolchain-lock: {msg}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
