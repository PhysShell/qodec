#!/usr/bin/env python3
"""Independently verify n2e-substrate-identity-v1.json.

Recomputes the self-hash from the committed file, re-reads flake.lock to confirm
every recorded input identity (owner/repo/rev/narHash) matches the in-repo
authority, and asserts the mission-pinned RTK identity constants are present and
well-formed. Fails closed. Does not trust the builder.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
REPO_ROOT = HERE.parents[5]
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

RECORD = N2E_DIR / "n2e-substrate-identity-v1.json"
FLAKE_LOCK = REPO_ROOT / "flake.lock"

RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
RTK_BINARY_SHA256 = "41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def verify(path: Path) -> tuple[bool, str]:
    if not path.is_file():
        return False, f"{path} does not exist"
    rec = c.load_record(path)

    ok, msg = c.verify_self_hash(rec)
    if not ok:
        return False, msg

    if rec.get("record_type") != "n2e-substrate-identity":
        return False, f"unexpected record_type {rec.get('record_type')!r}"

    rtk = rec.get("rtk", {})
    if rtk.get("source_commit") != RTK_SOURCE_COMMIT:
        return False, "rtk.source_commit does not match the mission-pinned commit"
    if rtk.get("binary_sha256") != RTK_BINARY_SHA256:
        return False, "rtk.binary_sha256 does not match the mission-pinned SHA-256"
    if not HEX64.match(rtk.get("binary_sha256", "")):
        return False, "rtk.binary_sha256 is not a full 64-hex digest"
    if rtk.get("not_a_release_binary") is not True:
        return False, "rtk.not_a_release_binary must be True"

    if rec.get("nix", {}).get("sandbox") is not True:
        return False, "nix.sandbox must be True (required to reproduce the pinned hash)"

    # Cross-check every recorded input against flake.lock (the in-repo authority).
    lock = json.loads(FLAKE_LOCK.read_text())["nodes"]
    inputs = rec.get("locked_inputs", [])
    if len(inputs) != 6:
        return False, f"expected 6 locked inputs, found {len(inputs)}"
    for inp in inputs:
        node = inp.get("flake_lock_node")
        if node not in lock:
            return False, f"input node {node!r} absent from flake.lock"
        locked = lock[node]["locked"]
        for field, key in (("owner", "owner"), ("repo", "repo"), ("rev", "rev"),
                           ("locked_nar_hash", "narHash")):
            if inp.get(field) != locked.get(key):
                return False, f"{node}.{field} drift vs flake.lock: {inp.get(field)!r} != {locked.get(key)!r}"
        if inp.get("reconstruction_nar_hash") != locked.get("narHash"):
            return False, f"{node}: reconstruction_nar_hash must equal the locked narHash"

    return True, "OK"


def main() -> int:
    ok, message = verify(RECORD)
    if not ok:
        print(f"::error::n2e substrate identity verification FAILED: {message}", file=sys.stderr)
        return 1
    print(f"n2e substrate identity verification passed: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
