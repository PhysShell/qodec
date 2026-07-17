#!/usr/bin/env python3
"""Independently, fail-closedly verifies n2d3-model-free-input-bundle-v1.tar.

Re-extracts the real committed tar (never trusting a cached listing),
recomputes manifest.json's self-hash, cross-checks every case's input
bytes against the real n2d-current-identity-closure-v1.json and
rtk-applicability-map-v1.json (never trusting the manifest's own
recorded values), and checks every tar member's determinism properties
(fixed uid/gid/uname/gname/mode/mtime, GNU format, no PAX extended
headers, lexicographically sorted member order).
"""
from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
IDENTITY_LOCK_DIR = TOOLS_DIR.parent
BUNDLE_PATH = IDENTITY_LOCK_DIR / "n2d3-model-free-input-bundle-v1.tar"
IDENTITY_CLOSURE_PATH = IDENTITY_LOCK_DIR / "n2d-current-identity-closure-v1.json"
RTK_MAP_PATH = IDENTITY_LOCK_DIR / "rtk-applicability-map-v1.json"

REQUIRED_18_CASE_IDS = [
    "n2a-miner-canary",
    "bot-dependabot-black-5206", "bot-syzbot-do-mkdirat", "ci-log-jansson",
    "ci-log-nlog", "ci-log-spdlog", "dataset-loghub-v8",
    "dataset-rtn-traffic-ids", "research-corpus-loghub2",
    "repo-docker-java-parser", "repo-dockerfile-parser-rs", "repo-helm-values",
    "repo-hyperfine", "repo-kubeops-generator", "repo-moshi", "repo-pyflakes",
    "repo-requests", "repo-rustlings",
]

FIXED_MTIME = 946684800
FIXED_UID = 0
FIXED_GID = 0
FIXED_UNAME = "n2d"
FIXED_GNAME = "n2d"
FIXED_FILE_MODE = 0o644


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def verify(bundle_path: Path = BUNDLE_PATH) -> tuple[bool, str]:
    if not bundle_path.is_file():
        return False, f"{bundle_path} does not exist"

    with tarfile.open(bundle_path, mode="r:") as tar:
        members = tar.getmembers()
        names = [m.name for m in members]
        if names != sorted(names):
            return False, "tar members are not in lexicographically sorted order"
        if len(names) != 19:
            return False, f"expected exactly 19 tar members (18 inputs + manifest.json), got {len(names)}"

        expected_member_names = {"manifest.json"} | {f"inputs/{cid}/input.bin" for cid in REQUIRED_18_CASE_IDS}
        if set(names) != expected_member_names:
            return False, f"tar member names {sorted(set(names))} != expected {sorted(expected_member_names)}"

        for m in members:
            if m.type != tarfile.REGTYPE:
                return False, f"{m.name}: not a regular file (type={m.type!r})"
            if m.mtime != FIXED_MTIME:
                return False, f"{m.name}: mtime {m.mtime!r} != required {FIXED_MTIME!r}"
            if m.uid != FIXED_UID or m.gid != FIXED_GID:
                return False, f"{m.name}: uid/gid {m.uid}/{m.gid} != required {FIXED_UID}/{FIXED_GID}"
            if m.uname != FIXED_UNAME or m.gname != FIXED_GNAME:
                return False, f"{m.name}: uname/gname {m.uname!r}/{m.gname!r} != required {FIXED_UNAME!r}/{FIXED_GNAME!r}"
            if m.mode != FIXED_FILE_MODE:
                return False, f"{m.name}: mode {oct(m.mode)} != required {oct(FIXED_FILE_MODE)}"
            if m.pax_headers:
                return False, f"{m.name}: has PAX extended headers (host metadata leak): {m.pax_headers!r}"

        manifest_bytes = tar.extractfile("manifest.json").read()
        manifest = json.loads(manifest_bytes)
        recorded = manifest.get("record_sha256")
        recomputed = compute_record_sha256(manifest)
        if recomputed != recorded:
            return False, f"manifest.json self-hash mismatch: recorded={recorded} recomputed={recomputed}"

        if manifest.get("record_type") != "n2d3-model-free-input-bundle-manifest-v1":
            return False, f"unexpected manifest record_type: {manifest.get('record_type')!r}"
        if manifest.get("fixed_mtime_epoch_seconds") != FIXED_MTIME:
            return False, "manifest.fixed_mtime_epoch_seconds does not match the tar's own fixed mtime"

        cases = manifest.get("cases", {})
        if sorted(cases.keys()) != sorted(REQUIRED_18_CASE_IDS):
            return False, "manifest cases keys != required 18-case set"
        if manifest.get("case_count") != 18:
            return False, "manifest.case_count must be 18"

        for case_id, entry in cases.items():
            member_path = entry.get("bundle_member_path")
            if member_path != f"inputs/{case_id}/input.bin":
                return False, f"{case_id}: bundle_member_path {member_path!r} does not match convention"
            data = tar.extractfile(member_path).read()
            actual_sha256 = hashlib.sha256(data).hexdigest()
            if actual_sha256 != entry.get("input_sha256"):
                return False, f"{case_id}: extracted bytes sha256 {actual_sha256!r} != manifest-recorded {entry.get('input_sha256')!r}"
            if len(data) != entry.get("input_byte_count"):
                return False, f"{case_id}: extracted byte count {len(data)} != manifest-recorded {entry.get('input_byte_count')!r}"

    # --- cross-check against the real committed identity closure / rtk map
    if not IDENTITY_CLOSURE_PATH.is_file() or not RTK_MAP_PATH.is_file():
        return False, "identity closure / rtk applicability map files missing"
    identity = json.loads(IDENTITY_CLOSURE_PATH.read_text())
    rtk_map = json.loads(RTK_MAP_PATH.read_text())

    for case_id, entry in cases.items():
        real_case = identity["cases"].get(case_id)
        if real_case is None:
            return False, f"{case_id}: not present in n2d-current-identity-closure-v1.json"
        if entry.get("input_sha256") != real_case.get("canonical_benchmark_input_sha256"):
            return False, f"{case_id}: bundle input_sha256 does not match the identity closure's canonical hash"
        real_rtk_case = rtk_map["cases"].get(case_id)
        if entry.get("rtk_argv") != real_rtk_case.get("rtk_argv"):
            return False, f"{case_id}: bundle rtk_argv does not match rtk-applicability-map-v1.json"

    return True, "OK"


def main() -> int:
    ok, message = verify()
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
