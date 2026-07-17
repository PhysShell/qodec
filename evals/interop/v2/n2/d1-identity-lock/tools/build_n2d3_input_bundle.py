#!/usr/bin/env python3
"""Builds n2d3-model-free-input-bundle-v1.tar -- the single, deterministic
input bundle every N2-D2 and N2-D3 job consumes. No job may reacquire or
derive its own variant of any case's benchmark input; every consumer reads
exclusively from this one committed archive.

Determinism properties (verified by build_twice_and_compare()):
  - lexicographically sorted member paths
  - fixed uid=0/gid=0
  - fixed uname="n2d"/gname="n2d"
  - fixed mode (0o644 files, 0o755 dirs)
  - fixed mtime = 946684800 (2000-01-01T00:00:00Z UTC -- the same fixed
    timestamp already established by source-mtime-materialization-policy-v1.json
    for this project's other ZIP/tar determinism work)
  - GNU tar format (never PAX -- PAX extended headers embed hostname/mtime
    metadata that varies by build machine/moment)
  - uncompressed (.tar, not .tar.gz -- side-steps gzip header mtime entirely)
  - byte-exact payloads, each independently verified against its own
    source evidence record before being staged (never re-derived here)

manifest.json (a member of the bundle, sorted lexicographically alongside
every `inputs/<case-id>/input.bin`) is itself self-hash-locked using the
project's standard protocol.
"""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

IDENTITY_LOCK_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = IDENTITY_LOCK_DIR.parents[4]
OUT_PATH = IDENTITY_LOCK_DIR / "n2d3-model-free-input-bundle-v1.tar"

FIXED_MTIME = 946684800  # 2000-01-01T00:00:00Z
FIXED_UID = 0
FIXED_GID = 0
FIXED_UNAME = "n2d"
FIXED_GNAME = "n2d"
FIXED_FILE_MODE = 0o644
FIXED_DIR_MODE = 0o755


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _is_valid_utf8(data: bytes) -> bool:
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def build_case_entries(staged_inputs_dir: Path, rtk_applicability_map: dict, identity_closure: dict) -> dict:
    """staged_inputs_dir must contain exactly one real, already-verified
    <case_id>.bin file per case -- this function only reads and describes
    those bytes, it never fetches or derives them."""
    cases = identity_closure["cases"]
    rtk_cases = rtk_applicability_map["cases"]

    entries = {}
    for case_id, case in sorted(cases.items()):
        input_path = staged_inputs_dir / f"{case_id}.bin"
        if not input_path.is_file():
            raise RuntimeError(f"missing staged input for {case_id}: {input_path}")
        data = input_path.read_bytes()
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != case["canonical_benchmark_input_sha256"]:
            raise RuntimeError(
                f"{case_id}: staged input sha256 {actual_sha256!r} != identity-closure-recorded "
                f"{case['canonical_benchmark_input_sha256']!r}"
            )
        entries[case_id] = {
            "case_id": case_id,
            "origin_kind": case["origin_kind"],
            "ecosystem": case.get("ecosystem"),
            "source_evidence_record": (
                case.get("source_record_path")
                or "evals/interop/v2/n2/d0-durable-evidence/durable-input-manifest.json"
            ),
            "durable_or_stage2_asset_identity": (
                case.get("durable_asset_sha256")
                or case.get("durable_release_asset_sha256")
            ),
            "contained_input_path": (
                case.get("contained_benchmark_input_path")
                or "raw.stdout"
            ),
            "input_byte_count": len(data),
            "input_sha256": actual_sha256,
            "utf8_valid": _is_valid_utf8(data),
            "canonicalization_policy_identity": case.get("canonicalization_policy_identity"),
            "rtk_argv": rtk_cases[case_id]["rtk_argv"],
            "bundle_member_path": f"inputs/{case_id}/input.bin",
        }
    return entries


def _add_deterministic_member(tar: tarfile.TarFile, arcname: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=arcname)
    info.size = len(data)
    info.mtime = FIXED_MTIME
    info.uid = FIXED_UID
    info.gid = FIXED_GID
    info.uname = FIXED_UNAME
    info.gname = FIXED_GNAME
    info.mode = FIXED_FILE_MODE
    info.type = tarfile.REGTYPE
    tar.addfile(info, io.BytesIO(data))


def write_bundle(out_path: Path, staged_inputs_dir: Path, rtk_applicability_map: dict, identity_closure: dict) -> dict:
    entries = build_case_entries(staged_inputs_dir, rtk_applicability_map, identity_closure)

    manifest_body = {
        "record_type": "n2d3-model-free-input-bundle-manifest-v1",
        "record_version": 1,
        "schema_version": 1,
        "case_count": len(entries),
        "fixed_mtime_epoch_seconds": FIXED_MTIME,
        "fixed_mtime_iso8601_utc": "2000-01-01T00:00:00Z",
        "cases": entries,
    }
    manifest_body["record_sha256"] = compute_record_sha256(manifest_body)
    manifest_bytes = (json.dumps(manifest_body, indent=2, sort_keys=True) + "\n").encode("utf-8")

    members = {"manifest.json": manifest_bytes}
    for case_id, entry in entries.items():
        input_path = staged_inputs_dir / f"{case_id}.bin"
        members[entry["bundle_member_path"]] = input_path.read_bytes()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for arcname in sorted(members.keys()):
            _add_deterministic_member(tar, arcname, members[arcname])
    tar_bytes = buf.getvalue()

    out_path.write_bytes(tar_bytes)
    return manifest_body


def build_twice_and_compare(staged_inputs_dir: Path, rtk_applicability_map: dict, identity_closure: dict) -> tuple[bytes, bytes]:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        p1 = Path(tmp) / "a.tar"
        p2 = Path(tmp) / "b.tar"
        write_bundle(p1, staged_inputs_dir, rtk_applicability_map, identity_closure)
        write_bundle(p2, staged_inputs_dir, rtk_applicability_map, identity_closure)
        b1 = p1.read_bytes()
        b2 = p2.read_bytes()
    return b1, b2


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--staged-inputs-dir", required=True, type=Path)
    args = parser.parse_args()

    rtk_map_path = IDENTITY_LOCK_DIR / "rtk-applicability-map-v1.json"
    rtk_applicability_map = json.loads(rtk_map_path.read_text())
    identity_closure_path = IDENTITY_LOCK_DIR / "n2d-current-identity-closure-v1.json"
    identity_closure = json.loads(identity_closure_path.read_text())

    b1, b2 = build_twice_and_compare(args.staged_inputs_dir, rtk_applicability_map, identity_closure)
    if b1 != b2:
        raise RuntimeError("bundle is NOT deterministic: two builds produced different bytes")
    sha1 = hashlib.sha256(b1).hexdigest()
    sha2 = hashlib.sha256(b2).hexdigest()
    if sha1 != sha2:
        raise RuntimeError("bundle sha256 mismatch across two builds")

    manifest_body = write_bundle(OUT_PATH, args.staged_inputs_dir, rtk_applicability_map, identity_closure)
    final_bytes = OUT_PATH.read_bytes()
    final_sha256 = hashlib.sha256(final_bytes).hexdigest()
    if final_sha256 != sha1:
        raise RuntimeError("final written bundle sha256 does not match the double-build verification pass")

    print(
        f"wrote {OUT_PATH} ({len(final_bytes)} bytes, sha256={final_sha256}); "
        f"double-build determinism verified ({manifest_body['case_count']} cases); "
        f"manifest record_sha256={manifest_body['record_sha256']}"
    )


if __name__ == "__main__":
    main()
