#!/usr/bin/env python3
"""N2-D1b: repo-requests-only deterministic ZIP-safe source metadata
materialization (D1b remediation round 2, 2026-07-17).

The durable N2-D0 source tar preserves (or was built with) mtime=0 (Unix
epoch, 1970-01-01) for every extracted file. Python's zipfile.ZipInfo
rejects any date_time[0] < 1980 ("ZIP does not support timestamps before
1980") -- repo-requests' own test_zipped_paths_extracted hits this
directly (confirmed against real CI run 29547420247's artifact bytes: this
was one of the two genuine execution-environment incompatibilities found).

This is a genuine acquisition-metadata incompatibility, not a defect in the
requests test suite -- the fix belongs at the shared acquisition boundary
(generic_capture.py, applied right after source archive hash verification
+ extraction, before trusted setup or confined execution), scoped to
repo-requests only via MTIME_MATERIALIZATION_AUTHORIZED_CASES (mirroring
generic_sandbox_policy.py's own per-case-id authorization discipline --
never inherited by another case). Do NOT patch requests' own tests/
test_utils.py: the defect belongs to the normalized acquisition metadata
boundary, not to that one test file.

Applies ONE fixed, documented, ZIP-safe timestamp to every extracted
REGULAR file's mtime. Never touches file bytes, paths, permission/
executable bits, or symlinks (symlinks are skipped entirely via
os.path.islink -- this policy never calls os.utime on a symlink or its
target).
"""
from __future__ import annotations

import calendar
import hashlib
import json
import os
import stat
import time
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent

# Case_id -> the single, fixed, documented ZIP-safe timestamp (ISO-8601 UTC,
# always "Z"-suffixed) this policy applies to every extracted regular
# file's mtime for that case. Authorized strictly per exact case_id --
# never inherited by another case, mirroring NETWORK_ENFORCEMENT_
# AUTHORIZED_CASES / TIMEOUT_SINK_AUTHORIZED_CASES's own discipline.
MTIME_MATERIALIZATION_AUTHORIZED_CASES = {
    "repo-requests": "2000-01-01T00:00:00Z",
}

MTIME_MATERIALIZATION_APPROVAL_IDENTITIES = {
    "repo-requests": "n2d1b-repo-requests-source-mtime-materialization-v1",
}


class MtimeMaterializationError(Exception):
    pass


class PolicyIntegrityError(Exception):
    pass


def _iso8601_utc_to_epoch_seconds(iso_ts: str) -> int:
    # Deliberately strict: only the exact "YYYY-MM-DDTHH:MM:SSZ" shape this
    # module itself ever emits -- never a general ISO-8601 parser.
    if not iso_ts.endswith("Z"):
        raise MtimeMaterializationError(f"timestamp {iso_ts!r} is not UTC ('Z'-suffixed)")
    parsed = time.strptime(iso_ts, "%Y-%m-%dT%H:%M:%SZ")
    return calendar.timegm(parsed)


def materialize_source_mtimes(*, case_id: str, source_root: Path) -> dict:
    """Walks source_root, setting every extracted REGULAR file's mtime
    (and atime, harmlessly) to the fixed epoch this case_id is authorized
    for. Returns a report dict (case_id, policy identity, exact epoch,
    affected-file count) -- generic_capture.py embeds this in the receipt.

    Raises MtimeMaterializationError if case_id is not in
    MTIME_MATERIALIZATION_AUTHORIZED_CASES -- this policy cannot silently
    apply to another case; there is no ecosystem-wide or default fallback.
    """
    if case_id not in MTIME_MATERIALIZATION_AUTHORIZED_CASES:
        raise MtimeMaterializationError(
            f"{case_id!r} is not authorized for source-mtime materialization "
            f"(authorized case_ids: {sorted(MTIME_MATERIALIZATION_AUTHORIZED_CASES)})"
        )
    iso_ts = MTIME_MATERIALIZATION_AUTHORIZED_CASES[case_id]
    epoch_seconds = _iso8601_utc_to_epoch_seconds(iso_ts)

    affected_relative_paths = []
    for root, _dirs, files in os.walk(source_root):
        for name in files:
            p = Path(root) / name
            # "Do not dereference or rewrite symlinks": skip entirely --
            # never call os.utime on a symlink or (by following it) its
            # target.
            if os.path.islink(p):
                continue
            st = os.stat(p)
            if not stat.S_ISREG(st.st_mode):
                continue
            os.utime(p, (epoch_seconds, epoch_seconds))
            affected_relative_paths.append(str(p.relative_to(source_root)))

    return {
        "report_type": "n2d1b-source-mtime-materialization-report-v1",
        "case_id": case_id,
        "policy_identity": MTIME_MATERIALIZATION_APPROVAL_IDENTITIES[case_id],
        "fixed_timestamp_iso8601_utc": iso_ts,
        "fixed_timestamp_epoch_seconds": epoch_seconds,
        "affected_file_count": len(affected_relative_paths),
        "affected_relative_paths": sorted(affected_relative_paths),
    }


def load_and_verify_policy(policy_path: Path) -> dict:
    """Loads source-mtime-materialization-policy-v1.json and verifies it
    against the ACTUAL running code before returning it -- never merely
    trusts the `policy_sha256` field embedded in the file itself. Raises
    PolicyIntegrityError (fail closed) if:

      - the file's own self-hash does not verify (tampered or corrupted);
      - its documented `applicable_case_ids` do not match
        MTIME_MATERIALIZATION_AUTHORIZED_CASES's keys exactly;
      - any per-case timestamp or the policy_identity string in the file
        does not match this module's own dicts.

    Both generic_capture.py (at capture time) and any future verifier call
    this SAME function, so neither can drift from the other's notion of
    what the policy actually authorizes.
    """
    body = json.loads(policy_path.read_text())
    if "policy_sha256" not in body:
        raise PolicyIntegrityError(f"{policy_path}: missing policy_sha256 -- not a self-hash-locked policy record")
    recorded = body["policy_sha256"]
    without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
    canonical_text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
    recomputed = hashlib.sha256(canonical_text.encode("utf-8")).hexdigest()
    if recomputed != recorded:
        raise PolicyIntegrityError(
            f"{policy_path}: policy_sha256 {recorded} does not match recomputed {recomputed} "
            "-- refusing to trust a tampered or corrupted policy record"
        )

    documented_cases = body.get("applicable_case_ids", {})
    if set(documented_cases) != set(MTIME_MATERIALIZATION_AUTHORIZED_CASES):
        raise PolicyIntegrityError(
            f"{policy_path}: documented applicable_case_ids {sorted(documented_cases)} does not match "
            f"MTIME_MATERIALIZATION_AUTHORIZED_CASES {sorted(MTIME_MATERIALIZATION_AUTHORIZED_CASES)} "
            "-- policy and code have drifted"
        )
    for case_id, documented_ts in documented_cases.items():
        if documented_ts != MTIME_MATERIALIZATION_AUTHORIZED_CASES[case_id]:
            raise PolicyIntegrityError(
                f"{policy_path}: documented timestamp for {case_id!r} ({documented_ts!r}) does not match "
                f"the code's own value ({MTIME_MATERIALIZATION_AUTHORIZED_CASES[case_id]!r})"
            )
    if body.get("policy_identity") != MTIME_MATERIALIZATION_APPROVAL_IDENTITIES["repo-requests"]:
        raise PolicyIntegrityError(
            f"{policy_path}: policy_identity {body.get('policy_identity')!r} does not match the code's own "
            f"MTIME_MATERIALIZATION_APPROVAL_IDENTITIES value"
        )
    return body
