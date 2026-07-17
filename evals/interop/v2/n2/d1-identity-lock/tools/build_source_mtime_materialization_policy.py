#!/usr/bin/env python3
"""Builds the immutable, self-hash-locked
source-mtime-materialization-policy-v1.json.

D1b remediation round 2 (2026-07-17): repo-requests' own
test_zipped_paths_extracted failed under real CI run 29547420247 with
"ValueError: ZIP does not support timestamps before 1980", because the
durable source tar's extracted files carry Unix-epoch (1970) mtimes.
source_mtime_materialization.py fixes this by setting every extracted
regular file's mtime to one fixed, documented, ZIP-safe timestamp
(2000-01-01T00:00:00Z) for repo-requests only, applied at the shared
acquisition boundary (generic_capture.py), never as a patch to requests'
own tests/test_utils.py.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import source_mtime_materialization as smm

OUT_PATH = Path(__file__).resolve().parents[1] / "source-mtime-materialization-policy-v1.json"


def build_policy() -> dict:
    body = {
        "policy_type": "n2d1b-source-mtime-materialization-policy-v1",
        "policy_identity": smm.MTIME_MATERIALIZATION_APPROVAL_IDENTITIES["repo-requests"],
        "applicable_case_ids": dict(smm.MTIME_MATERIALIZATION_AUTHORIZED_CASES),
        "rationale": (
            "The durable N2-D0 source tar preserves (or was built with) mtime=0 (Unix epoch, "
            "1970-01-01) for every extracted file. Python's zipfile.ZipInfo rejects any "
            "date_time[0] < 1980 ('ZIP does not support timestamps before 1980') -- confirmed "
            "against real CI run 29547420247's artifact bytes: repo-requests' own "
            "test_zipped_paths_extracted failed with exactly this ValueError. This is a genuine "
            "acquisition-metadata incompatibility, not a defect in the requests test suite -- the "
            "fix is applied at the shared acquisition boundary (generic_capture.py, immediately "
            "after source archive hash verification and extraction, before trusted setup or "
            "confined execution), scoped to repo-requests only, never a patch to requests' own "
            "tests/test_utils.py."
        ),
        "requirements": [
            "set every extracted regular file's mtime to one fixed, documented, ZIP-safe timestamp",
            "the fixed timestamp must be safely later than 1980 in every timezone",
            "do not change file bytes",
            "do not change paths",
            "do not change executable bits or other permission bits",
            "do not dereference or rewrite symlinks (symlinks are skipped entirely)",
            "apply the identical timestamp in capture-a and capture-b",
            "record the exact epoch and affected-file count in the receipt",
            "this policy cannot apply to any case_id not listed in applicable_case_ids",
        ],
        "prohibited_workarounds": [
            "patching requests' own tests/test_utils.py individually",
            "applying this policy to any case other than the ones listed in applicable_case_ids",
            "changing file bytes, paths, permission bits, or symlink targets",
            "using a timestamp that is not a fixed, single, documented value shared by both captures",
        ],
    }
    text = json.dumps(body, indent=2, sort_keys=True) + "\n"
    body["policy_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    return body


def main() -> int:
    body = build_policy()
    without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
    recomputed = hashlib.sha256((json.dumps(without_hash, indent=2, sort_keys=True) + "\n").encode()).hexdigest()
    assert recomputed == body["policy_sha256"], "self-hash did not verify stable"
    OUT_PATH.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT_PATH} (policy_sha256={body['policy_sha256']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
