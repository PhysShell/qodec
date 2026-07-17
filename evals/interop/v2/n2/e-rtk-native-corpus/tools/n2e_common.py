"""Shared helpers for N2-E records (compact-null self-hash protocol).

Every N2-E JSON record uses the same self-hash convention already established
across this repository (see tools/build_migration_provenance.py):

  1. Build the record body with ``record_sha256`` set to ``None``.
  2. Compute ``sha256`` over the COMPACT canonical serialization
     (``sort_keys=True, separators=(",", ":")``) of the body while the field
     is still ``None``.
  3. Store ``record_sha256 = "sha256:<hex>"``.
  4. Serialize to disk pretty-printed (``indent=2, sort_keys=True``) so the
     committed file is diff-friendly; the *hash* is over the compact form so
     it is independent of on-disk formatting.

Verifiers MUST recompute the hash from the committed file (never trust the
builder) by nulling ``record_sha256`` and repeating step 2.

This module is intentionally dependency-free (stdlib only) so it runs under the
bare Python already present in acquisition and measurement environments.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

SCHEMA_VERSION = "n2e-record-1"


def compact_canonical_bytes(body: dict) -> bytes:
    """Compact canonical JSON bytes used for self-hashing."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def compute_self_hash(body: dict) -> str:
    """Return 'sha256:<hex>' over the body with record_sha256 nulled."""
    probe = dict(body)
    probe["record_sha256"] = None
    return "sha256:" + hashlib.sha256(compact_canonical_bytes(probe)).hexdigest()


def finalize(body: dict) -> dict:
    """Set record_sha256 in place and assert it verifies stably."""
    body["record_sha256"] = None
    digest = compute_self_hash(body)
    body["record_sha256"] = digest
    # Re-derive from the finalized body to guarantee stability.
    assert compute_self_hash(body) == digest, "self-hash unstable"
    return body


def verify_self_hash(record: dict) -> tuple[bool, str]:
    recorded = record.get("record_sha256")
    if not isinstance(recorded, str) or not recorded.startswith("sha256:"):
        return False, "record_sha256 missing or not in 'sha256:<hex>' form"
    recomputed = compute_self_hash(record)
    if recomputed != recorded:
        return False, f"self-hash mismatch: recorded={recorded} recomputed={recomputed}"
    return True, "OK"


def write_record(path: str | os.PathLike, body: dict) -> str:
    """Finalize and write a record pretty-printed; return its record_sha256."""
    finalize(body)
    Path(path).write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return body["record_sha256"]


def load_record(path: str | os.PathLike) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha256_file(path: str | os.PathLike) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_json_file(path: str | os.PathLike) -> str:
    """SHA-256 of another record's own committed content, compact-canonical.

    Used to cross-link records (record A pins record B by hash) independently
    of B's on-disk pretty formatting.
    """
    obj = json.loads(Path(path).read_text(encoding="utf-8"))
    return "sha256:" + hashlib.sha256(compact_canonical_bytes(obj)).hexdigest()


def envelope(record_type: str, generated_by: str, **fields) -> dict:
    """Start a record body with the standard N2-E envelope fields.

    Callers append their own payload keys and then call write_record/finalize.
    """
    body = {
        "record_type": record_type,
        "record_version": "v1",
        "schema_version": SCHEMA_VERSION,
        "generated_by": generated_by,
        "mission": "N2-E",
        "mission_title": "external RTK-native claim-aligned command corpus",
    }
    body.update(fields)
    body["record_sha256"] = None
    return body
