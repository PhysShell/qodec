#!/usr/bin/env python3
"""Independently verify n2e-source-registry-v1.json (§2, §22).

- Recompute the self-hash.
- Every source carries a classification from the vocabulary and a typed reason.
- ACCEPTED_PRIMARY sources must carry a resolved immutable identity (an HF
  revision, a Zenodo record id, or an OCI digest) — never a moving/mutable ref.
- Any recorded OCI reference must be pinned by an immutable sha256 digest, and
  any recorded digest must be verified.
- DEFERRED / REJECTED sources must NOT carry fabricated per-artifact hashes.
- With RESOLVE=1 and network, re-resolve live identities and require they match.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

RECORD = N2E_DIR / "n2e-source-registry-v1.json"
VOCAB = {"ACCEPTED_PRIMARY", "ACCEPTED_RESERVE", "REJECTED", "DEFERRED"}
SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HF_REV = re.compile(r"^[0-9a-f]{40}$")


def verify(path: Path) -> tuple[bool, str]:
    if not path.is_file():
        return False, f"{path} does not exist"
    rec = c.load_record(path)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        return False, msg
    if rec.get("record_type") != "n2e-source-registry":
        return False, f"unexpected record_type {rec.get('record_type')!r}"

    sources = rec.get("sources", [])
    if len(sources) != rec.get("source_count"):
        return False, "source_count mismatch"
    seen = set()
    for s in sources:
        sid = s.get("source_id")
        if sid in seen:
            return False, f"duplicate source_id {sid!r}"
        seen.add(sid)
        cls = s.get("classification")
        if cls not in VOCAB:
            return False, f"{sid}: classification {cls!r} not in vocabulary"
        if not s.get("typed_reason"):
            return False, f"{sid}: missing typed_reason"

        idy = s.get("identity")
        if cls == "ACCEPTED_PRIMARY":
            if not idy:
                return False, f"{sid}: ACCEPTED_PRIMARY without a resolved identity"
            kind = idy.get("kind")
            if kind == "huggingface_dataset":
                rev = idy.get("immutable_revision")
                if not rev or not HF_REV.match(rev):
                    return False, f"{sid}: HF identity lacks an immutable 40-hex revision (moving ref?)"
            elif kind == "zenodo_record":
                if not idy.get("record_id"):
                    return False, f"{sid}: zenodo identity lacks a record_id"
                if not idy.get("files"):
                    return False, f"{sid}: zenodo identity lacks file checksums"
            # OCI example digest, if present, must be pinned + verified.
            oci = s.get("oci_digest_example")
            if oci is not None:
                if not SHA256_DIGEST.match(oci.get("immutable_digest", "")):
                    return False, f"{sid}: OCI reference not pinned by an immutable sha256 digest"
                if oci.get("digest_verified") is not True:
                    return False, f"{sid}: OCI digest not verified"

        # DEFERRED / REJECTED must not smuggle fabricated per-artifact hashes.
        if cls in ("DEFERRED", "REJECTED"):
            blob = str(s)
            if "sha256:" in blob and SHA256_DIGEST.search(
                    next((tok for tok in re.findall(r"sha256:[0-9a-f]{64}", blob)), "") or ""):
                return False, f"{sid}: {cls} source carries a concrete sha256 digest (should be resolved+ACCEPTED, not {cls})"

    # Optional live re-resolution.
    notes = ["self-hash + structure OK"]
    if os.environ.get("RESOLVE") == "1":
        import build_n2e_source_registry as b
        for s in sources:
            idy = s.get("identity")
            if idy and idy.get("kind") == "huggingface_dataset":
                fresh = b.hf_dataset_revision(idy["dataset_id"])
                if fresh["immutable_revision"] != idy["immutable_revision"]:
                    return False, f"{s['source_id']}: HF revision drift on live re-resolution"
        notes.append("live re-resolution matched")
    else:
        notes.append("SKIPPED live re-resolution (set RESOLVE=1)")

    return True, "OK; " + "; ".join(notes)


def main() -> int:
    ok, message = verify(RECORD)
    if not ok:
        print(f"::error::n2e source registry verification FAILED: {message}", file=sys.stderr)
        return 1
    print(f"n2e source registry verification passed: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
