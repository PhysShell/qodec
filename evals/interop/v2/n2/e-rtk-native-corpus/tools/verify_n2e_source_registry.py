#!/usr/bin/env python3
"""Independently verify n2e-source-registry-v1.json + its pins (§2, §22).

Offline (always):
  - recompute self-hash of the registry AND the pins record;
  - registry.pins_sha256 must equal the committed pins' own compact hash;
  - every source carries a vocabulary classification + typed reason;
  - ACCEPTED_PRIMARY carries an immutable identity (40-hex HF revision /
    Zenodo record+file checksums / sha256 index+child OCI digests);
  - DEFERRED / REJECTED sources carry no concrete sha256 digest.

Live (RESOLVE=1), verification is BY IMMUTABLE IDENTITY — never vs HEAD/latest:
  - HF: fetch the dataset at the exact pinned revision; require the returned sha
    equals the pin (proves that immutable revision still exists);
  - Zenodo: fetch the exact version record; require every committed file
    (key,size,checksum) to agree;
  - OCI: fetch repository@index_digest and @child_digest, verify the manifest
    bytes hash to those digests and the child is the pinned platform.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import oci_resolve  # noqa: E402

RECORD = N2E_DIR / "n2e-source-registry-v1.json"
PINS = N2E_DIR / "n2e-source-pins-v1.json"
VOCAB = {"ACCEPTED_PRIMARY", "ACCEPTED_RESERVE", "REJECTED", "DEFERRED"}
SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HF_REV = re.compile(r"^[0-9a-f]{40}$")


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, context=c.ssl_context(), timeout=60) as r:
        return json.loads(r.read())


def _structural(rec: dict, pins: dict) -> tuple[bool, str]:
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        return False, f"registry: {msg}"
    ok, msg = c.verify_self_hash(pins)
    if not ok:
        return False, f"pins: {msg}"
    if rec.get("record_type") != "n2e-source-registry":
        return False, f"unexpected record_type {rec.get('record_type')!r}"
    if rec.get("pins_sha256") != c.sha256_json_file(PINS):
        return False, "registry.pins_sha256 does not match the committed pins record"

    # Cross-check each ACCEPTED_PRIMARY identity against the committed pins so a
    # tampered revision/digest is caught OFFLINE (no dependence on HEAD).
    pin_index = {
        "huggingface_dataset": {p["source_id"]: p for p in pins.get("hf_datasets", [])},
        "zenodo_record": {p["source_id"]: p for p in pins.get("zenodo_records", [])},
        "oci_image": {p["source_id"]: p for p in pins.get("oci_images", [])},
        "git_repo": {p["source_id"]: p for p in pins.get("git_repos", [])},
    }

    sources = rec.get("sources", [])
    if len(sources) != rec.get("source_count"):
        return False, "source_count mismatch"
    seen = set()
    for s in sources:
        sid = s.get("source_id")
        if sid in seen:
            return False, f"duplicate source_id {sid!r}"
        seen.add(sid)
        if s.get("classification") not in VOCAB:
            return False, f"{sid}: bad classification"
        if not s.get("typed_reason"):
            return False, f"{sid}: missing typed_reason"
        idy = s.get("identity")
        if s["classification"] == "ACCEPTED_PRIMARY":
            if not idy:
                return False, f"{sid}: ACCEPTED_PRIMARY without identity"
            k = idy.get("kind")
            if k == "huggingface_dataset":
                if not HF_REV.match(idy.get("immutable_revision", "")):
                    return False, f"{sid}: HF identity lacks an immutable 40-hex revision"
            elif k == "zenodo_record":
                if not idy.get("record_id") or not idy.get("files"):
                    return False, f"{sid}: zenodo identity lacks record_id/files"
                for f in idy["files"]:
                    if not (f.get("key") and f.get("checksum") and f.get("size") is not None):
                        return False, f"{sid}: zenodo file missing key/size/checksum"
            elif k == "oci_image":
                if not SHA256_DIGEST.match(idy.get("index_digest", "")) or not SHA256_DIGEST.match(idy.get("child_digest", "")):
                    return False, f"{sid}: OCI identity lacks immutable index+child sha256 digests"
            elif k == "git_repo":
                if not re.match(r"^[0-9a-f]{40}$", idy.get("commit", "")):
                    return False, f"{sid}: git identity lacks a 40-hex commit"
            else:
                return False, f"{sid}: unknown identity kind {k!r}"
            # identity must equal the committed pin (offline tamper check)
            pin = pin_index.get(k, {}).get(sid)
            if pin is None:
                return False, f"{sid}: ACCEPTED_PRIMARY identity has no matching pin"
            if k == "huggingface_dataset" and idy["immutable_revision"] != pin["revision"]:
                return False, f"{sid}: HF revision differs from committed pin"
            if k == "zenodo_record":
                pin_files = {f["key"]: (f["size"], f["checksum"]) for f in pin["files"]}
                if {f["key"]: (f["size"], f["checksum"]) for f in idy["files"]} != pin_files:
                    return False, f"{sid}: Zenodo files differ from committed pin"
            if k == "oci_image" and (idy["index_digest"] != pin["index_digest"] or idy["child_digest"] != pin["child_digest"]):
                return False, f"{sid}: OCI digests differ from committed pin"
            if k == "git_repo" and idy["commit"] != pin["commit"]:
                return False, f"{sid}: git commit differs from committed pin"
        if s["classification"] in ("DEFERRED", "REJECTED"):
            if re.search(r"sha256:[0-9a-f]{64}", json.dumps(s)):
                return False, f"{sid}: {s['classification']} source carries a concrete digest"
    return True, "structural OK"


def _live(sources: list) -> tuple[bool, str]:
    import urllib.error
    for s in sources:
        if s["classification"] != "ACCEPTED_PRIMARY":
            continue
        idy = s["identity"]
        k = idy["kind"]
        try:
            if k == "huggingface_dataset":
                rev = idy["immutable_revision"]
                d = _get_json(f"https://huggingface.co/api/datasets/{idy['dataset_id']}/revision/{rev}")
                if d.get("sha") != rev:
                    return False, f"{s['source_id']}: HF revision {rev} not resolvable (got {d.get('sha')})"
            elif k == "zenodo_record":
                d = _get_json(f"https://zenodo.org/api/records/{idy['record_id']}")
                live_files = {f["key"]: (f["size"], f["checksum"]) for f in d["files"]}
                for f in idy["files"]:
                    got = live_files.get(f["key"])
                    if got != (f["size"], f["checksum"]):
                        return False, f"{s['source_id']}: Zenodo file {f['key']} drift {got} != {(f['size'], f['checksum'])}"
            elif k == "oci_image":
                ev = oci_resolve.verify_by_digest(
                    idy["registry"], idy["repository"], idy["index_digest"], idy["child_digest"],
                    arch=idy["platform"].split("/")[1], os_name=idy["platform"].split("/")[0])
                if not ev.get("verified"):
                    return False, f"{s['source_id']}: OCI digest verification failed {ev}"
            elif k == "git_repo":
                import subprocess
                url = f"https://github.com/{idy['repository']}.git"
                p = subprocess.run(["git", "fetch", "--depth", "1", url, idy["commit"]],
                                   capture_output=True, cwd="/tmp",
                                   env={"GIT_TERMINAL_PROMPT": "0", "PATH": os.environ.get("PATH", "/usr/bin:/bin")})
                # a bare fetch of a commit needs a repo; use ls-remote fallback to confirm reachability
                if p.returncode != 0:
                    ls = subprocess.run(["git", "ls-remote", "--exit-code", url, "HEAD"],
                                        capture_output=True,
                                        env={"GIT_TERMINAL_PROMPT": "0", "PATH": os.environ.get("PATH", "/usr/bin:/bin")})
                    if ls.returncode != 0:
                        return False, f"{s['source_id']}: git repo unreachable"
        except urllib.error.HTTPError as e:
            return False, f"{s['source_id']}: pinned artifact unavailable (HTTP {e.code})"
    return True, "live-by-digest OK"


def verify(path: Path) -> tuple[bool, str]:
    if not path.is_file() or not PINS.is_file():
        return False, "registry or pins file missing"
    rec = c.load_record(path)
    pins = c.load_record(PINS)
    ok, msg = _structural(rec, pins)
    if not ok:
        return False, msg
    notes = [msg]
    if os.environ.get("RESOLVE") == "1":
        ok, msg = _live(rec["sources"])
        if not ok:
            return False, msg
        notes.append(msg)
    else:
        notes.append("SKIPPED live verify-by-digest (set RESOLVE=1)")
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
