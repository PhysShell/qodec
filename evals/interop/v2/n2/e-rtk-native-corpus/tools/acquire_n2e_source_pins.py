#!/usr/bin/env python3
"""Acquisition (§2 step 1): resolve real identities ONCE and write explicit pins.

Emits n2e-source-pins-v1.json containing ONLY immutable, normative identity
fields:
  - HF dataset id + exact 40-hex revision
  - Zenodo version record id + version DOI + per-file (key, size, checksum)
  - OCI repository + index digest + platform child digest + media type

Mutable discovery metadata (last_modified, retrieval time, current HEAD, the
original :tag) is deliberately NOT written into the pin, so the pin — and the
canonical registry built from it — is stable across future upstream revisions.

This is a NETWORK command, run explicitly. It must never be invoked by the
deterministic build or by CI's canonical-record check. Re-running it after an
upstream move produces a NEW pin that a human reviews and commits deliberately;
it never silently rewrites the committed lock.

Usage:
  acquire_n2e_source_pins.py            # resolve dataset HEADs as the pins
  acquire_n2e_source_pins.py --check    # resolve and diff against committed pins
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import oci_resolve  # noqa: E402

PINS = N2E_DIR / "n2e-source-pins-v1.json"

# What to acquire. HF revision defaults to the dataset's current sha at
# acquisition time; pass an explicit historical revision to pin one deliberately.
HF_DATASETS = [
    {"source_id": "swe-bench-multilingual", "dataset_id": "SWE-bench/SWE-bench_Multilingual", "revision": None},
]
ZENODO_RECORDS = [
    {"source_id": "loghub-2.0", "record_id": "8275861"},
]
OCI_IMAGES = [
    # A real SWE-bench eval image, pinned by digest, used to validate the
    # per-instance OCI-by-digest lock path the corpus will rely on.
    {"source_id": "swe-bench-eval-image-sample",
     "registry": "registry-1.docker.io",
     "repository": "swebench/sweb.eval.x86_64.astropy_1776_astropy-12907",
     "tag_acquired_from": "latest", "platform_arch": "amd64", "platform_os": "linux"},
]


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, context=c.ssl_context(), timeout=60) as r:
        return json.loads(r.read())


def acquire_hf(entry: dict) -> dict:
    ds = entry["dataset_id"]
    rev = entry.get("revision")
    url = f"https://huggingface.co/api/datasets/{ds}"
    if rev:
        url += f"/revision/{rev}"
    d = _get_json(url)
    resolved = d["sha"]
    if rev and resolved != rev:
        raise SystemExit(f"{ds}: requested revision {rev} but API returned {resolved}")
    return {
        "source_id": entry["source_id"],
        "kind": "huggingface_dataset",
        "dataset_id": d["id"],
        "revision": resolved,  # exact 40-hex immutable commit
        "source_url": f"https://huggingface.co/datasets/{ds}",
    }


def acquire_zenodo(entry: dict) -> dict:
    recid = entry["record_id"]
    d = _get_json(f"https://zenodo.org/api/records/{recid}")
    meta = d.get("metadata", {})
    lic = meta.get("license")
    lic_id = lic.get("id") if isinstance(lic, dict) else lic
    files = sorted(
        ({"key": f["key"], "size": f["size"], "checksum": f["checksum"]} for f in d["files"]),
        key=lambda f: f["key"],
    )
    return {
        "source_id": entry["source_id"],
        "kind": "zenodo_record",
        "record_id": str(d["id"]),
        "version_doi": d.get("doi"),
        "concept_doi": d.get("conceptdoi"),
        "license": lic_id,
        "title": meta.get("title"),
        "files": files,
    }


def acquire_oci(entry: dict) -> dict:
    ev = oci_resolve.resolve(entry["registry"], entry["repository"], entry["tag_acquired_from"],
                             arch=entry["platform_arch"], os_name=entry["platform_os"])
    index_digest = ev.get("index_digest") or ev.get("top_registry_digest") or ev.get("pinned_digest")
    child_digest = ev.get("pinned_digest")
    return {
        "source_id": entry["source_id"],
        "kind": "oci_image",
        "registry": entry["registry"],
        "repository": entry["repository"],
        "platform": f"{entry['platform_os']}/{entry['platform_arch']}",
        "index_digest": index_digest,
        "child_digest": child_digest,
        "media_type": ev.get("child_media_type") or ev.get("top_media_type"),
    }


def acquire() -> dict:
    body = c.envelope(
        record_type="n2e-source-pins",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/acquire_n2e_source_pins.py",
        purpose="Explicit immutable source pins (§2 acquisition). Normative fields only; no mutable discovery metadata.",
        hf_datasets=[acquire_hf(e) for e in HF_DATASETS],
        zenodo_records=[acquire_zenodo(e) for e in ZENODO_RECORDS],
        oci_images=[acquire_oci(e) for e in OCI_IMAGES],
    )
    return body


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="resolve and diff against committed pins without writing")
    args = ap.parse_args()
    body = acquire()
    c.finalize(body)
    if args.check:
        if not PINS.exists():
            print("no committed pins to compare", file=sys.stderr)
            return 1
        committed = c.load_record(PINS)
        # compare everything except the self-hash / generated_by envelope noise
        a = {k: v for k, v in body.items() if k != "record_sha256"}
        b = {k: v for k, v in committed.items() if k != "record_sha256"}
        if a == b:
            print("pins unchanged vs upstream")
            return 0
        print("DRIFT: upstream identities differ from committed pins (review before committing)")
        return 2
    c.write_record(PINS, body)
    print(f"wrote {PINS.name} record_sha256={c.load_record(PINS)['record_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
