#!/usr/bin/env python3
"""Acquire the SWE-bench Multilingual instance manifest (metadata only).

Fetches all instances of the SWE-bench Multilingual dataset AT THE PINNED
REVISION recorded in n2e-source-pins-v1.json, and writes a committed metadata
manifest (n2e-swebench-instances-v1.json): per-instance instance_id, repo,
base_commit, version, FAIL_TO_PASS test identities, and PASS_TO_PASS count.

No patches, diffs, or dataset payloads are committed (§3) — only small,
content-addressed metadata derived from the immutable revision. Deterministic:
re-running against the same pinned revision yields the same manifest.

Network command (acquisition phase). The candidate-inventory build reads the
committed manifest offline.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

OUT = N2E_DIR / "n2e-swebench-instances-v1.json"
PINS = N2E_DIR / "n2e-source-pins-v1.json"
DATASET = "SWE-bench/SWE-bench_Multilingual"
ROWS_URL = "https://datasets-server.huggingface.co/rows"


def pinned_revision() -> str:
    pins = c.load_record(PINS)
    for p in pins["hf_datasets"]:
        if p["source_id"] == "swe-bench-multilingual":
            return p["revision"]
    raise SystemExit("swe-bench-multilingual pin not found")


def fetch_all(revision: str) -> list[dict]:
    rows = []
    offset = 0
    while True:
        url = (f"{ROWS_URL}?dataset={DATASET.replace('/', '%2F')}"
               f"&config=default&split=test&offset={offset}&length=100&revision={revision}")
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, context=c.ssl_context(), timeout=90) as r:
            d = json.loads(r.read())
        batch = d.get("rows", [])
        if not batch:
            break
        for item in batch:
            row = item["row"]
            rows.append({
                "instance_id": row["instance_id"],
                "repo": row["repo"],
                "base_commit": row["base_commit"],
                "version": str(row["version"]),
                "fail_to_pass": list(row["FAIL_TO_PASS"]),
                "pass_to_pass_count": len(row["PASS_TO_PASS"]),
            })
        offset += len(batch)
        if offset >= d.get("num_rows_total", offset):
            break
    rows.sort(key=lambda x: x["instance_id"])
    return rows


def build() -> dict:
    rev = pinned_revision()
    instances = fetch_all(rev)
    return c.envelope(
        record_type="n2e-swebench-instances",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/acquire_n2e_swebench_instances.py",
        purpose="SWE-bench Multilingual instance metadata manifest at the pinned revision (no payloads).",
        dataset_id=DATASET,
        pinned_revision=rev,
        instance_count=len(instances),
        instances=instances,
    )


def main() -> int:
    c.write_record(OUT, build())
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name} record_sha256={rec['record_sha256']} instances={rec['instance_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
