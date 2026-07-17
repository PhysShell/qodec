#!/usr/bin/env python3
"""Builds the self-hash-locked proof that the disposable trigger commit
(46a7986, on branch n2d/ci-trigger-full-run) differs from this PR's
accepted implementation commit (0abdde6, on
n2d/identity-canary-token-benchmark-v1) by *only* the scoped push trigger
added to run real CI without workflow_dispatch (which returns 403 in this
environment) -- no benchmark logic, input, or measurement code changed.

The diff text below is the literal, real `git diff` output between the two
commits, captured once via `git diff 0abdde672...46a7986...`. It is
embedded verbatim (not re-derived at verify time, since a shallow CI
checkout may not have both commits' history) and self-hash-locked so any
tampering with the embedded diff is caught by recomputing this record's
own hash.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

IDENTITY_LOCK_DIR = Path(__file__).resolve().parents[1]
OUT_PATH = IDENTITY_LOCK_DIR / "n2d-trigger-patch-proof-v1.json"

IMPLEMENTATION_SHA = "0abdde6723574e908415835612e8f520d85c33e7"
TRIGGER_SHA = "46a7986967c1837797f5edc32e79122d839c3de3"
CHANGED_FILE = ".github/workflows/qodec-n2d-canary-benchmark.yml"

# Literal `git diff 0abdde6723574e908415835612e8f520d85c33e7
# 46a7986967c1837797f5edc32e79122d839c3de3` output, captured once.
DIFF_TEXT = """diff --git a/.github/workflows/qodec-n2d-canary-benchmark.yml b/.github/workflows/qodec-n2d-canary-benchmark.yml
index c5c9cfe..615f80b 100644
--- a/.github/workflows/qodec-n2d-canary-benchmark.yml
+++ b/.github/workflows/qodec-n2d-canary-benchmark.yml
@@ -24,6 +24,9 @@ name: qodec-n2d-canary-benchmark

 on:
   workflow_dispatch:
+  push:
+    branches:
+      - n2d/ci-trigger-full-run
 permissions:
   contents: read
 concurrency:
"""


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def parse_diff(diff_text: str) -> dict:
    """Extracts changed file paths and added/removed content lines from a
    unified diff. Mirrors the additive-only-diff parsing already
    established by verify_stage1_current_head_reacceptance.py."""
    changed_files = set()
    added_lines = []
    removed_lines = []
    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            # "diff --git a/<path> b/<path>"
            parts = line.split(" ")
            b_path = parts[-1]
            if b_path.startswith("b/"):
                b_path = b_path[2:]
            changed_files.add(b_path)
        elif line.startswith("+++") or line.startswith("---"):
            continue
        elif line.startswith("+"):
            added_lines.append(line[1:])
        elif line.startswith("-"):
            removed_lines.append(line[1:])
    return {
        "changed_files": sorted(changed_files),
        "added_lines": added_lines,
        "removed_lines": removed_lines,
    }


def build_record() -> dict:
    parsed = parse_diff(DIFF_TEXT)
    if parsed["changed_files"] != [CHANGED_FILE]:
        raise RuntimeError(f"expected only {CHANGED_FILE!r} changed, got {parsed['changed_files']}")
    if parsed["removed_lines"]:
        raise RuntimeError(f"expected an additive-only diff, but removed lines were found: {parsed['removed_lines']}")
    expected_added = ["  push:", "    branches:", "      - n2d/ci-trigger-full-run"]
    if parsed["added_lines"] != expected_added:
        raise RuntimeError(f"added lines {parsed['added_lines']} != expected {expected_added}")

    body = {
        "record_type": "n2d-trigger-patch-proof-v1",
        "record_version": 1,
        "schema_version": 1,
        "implementation_sha": IMPLEMENTATION_SHA,
        "trigger_sha": TRIGGER_SHA,
        "changed_files": parsed["changed_files"],
        "additive_only": True,
        "added_line_count": len(parsed["added_lines"]),
        "removed_line_count": len(parsed["removed_lines"]),
        "diff_text": DIFF_TEXT,
    }
    body["record_sha256"] = compute_record_sha256(body)
    return body


def main() -> None:
    record = build_record()
    OUT_PATH.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT_PATH} (record_sha256={record['record_sha256']})")


if __name__ == "__main__":
    main()
