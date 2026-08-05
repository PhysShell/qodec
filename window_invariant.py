#!/usr/bin/env python3
"""Prove that the window blob is the anchored slice of the prefix blob.

Two blobs that are each individually well-formed do not establish the relation
claimed between them. This tool computes the relation and fails closed.

    python3 window_invariant.py \
        --prefix claude-session.prefix-r21.jsonl \
        --window claude-session.window-r21.jsonl \
        --start-uuid <uuid> --end-uuid <uuid> \
        --expect-records 527 \
        --expect-window-sha256 <hex>

Exit 0 only if every check passes. Any failure prints the failures and exits 1.
Nothing is repaired, nothing is warned about and continued past.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys


def load_lines(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    if not raw.endswith(b"\n"):
        return raw.split(b"\n"), False
    return raw[:-1].split(b"\n"), True


def record_uuids(lines):
    """Map uuid -> list of line offsets. A uuid seen twice keeps both."""
    seen = {}
    for offset, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except ValueError:
            continue
        uuid = record.get("uuid")
        if uuid:
            seen.setdefault(uuid, []).append(offset)
    return seen


def count_records(chunk_lines):
    total = 0
    for line in chunk_lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            json.loads(stripped)
        except ValueError:
            continue
        total += 1
    return total


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--window", required=True)
    parser.add_argument("--start-uuid", required=True)
    parser.add_argument("--end-uuid", required=True)
    parser.add_argument("--expect-records", type=int, required=True)
    parser.add_argument("--expect-window-sha256", required=True)
    args = parser.parse_args(argv)

    problems = []

    prefix_lines, prefix_newline_terminated = load_lines(args.prefix)
    if not prefix_newline_terminated:
        problems.append("prefix blob does not end with a newline")

    index = record_uuids(prefix_lines)

    start_hits = index.get(args.start_uuid, [])
    end_hits = index.get(args.end_uuid, [])
    if len(start_hits) != 1:
        problems.append(
            "start uuid occurs %d times in the prefix, expected exactly 1"
            % len(start_hits)
        )
    if len(end_hits) != 1:
        problems.append(
            "end uuid occurs %d times in the prefix, expected exactly 1"
            % len(end_hits)
        )

    extracted = None
    if len(start_hits) == 1 and len(end_hits) == 1:
        lo, hi = start_hits[0], end_hits[0]
        if lo > hi:
            problems.append("start uuid appears after end uuid in the prefix")
        else:
            extracted = b"\n".join(prefix_lines[lo : hi + 1]) + b"\n"
            found = count_records(prefix_lines[lo : hi + 1])
            if found != args.expect_records:
                problems.append(
                    "extracted %d records, expected %d" % (found, args.expect_records)
                )

    with open(args.window, "rb") as handle:
        window_bytes = handle.read()

    window_digest = hashlib.sha256(window_bytes).hexdigest()
    if window_digest != args.expect_window_sha256:
        problems.append(
            "window blob digest %s does not match the expected %s"
            % (window_digest, args.expect_window_sha256)
        )

    if extracted is None:
        problems.append("extraction did not run, so the relation is unproven")
    else:
        extracted_digest = hashlib.sha256(extracted).hexdigest()
        if extracted != window_bytes:
            problems.append(
                "extracted slice differs from the window blob "
                "(%d bytes / %s versus %d bytes / %s)"
                % (
                    len(extracted),
                    extracted_digest,
                    len(window_bytes),
                    window_digest,
                )
            )

    report = {
        "prefix": args.prefix,
        "window": args.window,
        "start_uuid": args.start_uuid,
        "end_uuid": args.end_uuid,
        "start_occurrences": len(start_hits),
        "end_occurrences": len(end_hits),
        "start_line_offset": start_hits[0] if len(start_hits) == 1 else None,
        "end_line_offset": end_hits[0] if len(end_hits) == 1 else None,
        "extracted_bytes": len(extracted) if extracted is not None else None,
        "extracted_records": (
            count_records(
                prefix_lines[start_hits[0] : end_hits[0] + 1]
            )
            if len(start_hits) == 1 and len(end_hits) == 1 and start_hits[0] <= end_hits[0]
            else None
        ),
        "window_bytes": len(window_bytes),
        "window_sha256": window_digest,
        "byte_identical": extracted == window_bytes if extracted is not None else False,
        "problems": problems,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
