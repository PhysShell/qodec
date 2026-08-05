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

Both blobs are scanned strictly and separately. A non-blank line that does not
parse, or that parses to anything other than a JSON object, is a refusal naming
its line number, not a line quietly dropped from the count. A parser that skips
what it cannot read reports a record count for a universe it silently edited.

The measurement contract is the output. This file is its implementation. The
strictness added in the hardening pass changes behaviour only on input the
earlier implementation should never have accepted, so a run over well-formed
input reproduces the earlier output byte for byte.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys


class MalformedBlob(Exception):
    """Raised on the first unreadable line. There is no second one."""


def read_blob(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    newline_terminated = raw.endswith(b"\n")
    body = raw[:-1] if newline_terminated else raw
    return body.split(b"\n"), newline_terminated


def scan(lines, label):
    """Parse every non-blank line. Return [(line_offset, record)].

    Raises MalformedBlob on the first line that is not a JSON object.
    """
    parsed = []
    for offset, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except ValueError as exc:
            raise MalformedBlob(
                "%s line %d does not parse as JSON: %s" % (label, offset + 1, exc)
            )
        if not isinstance(record, dict):
            raise MalformedBlob(
                "%s line %d parses as %s, expected a JSON object"
                % (label, offset + 1, type(record).__name__)
            )
        parsed.append((offset, record))
    return parsed


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

    prefix_lines, prefix_newline_terminated = read_blob(args.prefix)
    if not prefix_newline_terminated:
        problems.append("prefix blob does not end with a newline")

    with open(args.window, "rb") as handle:
        window_bytes = handle.read()
    window_lines, window_newline_terminated = read_blob(args.window)
    if not window_newline_terminated:
        problems.append("window blob does not end with a newline")

    try:
        prefix_records = scan(prefix_lines, "prefix")
        window_records = scan(window_lines, "window")
    except MalformedBlob as exc:
        print(json.dumps({"problems": [str(exc)]}, indent=2, sort_keys=True))
        return 1

    index = {}
    for offset, record in prefix_records:
        uuid = record.get("uuid")
        if uuid:
            index.setdefault(uuid, []).append(offset)

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
    extracted_records = None
    if len(start_hits) == 1 and len(end_hits) == 1:
        lo, hi = start_hits[0], end_hits[0]
        if lo > hi:
            problems.append("start uuid appears after end uuid in the prefix")
        else:
            extracted = b"\n".join(prefix_lines[lo : hi + 1]) + b"\n"
            extracted_records = sum(
                1 for offset, _ in prefix_records if lo <= offset <= hi
            )
            if extracted_records != args.expect_records:
                problems.append(
                    "extracted %d records, expected %d"
                    % (extracted_records, args.expect_records)
                )

    if len(window_records) != args.expect_records:
        problems.append(
            "window blob holds %d records, expected %d"
            % (len(window_records), args.expect_records)
        )

    window_digest = hashlib.sha256(window_bytes).hexdigest()
    if window_digest != args.expect_window_sha256:
        problems.append(
            "window blob digest %s does not match the expected %s"
            % (window_digest, args.expect_window_sha256)
        )

    if extracted is None:
        problems.append("extraction did not run, so the relation is unproven")
    elif extracted != window_bytes:
        problems.append(
            "extracted slice differs from the window blob "
            "(%d bytes / %s versus %d bytes / %s)"
            % (
                len(extracted),
                hashlib.sha256(extracted).hexdigest(),
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
        "extracted_records": extracted_records,
        "window_bytes": len(window_bytes),
        "window_sha256": window_digest,
        "byte_identical": extracted == window_bytes if extracted is not None else False,
        "problems": problems,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
