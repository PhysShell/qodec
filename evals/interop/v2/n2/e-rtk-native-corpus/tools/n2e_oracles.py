"""Semantic-preservation oracles (§14).

Each oracle derives invariants from the RAW output and checks the RTK output
preserves them. Formatting/grouping may differ; identities and counts may not.

Implemented here:
  - log_severity_counts(raw): error/warn/info line counts + total lines (§14 logs)
  - grep_match_identities(raw): set of (path, line_no, matched_text_hash) (§14 grep)

These are the invariants the corpus lock will pin per selected scenario; more
family oracles (test IDs, diagnostics, git paths, docker identities) are added as
their strata are executed.
"""
from __future__ import annotations

import hashlib
import re

_SEV = {
    "error": re.compile(rb"\b(error|err|fatal|panic|severe)\b", re.IGNORECASE),
    "warn": re.compile(rb"\b(warn|warning)\b", re.IGNORECASE),
    "info": re.compile(rb"\b(info|notice|debug|trace)\b", re.IGNORECASE),
}


def log_severity_counts(raw: bytes) -> dict:
    lines = raw.splitlines()
    counts = {"total_lines": len(lines), "error": 0, "warn": 0, "info": 0}
    for ln in lines:
        for sev, pat in _SEV.items():
            if pat.search(ln):
                counts[sev] += 1
                break
    return counts


def grep_match_identities(raw: bytes) -> set:
    """(path, line_no, sha256(matched_text)) for `grep -n` style output."""
    ids = set()
    for ln in raw.splitlines():
        # path:line:content  OR  line:content
        m = re.match(rb"(?:([^:]+):)?(\d+):(.*)$", ln)
        if m:
            path = (m.group(1) or b"").decode("utf-8", "replace")
            line_no = int(m.group(2))
            text_hash = hashlib.sha256(m.group(3)).hexdigest()
            ids.add((path, line_no, text_hash))
    return ids


def check_log_oracle(raw: bytes, rtk: bytes) -> dict:
    """A log case PASSES only if RTK preserves RAW severity counts. RTK may
    summarize/dedupe, but must not misreport how many error/warn/info events
    the RAW output contained. Returns a verdict dict."""
    raw_counts = log_severity_counts(raw)
    # RTK's summary reports counts like "[error] N errors"; parse them back.
    rtk_reported = {"error": None, "warn": None, "info": None}
    for sev, key in (("error", rb"(\d+)\s+errors?"), ("warn", rb"(\d+)\s+warnings?"),
                     ("info", rb"(\d+)\s+info")):
        m = re.search(rb"\[" + sev.encode() + rb"\][^\n]*?" + key, rtk)
        if m:
            rtk_reported[sev] = int(m.group(1))
    preserved = all(
        rtk_reported[s] is None or rtk_reported[s] == raw_counts[s]
        for s in ("error", "warn", "info")
    )
    return {
        "oracle": "log_severity_counts",
        "raw_counts": raw_counts,
        "rtk_reported": rtk_reported,
        "severity_counts_preserved": preserved,
        # A log case where RAW carries content but RTK reports zero across the
        # board is flagged: RTK dropped the content the oracle must preserve.
        "content_dropped": (raw_counts["total_lines"] > 0
                            and all(v == 0 for v in (rtk_reported["error"] or 0,
                                                     rtk_reported["warn"] or 0,
                                                     rtk_reported["info"] or 0))
                            and (raw_counts["error"] + raw_counts["warn"] + raw_counts["info"]) > 0),
    }
