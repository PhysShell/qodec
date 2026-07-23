#!/usr/bin/env python3
"""rtk-log-hdfs-oracle-v1: the semantic oracle for `rtk log HDFS.log`, defined FROM the pinned RTK
implementation (rtk-ai/rtk @5d32d07, src/cmds/system/log_cmd.rs: analyze_logs), NOT inferred from one
lucky output. RTK's `log` command "deduplicates repeated log lines and shows counts": it categorizes
each line by a SUBSTRING severity check (case-insensitive, priority error>warn>info) and reports
per-category TOTALS plus capped/truncated unique lists.

What RTK actually preserves -- and therefore ALL this oracle claims -- is the SEVERITY TOTALS
(errors / warnings / info). RTK's "unique" counts use its own normalizer, which (crucially for HDFS)
does NOT normalize `blk_<id>` block ids, so they are inflated and NOT comparable to the published
loghub EventIds. The published Loghub set remains the RAW capsule's identity authority; this oracle
proves only the severity-total overlap that is genuinely available in RTK's output. It invents no
counts or template identities RTK does not report.

Source-grounded categorization (mirrored from analyze_logs, exact keyword sets + priority):
  * error bucket: line contains any of error/fatal/panic/critical/alert/emerg/severe
  * warn  bucket: else contains warn/notice
  * info  bucket: else contains info
  * otherwise the line is DROPPED (counted in no bucket) -- exactly as RTK drops it.
"""
from __future__ import annotations

import re

ORACLE_ID = "rtk-log-hdfs-oracle-v1"
# source-identity constants consumed by build_n2e_command_oracle_source_proof
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
RTK_SOURCE_FILE = "src/cmds/system/log_cmd.rs"
RTK_SOURCE_FUNCTION = "analyze_logs"

# mirrored severity keyword sets + priority (analyze_logs, checked against line.to_lowercase())
_ERROR_KW = ("error", "fatal", "panic", "critical", "alert", "emerg", "severe")
_WARN_KW = ("warn", "notice")
_INFO_KW = ("info",)


def rtk_categorize(line: str) -> str:
    """Mirror RTK's per-line severity categorization (substring, priority error>warn>info, else drop)."""
    low = line.lower()
    if any(k in low for k in _ERROR_KW):
        return "error"
    if any(k in low for k in _WARN_KW):
        return "warn"
    if any(k in low for k in _INFO_KW):
        return "info"
    return "other"   # dropped by RTK (counted in no bucket)


# parse the RTK "Log Summary" header (the authoritative totals, computed before truncation)
_ERR = re.compile(r"\[error\]\s+(\d+)\s+errors\s+\((\d+)\s+unique\)")
_WARN = re.compile(r"\[warn\]\s+(\d+)\s+warnings\s+\((\d+)\s+unique\)")
_INFO = re.compile(r"\[info\]\s+(\d+)\s+info messages")


def parse_rtk(data: bytes) -> dict:
    """Parse `rtk log` output into the severity totals it reports. `derivable=False` when the
    Log Summary header is absent (e.g. RTK's never_worse guard printed the raw content instead)."""
    text = data.decode("utf-8", "replace")
    if "Log Summary" not in text:
        return {"outcome": "not_derivable", "derivable": False}
    em, wm, im = _ERR.search(text), _WARN.search(text), _INFO.search(text)
    if not (em and wm and im):
        return {"outcome": "not_derivable", "derivable": False}
    return {
        "outcome": "summary",
        "derivable": True,
        "total_errors": int(em.group(1)), "error_unique": int(em.group(2)),
        "total_warnings": int(wm.group(1)), "warn_unique": int(wm.group(2)),
        "total_info": int(im.group(1)),
    }


def raw_projection_from_capsule(capsule_summary: dict) -> dict:
    """The RAW-side reference: RTK's severity totals RE-DERIVED over the full RAW stream, carried in
    the log-evidence-capsule's rtk_semantic_projection (bounded counters). This is what RTK SHOULD
    report; a stream that never produced the projection is not derivable."""
    proj = (capsule_summary or {}).get("rtk_semantic_projection")
    if not proj:
        return {"outcome": "not_derivable", "derivable": False}
    return {
        "outcome": "summary", "derivable": True,
        "total_errors": proj["error"], "total_warnings": proj["warn"], "total_info": proj["info"],
        "dropped": proj.get("other", 0),
    }


# the ONLY fields RTK preserves -> the ONLY fields compared for equivalence
_EQUIV_KEYS = ("total_errors", "total_warnings", "total_info")


def equivalence(raw: dict, rtk: dict) -> dict:
    """RAW<->RTK semantic equivalence on the severity totals RTK actually reports. Both sides must be
    derivable; the per-category totals must agree. RTK's inflated unique counts + loghub EventIds are
    NOT compared (RTK does not report EventIds; its unique counts are normalizer-specific)."""
    if not raw.get("derivable") or not rtk.get("derivable"):
        return {"equivalent": False, "mismatches": ["not_derivable"],
                "raw_derivable": bool(raw.get("derivable")), "rtk_derivable": bool(rtk.get("derivable"))}
    mism = [k for k in _EQUIV_KEYS if raw.get(k) != rtk.get(k)]
    return {"equivalent": not mism, "mismatches": mism,
            "compared_fields": list(_EQUIV_KEYS),
            "note": "severity totals only; RTK reports no loghub EventIds or per-template counts"}
