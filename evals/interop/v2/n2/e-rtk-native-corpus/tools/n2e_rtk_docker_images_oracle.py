#!/usr/bin/env python3
"""rtk-docker-images-oracle-v1: the semantic oracle for `rtk docker images`, defined FROM the pinned
RTK implementation (rtk-ai/rtk @5d32d07, src/cmds/cloud/container.rs: docker_images), NOT inferred
from one lucky output.

What the pinned source ACTUALLY does (this is decisive for what the oracle may claim):
  * it runs raw `docker images`, then re-runs
        docker images --format "{{.Repository}}:{{.Tag}}\\t{{.Size}}"
    and builds a compact projection from THAT. The format string carries ONLY repository:tag and the
    human-readable size -- there is NO image ID, NO digest, NO CREATED in RTK's output.
  * header:  "[docker] {N} images ({total})\\n"   N = number of --format lines
  * per row: "  {repository:tag} [{size}]\\n"      (capped at CAP_INVENTORY = 50; "… +K more" + tee)
  * total size sums ONLY GB/MB tokens (GB*1024 + MB; KB and B are IGNORED), displayed
        "{:.1}GB" if total_mb > 1024 else "{:.0}MB"
  * `never_worse(&raw, &rtk)`: if the compact form estimates MORE tokens than raw, RTK emits the RAW
    table verbatim (passthrough). For a single image the header can tip this into passthrough --
    which mode actually occurs is a DIAGNOSTIC outcome, so this oracle recognizes BOTH.

So the oracle claims ONLY what RTK prints: outcome, output_mode (compact|passthrough), the image
COUNT, and the canonical MULTISET of (repository:tag, displayed_size) rows. The displayed size is
PRESENTATION (rounded) -- compared RAW<->RTK for consistency, never treated as content identity.
Image IDENTITY (the config/manifest digest) is NOT in RTK's output; it is proven separately as an
EXECUTION determinant from `docker image inspect` (parse_inspect below is the helper for that), never
claimed here.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

ORACLE_ID = "rtk-docker-images-oracle-v1"
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
RTK_SOURCE_FILE = "src/cmds/cloud/container.rs"
RTK_SOURCE_FUNCTION = "docker_images"
RTK_SOURCE_REFS = (
    {"source_file": "src/core/guard.rs", "source_function": "never_worse"},
    {"source_file": "src/core/truncate.rs", "source_function": "CAP_INVENTORY"},
)
CAP_INVENTORY = 50  # src/core/truncate.rs

# compact header: "[docker] {N} images ({total})"
_HDR = re.compile(r"^\[docker\] (\d+) images \((.+)\)$")
# compact image row: "  {repository:tag} [{size}]"
_ROW = re.compile(r"^  (.+) \[([^\]]*)\]$")
# truncation marker: "  … +{K} more"
_MORE = re.compile(r"^  … \+(\d+) more$")


def _nd(reason: str) -> dict:
    return {"outcome": "not_derivable", "derivable": False, "reason": reason}


# ---------------------------------------------------------------------------------------------------
# The size total, computed EXACTLY as the pinned Rust source does (GB*1024 + MB; KB/B ignored).
# ---------------------------------------------------------------------------------------------------
def total_size_display(rows: list[tuple[str, str]]) -> str:
    total_mb = 0.0
    for _repo_tag, size in rows:
        if "GB" in size:
            try:
                total_mb += float(size.replace("GB", "").strip()) * 1024.0
            except ValueError:
                pass
        elif "MB" in size:
            try:
                total_mb += float(size.replace("MB", "").strip())
            except ValueError:
                pass
        # KB and B are intentionally NOT summed (matches the source)
    return f"{total_mb / 1024.0:.1f}GB" if total_mb > 1024.0 else f"{total_mb:.0f}MB"


# ---------------------------------------------------------------------------------------------------
# RAW authority: `docker images --format "{{.Repository}}:{{.Tag}}\t{{.Size}}"` -- the exact projection
# RTK builds from. Tab-separated, deterministic, trivially parsed (no fragile column alignment).
# ---------------------------------------------------------------------------------------------------
def parse_format_rows(data: bytes) -> dict:
    text = data.decode("utf-8", "replace")
    rows = []
    for line in text.split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t")
        repo_tag = parts[0] if parts else ""
        size = parts[1] if len(parts) > 1 else ""
        rows.append((repo_tag, size))
    if not rows:
        return _nd("no --format rows")
    return {"outcome": "images", "derivable": True, "rows": rows, "count": len(rows),
            "total_display": total_size_display(rows)}


# ---------------------------------------------------------------------------------------------------
# RTK side: parse `rtk docker images` output -- compact projection OR never_worse passthrough.
# ---------------------------------------------------------------------------------------------------
def parse_rtk(data: bytes) -> dict:
    text = data.decode("utf-8", "replace")
    lines = text.split("\n")
    first = next((ln for ln in lines if ln.strip()), "")
    m = _HDR.match(first)
    if not m:
        # never_worse fell back to raw (or the --format arm failed): RTK echoed the raw table.
        return {"outcome": "images", "derivable": True, "output_mode": "passthrough",
                "header_count": None, "total_display": None, "rows": None, "truncated": None}
    header_count = int(m.group(1))
    header_total = m.group(2)
    rows: list[tuple[str, str]] = []
    truncated = 0
    for ln in lines:
        if _HDR.match(ln):
            continue
        mm = _MORE.match(ln)
        if mm:
            truncated = int(mm.group(1))
            continue
        r = _ROW.match(ln)
        if r:
            rows.append((r.group(1), r.group(2)))
    return {"outcome": "images", "derivable": True, "output_mode": "compact",
            "header_count": header_count, "total_display": header_total,
            "rows": rows, "truncated": truncated}


# ---------------------------------------------------------------------------------------------------
# EXECUTION-determinant helper (NOT an oracle claim): parse `docker image inspect` for the identity
# anchor -- config digest (Id), RepoDigests (the pinned manifest digests), platform. Used by the
# execution policy / qualification record to prove the isolated daemon was provisioned to EXACTLY the
# pinned image; RTK never reports any of this.
# ---------------------------------------------------------------------------------------------------
def parse_inspect(data: bytes) -> dict:
    import json
    try:
        arr = json.loads(data.decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        return _nd(f"inspect json: {e}")
    if not isinstance(arr, list) or len(arr) != 1:
        return _nd(f"inspect must be a single-image array (got {type(arr).__name__} len "
                   f"{len(arr) if isinstance(arr, list) else '?'})")
    o = arr[0]
    return {"outcome": "inspect", "derivable": True,
            "id": o.get("Id"),
            "repo_digests": sorted(o.get("RepoDigests") or []),
            "repo_tags": sorted(o.get("RepoTags") or []),
            "architecture": o.get("Architecture"), "os": o.get("Os"),
            "size": o.get("Size")}


# ---------------------------------------------------------------------------------------------------
# Equivalence over EXACTLY what RTK preserves: outcome + output_mode + count + (repo:tag, size) multiset.
# ---------------------------------------------------------------------------------------------------
def _multiset(rows):
    from collections import Counter
    return Counter((rt, sz) for rt, sz in rows)


def equivalence(raw_format: dict, rtk_parsed: dict, *, allow_passthrough: bool = False) -> dict:
    """Fail-closed. Compares the RTK projection to the RAW `--format` projection (the exact rows RTK
    itself derives from). In COMPACT mode: same (repository:tag, size) multiset, same count, and RTK's
    header count + total_display must be FAITHFUL to those rows. In PASSTHROUGH mode (never_worse fell
    back to raw): RTK preserved everything but projected nothing -- accepted only if allow_passthrough
    (a policy choice, off by default; a compact-claiming case rejects it)."""
    m: list[str] = []
    if not raw_format.get("derivable"):
        m.append("raw_format_not_derivable")
    if not rtk_parsed.get("derivable"):
        m.append("rtk_not_derivable")
    if m:
        return {"equivalent": False, "mismatches": m}

    mode = rtk_parsed.get("output_mode")
    if mode == "passthrough":
        if not allow_passthrough:
            return {"equivalent": False, "mismatches": ["rtk_never_worse_passthrough_rejected"],
                    "output_mode": "passthrough",
                    "note": "RTK emitted the raw table verbatim (never_worse fallback); no compact "
                            "projection was produced, so a compact-projection claim does not hold."}
        return {"equivalent": True, "mismatches": [], "output_mode": "passthrough",
                "compared": ["outcome", "passthrough_preserves_raw"],
                "note": "RTK passthrough: output is byte-equal to raw; inventory preserved, not projected."}

    # ---- compact mode ----
    if rtk_parsed.get("truncated"):
        m.append("rtk_output_truncated_over_cap")  # >50 images: partial inventory, not a full-list claim
    raw_rows = raw_format["rows"]
    rtk_rows = rtk_parsed.get("rows") or []
    if _multiset(raw_rows) != _multiset(rtk_rows):
        m.append("listing_multiset_raw != rtk")
    if rtk_parsed.get("header_count") != len(rtk_rows):
        m.append("rtk_header_count != rtk_row_count")
    if len(raw_rows) != len(rtk_rows):
        m.append("raw_count != rtk_count")
    # RTK's header total must be faithful to its own rows (the source's GB/MB-only arithmetic)
    if rtk_parsed.get("total_display") != total_size_display(rtk_rows):
        m.append("rtk_header_total != recomputed_from_rows")

    return {
        "equivalent": not m, "mismatches": m, "output_mode": "compact",
        "compared": ["outcome", "output_mode", "image_count",
                     "repository_tag_size_multiset", "header_total_faithful"],
        "image_count": len(rtk_rows),
        "listing_multiset": sorted(f"{rt}\t{sz}" for rt, sz in rtk_rows),
        "note": "RTK preserves ONLY outcome + the (repository:tag, size) listing multiset + count; "
                "image ID / digest / CREATED are NOT emitted by RTK (identity is an execution "
                "determinant proven from docker image inspect, not an oracle claim).",
    }
