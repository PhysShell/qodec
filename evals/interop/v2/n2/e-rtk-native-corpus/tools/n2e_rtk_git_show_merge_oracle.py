#!/usr/bin/env python3
"""rtk-git-show-merge-first-parent-oracle-v1: the CASE-SCOPED semantic oracle for `rtk git show` on a
MERGE commit (rubocop__rubocop-13687::git::show, base f0ec1b58...). It does NOT claim a general
git::show policy -- the diagnostic proved that `git show` means different things for different commit
types, and this oracle is proven only for this merge case.

Why a distinct oracle: for a bare `git show` on a MERGE commit, git suppresses the diff by default, so
the RAW arm is a DEGENERATE representation -- it carries the commit object + merge topology + message,
but NO diff. RTK's `rtk git show` does not invent changes: it deterministically obtains the
FIRST-PARENT diffstat via git (`git show --stat` internally). So the authority is split EXPLICITLY,
rather than pretending the 394-byte RAW output contains a stat it does not:

  * RAW  (bare `git show` on the pinned checkout)  -> IDENTITY + TOPOLOGY:
      full commit OID, successful outcome, commit IS a merge, ordered parent list (abbreviated), and
      the ABSENCE of a RAW diff is the EXPECTED state for this case.
  * REPOSITORY PLUMBING (same pinned checkout)      -> the normative FIRST-PARENT delta, derived from
      the EXACT first-parent pair: `git diff --numstat/--shortstat <first-parent-oid> <merge-oid>`,
      additionally cross-checked against RTK's own command shape `git show --stat --pretty=format:`.
      An empty `--name-status` is NEVER used as proof of "no files" (a merge trap the diagnostic caught).
  * RTK  (fresh `rtk git show` output, COMPACT mode) -> abbreviated hash, affected_paths,
      files_changed, insertions, deletions, output mode.

Equivalence passes ONLY when: RAW full OID == contract OID; RAW confirms merge topology (ordered
parents consistent with plumbing); repository first-parent stat == RTK compact stat (totals + path
SET); RTK abbreviated hash is a prefix of the full OID AND uniquely resolves to it in the pinned repo;
and RTK output mode == compact. never_worse RAW FALLBACK is REJECTED as not-derivable for this case
(the stat overlap vanishes in fallback, leaving the claim too weak). EXCLUDED: %ar, patch body,
subject/author formatting, the second-parent / combined diff, and any patch_semantic_hash.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import n2e_rtk_git_show_oracle as base  # noqa: E402  (reuse the tested parsers as a library)

ORACLE_ID = "rtk-git-show-merge-first-parent-oracle-v1"
# source-identity constants consumed by build_n2e_command_oracle_source_proof
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
RTK_SOURCE_FILE = "src/cmds/git/git_cmd.rs"
RTK_SOURCE_FUNCTION = "run_show"
RTK_SOURCE_REFS = (
    {"source_file": "src/cmds/git/git_cmd.rs", "source_function": "compact_diff"},
    {"source_file": "src/core/guard.rs", "source_function": "never_worse"},
    {"source_file": "src/cmds/git/diff_cmd.rs",
     "source_function": "condense_unified_diff (co-pinned sibling; not called by run_show)"},
)

_MERGE_LINE = re.compile(r"^Merge:\s+(.+?)\s*$")


def _nd(reason: str) -> dict:
    return {"outcome": "not_derivable", "derivable": False, "reason": reason}


# ---------------------------------------------------------------------------------------------------
# RAW authority: identity + topology from the bare `git show` bytes (NO stat -- expected on a merge).
# ---------------------------------------------------------------------------------------------------
def parse_raw_merge_identity(data: bytes) -> dict:
    text = data.decode("utf-8", "replace")
    lines = text.split("\n")
    if not lines:
        return _nd("empty")
    m = base._COMMIT_LINE.match(lines[0])
    if not m:
        return _nd("no commit header line")
    full_oid = m.group(1)
    abbreviated_parents = None
    for ln in lines[1:8]:                    # the `Merge:` line is in the header block
        mm = _MERGE_LINE.match(ln)
        if mm:
            abbreviated_parents = mm.group(1).split()
            break
    has_diff = any(ln.startswith("diff --git ") for ln in lines)
    is_merge = bool(abbreviated_parents) and len(abbreviated_parents) >= 2
    return {
        "outcome": "git_show_merge", "derivable": True,
        "full_commit_oid": full_oid,
        "is_merge": is_merge,
        "abbreviated_parents": abbreviated_parents or [],
        "raw_has_diff": has_diff,        # expected False for this merge case
    }


# ---------------------------------------------------------------------------------------------------
# Plumbing authority: ordered parents + the FIRST-PARENT delta (numstat + shortstat must agree).
# ---------------------------------------------------------------------------------------------------
def parse_rev_list_parents(text: str) -> dict:
    """`git rev-list --parents -n 1 <merge>` -> `<merge> <p1> <p2> ...` (full OIDs, ordered)."""
    toks = (text or "").split()
    if len(toks) < 2:
        return _nd("rev-list parents: fewer than one parent")
    return {"outcome": "parents", "derivable": True,
            "merge_oid": toks[0].lower(), "parents": [t.lower() for t in toks[1:]],
            "first_parent_oid": toks[1].lower()}


def parse_first_parent_stat(numstat: bytes, shortstat: bytes) -> dict:
    """Normative first-parent stat from `git diff --numstat/--shortstat <first-parent> <merge>`. The
    two plumbing views must AGREE on the totals, else not-derivable."""
    ns = base.parse_numstat(numstat)
    ss = base.parse_shortstat(shortstat)
    if not ns.get("derivable"):
        return _nd("numstat not derivable")
    if not ss.get("derivable"):
        return _nd("shortstat not derivable")
    if any(ns.get(k) != ss.get(k) for k in ("files_changed", "insertions", "deletions")):
        return _nd("numstat/shortstat totals disagree")
    return {"outcome": "first_parent_stat", "derivable": True,
            "files_changed": ns["files_changed"], "insertions": ns["insertions"],
            "deletions": ns["deletions"], "affected_paths": ns["affected_paths"],
            "binary_paths": ns.get("binary_paths", [])}


def parse_show_stat_crosscheck(show_stat: bytes) -> dict:
    """RTK's own command shape: `git show --stat --pretty=format: <merge>` (a bare --stat block:
    per-file `path | N +/-` + the `N files changed, ...` summary line). Used ONLY to cross-check the
    first-parent stat -- RTK derives its compact projection from exactly this -- not the authority."""
    paths, totals = [], None
    for ln in show_stat.decode("utf-8", "replace").split("\n"):
        sm = base._STAT_SUMMARY.match(ln)
        if sm:
            totals = (int(sm.group(1)), int(sm.group(2) or 0), int(sm.group(3) or 0)); break
        if "|" in ln:
            left = ln.split("|", 1)[0].strip()
            if left:
                paths.append(base._expand_stat_rename(base._dequote_path(left)))
    if totals is None:
        return _nd("show --stat missing summary line")
    return {"outcome": "first_parent_stat", "derivable": True,
            "files_changed": totals[0], "insertions": totals[1], "deletions": totals[2],
            "affected_paths": sorted(set(paths))}


# ---------------------------------------------------------------------------------------------------
# RTK authority: compact projection ONLY (raw_fallback rejected for this case).
# ---------------------------------------------------------------------------------------------------
def parse_rtk_compact(data: bytes) -> dict:
    p = base.parse_rtk(data)
    if p.get("derivable") and p.get("rtk_output_mode") != "compact":
        return _nd("rtk emitted raw_fallback; the merge-case oracle requires compact (stat overlap "
                   "vanishes in fallback)")
    return p


# ---------------------------------------------------------------------------------------------------
# Equivalence over the split authority.
# ---------------------------------------------------------------------------------------------------
_STAT_KEYS = ("files_changed", "insertions", "deletions")


def _parents_consistent(abbrev_parents: list, full_parents: list) -> bool:
    """The RAW `Merge:` abbreviated parents must match the plumbing full parents in ORDER and be
    genuine prefixes."""
    if len(abbrev_parents) != len(full_parents):
        return False
    return all(fp.startswith(ap.lower()) and len(ap) >= 4 for ap, fp in zip(abbrev_parents, full_parents))


def equivalence(raw_id: dict, fp_stat: dict, rtk: dict, plumbing_parents: dict,
                contract_oid: str, abbrev_resolved_oid: str | None) -> dict:
    """Fail-closed equivalence for the merge case. Every condition must hold; each failure is named."""
    m = []
    if not raw_id.get("derivable"):
        m.append("raw_identity_not_derivable")
    if not fp_stat.get("derivable"):
        m.append("first_parent_stat_not_derivable")
    if not rtk.get("derivable"):
        m.append("rtk_not_derivable")
    if not plumbing_parents.get("derivable"):
        m.append("plumbing_parents_not_derivable")
    if m:
        return {"equivalent": False, "mismatches": m}

    oid = (contract_oid or "").lower()
    if not base._HEX40.match(oid):
        m.append("contract_oid_invalid")
    # RAW identity == contract == plumbing merge oid
    if raw_id.get("full_commit_oid", "").lower() != oid:
        m.append("raw_full_oid != contract_oid")
    if plumbing_parents.get("merge_oid") != oid:
        m.append("plumbing_merge_oid != contract_oid")
    # RAW confirms merge topology; ordered parents consistent with plumbing
    if not raw_id.get("is_merge"):
        m.append("raw_not_merge")
    if len(plumbing_parents.get("parents") or []) < 2:
        m.append("plumbing_not_merge")
    if not _parents_consistent(raw_id.get("abbreviated_parents") or [],
                               plumbing_parents.get("parents") or []):
        m.append("parent_order_or_identity_mismatch")
    # repository first-parent stat == RTK compact stat (totals + path set)
    for k in _STAT_KEYS:
        if fp_stat.get(k) != rtk.get(k):
            m.append(f"stat.{k}")
    if sorted(fp_stat.get("affected_paths") or []) != sorted(rtk.get("affected_paths") or []):
        m.append("affected_paths")
    # RTK abbreviated hash: prefix of full oid AND uniquely resolves to it in the pinned repo
    abbr = (rtk.get("abbreviated_oid") or "").lower()
    if not abbr or len(abbr) < 4 or not oid.startswith(abbr):
        m.append("abbreviated_oid_not_prefix")
    if (abbrev_resolved_oid or "").lower() != oid:
        m.append("abbreviated_oid_not_uniquely_resolved")
    # RTK output mode must be compact (raw_fallback would drop the stat overlap)
    if rtk.get("rtk_output_mode") != "compact":
        m.append("rtk_output_mode_not_compact")

    return {
        "equivalent": not m, "mismatches": m,
        "compared": ["full_commit_oid", "merge_topology", "ordered_parents",
                     *(f"first_parent_{k}" for k in _STAT_KEYS), "affected_paths",
                     "abbreviated_oid_prefix", "abbreviated_oid_unique_resolution", "rtk_output_mode"],
        "first_parent_oid": plumbing_parents.get("first_parent_oid"),
        "rtk_output_mode": rtk.get("rtk_output_mode"),
        "note": "split authority: RAW=identity+topology, plumbing=first-parent stat, RTK=compact stat. "
                "%ar/patch/subject/author/second-parent/combined-diff excluded; raw_fallback rejected.",
    }
