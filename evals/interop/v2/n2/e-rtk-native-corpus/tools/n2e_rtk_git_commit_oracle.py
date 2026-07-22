#!/usr/bin/env python3
"""rtk-git-commit-oracle-v1: the semantic oracle for `rtk git commit`, defined FROM the pinned RTK
implementation (rtk-ai/rtk @5d32d07, src/cmds/git/git_cmd.rs: run_commit -> build_commit_command +
classify_commit_outcome + parse_commit_output), NOT inferred from one lucky output.

`rtk git commit` runs the identical `git commit <args>` and, on success, prints `ok <7-hex>` -- the
first 7 characters of git's reported short hash of the NEW commit (parse_commit_output). It preserves
ONLY the OUTCOME and the created commit's ABBREVIATED OID. It does NOT report the subject (dropped),
the parent, the changed paths, the author/committer, or any stat.

So the risk here is NOT the parser -- it is the IDENTITY of the new commit object. A commit OID is a
hash of {tree, parent(s), author name/email/date, committer name/email/date, message}. When ALL of
those determinants are pinned identically, the RAW `git commit` and the RTK `rtk git commit` (run on
two identically-prepared fresh checkouts) produce the SAME full 40-hex OID. The commit hash is NEVER
normalized: if it fails to reproduce, a hidden determinant (timezone, signing, a hook, index state,
the parent) leaked -- that is a real finding, not "git is just like that".

Normative equivalence (resulting_ref identity):
  * both arms exit 0 and CREATED a commit (HEAD advanced; the new commit's parent == the pinned base);
  * RAW full commit OID == RTK full commit OID (exact 40-hex; reproducibility of the commit object);
  * RTK's reported abbreviated OID is an unambiguous PREFIX of that full OID.
NOT claimed (RTK does not report them): changed paths / stat (captured only as characterization),
subject, author/committer identity.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import n2e_rtk_git_show_oracle as base  # noqa: E402  (reuse parse_name_status / _dequote_path)

ORACLE_ID = "rtk-git-commit-oracle-v1"
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
RTK_SOURCE_FILE = "src/cmds/git/git_cmd.rs"
RTK_SOURCE_FUNCTION = "run_commit"
RTK_SOURCE_REFS = (
    {"source_file": "src/cmds/git/git_cmd.rs", "source_function": "parse_commit_output"},
    {"source_file": "src/cmds/git/git_cmd.rs", "source_function": "classify_commit_outcome"},
)

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
# RTK success line: `ok <7..40 hex>` (parse_commit_output takes the first 7 of git's short hash)
_RTK_OK = re.compile(r"^ok ([0-9a-f]{7,40})\s*$")
_RTK_OK_BARE = re.compile(r"^ok\s*$")


def _nd(reason: str) -> dict:
    return {"outcome": "not_derivable", "derivable": False, "reason": reason}


# ---------------------------------------------------------------------------------------------------
# RTK side: parse `rtk git commit` output (outcome + abbreviated OID).
# ---------------------------------------------------------------------------------------------------
def parse_rtk(data: bytes) -> dict:
    text = data.decode("utf-8", "replace")
    first = next((ln for ln in text.split("\n") if ln.strip()), "")
    m = _RTK_OK.match(first.strip())
    if m:
        return {"outcome": "committed", "derivable": True, "created": True,
                "abbreviated_oid": m.group(1).lower()}
    if _RTK_OK_BARE.match(first.strip()):
        # committed but git's short hash was too short to abbreviate (parse_commit_output -> "ok")
        return {"outcome": "committed", "derivable": True, "created": True, "abbreviated_oid": None}
    return _nd(f"rtk git commit did not report success (first line {first.strip()!r})")


# ---------------------------------------------------------------------------------------------------
# Git-state authority: the resulting commit, from plumbing captured on each arm's own checkout.
# ---------------------------------------------------------------------------------------------------
def parse_git_state(exit_code: int, head_oid: str, parent_oid: str, name_status: bytes,
                    base_commit: str) -> dict:
    """The resulting git state after `git commit`, from `git rev-parse HEAD` / `HEAD^` / the new
    commit's `--name-status`. `created` requires HEAD to have advanced off the pinned base and the new
    commit's first parent to BE the pinned base."""
    head = (head_oid or "").strip().lower()
    parent = (parent_oid or "").strip().lower()
    base_oid = (base_commit or "").lower()
    if exit_code != 0:
        return {"outcome": "not_committed", "derivable": False, "reason": f"exit_code={exit_code}"}
    if not _HEX40.match(head):
        return _nd("HEAD is not a 40-hex oid")
    created = head != base_oid and parent == base_oid
    return {"outcome": "committed" if created else "no_new_commit", "derivable": True,
            "created": created, "full_commit_oid": head, "parent_oid": parent,
            "changed_paths": base.parse_name_status(name_status),
            "exit_code": exit_code}


# ---------------------------------------------------------------------------------------------------
# Equivalence over the resulting-ref identity.
# ---------------------------------------------------------------------------------------------------
def equivalence(raw_state: dict, rtk_state: dict, rtk_parsed: dict, base_commit: str) -> dict:
    """Fail-closed. Both arms must have committed; the RAW and RTK full OIDs must be EXACTLY equal
    (the commit object reproduced under the pinned determinants); both parents must be the pinned
    base; and RTK's reported abbreviated OID must be an unambiguous prefix of that full OID. The hash
    is never normalized."""
    m = []
    for who, st in (("raw", raw_state), ("rtk", rtk_state)):
        if not st.get("derivable"):
            m.append(f"{who}_state_not_derivable")
        elif not st.get("created"):
            m.append(f"{who}_did_not_create_commit")
    if not rtk_parsed.get("derivable") or not rtk_parsed.get("created"):
        m.append("rtk_output_not_committed")
    if m:
        return {"equivalent": False, "mismatches": m}

    base = (base_commit or "").lower()
    raw_oid = raw_state.get("full_commit_oid", "")
    rtk_oid = rtk_state.get("full_commit_oid", "")
    if not _HEX40.match(base):
        m.append("base_commit_invalid")
    if raw_state.get("parent_oid") != base:
        m.append("raw_parent != base_commit")
    if rtk_state.get("parent_oid") != base:
        m.append("rtk_parent != base_commit")
    # THE reproducibility claim: identical determinants -> identical commit object
    if raw_oid != rtk_oid:
        m.append("raw_commit_oid != rtk_commit_oid")
    # RTK's abbreviated hash must be an unambiguous prefix of the (equal) full OID
    abbr = (rtk_parsed.get("abbreviated_oid") or "")
    if not abbr:
        m.append("rtk_reported_no_abbreviated_oid")
    elif len(abbr) < 7 or not raw_oid.startswith(abbr):
        m.append("rtk_abbreviated_oid_not_prefix")

    return {
        "equivalent": not m, "mismatches": m,
        "compared": ["outcome", "commit_created", "resulting_ref_oid_equal",
                     "parent_is_base", "abbreviated_oid_prefix"],
        "raw_commit_oid": raw_oid, "rtk_commit_oid": rtk_oid,
        "rtk_abbreviated_oid": abbr or None,
        "note": "resulting-ref identity: RAW commit OID == RTK commit OID (reproducible; never "
                "normalized), both parents == base, RTK abbrev is a prefix. Subject / author / "
                "committer / changed-paths are NOT claimed (RTK does not report them).",
    }
