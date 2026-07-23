#!/usr/bin/env python3
"""rtk-git-show-oracle-v1: the semantic oracle for `rtk git show`, defined FROM the pinned RTK
implementation (rtk-ai/rtk @5d32d07, src/cmds/git/git_cmd.rs: run_show + compact_diff; core/guard.rs:
never_worse), NOT inferred from one lucky output.

For a bare `git show` (no ref, no --stat/--format/blob-spec args -> the compacting path, not
passthrough) run_show emits, in order:
  1. a one-line summary  `git show --no-patch --pretty=format:%h %s (%ar) <%an>`;
  2. the `git show --stat --pretty=format:` block (per-file `path | N +/-` + a
     `N files changed, I insertions(+), D deletions(-)` summary line);
  3. a COMPACTED diff (compact_diff): hunks capped at 100 lines, `... (N lines truncated)` markers,
     per-file `+added -removed`.
Then `never_worse(raw, printed)` emits the compact form UNLESS it estimates more tokens than raw
`git show`, in which case RTK emits the RAW `git show` output verbatim (raw_fallback). BOTH are
legitimate RTK output modes and parse_rtk recognises both.

What RTK provably preserves -- and therefore ALL this oracle claims -- is the STAT + IDENTITY core:
  * full_commit_oid  (authoritative from the pinned case contract; RTK's abbreviated %h must be an
    unambiguous prefix of it, and the RAW `git show` `commit <oid>` line must equal it);
  * affected_paths   (canonical SET; order is not promised);
  * files_changed, insertions, deletions.
EXCLUDED as non-normative: %ar relative date, author name, subject formatting, absolute dates, the
full patch body, and any truncated/compacted diff fragments. The abbreviated hash, the compacted diff
and the never_worse mode are presentation; the stat/identity core is the semantics.
"""
from __future__ import annotations

import re

ORACLE_ID = "rtk-git-show-oracle-v1"
# source-identity constants consumed by build_n2e_command_oracle_source_proof
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
RTK_SOURCE_FILE = "src/cmds/git/git_cmd.rs"
RTK_SOURCE_FUNCTION = "run_show"
# additional pinned RTK sources, frozen alongside the primary in the source proof. compact_diff (same
# file as run_show) and never_worse (core/guard.rs) are TRUE semantic dependencies of `rtk git show`
# (the compaction + the compact-vs-raw_fallback mode selection). diff_cmd.rs is a co-pinned SIBLING
# (`rtk git diff` file-vs-file) -- NOT called by run_show, pinned for audit completeness only.
RTK_SOURCE_REFS = (
    {"source_file": "src/cmds/git/git_cmd.rs", "source_function": "compact_diff"},
    {"source_file": "src/core/guard.rs", "source_function": "never_worse"},
    {"source_file": "src/cmds/git/diff_cmd.rs",
     "source_function": "condense_unified_diff (co-pinned sibling; not called by run_show)"},
)

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
# `git show` header commit line (non-merge): `commit <40-hex>` optionally followed by decorations
_COMMIT_LINE = re.compile(r"^commit ([0-9a-f]{40})\b")
# git's stat summary line, e.g. "3 files changed, 12 insertions(+), 4 deletions(-)"
_STAT_SUMMARY = re.compile(
    r"^\s*(\d+)\s+files?\s+changed"
    r"(?:,\s*(\d+)\s+insertions?\(\+\))?"
    r"(?:,\s*(\d+)\s+deletions?\(-\))?\s*$")


def _not_derivable(reason: str) -> dict:
    return {"outcome": "not_derivable", "derivable": False, "reason": reason}


def _dequote_path(p: str) -> str:
    """git quotes paths containing special bytes as C-strings in double quotes. Strip the quoting to
    the logical path (best-effort octal/backslash unescape); a plain path is returned unchanged."""
    p = p.strip()
    if len(p) >= 2 and p[0] == '"' and p[-1] == '"':
        inner = p[1:-1]
        out, i = [], 0
        while i < len(inner):
            ch = inner[i]
            if ch == "\\" and i + 1 < len(inner):
                nxt = inner[i + 1]
                if nxt in "0123456789" and i + 3 < len(inner) + 1 and inner[i+1:i+4].isdigit():
                    out.append(chr(int(inner[i+1:i+4], 8))); i += 4; continue
                esc = {"n": "\n", "t": "\t", "\\": "\\", '"': '"'}.get(nxt, nxt)
                out.append(esc); i += 2; continue
            out.append(ch); i += 1
        return "".join(out)
    return p


def _expand_stat_rename(path: str) -> str:
    """git --stat renders a rename/copy with common-prefix compression, e.g.
    `dir/{old => new}/file` or `old => new`. Expand to the RESULTING (new) path so the canonical
    affected-path set matches the RAW diff's b-side path. A plain path is returned unchanged."""
    if "=>" not in path:
        return path
    m = re.search(r"\{(.*?) => (.*?)\}", path)
    if m:
        return (path[:m.start()] + m.group(2) + path[m.end():]).replace("//", "/")
    # bare `old => new`
    parts = path.split("=>")
    return parts[-1].strip()


# ---------------------------------------------------------------------------------------------------
# RAW side: parse a full `git show` (unified diff) into the stat/identity projection.
# ---------------------------------------------------------------------------------------------------
def parse_raw(data: bytes) -> dict:
    """Derive the stat/identity projection from the captured RAW `git show` bytes. Insertions/
    deletions are counted ONLY inside hunks (after a `@@` for the current file), so the `+++`/`---`
    file headers, `\\ No newline` lines and binary markers are never miscounted. affected_paths is the
    canonical b-side path per file (the deleted path for deletions). files_changed counts file entries
    (text + binary + mode-only). This is a projection of the RAW arm's own bytes, cross-checked
    independently against git plumbing by the probe/verifier -- never replaced by it."""
    text = data.decode("utf-8", "replace")
    lines = text.split("\n")
    if not lines:
        return _not_derivable("empty")
    m = _COMMIT_LINE.match(lines[0])
    if not m:
        return _not_derivable("no commit header line")
    full_oid = m.group(1)

    files: list[dict] = []
    cur: dict | None = None
    in_hunk = False
    ins = dele = 0

    def _flush():
        nonlocal cur
        if cur is not None:
            files.append(cur)
            cur = None

    for ln in lines:
        if ln.startswith("diff --git "):
            _flush()
            in_hunk = False
            # `diff --git a/OLD b/NEW` -- may be quoted; b-side is the default canonical path
            rest = ln[len("diff --git "):]
            a_path, b_path = _split_diff_git(rest)
            cur = {"a": a_path, "b": b_path, "status": "modify",
                   "binary": False, "path": b_path}
        elif cur is not None and ln.startswith("new file mode"):
            cur["status"] = "add"; cur["path"] = cur["b"]
        elif cur is not None and ln.startswith("deleted file mode"):
            cur["status"] = "delete"; cur["path"] = cur["a"]
        elif cur is not None and ln.startswith("rename from "):
            cur["status"] = "rename"; cur["a"] = _dequote_path(ln[len("rename from "):])
        elif cur is not None and ln.startswith("rename to "):
            cur["status"] = "rename"; cur["b"] = _dequote_path(ln[len("rename to "):]); cur["path"] = cur["b"]
        elif cur is not None and ln.startswith("copy from "):
            cur["status"] = "copy"; cur["a"] = _dequote_path(ln[len("copy from "):])
        elif cur is not None and ln.startswith("copy to "):
            cur["status"] = "copy"; cur["b"] = _dequote_path(ln[len("copy to "):]); cur["path"] = cur["b"]
        elif cur is not None and ln.startswith("Binary files "):
            cur["binary"] = True
        elif cur is not None and ln.startswith("@@"):
            in_hunk = True
        elif cur is not None and in_hunk:
            # inside a hunk EVERY `+`/`-` line is content -- the `+++ b/` / `--- a/` file headers
            # appear only BEFORE the first `@@` (in_hunk is False there), so a content line that is
            # itself `+++counter` / `---dashes` is correctly counted (no fragile prefix guard).
            if ln.startswith("+"):
                ins += 1
            elif ln.startswith("-"):
                dele += 1
            # context lines (' '...) and `\ No newline at end of file` are not counted
    _flush()

    if not files:
        # a commit with an empty tree diff (no files) is not a `git show` this oracle qualifies
        return _not_derivable("no file entries in diff")

    return {
        "outcome": "git_show", "derivable": True,
        "full_commit_oid": full_oid,
        "files_changed": len(files),
        "insertions": ins, "deletions": dele,
        "affected_paths": sorted({f["path"] for f in files}),
        "binary_paths": sorted({f["path"] for f in files if f["binary"]}),
    }


def _split_diff_git(rest: str) -> tuple[str, str]:
    """Split the `a/OLD b/NEW` tail of a `diff --git` line into (OLD, NEW), tolerating quoted paths
    and spaces. Falls back to a b/ split when unquoted."""
    rest = rest.strip()
    if rest.startswith('"'):
        # quoted a-path: `"a/..." "b/..."` or `"a/..." b/...`
        end = _closing_quote(rest)
        a = rest[:end + 1]
        b = rest[end + 1:].strip()
        return _strip_ab(_dequote_path(a), "a/"), _strip_ab(_dequote_path(b.strip('"')) if b.startswith('"') else b, "b/")
    idx = rest.find(" b/")
    if idx == -1:
        return rest, rest
    return _strip_ab(rest[:idx], "a/"), _strip_ab(rest[idx + 1:], "b/")


def _closing_quote(s: str) -> int:
    i = 1
    while i < len(s):
        if s[i] == "\\":
            i += 2; continue
        if s[i] == '"':
            return i
        i += 1
    return len(s) - 1


def _strip_ab(p: str, pfx: str) -> str:
    p = p.strip()
    if p.startswith(pfx):
        p = p[len(pfx):]
    return _dequote_path(p)


# ---------------------------------------------------------------------------------------------------
# RTK side: dual-mode parse (compact | raw_fallback). A compact-looking-but-incomplete output is
# REJECTED (not_derivable), never silently reparsed as RAW.
# ---------------------------------------------------------------------------------------------------
def parse_rtk(data: bytes) -> dict:
    """Parse `rtk git show` output. Two legitimate modes:
      * raw_fallback -- output begins with `commit <40-hex>` (never_worse chose raw): parse as RAW.
      * compact      -- `%h %s (%ar) <%an>` summary + `git show --stat` block (+ compacted diff):
        parse the STAT block only (identity + affected paths + stat totals).
    A compact-looking output whose `N files changed, ...` stat summary line is absent/malformed is
    NOT reparsed as RAW -- it is not_derivable, so a truncated compact output cannot accidentally
    qualify through the RAW parser."""
    text = data.decode("utf-8", "replace")
    lines = text.split("\n")
    if not lines or not lines[0].strip():
        return _not_derivable("empty")

    if _COMMIT_LINE.match(lines[0]):
        proj = parse_raw(data)
        if proj.get("derivable"):
            proj = dict(proj)
            proj["rtk_output_mode"] = "raw_fallback"
            proj["abbreviated_oid"] = proj["full_commit_oid"]
        return proj

    # ---- compact mode ----
    summary_line = lines[0].strip()
    abbrev = summary_line.split(" ", 1)[0] if summary_line else ""
    if not re.fullmatch(r"[0-9a-f]{4,40}", abbrev):
        return _not_derivable("compact summary line has no abbreviated oid")

    # locate the git --stat summary line ("N files changed, ...") -- REQUIRED. Everything between the
    # summary line and it is the per-file stat block; anything after is the compacted diff (ignored).
    stat_paths: list[str] = []
    stat_totals = None
    for ln in lines[1:]:
        sm = _STAT_SUMMARY.match(ln)
        if sm:
            stat_totals = (int(sm.group(1)), int(sm.group(2) or 0), int(sm.group(3) or 0))
            break
        # a per-file stat line: `path | N +/-` (the `|` separates path from the change bar)
        if "|" in ln:
            left = ln.split("|", 1)[0].strip()
            if left:
                stat_paths.append(_expand_stat_rename(_dequote_path(left)))
    if stat_totals is None:
        # compact-looking but incomplete -> REJECT (do not fall through to the RAW parser)
        return _not_derivable("compact output missing the '<N> files changed' stat summary line")

    files_changed, ins, dele = stat_totals
    return {
        "outcome": "git_show", "derivable": True,
        "rtk_output_mode": "compact",
        "abbreviated_oid": abbrev,
        "files_changed": files_changed, "insertions": ins, "deletions": dele,
        "affected_paths": sorted(set(stat_paths)),
    }


# ---------------------------------------------------------------------------------------------------
# git-plumbing authority (VERIFIER OBSERVATIONS): the RAW projection derived from the `git show` bytes
# is INDEPENDENTLY cross-checked, on the same pinned checkout, against `git show --numstat` /
# `--name-status` / `--shortstat` / `rev-parse HEAD`. These never replace the RAW arm -- they are a
# second, plumbing-grade authority that must agree with the parsed RAW projection.
# ---------------------------------------------------------------------------------------------------
def _numstat_path(field: str) -> str:
    """--numstat renders a rename/copy path as `old => new` or `pre{old => new}post`; canonicalise to
    the resulting (new) path, matching the RAW b-side canonical form. Plain paths pass through."""
    field = field.strip()
    if "=>" in field:
        return _expand_stat_rename(field)
    return _dequote_path(field)


def parse_numstat(data: bytes) -> dict:
    """`git show --numstat --format=` -> per-file `<ins>\\t<del>\\t<path>` (binary files show `-`).
    files_changed = number of entries; insertions/deletions sum the numeric fields; affected_paths is
    the canonical set; binary_paths are the `-`/`-` entries."""
    files, ins, dele, binary = [], 0, 0, []
    for ln in data.decode("utf-8", "replace").split("\n"):
        if not ln.strip():
            continue
        parts = ln.split("\t")
        if len(parts) < 3:
            continue
        a, d, path = parts[0], parts[1], "\t".join(parts[2:])
        cpath = _numstat_path(path)
        files.append(cpath)
        if a == "-" and d == "-":
            binary.append(cpath)
        else:
            ins += int(a) if a.isdigit() else 0
            dele += int(d) if d.isdigit() else 0
    if not files:
        return _not_derivable("numstat empty")
    return {"outcome": "git_show", "derivable": True,
            "files_changed": len(files), "insertions": ins, "deletions": dele,
            "affected_paths": sorted(set(files)), "binary_paths": sorted(set(binary))}


def parse_name_status(data: bytes) -> list[str]:
    """`git show --name-status --format=` -> the authoritative affected-path SET (resulting/current
    path per file; renames/copies use the new path; deletions use the deleted path)."""
    paths = []
    for ln in data.decode("utf-8", "replace").split("\n"):
        if not ln.strip():
            continue
        parts = ln.split("\t")
        status = parts[0]
        if status[:1] in ("R", "C") and len(parts) >= 3:
            paths.append(_dequote_path(parts[2]))          # new path
        elif len(parts) >= 2:
            paths.append(_dequote_path(parts[1]))          # delete uses its own path too
    return sorted(set(paths))


def parse_shortstat(data: bytes) -> dict:
    """`git show --shortstat --format=` -> the `N files changed, I insertions(+), D deletions(-)`
    summary line (git's own totals)."""
    for ln in data.decode("utf-8", "replace").split("\n"):
        sm = _STAT_SUMMARY.match(ln)
        if sm:
            return {"outcome": "git_show", "derivable": True,
                    "files_changed": int(sm.group(1)),
                    "insertions": int(sm.group(2) or 0), "deletions": int(sm.group(3) or 0)}
    return _not_derivable("no shortstat summary line")


def plumbing_crosscheck(raw_proj: dict, rev_parse_head: str, numstat: bytes,
                        name_status: bytes, shortstat: bytes, full_commit_oid: str) -> dict:
    """Independently confirm the parsed RAW projection against git plumbing on the same checkout.
    Every mismatch is reported; `consistent` is true only when the RAW projection agrees with numstat
    (totals + paths + files_changed), name-status (path set), shortstat (totals) AND the pinned OID."""
    ns = parse_numstat(numstat)
    ss = parse_shortstat(shortstat)
    name_paths = parse_name_status(name_status)
    head = (rev_parse_head or "").strip().lower()
    oid = (full_commit_oid or "").lower()
    m = []
    if head != oid:
        m.append("rev_parse_head != pinned_oid")
    if raw_proj.get("full_commit_oid", "").lower() != oid:
        m.append("raw_commit_oid != pinned_oid")
    for k in _STAT_KEYS:
        if ns.get(k) != raw_proj.get(k):
            m.append(f"numstat.{k}")
        if ss.get(k) != raw_proj.get(k):
            m.append(f"shortstat.{k}")
    if sorted(raw_proj.get("affected_paths") or []) != (ns.get("affected_paths") or []):
        m.append("numstat.affected_paths")
    if sorted(raw_proj.get("affected_paths") or []) != name_paths:
        m.append("name_status.affected_paths")
    return {"consistent": not m, "mismatches": m,
            "numstat": ns, "shortstat": ss, "name_status_paths": name_paths,
            "rev_parse_head": head}


# ---------------------------------------------------------------------------------------------------
# Equivalence over the normative stat/identity projection.
# ---------------------------------------------------------------------------------------------------
_STAT_KEYS = ("files_changed", "insertions", "deletions")


def equivalence(raw: dict, rtk: dict, full_commit_oid: str | None = None) -> dict:
    """RAW<->RTK semantic equivalence on the stat/identity core. Both sides must be derivable. Compared:
    the full commit identity (RTK's abbreviated %h is an unambiguous prefix of full_commit_oid, and the
    RAW `commit <oid>` equals it), files_changed / insertions / deletions, and the affected_paths SET.
    %ar / author / subject / dates / full patch / truncated fragments are NEVER compared."""
    if not raw.get("derivable") or not rtk.get("derivable"):
        return {"equivalent": False, "mismatches": ["not_derivable"],
                "raw_derivable": bool(raw.get("derivable")), "rtk_derivable": bool(rtk.get("derivable"))}

    mism = [k for k in _STAT_KEYS if raw.get(k) != rtk.get(k)]
    if sorted(raw.get("affected_paths") or []) != sorted(rtk.get("affected_paths") or []):
        mism.append("affected_paths")

    oid = (full_commit_oid or raw.get("full_commit_oid") or "").lower()
    identity_ok = True
    if not _HEX40.match(oid or ""):
        mism.append("full_commit_oid_invalid"); identity_ok = False
    else:
        if raw.get("full_commit_oid") != oid:
            mism.append("raw_commit_oid"); identity_ok = False
        abbr = (rtk.get("abbreviated_oid") or "").lower()
        # abbreviated hash must be an UNAMBIGUOUS prefix of the pinned full oid (>=4 hex, a real prefix)
        if not abbr or len(abbr) < 4 or not oid.startswith(abbr):
            mism.append("abbreviated_oid_not_prefix"); identity_ok = False

    return {
        "equivalent": not mism, "mismatches": mism,
        "compared_fields": list(_STAT_KEYS) + ["affected_paths", "commit_identity"],
        "rtk_output_mode": rtk.get("rtk_output_mode"),
        "identity_ok": identity_ok,
        "note": "stat + identity core only; %ar/author/subject/dates/full-patch excluded as "
                "non-normative presentation",
    }
