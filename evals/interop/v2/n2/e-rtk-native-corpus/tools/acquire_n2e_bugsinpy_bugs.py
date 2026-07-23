#!/usr/bin/env python3
"""Acquire the BugsInPy bug manifest (metadata only) at a pinned commit.

Clones soarsmu/BugsInPy at the pinned commit over the git smart-HTTP transport,
enumerates every project/bug, and writes a committed metadata manifest
(n2e-bugsinpy-bugs-v1.json): per-bug project, bug id, python version, buggy and
fixed commit ids, test file, and the exact test command from run_test.sh. No
project source or payloads are committed (§3).

Deterministic at the pinned commit. Network command (acquisition phase).
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

OUT = N2E_DIR / "n2e-bugsinpy-bugs-v1.json"
REPO = "https://github.com/soarsmu/BugsInPy.git"
PINNED_COMMIT = "11c5f1eea954a42132cfd06bf257766a7963e0fd"


def _kv(text: str) -> dict:
    out = {}
    for ln in text.splitlines():
        if "=" in ln:
            k, _, v = ln.partition("=")
            out[k.strip()] = v.strip().strip('"')
    return out


def enumerate_bugs(root: Path) -> list[dict]:
    bugs = []
    projects_dir = root / "projects"
    for proj in sorted(p.name for p in projects_dir.iterdir() if (p / "bugs").is_dir()):
        pinfo = _kv((projects_dir / proj / "project.info").read_text(errors="replace")) \
            if (projects_dir / proj / "project.info").exists() else {}
        bugs_dir = projects_dir / proj / "bugs"
        for bid in sorted((b.name for b in bugs_dir.iterdir() if b.name.isdigit()), key=int):
            bdir = bugs_dir / bid
            info = _kv((bdir / "bug.info").read_text(errors="replace")) if (bdir / "bug.info").exists() else {}
            run_test = ""
            if (bdir / "run_test.sh").exists():
                run_test = (bdir / "run_test.sh").read_text(errors="replace").strip()
            bugs.append({
                "project": proj,
                "bug_id": bid,
                "github_url": pinfo.get("github_url"),
                "python_version": info.get("python_version"),
                "buggy_commit_id": info.get("buggy_commit_id"),
                "fixed_commit_id": info.get("fixed_commit_id"),
                "test_file": info.get("test_file"),
                "run_test_cmd": run_test,
            })
    return bugs


def build() -> dict:
    with tempfile.TemporaryDirectory(prefix="n2e-bugsinpy-") as td:
        td = Path(td)
        subprocess.run(["git", "init", "-q", str(td)], check=True)
        subprocess.run(["git", "-C", str(td), "fetch", "-q", "--depth", "1", REPO, PINNED_COMMIT],
                       check=True, env={"GIT_TERMINAL_PROMPT": "0", "PATH": _path()})
        subprocess.run(["git", "-C", str(td), "checkout", "-q", "FETCH_HEAD"], check=True)
        bugs = enumerate_bugs(td)
    from collections import Counter
    return c.envelope(
        record_type="n2e-bugsinpy-bugs",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/acquire_n2e_bugsinpy_bugs.py",
        purpose="BugsInPy bug metadata manifest at the pinned commit (Python/pytest source; no payloads).",
        source_repo="soarsmu/BugsInPy",
        pinned_commit=PINNED_COMMIT,
        project_count=len({b["project"] for b in bugs}),
        bug_count=len(bugs),
        bugs_per_project=dict(Counter(b["project"] for b in bugs)),
        bugs=bugs,
    )


def _path() -> str:
    import os
    return os.environ.get("PATH", "/usr/bin:/bin")


def main() -> int:
    c.write_record(OUT, build())
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name} record_sha256={rec['record_sha256']} bugs={rec['bug_count']} projects={rec['project_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
