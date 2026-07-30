#!/usr/bin/env python3
"""Assert the checkout is byte-clean — and prove the check can say otherwise.

The previous version of this gate was one line of shell:

    git diff --exit-code && git status --porcelain --untracked-files=all evals/provider-matrix

`git status --porcelain` prints what it finds and exits **0**. So the step that
existed to prove the mutation harness had left nothing behind would have stayed
green while printing the mess it was meant to catch, and it looked only at one
directory while claiming the repository was clean. A gate that cannot fail is
not a gate; it is a reassuring noise.

Hence two things here. The check itself asserts on *output*, over the whole
checkout, in all three ways a tree can be dirty. And `--self-test` builds
throwaway repositories that are dirty in each of those ways and requires the
check to report every one — the positive control, without which "it passed" and
"it is incapable of failing" are the same observation.

    python3 evals/provider-matrix/check_clean_tree.py
    python3 evals/provider-matrix/check_clean_tree.py --self-test

Exit 0 when clean, 1 when dirty or when a self-test fails.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

TIMEOUT = 120


class GitUnavailable(RuntimeError):
    """git could not be run to a verdict: it stalled, or it is not there.

    Raised rather than returned so no caller can read "no dirt was listed" as
    "the tree is clean" — those are different answers, and only one of them is
    an answer. Caught at `main()` and printed as a FAIL: a traceback out of a
    120-second stall reads like the gate is broken, when what happened is that
    the gate could not tell, which is a result and belongs in the exit code.
    """


def git(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=TIMEOUT
        )
    except subprocess.TimeoutExpired as exc:
        raise GitUnavailable(
            f"`git {' '.join(args)}` in {cwd} exceeded {TIMEOUT}s; a stalled "
            "git leaves the state of the tree unknown, which is not clean"
        ) from exc
    except OSError as exc:
        # `timeout=` was already passed here; what was missing was anyone to
        # catch what it throws. The same was true of a missing git, so both
        # arrive as one reported outcome rather than two tracebacks.
        raise GitUnavailable(f"could not run `git {' '.join(args)}` in {cwd}: {exc}") from exc


def dirt(root: Path) -> list[str]:
    """Every way the tree is not byte-clean, as lines. Empty means clean.

    `--untracked-files=all` so a directory of leftovers is listed file by file
    rather than as one forgettable entry, and `--ignored` deliberately *not*
    passed: build output is not dirt.
    """
    status = git("status", "--porcelain", "--untracked-files=all", cwd=root)
    if status.returncode != 0:
        return [f"git status failed: {status.stderr.strip()}"]
    lines = [line for line in status.stdout.splitlines() if line.strip()]

    # `git status` covers staged, unstaged and untracked. `git diff HEAD` is
    # kept as a second opinion: if the two ever disagree, that disagreement is
    # itself worth failing on rather than resolving in favour of the quiet one.
    diff = git("diff", "--exit-code", "HEAD", "--", cwd=root)
    if diff.returncode not in (0, 1):
        lines.append(f"git diff failed: {diff.stderr.strip()}")
    elif diff.returncode == 1 and not lines:
        lines.append("git diff reports changes that git status did not")
    return lines


def repo_root(start: Path | None = None) -> Path:
    """The checkout root, asked of git rather than counted in `..`s.

    The scope is part of the contract: a guard that claims the repository is
    clean while looking at one subdirectory is the same lie in a smaller font.
    Asking git makes that claim testable from anywhere, including the throwaway
    copy the mutation harness runs in.
    """
    here = (start or Path(__file__).resolve().parent)
    top = git("rev-parse", "--show-toplevel", cwd=here)
    if top.returncode != 0:
        raise GitUnavailable(f"{here} is not inside a git checkout")
    return Path(top.stdout.strip())


def self_test() -> int:
    """Make a tree dirty in each way and require the check to notice."""
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "repo"
        root.mkdir()
        git("init", "-q", cwd=root)
        git("config", "user.email", "self-test@example", cwd=root)
        git("config", "user.name", "self test", cwd=root)
        (root / "tracked.txt").write_text("original\n", encoding="utf-8")
        git("add", "tracked.txt", cwd=root)
        git("commit", "-qm", "seed", cwd=root)

        if dirt(root):
            failures.append("a freshly committed tree was reported dirty")

        # Scope: called from deep inside the tree, it must still resolve to the
        # top. A check that silently narrows to its own directory would report a
        # clean repository while ignoring most of it.
        deep = root / "one" / "two"
        deep.mkdir(parents=True)
        resolved = repo_root(deep)
        if resolved.resolve() != root.resolve():
            failures.append(f"repo_root({deep}) resolved to {resolved}, not the checkout root")

        cases = [
            ("tracked modification", lambda: (root / "tracked.txt").write_text("changed\n", encoding="utf-8")),
            ("untracked file", lambda: (root / "stray.tmp").write_text("x", encoding="utf-8")),
            ("staged change", lambda: (
                (root / "staged.txt").write_text("new\n", encoding="utf-8"),
                git("add", "staged.txt", cwd=root),
            )),
        ]
        for name, make_dirty in cases:
            make_dirty()
            if not dirt(root):
                failures.append(f"a {name} was not reported")
            # Reset to clean for the next case.
            git("reset", "-q", "--hard", "HEAD", cwd=root)
            git("clean", "-qfd", cwd=root)
            if dirt(root):
                failures.append(f"the tree stayed dirty after resetting the {name}")

    if failures:
        print("FAIL the clean-tree check cannot detect:")
        for line in failures:
            print(f"  {line}")
        return 1
    print("OK the clean-tree check reports a tracked modification, an untracked "
          "file and a staged change, and reports a clean tree as clean")
    return 0


def main(argv: list[str]) -> int:
    # One handler for both modes: the self-test drives git a dozen times over
    # throwaway repositories, and a stall in any of them is the same kind of
    # non-answer as a stall over the checkout.
    try:
        if "--self-test" in argv:
            return self_test()
        lines = dirt(repo_root())
    except GitUnavailable as exc:
        print(f"FAIL {exc}")
        return 1
    if lines:
        print(f"FAIL the checkout is not byte-clean ({len(lines)} entr{'y' if len(lines) == 1 else 'ies'}):")
        for line in lines:
            print(f"  {line}")
        return 1
    print("OK the checkout is byte-clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
