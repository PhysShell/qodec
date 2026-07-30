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

import os
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


def git(*args: str, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run git and return the result. A nonzero exit is a value, not an error.

    `status` and `diff` use their exit codes to *mean* something, so the caller
    reads them. Setup commands do not — see `must_git`.
    """
    try:
        return subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=TIMEOUT, env=env
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


def must_git(*args: str, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """A git command whose failure is a broken self-test, not a finding.

    Every setup step used to be fired and forgotten. A seed commit that did not
    happen — because the machine turned on `commit.gpgsign`, or a global hook
    said no — left an unborn HEAD, and the very next assertion reported *"a
    freshly committed tree was reported dirty"*. That is the gate diagnosing its
    own failed preparation as a defect in the property it was checking, which is
    the most misleading thing a positive control can do.
    """
    proc = git(*args, cwd=cwd, env=env)
    if proc.returncode != 0:
        raise GitUnavailable(
            f"self-test setup: `git {' '.join(args)}` exited {proc.returncode}: "
            f"{proc.stderr.strip()[:400]}"
        )
    return proc


def dirt(root: Path, env: dict[str, str] | None = None) -> list[str]:
    """Every way the tree is not byte-clean, as lines. Empty means clean.

    `--untracked-files=all` so a directory of leftovers is listed file by file
    rather than as one forgettable entry, and `--ignored` deliberately *not*
    passed: build output is not dirt.
    """
    status = git("status", "--porcelain", "--untracked-files=all", cwd=root, env=env)
    if status.returncode != 0:
        return [f"git status failed: {status.stderr.strip()}"]
    lines = [line for line in status.stdout.splitlines() if line.strip()]

    # `git status` covers staged, unstaged and untracked. `git diff HEAD` is
    # kept as a second opinion: if the two ever disagree, that disagreement is
    # itself worth failing on rather than resolving in favour of the quiet one.
    diff = git("diff", "--exit-code", "HEAD", "--", cwd=root, env=env)
    if diff.returncode not in (0, 1):
        lines.append(f"git diff failed: {diff.stderr.strip()}")
    elif diff.returncode == 1 and not lines:
        lines.append("git diff reports changes that git status did not")
    return lines


def hostile_home(tmp: Path) -> Path:
    """A HOME whose git configuration would wreck this self-test if it were read.

    The positive control has to be hostile to itself. One that only ever runs
    against a clean machine proves the machine: the day a developer turns on
    commit signing, or installs a global hook, or excludes `*.tmp` from
    `status`, this gate starts reporting a defect in the tree that is really a
    defect in its own setup — and the excludes case is worse than the others,
    because it stays *green* while the untracked-file case silently stops being
    tested.

    So all three are planted here on purpose, and the isolation below has to
    beat them for the self-test to pass at all.
    """
    home = tmp / "hostile-home"
    hooks = tmp / "hostile-hooks"
    hooks.mkdir(parents=True)
    hook = hooks / "pre-commit"
    hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)
    excludes = tmp / "hostile-excludes"
    excludes.write_text("*.tmp\n", encoding="utf-8")
    home.mkdir()
    (home / ".gitconfig").write_text(
        "[commit]\n\tgpgsign = true\n"
        f"[core]\n\thooksPath = {hooks}\n\texcludesFile = {excludes}\n",
        encoding="utf-8",
    )
    return home


def isolated_env(home: Path) -> dict[str, str]:
    """An environment for a git that must ignore whatever this machine believes.

    Every `GIT_*` variable is dropped, not overridden: an inherited `GIT_DIR` or
    `GIT_INDEX_FILE` would point the throwaway repository at somebody else's,
    and enumerating the ones that matter is a list that rots.
    """
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / "config")
    # Both files deliberately do not exist. Git reads no global or system
    # configuration at all, so `~/.gitconfig` — hostile or merely opinionated —
    # cannot reach the commands below.
    env["GIT_CONFIG_GLOBAL"] = str(home / "absent-global-config")
    env["GIT_CONFIG_SYSTEM"] = str(home / "absent-system-config")
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


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
    """Make a tree dirty in each way and require the check to notice.

    Run against a deliberately hostile HOME, so a green result means the check
    works *and* is hermetic. Every setup command goes through `must_git`: a
    broken preparation must be reported as a broken preparation and never as a
    finding about the tree.
    """
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        home = hostile_home(Path(tmp))
        env = isolated_env(home)
        empty_hooks = Path(tmp) / "no-hooks"
        empty_hooks.mkdir()
        root = Path(tmp) / "repo"
        root.mkdir()
        must_git("init", "-q", cwd=root, env=env)
        must_git("config", "user.email", "self-test@example", cwd=root, env=env)
        must_git("config", "user.name", "self test", cwd=root, env=env)
        # Belt behind the brace. `isolated_env` already keeps the ambient
        # configuration out; these pin the two settings that would otherwise be
        # inherited from a repository template or a future default.
        must_git("config", "commit.gpgsign", "false", cwd=root, env=env)
        must_git("config", "core.hooksPath", str(empty_hooks), cwd=root, env=env)
        (root / "tracked.txt").write_text("original\n", encoding="utf-8")
        must_git("add", "tracked.txt", cwd=root, env=env)
        must_git("commit", "-qm", "seed", cwd=root, env=env)

        if dirt(root, env):
            failures.append("a freshly committed tree was reported dirty")

        # The negative control for the setup guard itself: a command that cannot
        # succeed must be reported as a failed setup, naming the command, rather
        # than passing quietly and being blamed on the tree three lines later.
        try:
            must_git("cat-file", "-e", "0000000000000000000000000000000000000000",
                     cwd=root, env=env)
        except GitUnavailable as exc:
            if "self-test setup" not in str(exc) or "cat-file" not in str(exc):
                failures.append(f"a failed setup command was reported as {exc!r}")
        else:
            failures.append("a git command that cannot succeed was not reported as a setup failure")

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
            # `.tmp` on purpose: the hostile HOME excludes exactly this pattern,
            # so if the isolation ever stops working this case goes quiet rather
            # than red — the failure mode a positive control exists to prevent.
            ("untracked file", lambda: (root / "stray.tmp").write_text("x", encoding="utf-8")),
            ("staged change", lambda: (
                (root / "staged.txt").write_text("new\n", encoding="utf-8"),
                must_git("add", "staged.txt", cwd=root, env=env),
            )),
        ]
        for name, make_dirty in cases:
            make_dirty()
            if not dirt(root, env):
                failures.append(f"a {name} was not reported")
            # Reset to clean for the next case.
            must_git("reset", "-q", "--hard", "HEAD", cwd=root, env=env)
            must_git("clean", "-qfd", cwd=root, env=env)
            if dirt(root, env):
                failures.append(f"the tree stayed dirty after resetting the {name}")

    if failures:
        print("FAIL the clean-tree check cannot detect:")
        for line in failures:
            print(f"  {line}")
        return 1
    print("OK the clean-tree check reports a tracked modification, an untracked "
          "file and a staged change, reports a clean tree as clean, and does so "
          "against a HOME configured to break it")
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
