#!/usr/bin/env python3
"""The one place in this vertical that starts a process and reads its output.

Two gates learned the same lesson a round apart. `subprocess.run(..., text=True)`
decodes with the host locale *inside the standard library* and raises
`UnicodeDecodeError` — a `ValueError` — from within the call, where a handler
written for `TimeoutExpired` and `OSError` does not reach it. The first gate was
fixed; the second was found by a reviewer a round later, wearing the same
clothes. That is not two bugs. It is a boundary with no owner.

So the boundary has one owner and one shape:

    argv, cwd, env, timeout
            ↓
    run_bytes  — bytes out, always; no decoding happens here
            ↓
    an explicit, per-call decoding policy
            ↓
    text this module chose, or a typed failure

Nothing else in the vertical calls `subprocess` directly, and an AST inventory
in the test suite enforces that rather than trusting it.

**Decoding is a policy, not a default.** Two are declared here because the
vertical has exactly two kinds of child:

* `decode_output` — for a child whose output *contract* is UTF-8, such as a
  Python test run. Invalid bytes are a broken contract, so they raise.
* `decode_path` — for git, whose filenames are arbitrary bytes by design.
  Refusing to read them would be inventing a rule the tool does not have, so
  they are decoded with `surrogateescape` for local use and rendered through
  `printable` before they are ever shown.

**Failures never quote what caused them.** `UnicodeDecodeError`'s message
contains the offending bytes, and a child's stderr is whatever the child chose
to write. Both are described by size, not repeated — the same reasoning that
keeps a provider's error prose out of a receipt, one layer down.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


class ProcessFailure(RuntimeError):
    """A child could not be run to a verdict. Reported, never raised past main."""


class ProcessTimeout(ProcessFailure):
    """The child outlived its deadline."""


class ProcessUnavailable(ProcessFailure):
    """The child could not be started at all."""


class UndecodableOutput(ProcessFailure):
    """Bytes that the declared decoding policy for this call cannot read.

    Carries nothing but its type. The only detail available is the bytes that
    caused it, which is exactly what must not be repeated.
    """


@dataclass(frozen=True)
class CompletedBytes:
    """What a child produced, before anyone has decided how to read it."""

    returncode: int
    stdout: bytes
    stderr: bytes

    def stderr_size(self) -> str:
        """A local description of stderr — never its contents.

        `must_git` used to put `proc.stderr[:400]` into a failure message. The
        four hundred is the wrong half of the fix: the bytes are a child's
        choice however few of them are kept.
        """
        return f"{len(self.stderr)} bytes of stderr"


def run_bytes(
    argv: Sequence[str],
    *,
    timeout: float,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> CompletedBytes:
    """Run a child and return its bytes. The only `subprocess` call in the vertical.

    `text=False` is the whole point: decoding is a decision, and a decision made
    inside a library is a decision nobody caught.
    """
    try:
        proc = subprocess.run(
            list(argv), cwd=cwd, env=env, timeout=timeout,
            capture_output=True, text=False,
        )
    except subprocess.TimeoutExpired:
        raise ProcessTimeout(f"`{described(argv)}` exceeded {timeout}s") from None
    except OSError as exc:
        # `exc` here describes our own filesystem, not the child's output, so it
        # is local — but only its class and errno are kept, for consistency
        # with everything else that crosses out of this module.
        raise ProcessUnavailable(
            f"could not run `{described(argv)}`: {type(exc).__name__}"
        ) from None
    return CompletedBytes(proc.returncode, proc.stdout, proc.stderr)


def described(argv: object) -> str:
    """A command line as a line, not as a repr of a list.

    A string is already a command line; iterating it would spell it out one
    character at a time, which is the sort of output that makes a reader
    distrust the whole report.
    """
    if isinstance(argv, (list, tuple)):
        return " ".join(str(part) for part in argv)
    return str(argv)


def decode_output(data: bytes) -> str:
    """For a child whose output contract is UTF-8. Invalid bytes are a failure."""
    try:
        return data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise UndecodableOutput from None


def decode_path(data: bytes) -> str:
    """For a child whose output is filesystem paths — arbitrary bytes by design.

    `os.fsdecode` rather than a locale-driven decode, so a path that is not
    valid UTF-8 round-trips instead of raising. The result carries surrogates
    and is unsafe to print, which is what `printable` is for.
    """
    return os.fsdecode(data)


def printable(text: str) -> str:
    """A form safe to write to a terminal, with nothing raw left in it."""
    return text.encode("utf-8", "backslashreplace").decode("ascii", "backslashreplace")
