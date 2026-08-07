#!/usr/bin/env python3
"""Assert both ways of running the suite find the same tests.

`if __name__ == "__main__": unittest.main()` sat on line 1033 of a 1975-line
file, above fourteen more test classes. `python3 test_provider_matrix.py` ran
the first four classes, skipped the envelope oracle, the observed-result
grading, the send-stage table, the strict-JSON gate, the encoding rules, the
admission parity, the depth guard and the integer range — everything the last
five review rounds built — and printed **OK**. CI uses `python -m unittest`,
which imports the module before running it and is therefore unaffected, so the
hole was invisible from the green side.

Moving the entrypoint fixes today's file. It does not stop the next person
adding a class below a stray `unittest.main()`, and "the file looks right" is
the kind of evidence that has failed repeatedly here. So this compares the two
invocations by the **set of test ids each one actually ran** — not by a count,
and not against a number written down somewhere that would rot the first time a
test is added.

    python3 evals/provider-matrix/check_test_discovery.py

Exit 0 when both runs report the same test ids, 1 otherwise.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

from process_boundary import (
    ProcessFailure,
    UndecodableOutput,
    decode_output,
    described,
    run_bytes,
)

HERE = Path(__file__).resolve().parent
MODULE = "test_provider_matrix"
TIMEOUT = 600

# unittest's verbose line: "test_name (pkg.Class.test_name) ... ok"
TEST_LINE = re.compile(r"^(\S+) \(([^)]+)\)")


# The decoding policy for this gate's children, declared rather than defaulted:
# a Python test run's output contract is UTF-8, so bytes outside it are a broken
# contract and become a typed failure.
def decode_test_output(stdout: bytes, stderr: bytes) -> str:
    """Decode a child's output under this gate's declared policy."""
    return decode_output(stdout + stderr)


def ids_from(argv: list[str], cwd: Path | None = None) -> tuple[set[str], str]:
    proc = run_bytes(
        [sys.executable, *argv, "-v"], cwd=cwd or HERE, timeout=TIMEOUT,
    )
    combined = decode_test_output(proc.stdout, proc.stderr)
    found = set()
    for line in combined.splitlines():
        match = TEST_LINE.match(line.strip())
        if match:
            # The direct run names the module `__main__`, `-m unittest` names it
            # `test_provider_matrix`. Compare `Class.test`, which is the part
            # that says *which test ran*.
            qualified = match.group(2).split(" ")[0]
            found.add(qualified.split(".", 1)[1] if "." in qualified else qualified)
    # Total for any output at all. The guard used to test the truthiness of the
    # *raw* streams and then index into the *stripped* split, so a run that
    # printed a single newline was truthy, split to `[]`, and `[-1]` raised —
    # a traceback out of the gate instead of the report the gate exists to
    # print. `run_gate`/`run_suite` in `mutations.py` already had this shape.
    tail = combined.strip().splitlines()
    return found, tail[-1] if tail else "(no output)"


# Straight to the file descriptor, so no encoder gets a say: this is the byte
# sequence a child can emit and a locale-driven decode cannot read.
UNREADABLE = 'import os\nos.write(1, b"\\xff")\n'

SYNTHETIC = 'import unittest\n\n\nclass Early(unittest.TestCase):\n    def test_one(self):\n        pass\n\n\nif __name__ == "__main__":\n    unittest.main()\n\n\nclass Late(unittest.TestCase):\n    def test_two(self):\n        pass\n'


def disagreements(direct: set[str], module: set[str]) -> tuple[list[str], list[str]]:
    """The comparison itself, so the self-test proves the code main() runs."""
    return sorted(module - direct), sorted(direct - module)


def verdict_for(exc: BaseException) -> str:
    """The line this gate prints for a failure it can suffer.

    One mapping rather than three `print`s inside `main`, because a mutated
    gate is qualified by its own `--self-test` and a branch the control cannot
    reach cannot be killed by any mutation. As a function it is reachable, and
    the control checks it.

    `UndecodableOutput` prints no detail on purpose: the only detail available
    is the bytes that caused it. The others carry a command line and a class
    name, both of which this module chose.
    """
    if isinstance(exc, UndecodableOutput):
        return "FAIL a test run produced output that was not valid UTF-8"
    return f"FAIL could not run the suite: {exc}"


def self_test() -> int:
    """Build the defect on purpose and require the comparison to see it.

    A module with `unittest.main()` above a later class: the direct run finds
    `Early` only, `-m unittest` finds both. If this check cannot tell those
    apart it is decoration, and "it passed" would mean nothing.
    """
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "synthetic_case.py").write_text(SYNTHETIC, encoding="utf-8")
        direct, _ = ids_from(["synthetic_case.py"], work)
        module, _ = ids_from(["-m", "unittest", "synthetic_case"], work)
        only_module, only_direct = disagreements(direct, module)
        if not (only_module or only_direct):
            print("FAIL the check cannot tell a mid-file entrypoint from a complete run")
            print(f"  direct: {sorted(direct)}")
            print(f"  module: {sorted(module)}")
            return 1

        # The other half of the control: a run that says nothing must produce a
        # verdict, not a traceback. `print()` emits one newline, which is
        # truthy and strips to nothing — the exact input that used to index an
        # empty list and take the gate down with it.
        (work / "silent_case.py").write_text("print()\n", encoding="utf-8")
        silent, verdict = ids_from(["silent_case.py"], work)
        if silent or verdict != "(no output)":
            print("FAIL a run that printed only whitespace was not reported as no output")
            print(f"  ids: {sorted(silent)}")
            print(f"  verdict: {verdict!r}")
            return 1

        # The third arm, and the reason it lives here rather than only in the
        # unit suite: a mutated gate is qualified by its own `--self-test`, so a
        # contract this control does not exercise cannot be killed by a
        # mutation. A decoding rule proved only by a test the harness never runs
        # would be a certificate on a wall.
        (work / "unreadable_case.py").write_text(UNREADABLE, encoding="utf-8")
        try:
            ids_from(["unreadable_case.py"], work)
        except UndecodableOutput:
            pass
        else:
            print("FAIL output that is not valid UTF-8 was not reported as unreadable")
            return 1

        # And the failure has to become a verdict, not merely a distinct
        # exception. This is the branch `main` takes, checked here because the
        # control is what qualifies a mutated gate.
        spoken = verdict_for(UndecodableOutput())
        if "not valid UTF-8" not in spoken:
            print(f"FAIL unreadable output is not reported as a verdict: {spoken!r}")
            return 1

        print("OK the check detects a mid-file entrypoint "
              f"(the direct run misses {', '.join(only_module)}), "
              "reports a silent run rather than raising, and refuses "
              "output it cannot decode")
        return 0


def main() -> int:
    # The self-test is inside the handler, not dispatched above it. It runs the
    # synthetic module twice through the same `ids_from`, so it can stall in
    # exactly the same way — and a traceback there would be the positive
    # control failing to report, which is the one place it must not.
    try:
        if "--self-test" in sys.argv[1:]:
            return self_test()
        direct, direct_verdict = ids_from([f"{MODULE}.py"])
        module, module_verdict = ids_from(["-m", "unittest", MODULE])
    except ProcessFailure as exc:
        print(verdict_for(exc))
        return 1

    if not direct or not module:
        print("FAIL one of the runs reported no tests at all")
        print(f"  direct: {len(direct)} ({direct_verdict})")
        print(f"  module: {len(module)} ({module_verdict})")
        return 1

    only_module, only_direct = disagreements(direct, module)
    if only_module or only_direct:
        print("FAIL the two ways of running the suite do not find the same tests")
        print(f"  python3 {MODULE}.py      ran {len(direct)}")
        print(f"  python3 -m unittest {MODULE}  ran {len(module)}")
        for name in only_module[:20]:
            print(f"  only under -m unittest: {name}")
        for name in only_direct[:20]:
            print(f"  only under the direct run: {name}")
        if len(only_module) > 20 or len(only_direct) > 20:
            print("  (truncated)")
        return 1

    print(f"OK both invocations run the same {len(direct)} tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
