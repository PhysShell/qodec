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
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE = "test_provider_matrix"
TIMEOUT = 600

# unittest's verbose line: "test_name (pkg.Class.test_name) ... ok"
TEST_LINE = re.compile(r"^(\S+) \(([^)]+)\)")


def ids_from(argv: list[str], cwd: Path | None = None) -> tuple[set[str], str]:
    proc = subprocess.run(
        [sys.executable, *argv, "-v"],
        cwd=cwd or HERE, capture_output=True, text=True, timeout=TIMEOUT,
    )
    found = set()
    for line in (proc.stdout + proc.stderr).splitlines():
        match = TEST_LINE.match(line.strip())
        if match:
            # The direct run names the module `__main__`, `-m unittest` names it
            # `test_provider_matrix`. Compare `Class.test`, which is the part
            # that says *which test ran*.
            qualified = match.group(2).split(" ")[0]
            found.add(qualified.split(".", 1)[1] if "." in qualified else qualified)
    return found, (proc.stdout + proc.stderr).strip().splitlines()[-1] if proc.stdout or proc.stderr else ""


SYNTHETIC = 'import unittest\n\n\nclass Early(unittest.TestCase):\n    def test_one(self):\n        pass\n\n\nif __name__ == "__main__":\n    unittest.main()\n\n\nclass Late(unittest.TestCase):\n    def test_two(self):\n        pass\n'


def disagreements(direct: set[str], module: set[str]) -> tuple[list[str], list[str]]:
    """The comparison itself, so the self-test proves the code main() runs."""
    return sorted(module - direct), sorted(direct - module)


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
        print("OK the check detects a mid-file entrypoint "
              f"(the direct run misses {', '.join(only_module)})")
        return 0


def described(cmd: object) -> str:
    """A command line as a line, not as a repr of a list of strings."""
    if isinstance(cmd, (list, tuple)):
        return " ".join(str(part) for part in cmd)
    return str(cmd)


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
    except subprocess.TimeoutExpired as exc:
        print(f"FAIL a test run exceeded {TIMEOUT}s: {described(exc.cmd)}")
        return 1
    except OSError as exc:
        print(f"FAIL could not run the suite: {exc}")
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
