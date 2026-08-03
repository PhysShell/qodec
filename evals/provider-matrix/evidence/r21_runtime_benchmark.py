#!/usr/bin/env python3
"""Measure what the duplicated corpora cost, with enough provenance to re-run.

A rounded table is a claim; a rounded table with no command, no interpreter
version and no raw repeats is a claim nobody can check. Every number here
carries what produced it, and the individual repeats are kept rather than
averaged away — a median hides a first run that paid for a cold import cache,
and that difference is exactly the sort of thing that turns into folklore.

What is measured, all on one head:

  suite as shipped            the unit suite, including the five tests that
                              re-run a shipped self-test corpus in process
  suite minus duplicates      the same suite with those five deselected
  each shipped self-test      run once on its own, as CI and the mutation
                              harness run it

What is *not* measured here, and must not be inferred from it: the runtime of
the full mutation harness. That depends on how the 317 specifications are
distributed across target files and assigned oracles, and only a full run
settles it.
"""

from __future__ import annotations

import json
import os
import pathlib
import platform
import statistics
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
MATRIX = HERE.parent
sys.path.insert(0, str(MATRIX))

from process_boundary import ProcessFailure, decode_output, run_bytes  # noqa: E402

REPEATS = 3

RUNNER_NAME = "_benchmark_suite.py"


def runner_source(deselect: bool) -> str:
    from r21_topology_evidence import DUPLICATES
    skips = [f"test_provider_matrix.{cls}.{name} = "
             f"lambda self: self.skipTest('deselected: duplicated shipped corpus')"
             for cls, name in DUPLICATES] if deselect else []
    return "\n".join([
        "import sys, unittest",
        'sys.path.insert(0, ".")',
        "import test_provider_matrix",
        *skips,
        "loader = unittest.TestLoader()",
        "suite = loader.loadTestsFromModule(test_provider_matrix)",
        "result = unittest.TextTestRunner(verbosity=0).run(suite)",
        'print("RESULT", "GREEN" if result.wasSuccessful() else "RED", result.testsRun)',
    ])


def timed(argv: list[str], env: dict, cwd: pathlib.Path) -> tuple[float, str]:
    """Wall time by `perf_counter` around a completed subprocess.

    Wall rather than CPU because the thing being described is how long a person
    or a CI step waits, and several of these gates spend their time in `git` and
    in child interpreters rather than in this one.
    """
    start = time.perf_counter()
    try:
        proc = run_bytes(argv, cwd=cwd, env=env, timeout=1800)
        elapsed = time.perf_counter() - start
        output, code = decode_output(proc.stdout + proc.stderr), proc.returncode
    except ProcessFailure as exc:
        return time.perf_counter() - start, f"failed: {exc}"
    said = [ln for ln in output.splitlines() if ln.startswith(("RESULT ", "OK "))]
    return elapsed, (said[-1] if said else f"exit={code}")


def main() -> int:
    import mutations as m
    env = dict(os.environ, PYTHONPATH=str(m.CORPUS_TOOLS), PYTHONDONTWRITEBYTECODE="1")
    head = decode_output(run_bytes(["git", "rev-parse", "HEAD"], cwd=MATRIX,
                                   timeout=60).stdout).strip()

    subjects = {}
    for label, deselect in (("suite as shipped", False),
                            ("suite minus duplicated corpora", True)):
        (MATRIX / RUNNER_NAME).write_text(runner_source(deselect), encoding="utf-8")
        repeats, note = [], ""
        for _ in range(REPEATS):
            seconds, note = timed([sys.executable, RUNNER_NAME], env, MATRIX)
            repeats.append(round(seconds, 3))
        subjects[label] = {"command": f"python3 {RUNNER_NAME}",
                           "deselected": deselect, "repeats": repeats,
                           "median": round(statistics.median(repeats), 3),
                           "verdict": note}
    (MATRIX / RUNNER_NAME).unlink()

    for gate in ("receipt_policy.py", "check_clean_tree.py",
                 "check_test_discovery.py", "check_readme.py"):
        repeats, note = [], ""
        for _ in range(REPEATS):
            seconds, note = timed([sys.executable, gate, "--self-test"], env, MATRIX)
            repeats.append(round(seconds, 3))
        subjects[f"{gate} --self-test"] = {
            "command": f"python3 {gate} --self-test", "repeats": repeats,
            "median": round(statistics.median(repeats), 3), "verdict": note[:80]}

    report = {
        "head": head,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "repeats_per_subject": REPEATS,
        "wall_time": "time.perf_counter around subprocess.run, seconds",
        "subjects": subjects,
        "derived": {
            "suite_saving_median_seconds": round(
                subjects["suite as shipped"]["median"]
                - subjects["suite minus duplicated corpora"]["median"], 3),
        },
        "not_measured": "full mutation harness runtime; only a full run settles it",
    }
    out = HERE / "artifacts" / "runtime-before.json"
    out.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    for label, row in subjects.items():
        print(f"  {label:38} median {row['median']:7.3f}s   {row['repeats']}")
    print(f"  suite saving (median): "
          f"{report['derived']['suite_saving_median_seconds']}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
