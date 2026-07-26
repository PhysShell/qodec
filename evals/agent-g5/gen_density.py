#!/usr/bin/env python3
"""Dose-response fixtures along the alias-density axis.

`g5-codex-v1` produced the hypothesis: the codex reader's cross-ref joins
fail deterministically when the squeeze legend is large (passed task: 9
entries; failed: 45 and 43), and n=3 cannot separate "density threshold"
from "task coincidence". This generator controls the dose: the same
cross-ref task shape (exactly one file carries both markers, every other
file carries one kind) at increasing file counts, which drives the mined
legend size. Ground truth stays known by construction; grading stays
substring; the runner and closed-world discipline are unchanged.

`density-codex-v1` then measured an onset in (7, 15] for that ONE task
family, which is exactly the scope limit the finding carries. The
`decision` family here is the replication arm: a different join shape
(intersect the FAILED sets of three retry attempts, rather than two marker
sets over paths), a different surface (test names + status lines rather
than `path:line` comments), and a different hiding pattern — the miner
carves the `mod::file_` stem of the join key across many legend entries
instead of aliasing whole paths. Same reader, same doses by *measured*
legend load, so a difference in outcome is attributable to the family and
not to the dose.

Fixtures land in `tasks-density/` and `tasks-density-decision/` (not
`tasks/`) so the main 12-task battery keeps its identity; run with
    python3 evals/agent-g5/gen_density.py --family decision
    python3 evals/agent-g5/run.py --name <run> --tasks-dir tasks-density ...

Legend size is a *consequence* of mining, not a dial we set directly —
after generating, measure the actual entries per artifact (the runner's
record and the density README table report measured values, never the
intended ones). For `decision` the mapping happens to be exact (one entry
per suite over the whole tested range), which is a measured property of
these fixtures, not a guarantee.
"""

import argparse
import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
TASKS = os.path.join(HERE, "tasks-density")
TASKS_DECISION = os.path.join(HERE, "tasks-density-decision")

MODS = ["net", "auth", "cache", "index", "wal", "codec", "sched", "fs",
        "gc", "tls", "dns", "log", "cli", "fmt", "vm", "ipc"]
FILES = ["session", "handshake", "reader", "writer", "pool", "frame",
         "cursor", "ledger", "probe", "mount"]

MARKER_A, MARKER_B = "TODO(remove_before_ship)", "unwrap_unchecked"

# File counts chosen to bracket the observed pass/fail anchors (9 vs 43/45
# legend entries came from 40-path fixtures; the passed one mined shallow).
DOSES = [6, 12, 20, 30, 40]
# Suite counts chosen so the MEASURED legend lands inside the same five
# bands the cross-ref battery covered (6-7 / 15 / 22-23 / 31-34 / 42-45);
# for this shape one suite mines to exactly one entry across the range.
DECISION_DOSES = [6, 15, 22, 32, 44]
INSTANCES = 3
ATTEMPTS = 3


def gen(dose: int, idx: int, rng: random.Random) -> None:
    pool = [f"src/{m}/{f}.rs" for m in MODS for f in FILES]
    paths = rng.sample(pool, dose)
    both = rng.choice(paths)
    lines = []
    for p in paths:
        kinds = [MARKER_A, MARKER_B] if p == both else [
            MARKER_A if paths.index(p) % 2 == 0 else MARKER_B
        ]
        for kind in kinds:
            for _ in range(rng.randrange(2, 6)):
                lines.append(f"{p}:{rng.randrange(5, 300)}:    // {kind} — see review notes\n")
    rng.shuffle(lines)
    name = f"xref-d{dose:02d}-{idx}"
    os.makedirs(TASKS, exist_ok=True)
    with open(os.path.join(TASKS, f"{name}.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("".join(lines))
    question = (
        f"Which single file contains BOTH `{MARKER_A}` and `{MARKER_B}` "
        "markers? Reply with the file path."
    )
    with open(
        os.path.join(TASKS, f"{name}.questions.json"), "w", encoding="utf-8", newline="\n"
    ) as f:
        json.dump([{"id": "t1", "question": question, "accept": [both]}], f)
        f.write("\n")
    print(f"{name}: {dose} files, {len(lines)} lines -> {both!r}")


def gen_decision(dose: int, idx: int, rng: random.Random) -> None:
    # The join is an intersection over the three attempt blocks: a flaky
    # suite recovers by the last attempt, so exactly one name is FAILED in
    # all of them. Uniqueness holds by construction — the non-culprit
    # branches can only fail on attempts 1 and 2.
    suites = [
        f"{rng.choice(MODS)}::{rng.choice(FILES)}_{k:02d}" for k in range(dose)
    ]
    culprit = rng.choice(suites)
    lines = [f"running retry harness (max {ATTEMPTS} attempts per test)\n"]
    for attempt in range(1, ATTEMPTS + 1):
        lines.append(f"--- attempt {attempt} ---\n")
        for s in suites:
            if s == culprit:
                lines.append(f"test {s} ... FAILED\n")
            elif attempt == 1 and rng.random() < 0.5:
                lines.append(f"test {s} ... FAILED\n")
            elif attempt == 2 and rng.random() < 0.15:
                lines.append(f"test {s} ... FAILED\n")
            else:
                lines.append(f"test {s} ... ok\n")
    lines.append("retry harness done\n")
    name = f"dec-d{dose:02d}-{idx}"
    os.makedirs(TASKS_DECISION, exist_ok=True)
    with open(
        os.path.join(TASKS_DECISION, f"{name}.txt"), "w", encoding="utf-8", newline="\n"
    ) as f:
        f.write("".join(lines))
    question = (
        "Flaky tests recover on retry. Which test failed on EVERY attempt "
        "(genuinely failing, not flaky)? Reply with the full test name."
    )
    with open(
        os.path.join(TASKS_DECISION, f"{name}.questions.json"),
        "w",
        encoding="utf-8",
        newline="\n",
    ) as f:
        json.dump([{"id": "t1", "question": question, "accept": [culprit]}], f)
        f.write("\n")
    print(f"{name}: {dose} suites, {len(lines)} lines -> {culprit!r}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--family", choices=("xref", "decision"), default="xref")
    args = ap.parse_args()
    if args.family == "xref":
        for dose in DOSES:
            for idx in range(1, INSTANCES + 1):
                gen(dose, idx, random.Random(dose * 100 + idx))
    else:
        for dose in DECISION_DOSES:
            for idx in range(1, INSTANCES + 1):
                gen_decision(dose, idx, random.Random(dose * 100 + idx))


if __name__ == "__main__":
    main()
