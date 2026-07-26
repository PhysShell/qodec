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

Fixtures land in `tasks-density/` (not `tasks/`) so the main 12-task
battery keeps its identity; run with
    python3 evals/agent-g5/run.py --name <run> --tasks-dir tasks-density ...

Legend size is a *consequence* of mining, not a dial we set directly —
after generating, measure the actual entries per artifact (the runner's
record and the density README table report measured values, never the
intended ones).
"""

import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
TASKS = os.path.join(HERE, "tasks-density")

MODS = ["net", "auth", "cache", "index", "wal", "codec", "sched", "fs",
        "gc", "tls", "dns", "log", "cli", "fmt", "vm", "ipc"]
FILES = ["session", "handshake", "reader", "writer", "pool", "frame",
         "cursor", "ledger", "probe", "mount"]

MARKER_A, MARKER_B = "TODO(remove_before_ship)", "unwrap_unchecked"

# File counts chosen to bracket the observed pass/fail anchors (9 vs 43/45
# legend entries came from 40-path fixtures; the passed one mined shallow).
DOSES = [6, 12, 20, 30, 40]
INSTANCES = 3


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


def main() -> None:
    for dose in DOSES:
        for idx in range(1, INSTANCES + 1):
            gen(dose, idx, random.Random(dose * 100 + idx))


if __name__ == "__main__":
    main()
