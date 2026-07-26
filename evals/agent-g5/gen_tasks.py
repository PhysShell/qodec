#!/usr/bin/env python3
"""G5 work-task generator — fixtures where the *task* answer is known by
construction, so grading stays exact-substring and no LLM judge exists.

The move beyond the counting panels (reader-cli v2-v5): those probed recall
("how many X?"); G5 probes *utility* — can a reader do the diagnostic work an
agent actually gets paid for, from the compressed artifact instead of raw?
Four families, each requiring aggregation or cross-referencing over the
payload, not a single-line lookup:

* root-cause  — a failed build log: one primary error among repeated warning
                noise and cascade failures; answer = its `path:line`.
* cross-ref   — matcher output: exactly one file contains both markers;
                answer = that path.
* state       — a unified diff over several files; answer = the value of one
                constant *after* the diff, with a stale-value distractor in a
                comment elsewhere.
* decision    — a flaky-retry CI log: every test recovers on retry except
                one; answer = the test that failed all attempts.

Payloads are deliberately noise-heavy (identical repeated lines, templated
rows) so structural codecs genuinely compress them: an incompressible payload
would make the raw-vs-encoded comparison vacuous.

Deterministic: fixed seeds, LF newlines, stable iteration order. Answers are
multi-character distinctive strings (paths, `path:line`, values like `16384`)
so substring grading cannot false-positive on digits inside larger numbers.
"""

import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
TASKS = os.path.join(HERE, "tasks")

MODS = ["net", "auth", "cache", "index", "wal", "codec", "sched", "fs"]
FILES = ["session", "handshake", "reader", "writer", "pool", "frame", "cursor"]


def write(name, lines, question, accept):
    os.makedirs(TASKS, exist_ok=True)
    with open(os.path.join(TASKS, f"{name}.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("".join(lines))
    with open(
        os.path.join(TASKS, f"{name}.questions.json"), "w", encoding="utf-8", newline="\n"
    ) as f:
        json.dump([{"id": "t1", "question": question, "accept": accept}], f)
        f.write("\n")
    print(f"{name}: {len(lines)} lines -> {accept[0]!r}")


def gen_root_cause(idx, rng):
    culprit = f"src/{rng.choice(MODS)}/{rng.choice(FILES)}.rs"
    line_no = rng.randrange(40, 400)
    warn_pool = [
        f"warning: unused import `crate::{rng.choice(MODS)}::{rng.choice(FILES)}`\n"
        for _ in range(3)
    ]
    lines = [f"   Compiling qodec-lab v0.{idx}.0 (/work/qodec-lab)\n"]
    for _ in range(rng.randrange(110, 150)):
        lines.append(rng.choice(warn_pool))
    # Cascade AFTER the primary error references different files, so the
    # unique correct answer is the first `error[...]` site, and finding it
    # means separating cause from consequence, not grepping "error".
    lines.append(
        f"error[E0308]: mismatched types\n --> {culprit}:{line_no}:17\n"
        "  = note: expected `u64`, found `Option<u64>`\n"
    )
    for _ in range(rng.randrange(8, 12)):
        other = f"src/{rng.choice(MODS)}/{rng.choice(FILES)}.rs"
        lines.append(
            f"error[E0599]: no method named `commit` found — aborted expansion\n"
            f" --> {other}:{rng.randrange(10, 90)}:5\n"
            f"  = note: this error is a consequence of the previous error\n"
        )
    for _ in range(rng.randrange(40, 60)):
        lines.append(rng.choice(warn_pool))
    lines.append("error: could not compile `qodec-lab` (lib) due to previous errors\n")
    write(
        f"root-cause-{idx}",
        lines,
        "This build failed. Identify the PRIMARY error (the cause, not a "
        "consequence). Reply with its location as path:line.",
        [f"{culprit}:{line_no}"],
    )


def gen_cross_ref(idx, rng):
    marker_a, marker_b = "TODO(remove_before_ship)", "unwrap_unchecked"
    paths = [
        f"src/{m}/{f}.rs" for m in MODS for f in rng.sample(FILES, 5)
    ]
    both = rng.choice(paths)
    # Every file except `both` gets exactly one marker kind, so the answer is
    # unique by construction and requires joining two match sets, not lookup.
    lines = []
    for p in paths:
        kinds = [marker_a, marker_b] if p == both else [
            marker_a if paths.index(p) % 2 == 0 else marker_b
        ]
        for kind in kinds:
            for _ in range(rng.randrange(2, 6)):
                lines.append(f"{p}:{rng.randrange(5, 300)}:    // {kind} — see review notes\n")
    rng.shuffle(lines)
    write(
        f"cross-ref-{idx}",
        lines,
        f"Which single file contains BOTH `{marker_a}` and `{marker_b}` "
        "markers? Reply with the file path.",
        [both],
    )


def gen_state(idx, rng):
    value_new = rng.choice(["16384", "49152", "262144", "8192000"])
    value_old = rng.choice(["4096", "1024000", "327680"])
    const = "WAL_SEGMENT_BYTES"
    files = [f"src/{m}/config.rs" for m in rng.sample(MODS, 5)]
    target = files[0]
    lines = []
    for path in files:
        lines.append(f"--- a/{path}\n+++ b/{path}\n")
        for hunk in range(rng.randrange(3, 6)):
            base = rng.randrange(10, 200)
            lines.append(f"@@ -{base},4 +{base},4 @@\n")
            if path == target and hunk == 0:
                lines.append(f"     /// Segment size; was {value_old} before the 2024 compaction rework.\n")
                lines.append(f"-    pub const {const}: u64 = {value_old};\n")
                lines.append(f"+    pub const {const}: u64 = {value_new};\n")
                lines.append("     pub const WAL_DIR: &str = \"wal\";\n")
            else:
                k = rng.choice(["RETRY_BUDGET_MS", "POOL_CAP", "FSYNC_EVERY"])
                old_v, new_v = rng.randrange(100, 900), rng.randrange(1000, 9000)
                lines.append(f"     // tuning pass {idx}\n")
                lines.append(f"-    pub const {k}: u32 = {old_v};\n")
                lines.append(f"+    pub const {k}: u32 = {new_v};\n")
                lines.append("     // end tuning\n")
    write(
        f"state-{idx}",
        lines,
        f"After applying this diff, what is the value of `{const}`? "
        "Reply with the number only.",
        [value_new],
    )


def gen_decision(idx, rng):
    suites = [f"{rng.choice(MODS)}::{rng.choice(FILES)}_{k:02d}" for k in range(rng.randrange(26, 34))]
    genuinely_failing = rng.choice(suites)
    lines = ["running retry harness (max 3 attempts per test)\n"]
    for attempt in (1, 2, 3):
        lines.append(f"--- attempt {attempt} ---\n")
        for s in suites:
            if s == genuinely_failing:
                lines.append(f"test {s} ... FAILED\n")
            elif attempt == 1 and rng.random() < 0.5:
                lines.append(f"test {s} ... FAILED\n")
            elif attempt == 2 and rng.random() < 0.15:
                lines.append(f"test {s} ... FAILED\n")
            else:
                lines.append(f"test {s} ... ok\n")
    lines.append("retry harness done\n")
    write(
        f"decision-{idx}",
        lines,
        "Flaky tests recover on retry. Which test failed on EVERY attempt "
        "(genuinely failing, not flaky)? Reply with the full test name.",
        [genuinely_failing],
    )


def main():
    for idx in range(1, 4):
        gen_root_cause(idx, random.Random(1000 + idx))
        gen_cross_ref(idx, random.Random(2000 + idx))
        gen_state(idx, random.Random(3000 + idx))
        gen_decision(idx, random.Random(4000 + idx))


if __name__ == "__main__":
    main()
