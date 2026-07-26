#!/usr/bin/env python3
"""Deterministic fixtures for the mosaic cost-model experiment.

Two disjoint sets from one generator family:
* demo/     — off-grid multi-regime BENCH fixtures (never harvested for
  training): block lengths chosen so the geometric grid must overpay
  (45 = 32+8+4+1) and, at 864 lines, the measured all-span DP refuses.
* train-synth/ — TRAINING synthetics with different seeds, lengths and
  identifiers, giving the harvester long-span coverage the 6-file corpus
  lacks. Same family, zero shared files — the split stays by-file.

Regenerating overwrites byte-identically (fixed seeds, no timestamps).
"""

import os
import random


def fold_block(n, tag):
    return [
        f"warning: connection pool {tag} exhausted, retrying with exponential backoff\n"
    ] * n


def grep_block(n, base):
    return [
        f"src/app/module_{base}/handler.rs:{40+i}:9: unused variable `ctx_{i%7}`\n"
        for i in range(n)
    ]


def prose_block(n, seed):
    words = (
        "the quick analysis shows that release notes describe wholly unrelated "
        "features while reviewers argue about semantics of tokens and bytes in "
        "modern pipelines"
    ).split()
    out = []
    rnd = random.Random(seed)
    for i in range(n):
        rnd.shuffle(words)
        out.append(" ".join(words[: 9 + i % 4]) + f" #{seed}-{i}\n")
    return out


def diag_block(n, base):
    return [
        f"pkg/core/engine_{base}.cs({120+i},17): error CS86{i%10:02d}: "
        "Non-nullable field must contain a non-null value\n"
        for i in range(n)
    ]


HERE = os.path.dirname(os.path.abspath(__file__))


def write(path, lines):
    with open(os.path.join(HERE, path), "w") as f:
        f.write("".join(lines))
    print(f"{path}: {len(lines)} lines")


def main():
    os.makedirs(os.path.join(HERE, "demo"), exist_ok=True)
    os.makedirs(os.path.join(HERE, "train-synth"), exist_ok=True)

    random.seed(7)
    write(
        "demo/offgrid-250.txt",
        fold_block(45, "alpha") + grep_block(37, 1) + prose_block(23, 1)
        + diag_block(41, 1) + fold_block(29, "beta") + prose_block(19, 2)
        + grep_block(33, 2) + prose_block(23, 3),
    )
    blocks_900 = []
    for r in range(3):
        blocks_900 += (
            fold_block(45 + r * 7, f"g{r}") + grep_block(37 + r * 11, 10 + r)
            + prose_block(53 + r * 5, 10 + r) + diag_block(41 + r * 13, 10 + r)
            + fold_block(29 + r * 3, f"h{r}") + prose_block(37 + r * 7, 20 + r)
        )
    write("demo/offgrid-900.txt", blocks_900)

    random.seed(101)
    write(
        "train-synth/mix-a.txt",
        fold_block(62, "train-a") + prose_block(31, 101) + grep_block(58, 101)
        + diag_block(27, 101) + fold_block(18, "train-b"),
    )
    write(
        "train-synth/mix-b.txt",
        grep_block(71, 102) + fold_block(35, "train-c") + prose_block(47, 102)
        + diag_block(52, 102),
    )
    write(
        "train-synth/mix-c.txt",
        prose_block(60, 103) + fold_block(80, "train-d") + grep_block(24, 103),
    )


if __name__ == "__main__":
    main()
