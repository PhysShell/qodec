#!/usr/bin/env python3
"""Risk-driven distractor battery — turn `qodec risk` flags into questions.

`qodec risk` computes, without running any model, the plausible-but-wrong
count a reader could fall into (the artifact-visible occurrences of a span
whose remaining occurrences hide inside legend values). This generator turns
each flagged span into an exact-occurrence count question whose ground truth
is the source count — so a panel run directly measures whether readers fall
into the precomputed trap, and `record.json`'s per-question `trap` field
says what falling in would look like.

The battery is generated *from one codec's artifact* (the codec under test)
but is valid for every arm: the question asks about the original data, which
all arms carry — literally (raw), or behind their own notation.

    python3 evals/reader-cli/gen_questions.py \
        --payload corpus/findings.json --codec paper --top 4 \
        --out ab/risk-probe-paper.json
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
QODEC = ROOT / "target" / "release" / "qodec"

WORDS = {
    1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
    7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven",
    12: "twelve", 13: "thirteen", 14: "fourteen", 15: "fifteen",
    16: "sixteen", 17: "seventeen", 18: "eighteen", 19: "nineteen",
    20: "twenty",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--payload", required=True)
    ap.add_argument("--codec", required=True)
    ap.add_argument("--top", type=int, default=4)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    proc = subprocess.run(
        [str(QODEC), "risk", "-i", str(ROOT / args.payload), "--codec", args.codec, "--json"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        return 1
    report = json.loads(proc.stdout)

    flagged = list(report["split"]) + list(report["heterogeneous_hidden"])
    # Biggest miscount potential first; skip spans that are pure whitespace
    # noise or too short to phrase unambiguously.
    flagged = [s for s in flagged if len(s["span"].strip()) >= 6]
    flagged.sort(key=lambda s: s["truth"] - s["body_visible"], reverse=True)

    questions = []
    for i, s in enumerate(flagged[: args.top], start=1):
        truth = s["truth"]
        accept = [str(truth)]
        if truth in WORDS:
            accept.append(WORDS[truth])
        questions.append({
            "id": f"r{i}",
            "question": (
                "In the ORIGINAL data this payload represents, how many times "
                f"does the exact character sequence {json.dumps(s['span'])} occur?"
            ),
            "accept": accept,
            # Not read by the grader — the precomputed plausible-wrong answer
            # (artifact-visible count) this probe exists to detect.
            "trap": s["body_visible"] + s["legend_visible"],
            "class": s["class"],
        })

    if not questions:
        print("no flagged spans — nothing to probe", file=sys.stderr)
        return 1
    out = ROOT / args.out
    out.write_text(json.dumps(questions, indent=2) + "\n")
    print(f"wrote {len(questions)} probes to {out} "
          f"(traps: {[q['trap'] for q in questions]})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
