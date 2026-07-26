#!/usr/bin/env python3
"""G5 work-task A/B — does the compressed artifact preserve *task* utility?

The reader-cli panels (v1-v5) established recall: readers answer counting and
lookup questions over encoded payloads, and `qodec risk`'s flagged classes
mark where they miscount. G5 asks the program's central unproven question at
the level the milestone actually left open: an agent's *work* — root-cause
diagnosis, cross-referencing, post-diff state, flaky-vs-genuine decisions —
done from the squeeze artifact instead of raw.

Honest scope (unchanged from reader-cli, stated again because G5 tempts
overclaiming):
* Readers run in the closed-world `claude -p` configuration proven in
  PhysShell/007 (no tools, no MCP, no ambient settings). This measures the
  artifact as *context*, which is qodec's actual use; it is NOT a tool-loop
  agent harness — interop L3 stays open regardless of this panel's outcome.
* Ground truth is known by construction (`gen_tasks.py`); grading is
  `qodec ab grade`'s substring matching. No LLM judge.
* No temperature/seed control in `claude -p`: nondeterminism is handled by
  repeats and the paired design; envelopes are recorded verbatim.
* The pooled raw-vs-codec comparison gets a two-sided Fisher exact test —
  the same bar the counting panels used before claiming a difference.

Usage (repo root, after `cargo build --release` and `python3
evals/agent-g5/gen_tasks.py`; `claude` logged in):
    python3 evals/agent-g5/run.py --name g5-v1
    python3 evals/agent-g5/run.py --name quick --tasks root-cause-1 --codecs squeeze --repeats 1
"""

import argparse
import hashlib
import json
import math
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
QODEC = ROOT / "target" / "release" / "qodec"
TASKS_DIR = HERE / "tasks"

# PhysShell/007 `invoke.rs::call_claude`'s proven closed-world flag set —
# byte-identical to evals/reader-cli/run.py.
CLOSED_WORLD = [
    "-p",
    "--output-format", "json",
    "--input-format", "text",
    "--tools", "",
    "--strict-mcp-config",
    "--setting-sources", "",
    "--permission-mode", "default",
    "--no-session-persistence",
    "--max-budget-usd", "0.50",
]


def discover_tasks() -> dict[str, tuple[Path, Path]]:
    tasks = {}
    for payload in sorted(TASKS_DIR.glob("*.txt")):
        questions = payload.with_name(payload.stem + ".questions.json")
        if questions.exists():
            tasks[payload.stem] = (payload, questions)
    return tasks


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def emit(payload: Path, questions: Path, codec: str, out_dir: Path) -> bool:
    proc = subprocess.run(
        [
            str(QODEC), "ab", "emit",
            "-i", str(payload),
            "--questions", str(questions),
            "--codec", codec,
            "--out-dir", str(out_dir),
        ],
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def call_claude(prompt: str, model: str | None, timeout: int) -> dict:
    cmd = ["claude", *CLOSED_WORLD]
    if model:
        cmd += ["--model", model]
    try:
        proc = subprocess.run(
            cmd, input=prompt, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return {"error": f"reader timed out after {timeout}s"}
    except FileNotFoundError:
        return {"error": "claude CLI not installed"}
    if proc.returncode != 0:
        return {"error": proc.stderr.strip()[:500]}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": f"non-JSON envelope: {proc.stdout[:300]}"}


def grade(questions: Path, answers_path: Path, prompt_path: Path) -> dict:
    proc = subprocess.run(
        [
            str(QODEC), "ab", "grade",
            "--questions", str(questions),
            "--answers", str(answers_path),
            "--prompt", str(prompt_path),
        ],
        capture_output=True,
        text=True,
    )
    out = {"output": proc.stdout, "ok": proc.returncode == 0}
    for line in proc.stdout.splitlines():
        if line.startswith("score: "):
            got, total = line.removeprefix("score: ").split("/")
            out["correct"], out["total"] = int(got), int(total)
        if line.startswith("prompt: "):
            out["prompt_tokens_o200k"] = int(line.split()[1])
    return out


def envelope_tokens(env: dict) -> dict:
    usage = env.get("modelUsage", {})
    if not usage:
        return {}
    label, m = max(
        usage.items(),
        key=lambda kv: kv[1].get("inputTokens", 0)
        + kv[1].get("cacheCreationInputTokens", 0)
        + kv[1].get("cacheReadInputTokens", 0),
    )
    return {
        "model": label,
        "input_tokens": m.get("inputTokens", 0),
        "cache_creation": m.get("cacheCreationInputTokens", 0),
        "cache_read": m.get("cacheReadInputTokens", 0),
        "output_tokens": m.get("outputTokens", 0),
        "cost_usd": env.get("total_cost_usd"),
    }


def fisher_two_sided(a_hit: int, a_n: int, b_hit: int, b_n: int) -> float:
    """Two-sided Fisher exact on a 2x2 (hits/misses per arm), stdlib only.

    Sums hypergeometric probabilities <= the observed table's, the standard
    small-sample definition — same test the counting panels reported.
    """
    row1, row2 = a_n, b_n
    col1 = a_hit + b_hit
    n = row1 + row2
    def p_table(k: int) -> float:
        return (
            math.comb(row1, k) * math.comb(row2, col1 - k) / math.comb(n, col1)
        )
    lo = max(0, col1 - row2)
    hi = min(col1, row1)
    p_obs = p_table(a_hit)
    return min(1.0, sum(p for k in range(lo, hi + 1) if (p := p_table(k)) <= p_obs + 1e-12))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--tasks", default=None, help="comma-separated task names (default: all generated)")
    ap.add_argument("--codecs", default="squeeze", help="encoded arms")
    ap.add_argument("--repeats", type=int, default=2)
    ap.add_argument("--model", default=None)
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    if not QODEC.exists():
        print("build first: cargo build --release", file=sys.stderr)
        return 1
    tasks = discover_tasks()
    if not tasks:
        print("no tasks — run gen_tasks.py first", file=sys.stderr)
        return 1
    selected = args.tasks.split(",") if args.tasks else list(tasks)
    run_dir = HERE / "runs" / args.name
    run_dir.mkdir(parents=True, exist_ok=True)

    try:
        reader_version = subprocess.run(
            ["claude", "--version"], capture_output=True, text=True
        ).stdout.strip()
    except FileNotFoundError:
        reader_version = "not-installed"

    record: dict = {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "provider": "claude",
        "reader_version": reader_version,
        "model_arg": args.model,
        "closed_world_argv": CLOSED_WORLD,
        "qodec_sha256": sha256_file(QODEC),
        "git_commit": subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip(),
        "repeats": args.repeats,
        "inputs": {
            t: {"payload_sha256": sha256_file(p), "questions_sha256": sha256_file(q)}
            for t, (p, q) in tasks.items()
            if t in selected
        },
        "cells": [],
    }

    codecs = [c for c in args.codecs.split(",") if c]
    for task in selected:
        if task not in tasks:
            print(f"unknown task {task!r} — skipping", file=sys.stderr)
            continue
        payload, questions = tasks[task]
        task_dir = run_dir / task
        arms: list[tuple[str, Path]] = []
        for codec in codecs:
            out_dir = task_dir / codec
            out_dir.mkdir(parents=True, exist_ok=True)
            if not emit(payload, questions, codec, out_dir):
                print(f"  {task}/{codec}: emit refused — arm skipped", file=sys.stderr)
                record["cells"].append({"task": task, "arm": codec, "status": "emit-refused"})
                continue
            if not any(a == "raw" for a, _ in arms):
                arms.append(("raw", out_dir / "raw.prompt.txt"))
            arms.append((codec, out_dir / "encoded.prompt.txt"))

        for arm, prompt_path in arms:
            prompt = prompt_path.read_text()
            for rep in range(1, args.repeats + 1):
                print(f"  {task}/{arm} rep {rep} …", file=sys.stderr, flush=True)
                env = call_claude(prompt, args.model, args.timeout)
                cell = {"task": task, "arm": arm, "rep": rep}
                if "error" in env:
                    cell.update(status="reader-error", error=env["error"])
                    record["cells"].append(cell)
                    continue
                answers_path = task_dir / f"{arm}.rep{rep}.answers.json"
                answers_path.write_text(env.get("result", ""))
                (task_dir / f"{arm}.rep{rep}.envelope.json").write_text(
                    json.dumps(env, indent=2) + "\n"
                )
                g = grade(questions, answers_path, prompt_path)
                cell.update(
                    status="ok" if g["ok"] else "grade-failed",
                    correct=g.get("correct"),
                    total=g.get("total"),
                    prompt_tokens_o200k=g.get("prompt_tokens_o200k"),
                    envelope=envelope_tokens(env),
                    grade_output=g["output"],
                )
                record["cells"].append(cell)

    (run_dir / "record.json").write_text(json.dumps(record, indent=2) + "\n")

    # Summary: per-task table + pooled per-arm totals + Fisher vs raw.
    ok = [c for c in record["cells"] if c.get("status") == "ok"]
    by_arm: dict[str, list[dict]] = {}
    for c in ok:
        by_arm.setdefault(c["arm"], []).append(c)
    lines = [
        f"# G5 work-task A/B — run `{args.name}`",
        "",
        f"date {record['date']} · claude {reader_version} · qodec `{record['git_commit'][:12]}` · "
        f"repeats {args.repeats} · closed-world flags as in 007 judge",
        "",
        "| task | " + " | ".join(f"{a}" for a in by_arm) + " | prompt tok raw/enc |",
        "|---|" + "---|" * (len(by_arm) + 1),
    ]
    for task in selected:
        cells_by_arm = {
            a: [c for c in by_arm.get(a, []) if c["task"] == task] for a in by_arm
        }
        toks = {
            a: next((c.get("prompt_tokens_o200k") for c in cs), "?")
            for a, cs in cells_by_arm.items()
        }
        row = [task]
        for a, cs in cells_by_arm.items():
            row.append(" ".join(f"{c['correct']}/{c['total']}" for c in cs) or "-")
        tok_pair = "/".join(str(toks.get(a, "?")) for a in by_arm)
        lines.append("| " + " | ".join(row) + f" | {tok_pair} |")
    lines.append("")
    pooled = {
        a: (sum(c["correct"] for c in cs), sum(c["total"] for c in cs))
        for a, cs in by_arm.items()
    }
    for a, (hit, n) in pooled.items():
        extra = ""
        if a != "raw" and "raw" in pooled:
            rh, rn = pooled["raw"]
            p = fisher_two_sided(rh, rn, hit, n)
            extra = f" · Fisher vs raw p={p:.3g}"
        lines.append(f"pooled {a}: {hit}/{n}{extra}")
    failed = [c for c in record["cells"] if c.get("status") != "ok"]
    if failed:
        lines.append(
            "failed cells: "
            + ", ".join(f"{c['task']}/{c['arm']}:{c['status']}" for c in failed)
        )
    lines += [
        "",
        "Scope: closed-world readers over emitted prompts — artifact-as-context "
        "utility, not a tool-loop agent harness (interop L3 remains open). "
        "Envelopes, answers and hashes live next to this file.",
    ]
    (run_dir / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
