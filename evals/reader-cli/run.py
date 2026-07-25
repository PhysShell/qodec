#!/usr/bin/env python3
"""CLI-reader comprehension A/B — `qodec ab` driven through agent-CLI readers.

The missing model rung for people without a served endpoint: Claude Code (and
later Codex) subscriptions already provide an authenticated model behind a
CLI. This runner takes the deterministic ends qodec already owns (`qodec ab
emit` builds paired prompts, `qodec ab grade` string-matches answers) and
drives the model invocations through `claude -p` in the closed-world
configuration proven in PhysShell/007's judge (`--tools ""` +
`--strict-mcp-config` + `--setting-sources ""` + `--permission-mode default`
+ `--no-session-persistence`): no built-in tools, no ambient MCP, no ambient
CLAUDE.md — the reader sees exactly the emitted prompt.

Honest scope:
* The CLI wraps the model in Claude Code's system prompt (visible in the
  envelope's cache-creation tokens). It is identical across arms, so paired
  deltas isolate the payload representation; absolute scores are "reader
  inside Claude Code", not bare-model numbers.
* No temperature/seed control exists in `claude -p`; nondeterminism is
  handled by repeats and the paired design, and every envelope (model id,
  usage, cost) is recorded verbatim.
* Grading is `qodec ab grade`'s deliberately dumb substring matching — no
  LLM judge anywhere.

Usage (from the repo root, after `cargo build --release`; `claude` logged in):
    python3 evals/reader-cli/run.py --name panel-v1
    python3 evals/reader-cli/run.py --name quick --cases stacktrace --codecs deep --repeats 1
"""

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
QODEC = ROOT / "target" / "release" / "qodec"

CASES = {
    "stacktrace": ("corpus/stacktrace.txt", "ab/stacktrace.json"),
    "build-log": ("corpus/build-log.txt", "ab/build-log.json"),
    "rg-output": ("corpus/rg-output.txt", "ab/rg-output.json"),
    "findings": ("corpus/findings.json", "ab/findings.json"),
    # Count-only probes over the same payload — the questions `qodec risk`
    # predicts specific codecs to fail (split / heterogeneous-hidden spans).
    "findings-count": ("corpus/findings.json", "ab/counting.json"),
}

# PhysShell/007 `invoke.rs::call_claude`'s proven closed-world flag set.
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


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def emit(case: str, codec: str, out_dir: Path) -> dict | None:
    payload, questions = CASES[case]
    proc = subprocess.run(
        [
            str(QODEC), "ab", "emit",
            "-i", str(ROOT / payload),
            "--questions", str(ROOT / questions),
            "--codec", codec,
            "--out-dir", str(out_dir),
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None
    return {"emit_stderr": proc.stderr.strip()}


def call_reader(prompt: str, model: str | None, timeout: int) -> dict:
    cmd = ["claude", *CLOSED_WORLD]
    if model:
        cmd += ["--model", model]
    proc = subprocess.run(
        cmd, input=prompt, capture_output=True, text=True, timeout=timeout
    )
    if proc.returncode != 0:
        return {"error": proc.stderr.strip()[:500]}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": f"non-JSON envelope: {proc.stdout[:300]}"}


def grade(case: str, answers_path: Path, prompt_path: Path) -> dict:
    _, questions = CASES[case]
    proc = subprocess.run(
        [
            str(QODEC), "ab", "grade",
            "--questions", str(ROOT / questions),
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
    """Request-size evidence from the envelope: per-model input totals."""
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True, help="run directory name under runs/")
    ap.add_argument("--cases", default=",".join(CASES), help="comma-separated case names")
    ap.add_argument("--codecs", default="deep,paper", help="encoded arms to run")
    ap.add_argument("--repeats", type=int, default=2)
    ap.add_argument("--model", default=None, help="claude --model override (else CLI default, recorded from envelope)")
    ap.add_argument("--timeout", type=int, default=300, help="seconds per reader call")
    args = ap.parse_args()

    if not QODEC.exists():
        print("build first: cargo build --release", file=sys.stderr)
        return 1
    run_dir = HERE / "runs" / args.name
    run_dir.mkdir(parents=True, exist_ok=True)

    claude_version = subprocess.run(
        ["claude", "--version"], capture_output=True, text=True
    ).stdout.strip()

    record: dict = {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "claude_version": claude_version,
        "model_arg": args.model,
        "closed_world_argv": CLOSED_WORLD,
        "qodec_sha256": sha256_file(QODEC),
        "git_commit": subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip(),
        "repeats": args.repeats,
        "inputs": {
            c: {"payload_sha256": sha256_file(ROOT / p), "questions_sha256": sha256_file(ROOT / q)}
            for c, (p, q) in CASES.items()
            if c in args.cases.split(",")
        },
        "cells": [],
    }

    codecs = [c for c in args.codecs.split(",") if c]
    for case in args.cases.split(","):
        if case not in CASES:
            print(f"unknown case {case!r} — skipping", file=sys.stderr)
            continue
        case_dir = run_dir / case
        arms: list[tuple[str, Path]] = []  # (arm label, prompt file)
        for codec in codecs:
            out_dir = case_dir / codec
            out_dir.mkdir(parents=True, exist_ok=True)
            if emit(case, codec, out_dir) is None:
                print(f"  {case}/{codec}: emit refused (raw fallback) — arm skipped", file=sys.stderr)
                record["cells"].append({"case": case, "arm": codec, "status": "emit-refused"})
                continue
            if not any(a == "raw" for a, _ in arms):
                arms.append(("raw", out_dir / "raw.prompt.txt"))
            arms.append((codec, out_dir / "encoded.prompt.txt"))

        for arm, prompt_path in arms:
            prompt = prompt_path.read_text()
            for rep in range(1, args.repeats + 1):
                print(f"  {case}/{arm} rep {rep} …", file=sys.stderr)
                env = call_reader(prompt, args.model, args.timeout)
                cell = {"case": case, "arm": arm, "rep": rep}
                if "error" in env:
                    cell.update(status="reader-error", error=env["error"])
                    record["cells"].append(cell)
                    continue
                answers_path = case_dir / f"{arm}.rep{rep}.answers.json"
                answers_path.write_text(env.get("result", ""))
                (case_dir / f"{arm}.rep{rep}.envelope.json").write_text(
                    json.dumps(env, indent=2) + "\n"
                )
                g = grade(case, answers_path, prompt_path)
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

    # Summary: per case × arm, scores across repeats + token evidence.
    lines = [
        f"# reader-cli A/B — run `{args.name}`",
        "",
        f"date {record['date']} · {claude_version} · qodec `{record['git_commit'][:12]}` · "
        f"repeats {args.repeats} · closed-world flags as in 007 judge",
        "",
        "| case | arm | scores | mean | prompt tok (o200k) | fresh input tok (envelope) | model |",
        "|---|---|---|---:|---:|---:|---|",
    ]
    by_arm: dict[tuple[str, str], list[dict]] = {}
    for cell in record["cells"]:
        if cell.get("status") == "ok":
            by_arm.setdefault((cell["case"], cell["arm"]), []).append(cell)
    for (case, arm), cells in by_arm.items():
        scores = [f"{c['correct']}/{c['total']}" for c in cells]
        mean = sum(c["correct"] for c in cells) / len(cells)
        fresh = [
            c["envelope"].get("input_tokens", 0) + c["envelope"].get("cache_creation", 0)
            for c in cells
            if c.get("envelope")
        ]
        model = next((c["envelope"].get("model") for c in cells if c.get("envelope")), "?")
        lines.append(
            f"| {case} | {arm} | {' '.join(scores)} | {mean:.1f} | "
            f"{cells[0].get('prompt_tokens_o200k', '?')} | "
            f"{round(sum(fresh) / len(fresh)) if fresh else '?'} | {model} |"
        )
    skipped = [c for c in record["cells"] if c.get("status") != "ok"]
    if skipped:
        lines += ["", "skipped/failed cells: " + ", ".join(
            f"{c['case']}/{c['arm']}:{c['status']}" for c in skipped
        )]
    lines += [
        "",
        "`fresh input tok` = envelope inputTokens + cacheCreation for the main "
        "model (what a cold request pays, incl. the CLI's own system prompt — "
        "identical across arms, so deltas isolate the payload). Full envelopes, "
        "answers and hashes live next to this file.",
    ]
    (run_dir / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
