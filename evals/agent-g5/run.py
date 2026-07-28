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
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
QODEC = ROOT / "target" / "release" / "qodec"
DEFAULT_TASKS_DIR = "tasks"

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

# The codex analogue, byte-identical to evals/reader-cli/run.py: read-only
# sandbox, ephemeral, no user config or rule files, shell tool off, prompt on
# stdin, answer from --output-last-message, cwd = a fresh empty dir. NOTE:
# read-only denies writes but NOT network — prefer the claude backend for
# untrusted payloads (007 docs/security-layers.md).
CODEX_FLAGS = [
    "exec",
    "--sandbox", "read-only",
    "--skip-git-repo-check",
    "--ephemeral",
    "--color", "never",
    "-c", "features.shell_tool=false",
    "--ignore-user-config",
    "--ignore-rules",
]


def discover_tasks(tasks_dir: Path) -> dict[str, tuple[Path, Path]]:
    tasks = {}
    for payload in sorted(tasks_dir.glob("*.txt")):
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


def call_claude(prompt: str, model: str | None, timeout: int,
                effort: str | None = None) -> dict:
    """Run the closed-world claude reader; effort provenance is CLI-level only."""
    cmd = ["claude", *CLOSED_WORLD]
    if model:
        cmd += ["--model", model]
    if effort:
        cmd += ["--effort", effort]
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
        env = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": f"non-JSON envelope: {proc.stdout[:300]}"}
    if effort:
        # The claude JSON envelope carries NO effort field — measured, not
        # assumed (`claude -p --output-format json` at 2.1.220 exposes
        # usage/modelUsage/timings and nothing about reasoning effort). So
        # the only available signal is that the CLI did not reject the
        # level: an unknown value prints "Unknown --effort value ... using
        # the default effort" and proceeds, which is exactly the silent
        # downgrade that must never be recorded as the requested level.
        # Fail closed on that warning; otherwise record the provenance as
        # CLI-accepted and NOT server-confirmed, so no analysis can quote
        # it as if it were.
        if "Unknown --effort value" in proc.stderr:
            return {"error": f"claude rejected --effort {effort}: silent downgrade to default"}
        env["effort_requested"] = effort
        env["effort_source"] = "cli-flag-accepted-not-server-confirmed"
    return env


def call_codex(prompt: str, model: str | None, timeout: int,
               effort: str | None = None) -> dict:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="qodec-codex-") as cwd:
        last_msg = Path(cwd) / "last-message.txt"
        cmd = ["codex", *CODEX_FLAGS, "--output-last-message", str(last_msg)]
        if effort:
            cmd += ["-c", f"model_reasoning_effort={effort}"]
        if model:
            cmd += ["--model", model]
        cmd.append("-")  # prompt on stdin
        try:
            proc = subprocess.run(
                cmd, input=prompt, capture_output=True, text=True,
                timeout=timeout, cwd=cwd,
            )
        except subprocess.TimeoutExpired:
            return {"error": f"reader timed out after {timeout}s"}
        except FileNotFoundError:
            return {"error": "codex CLI not installed"}
        if proc.returncode != 0 or not last_msg.exists():
            return {"error": proc.stderr.strip()[:500] or "codex produced no last message"}
        # No usage envelope from codex — record what exists, honestly. The
        # session header (model, reasoning effort) prints at the START of the
        # stream; keeping only a tail dropped it and made the committed runs'
        # model/effort unverifiable (Codex review on PR #11) — parse it out
        # and keep the head too.
        header = {}
        for line in (proc.stderr + "\n" + proc.stdout).splitlines():
            line = line.strip()
            if line.startswith("model:"):
                header["model"] = line.removeprefix("model:").strip()
            elif line.startswith("reasoning effort:"):
                header["reasoning_effort"] = line.removeprefix("reasoning effort:").strip()
        # Unlike claude, codex ECHOES the applied effort in the session
        # header, so the request can be verified rather than trusted. Fail
        # closed on any mismatch: a cell whose effort cannot be confirmed
        # is not evidence about effort.
        if effort:
            applied = header.get("reasoning_effort")
            if applied != effort:
                return {"error": f"codex effort mismatch: requested {effort}, header says {applied!r}"}
            header["effort_requested"] = effort
            header["effort_source"] = "session-header-confirmed"
        return {"result": last_msg.read_text(), "provider": "codex",
                **header,
                "stderr_head": proc.stderr.strip()[:600],
                "stderr_tail": proc.stderr.strip()[-300:]}


def call_reader(provider: str, prompt: str, model: str | None, timeout: int,
                effort: str | None = None) -> dict:
    """Dispatch to the configured reader backend, timing the call."""
    # Wall-clock is recorded here rather than derived afterwards: an effort
    # arm's overhead is only reportable if the frozen artifact carries it,
    # and a run whose durations were never persisted cannot substantiate a
    # latency claim later (`effort-high-codex-*` learned this the hard way).
    started = time.monotonic()
    if provider == "codex":
        env = call_codex(prompt, model, timeout, effort)
    else:
        env = call_claude(prompt, model, timeout, effort)
    env["duration_s"] = round(time.monotonic() - started, 3)
    return env


def candidate_shape(accept: str) -> str | None:
    """Regex for tokens shaped like this task's answer, or None if unknown."""
    if re.fullmatch(r"[a-z]+::[a-z]+_\d+", accept):
        return r"[a-z]+::[a-z]+_\d+"
    if re.fullmatch(r"src/[\w/]+\.rs", accept):
        return r"src/[\w/]+\.rs"
    return None


def answer_shape(questions: Path, payload: Path, answers_path: Path) -> dict:
    """Count how many distinct payload candidates the answer names.

    Substring grading credits an answer that CONTAINS the accepted string,
    so a hedged reply naming several candidates ("both A and B failed on
    every attempt") scores identically to the single correct one —
    measured, not hypothesised. Elevated reasoning effort produces exactly
    that shape, which would inflate a rescue count in the direction the
    hypothesis predicts. This audit records the shape alongside the grade
    so the analysis can report as-graded and strict-single-candidate
    counts separately; the grader itself is left untouched so prior runs
    stay comparable.
    """
    try:
        qs = json.loads(questions.read_text())
        answers = json.loads(answers_path.read_text())
        body = payload.read_text()
    except (OSError, json.JSONDecodeError):
        return {}
    named, hedged = 0, False
    for q in qs:
        accept = (q.get("accept") or [""])[0]
        shape = candidate_shape(accept)
        got = str(answers.get(q.get("id"), ""))
        if not shape or not got:
            continue
        pool = set(re.findall(shape, body))
        # Match whole candidate tokens on both sides. `c in got` would count
        # `cli::reader_1` as named by an answer that only says
        # `cli::reader_17`, which would inflate `candidates_named` and flip
        # cells into `hedged` on prefix collisions alone.
        hits = pool & set(re.findall(shape, got))
        named = max(named, len(hits))
        if len(hits) > 1:
            hedged = True
    return {"candidates_named": named, "hedged": hedged}


def derive_effort_provenance(record: dict) -> str | None:
    """Summarise per-cell effort provenance; never assert it from the request.

    A run-level claim is only as good as the weakest cell that backs it, so
    the aggregate is computed from what the backends actually returned. Any
    cell that failed to confirm the requested level — including a cell that
    never completed — downgrades the whole run to `partial`, and a run with
    no completed cells stays unconfirmed. `--effort` on its own confirms
    nothing.
    """
    if not record.get("effort_requested"):
        return None
    graded = [c for c in record["cells"] if "effort_provenance" in c]
    if not graded or len(graded) != len([c for c in record["cells"] if "rep" in c]):
        return "partial-run-unconfirmed"
    levels = {c.get("effort_provenance") for c in graded}
    applied = {c.get("effort_applied") for c in graded}
    if levels == {"cli-flag-accepted-not-server-confirmed"}:
        # The claude envelope carries no effort field, so `effort_applied` is
        # empty by construction here and cannot be checked against the request.
        return "cli-flag-accepted-not-server-confirmed"
    if applied != {record["effort_requested"]}:
        return f"downgraded-or-mixed: backend applied {sorted(str(x) for x in applied)}"
    if levels == {"session-header-confirmed"}:
        return "session-header-confirmed"
    return f"mixed: {sorted(str(x) for x in levels)}"


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


def mcnemar_exact(b: int, c: int) -> float:
    """Exact two-sided McNemar on discordant pair counts (binomial p=0.5).

    The PRIMARY test for arm comparisons here: raw and encoded run on the
    same tasks, so observations are paired, and Fisher's independent-table
    assumption overstates evidence (review on the density battery). With b
    discordant pairs favoring the first arm and c the second, the two-sided
    exact p is 2 * P(Binom(b+c, 1/2) <= min(b, c)), capped at 1.
    """
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


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
    ap.add_argument("--provider", default="claude", choices=["claude", "codex"],
                    help="reader CLI backend (codex: read-only sandbox, no usage envelope)")
    ap.add_argument("--tasks-dir", default=DEFAULT_TASKS_DIR,
                    help="fixture directory under evals/agent-g5/ (tasks | tasks-density)")
    ap.add_argument("--effort", default=None,
                    help="reasoning effort; codex: confirmed from the session "
                         "header, claude: CLI-accepted only (no envelope field)")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    if not QODEC.exists():
        print("build first: cargo build --release", file=sys.stderr)
        return 1
    tasks = discover_tasks(HERE / args.tasks_dir)
    if not tasks:
        print("no tasks — run gen_tasks.py first", file=sys.stderr)
        return 1
    selected = args.tasks.split(",") if args.tasks else list(tasks)
    run_dir = HERE / "runs" / args.name
    run_dir.mkdir(parents=True, exist_ok=True)

    try:
        reader_version = subprocess.run(
            [args.provider, "--version"], capture_output=True, text=True
        ).stdout.strip()
    except FileNotFoundError:
        reader_version = "not-installed"

    record: dict = {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "provider": args.provider,
        "reader_version": reader_version,
        "model_arg": args.model,
        "closed_world_argv": CLOSED_WORLD if args.provider == "claude" else CODEX_FLAGS,
        "qodec_sha256": sha256_file(QODEC),
        "git_commit": subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip(),
        "repeats": args.repeats,
        "effort_requested": args.effort,
        # Deliberately NOT filled in from `args`: the requested level is not
        # evidence that the backend applied it. The run-level value is
        # derived from the completed cells after the loop, so a partial or
        # failed run cannot inherit a confirmation it never earned.
        "effort_provenance": None,
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
                env = call_reader(
                    args.provider, prompt, args.model, args.timeout, args.effort
                )
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
                    reader_model=env.get("model"),
                    effort_requested=env.get("effort_requested"),
                    effort_applied=env.get("reasoning_effort"),
                    effort_provenance=env.get("effort_source"),
                    duration_s=env.get("duration_s"),
                    **answer_shape(questions, payload, answers_path),
                    correct=g.get("correct"),
                    total=g.get("total"),
                    prompt_tokens_o200k=g.get("prompt_tokens_o200k"),
                    envelope=envelope_tokens(env),
                    grade_output=g["output"],
                )
                record["cells"].append(cell)

    record["effort_provenance"] = derive_effort_provenance(record)
    (run_dir / "record.json").write_text(json.dumps(record, indent=2) + "\n")

    # Summary: per-task table + pooled per-arm totals + Fisher vs raw.
    ok = [c for c in record["cells"] if c.get("status") == "ok"]
    by_arm: dict[str, list[dict]] = {}
    for c in ok:
        by_arm.setdefault(c["arm"], []).append(c)
    lines = [
        f"# G5 work-task A/B — run `{args.name}`",
        "",
        f"date {record['date']} · {args.provider} {reader_version} · qodec `{record['git_commit'][:12]}` · "
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
    # Pooled cell counts are DESCRIPTIVE only: repeats of one task are not
    # independent observations (a deterministic failure repeats verbatim),
    # so running Fisher over cells pseudo-replicates and overstates
    # significance (Codex review on PR #11 — p=0.0219 over cells collapsed
    # to p≈0.217 over tasks). The inferential unit is the TASK: an arm gets
    # a task credit only when every valid repeat is correct (conservative),
    # and Fisher runs on those.
    pooled = {
        a: (sum(c["correct"] for c in cs), sum(c["total"] for c in cs))
        for a, cs in by_arm.items()
    }
    collapsed = {}
    per_task_pass = {}
    per_task_complete = {}
    for a, cs in by_arm.items():
        outcomes: dict[str, list[bool]] = {}
        for c in cs:
            outcomes.setdefault(c["task"], []).append(c["correct"] == c["total"])
        per_task_pass[a] = {t: all(oks) for t, oks in outcomes.items()}
        # A task is a valid McNemar member only when every requested repeat
        # produced a graded cell — a reader-error/grade-failed repeat leaves
        # the arm's outcome observed on weaker evidence than its pair (Codex
        # review on PR #12), so incomplete tasks are excluded from the
        # inferential test (they stay visible in the failed-cells line).
        per_task_complete[a] = {t: len(oks) == args.repeats for t, oks in outcomes.items()}
        # "All repeats correct" is only claimable on full evidence: a task
        # with an ungraded repeat can't earn the credit (CodeRabbit review
        # on PR #12) — it counts as observed but not passed here too, not
        # just in the McNemar gate above.
        collapsed[a] = (
            sum(
                1
                for t, oks in outcomes.items()
                if all(oks) and per_task_complete[a][t]
            ),
            len(outcomes),
        )
    for a in by_arm:
        hit, n = pooled[a]
        thit, tn = collapsed[a]
        extra = ""
        if a != "raw" and "raw" in collapsed:
            # Paired by task: the primary test is exact McNemar over
            # discordant task cells; Fisher on the collapsed table is kept
            # as a supplementary independent-table calculation only.
            union = set(per_task_pass["raw"]) | set(per_task_pass[a])
            shared = sorted(
                t
                for t in set(per_task_pass["raw"]) & set(per_task_pass[a])
                if per_task_complete["raw"].get(t) and per_task_complete[a].get(t)
            )
            dropped = len(union) - len(shared)
            b = sum(1 for t in shared if per_task_pass["raw"][t] and not per_task_pass[a][t])
            c = sum(1 for t in shared if not per_task_pass["raw"][t] and per_task_pass[a][t])
            rh, rn = collapsed["raw"]
            p_mc = mcnemar_exact(b, c)
            p_f = fisher_two_sided(rh, rn, thit, tn)
            note = f", {dropped} incomplete excluded" if dropped else ""
            extra = (
                f" · paired exact McNemar vs raw p={p_mc:.3g}"
                f" (b={b} c={c} over {len(shared)} complete pairs{note}; primary)"
                f" · Fisher p={p_f:.3g} (supplementary)"
            )
        lines.append(
            f"pooled {a}: {hit}/{n} (descriptive) · tasks all-repeats-correct: {thit}/{tn}{extra}"
        )
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
