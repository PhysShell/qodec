# Milestone — lossless program boundary at `e8815f0` (2026-07-25)

**Frozen record.** This document names the exact status of four work items
as of commit `e8815f0` on `claude/qodec-lossless-compression-h5m7uv`. It
exists so that careful evidence does not later get flattened into marketing
mush. Statuses are deliberately non-interchangeable; do not upgrade any of
them without the referenced missing evidence.

Session scope leading here (commits `8bf12fe`..`e8815f0`): `paper` codec
(faithful arXiv:2604.13066 baseline) + comparison ladder; tokenizer matrix
(8 open families); `reader-cli` stand (closed-world CLI readers per
PhysShell/007); panels v1–v5; `qodec risk`; full-request wire-format
accounting.

---

## A. Attribution of the count-loss — ACCEPTED / CLOSED

On the specific mixed battery (`ab/findings.json`, Sonnet 5 reader,
`corpus/findings.json` payload), pooled v1+v3+v4:

* raw: 0/14 failures; deep: 0/2; paper (split representation): **12/16**;
* Fisher exact, one-sided: **p ≈ 2.1×10⁻⁵**;
* all 12 wrong answers equal the number `qodec risk` precomputes without a
  model (artifact-visible count = 4);
* the deep representation showed no effect.

Accepted claim, exactly this strong and no stronger:

> **On this battery**, the baseline's split representation systematically
> causes a mechanistically predicted undercount; the deep representation
> does not.

The words "on this battery" are load-bearing. No global law of cognitive
physics has been discovered; humanity will survive.

## C. Risk hazard loop — ACCEPTED / CLOSED

Semantics settled by v2 and v5 against v1/v3/v4:

* `qodec risk` does **not** predict that a model will fail;
* it detects a **latent trap**;
* its number predicts the *specific wrong answer* when the trap fires;
* an explicit counting request can neutralize the effect entirely
  (v5: all arms passed the exact-occurrence probes, traps 9 and 1 unsprung).

This is stronger and more honest than `risk=true ⇒ fail`: the metric
describes a hazard, it does not impersonate an oracle. The automated cycle
— risk flags → generated probes (`gen_questions.py`) → model panel → trap
comparison — is closed end-to-end.

## B. Codex backend — IMPLEMENTED / ENVIRONMENT-BLOCKED

Code complete in `evals/reader-cli/run.py`: 007's exact argv (read-only
sandbox, ephemeral session, shell tool off, user config/rules excluded,
fresh cwd, prompt via stdin, `--output-last-message`), absence of a usage
envelope recorded honestly.

**Not** validated end-to-end: no live run has occurred, because this
container has no Codex CLI or subscription. Correct status, verbatim:

> Implementation complete; live execution pending external environment.

Do not conflate *Codex backend implemented* with *Codex backend
empirically validated*. The second requires one panel run on a machine
with `codex` logged in.

## D. Full-request G2 — ACCEPTED at the wire/tokenizer level

`evals/tokenizer-matrix/full_request.py`, 2026-07-25 run:

* 7/7 chat templates rendered; templates pinned by SHA-256;
* task line, notation brief and dictionary all inside the real wire form;
* counting via Python `tokenizers`, parity-proven against the crate's
  fail-closed `hf:` meter.

Numbers (corpus totals per family):

* warm squeeze: **+29.8% … +35.6%** across all families;
* cold squeeze: **−6% … −18.5%** — the per-message brief eats the gain on
  payloads this small;
* paper warm: only **+4.0% … +5.4%**.

Product-level conclusion, fog-free:

> Qodec pays off when the brief/cache prefix is reused; on a cold small
> one-shot request the overhead can make things worse. The paper baseline
> saves too little to amortize its own framing.

Do not conflate *full-request token savings proven* with *live-agent
utility proven*. The second is item 1 below.

---

## Milestone freeze

> Static attribution, automated hazard validation, Codex backend wiring,
> and full-request wire-format/tokenizer evaluation are
> **ACCEPTED / CLOSED at `e8815f0`** (Codex backend: implemented,
> environment-blocked).

## What remains open — the only two items worth doing next

1. **G5 / live agent (Stage F).** Behavior in a real agentic loop —
   task success, tool trajectories, total session cost — not just
   wire-format size. Blocked on a containerized agent-eval environment;
   `evals/interop/` Level 3 is the designated harness.
2. **Second reader for the Codex panels.** An independent backend/model
   line so the attribution in A does not remain proven inside a single
   model family. Blocked on a machine with the Codex CLI and subscription;
   the runner is ready (item B).

Not on the list, on purpose: further internal refactors, another
generational JSON migration, or any restatement of the numbers above with
adjectives attached.
