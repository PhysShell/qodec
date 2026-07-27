# Effort × comprehension — pre-registration

Committed **before** any elevated-effort cell was collected. The point of
writing it first is that a null result stays a null result: if elevated
effort does not rescue squeeze, this file already says so counts as the
answer, and nothing here licenses a later "complex non-linear tendency".

## The question

PR #13 established that the join hazard transfers between join families
**by direction** but not by rate or onset. That closed "does it
generalise?" and opened the one whose answer changes policy:

> Can the squeeze-specific join failures be removed, or materially
> reduced, by raising reasoning effort — and does any such rescue carry
> across reader families?

The branches all have consequences: a durable rescue makes escalation a
viable strategy; no rescue strengthens the case for a RAW path on
join/aggregation workloads; a reader-family-dependent rescue means
`qodec risk` must stay advisory and become consumer-aware; and a lookup
control that is flat under every condition keeps the hazard pinned to
cross-entry composition rather than to artifact legibility at large.

## Corpus — frozen, not regenerated

The three fixture sets already accepted in PR #12/#13, byte-identical, no
new families and no semantic edits:

| arm | fixtures | shape |
|---|---|---|
| cross-ref | `tasks-density/` | join two marker sets over paths |
| decision-join | `tasks-density-decision-join/` | intersect three retry blocks |
| decision | `tasks-density-decision/` | lookup control (answerable from one block) |

15 tasks each, five measured legend doses (6–7 / 15 / 22–23 / 31–34 /
42–45 entries).

## Matrix

`representation ∈ {RAW, squeeze}` × `reader ∈ {codex, sonnet}` ×
`effort ∈ {baseline, elevated}`, 2 repeats.

**The codex baseline arm already exists and is reused rather than
re-collected.** All 180 envelopes of `density-codex-v1`,
`density-decision-join-codex-v2` and `density-decision-codex-v1` record
`reasoning effort: none` and `model: gpt-5.6-sol`, confirmed from the
session header, over exactly these fixtures and the same closed-world
flags. Re-running them would burn budget to reproduce frozen evidence.
The honest cost of the reuse: the baseline was collected earlier in
wall-clock time, so a silent server-side model revision between arms
cannot be excluded — the model string is identical, which is the
strongest available check and not a proof.

## Effort provenance — measured, and asymmetric between backends

Recorded per cell, and the asymmetry is a finding in itself rather than
a detail:

* **codex** echoes `reasoning effort:` in the session header, so the
  request is *verified*. A mismatch fails the cell closed
  (`effort_source: session-header-confirmed`).
* **claude** has `--effort {low,medium,high,xhigh,max}` — the previously
  recorded note that `claude -p` has no effort knob is out of date as of
  CLI 2.1.220 — but its JSON envelope carries **no effort field at all**.
  An unknown value prints `Unknown --effort value … using the default
  effort` and proceeds, which is precisely the silent downgrade that must
  never be recorded as the requested level; the runner fails closed on
  that warning. What survives is `effort_source:
  cli-flag-accepted-not-server-confirmed`, which is weaker evidence than
  the codex arm's and must not be quoted as if it were equal.

Manipulation check on the claude side, since a knob that does nothing
would make a null result meaningless: on `decj-d32-3` squeeze, `low` →
`high` moved sonnet output tokens 5 559 → 27 176, API time 48 s → 254 s,
cost $0.095 → $0.419. The knob is live.

## A grading-validity threat, found before the run

`qodec ab grade` matches by substring, so an answer that *contains* the
accepted string scores 1/1 regardless of what else it contains. Measured:

```
{"t1": "cli::reader_17"}                                             -> score: 1/1
{"t1": "Both cli::reader_17 and dns::reader_25 failed on all 3 …"}   -> score: 1/1
```

The second answer is wrong — only `cli::reader_17` fails all three
attempts — and it is exactly the shape elevated effort produced in the
probe above. Left alone, hedged answers would inflate the rescue count in
the direction the hypothesis predicts.

The grader is **not** changed, so prior runs stay comparable. Instead the
runner records an answer-shape audit per cell (`candidates_named`,
`hedged`): how many distinct payload tokens of the answer's own shape the
reply names. Every rescue count is reported twice — as-graded, and strict
(correct **and** naming exactly one candidate). If the two disagree, that
disagreement is the finding, not a footnote.

## Unit of analysis

Unchanged from PR #12/#13, and repeats remain technical replications:

* pooled cells are descriptive only;
* a task counts only when every requested repeat produced a graded cell;
* an incomplete task is excluded from paired tests and the exclusion is
  printed;
* McNemar is computed *within* one pair of conditions;
* pooling across families is permitted only with the standing caveat that
  it tests a shared directional effect, not a prevalence.

The headline statistic is a **rescue table**, paired on squeeze, per
family and per reader:

| | elevated correct | elevated wrong |
|---|---|---|
| **baseline correct** | held | broken |
| **baseline wrong** | **rescued** | still wrong |

with the identical table computed for RAW as a control — elevated effort
must not look like a saviour merely because the model got better at the
task in general.

## Hypotheses, fixed in advance

1. **H1** — squeeze-specific join failures occur more at baseline effort.
2. **H2** — elevated effort reduces the number of such failures.
3. **H3** — the lookup control is close to independent of representation.
4. **H4** — the effect may differ between reader families.

## Completion criteria

The scope is closed when there is: a matrix with no provenance gaps; RAW
and squeeze reported separately; families reported separately; effort
levels reported separately; paired rescue counts (as-graded and strict);
a recomposition-slip taxonomy; latency and usage overhead; explicit
handling of timeouts and grade failures; frozen run artifacts; a README
stating claims **and** non-claims; and no change to the production encode
path.
