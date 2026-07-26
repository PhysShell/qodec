# G5 — work-task utility of the compressed artifact

The program's central unclosed gate, at the level the milestone left it:
token savings are proven at the wire/tokenizer level (stage B, full-request
G2), reader *recall* is measured (reader-cli panels v1-v5, `qodec risk`
hazards) — but nobody had shown that a reader can do an agent's *work* from
the squeeze artifact instead of raw. This stand measures exactly that gap.

## Design

Four task families (`gen_tasks.py`, deterministic, ground truth known by
construction — no LLM judge anywhere), three instances each:

| family | payload | the work | answer |
|---|---|---|---|
| root-cause | failed build log: one primary error among ~150 repeated warnings and 8-12 cascade errors marked "consequence of the previous error" | separate cause from consequence | `path:line` |
| cross-ref | matcher output over 40 files, each carrying one marker kind except one carrying both | join two match sets | file path |
| state | unified diff over 5 files, tuning-noise hunks, a stale-value distractor in a comment | apply the diff mentally, report the post-state | constant value |
| decision | 3-attempt retry harness over ~30 tests, half flaky on attempt 1 | aggregate across attempts: flaky vs genuinely failing | test name |

Families 1-2 lean on the codecs' strengths (fold/tmpl noise). Families 3-4
sit deliberately in `qodec risk`'s flagged territory — aggregation over
repeated structure is where counting panels showed encoded readers failing.
Payload sizes are tuned so the notation brief amortizes: wire savings
(o200k, cold) run 60.5% / 58.2% / 13.0% / 5.4% per family instance 1.

Answers are multi-character distinctive strings (paths, `path:line`,
values like `262144`, zero-padded test names) so `qodec ab grade`'s
substring matching cannot false-positive.

## Runner

`run.py` — the reader-cli runner adapted to task fixtures: `qodec ab emit`
builds paired prompts, the closed-world `claude -p` configuration from
PhysShell/007 answers them (no tools, no MCP, no ambient settings,
`--max-budget-usd 0.50`), `qodec ab grade` scores, envelopes are recorded
verbatim, and the pooled raw-vs-codec comparison gets a two-sided Fisher
exact test before any difference is claimed.

```bash
cargo build --release
python3 evals/agent-g5/gen_tasks.py
python3 evals/agent-g5/run.py --name g5-v1 --repeats 2
```

## Honest scope

* Closed-world readers over emitted prompts measure the artifact **as
  context** — qodec's actual use. This is NOT a tool-loop agent harness;
  interop L3 stays open regardless of this panel's outcome.
* The CLI wraps readers in Claude Code's system prompt — identical across
  arms, so paired deltas isolate the payload representation; absolute
  scores are "reader inside Claude Code", not bare-model numbers.
* No temperature/seed control in `claude -p`; repeats + paired design +
  verbatim envelopes.
* The codex backend from reader-cli remains implemented but
  environment-blocked here (no `codex` binary in this container) — a second
  reader family is still the recorded next step, not a claim.

Runs live under `runs/<name>/` with `record.json` (hashes, envelopes,
per-cell grades) and `summary.md`.

**Completion criterion**: the runner writes `record.json` and `summary.md`
only after the last cell finishes — a run directory without `record.json`
is an in-progress or aborted run and must not be read as evidence (cell
files land incrementally and can be swept into interim commits).

## Result — `g5-sonnet-v1` (2026-07-26, claude 2.1.220, repeats 2)

| pooled | score | note |
|---|---|---|
| raw | 24/24 | |
| squeeze | 21/23 | Fisher vs raw p=0.234 — no significant difference |

One squeeze cell (cross-ref-2 rep 1) timed out at 300 s and is recorded as
a failed cell, not a wrong answer; its repeat passed. Cold wire savings
across the 12 tasks: 22 481 → 12 500 prompt tokens (**−44.4%**).

The two squeeze misses (each recovered on the repeat) are the finding:

* `decision-3`: answered `codecpool_28` for `codec::pool_28` — the
  aggregation was **correct** (right test out of ~30 across 3 attempts);
  the `::` separator was lost reconstructing the aliased name.
* `state-3`: answered `819200` for `8192000` — right hunk, right constant,
  a digit dropped reproducing the value.

Both are surface-reconstruction slips at alias/legend boundaries — the
`boundary-recomposed` class `qodec risk` flags — not task-logic failures.
Read precisely: on this battery, work-task utility survives compression
(p=0.234, n small — "no significant difference", not "proven equal"), and
the residual error mode is the one the risk metric already names, which
means mitigation is representational (safer aliasing of `::`-joined
identifiers and long numerals), not "compress less".

What this does NOT show: tool-loop agent behavior (L3), other reader
families (codex backend still environment-blocked), non-synthetic payloads.
Those remain the recorded next steps.

## Mitigation (landed after this run)

`risk::splits_token` + the miners now keep alias edges and template/slot
cuts on whole-token boundaries: no cut inside a `[A-Za-z0-9_]` run, no cut
against `::` glue (`mine::boundary_safe`, `tmpl::snap_affixes`). Scoped to
the evidence: a single `:` stays a legal cut — the counting panels measured
readers holding on `"key":`/`path:`-shaped aliases, and a draft rule that
refused those cuts fragmented previously uniform representations into the
worse `split` risk class (caught by `deep_same_predicate_is_not_split` and
the cost-model label canary during development). Cost on this battery:
wire savings 44.4% → 43.8%. Pinned by `tests/boundary.rs`; whether the
slips actually disappear needs a fresh panel, not a claim.

### Validation — `g5-sonnet-v2-mitigated` (decision + state, the two
### families that slipped)

* **Valid calls**: 24/24 (12 raw, 12 squeeze; no timeouts, no reader
  errors).
* **Prior slip types**: 0 of either. The two previously-failing cells are
  now exact on both repeats — decision-3 answers `codec::pool_28` with the
  `::` intact, state-3 answers `8192000` with all digits.
* **New error classes**: none — all 24 answers are exact matches.
* **Per family**: decision raw 6/6, squeeze 6/6; state raw 6/6,
  squeeze 6/6.
* **Against `g5-sonnet-v1`**: same families were squeeze 10/12 with the
  two recomposition slips; now 12/12.
* **Cost surfaced by the fix**: keeping identifiers whole makes the
  decision payloads nearly incompressible — encoded prompts now cost
  slightly *more* than raw there (1010/1034/969 vs 1000/1006/922 tokens;
  the notation brief no longer amortizes at this payload size). State
  keeps its ~13% saving. Payload-level arbitration still guarantees the
  artifact never exceeds raw; the brief is a per-prompt overhead that
  amortizes with payload size and prefix caching.

**Evidence, not proof**: the original slips were stochastic (each hit 1
of 2 repeats), so 12 clean squeeze calls bound the residual rate — they
do not prove impossibility. Whether a larger repeat is worth the
subscription budget is a separate decision now that the mitigation slice
is closed.

## Second reader — `g5-codex-v1` (codex-cli 0.145.0, ChatGPT login)

The full battery under the codex reader, same closed-world discipline
(read-only sandbox, ephemeral, no configs; no usage envelope — recorded
as such). 48/48 valid calls:

| pooled cells (descriptive) | tasks all-repeats-correct | note |
|---|---|---|
| raw 24/24 | 12/12 | |
| squeeze 18/24 | 9/12 | task-level Fisher vs raw p≈0.217, exact McNemar p=0.25 — **not significant at n=12** |

Corrected after Codex review on PR #11: an earlier wording claimed
significance from Fisher over the 24 cells (p=0.0219), but repeats of
one task are not independent observations — the failures repeat
verbatim — so that number was pseudo-replication. The runner now
reports the task-collapsed test as the inferential line. What the data
*does* support: three tasks fail **deterministically** (both repeats,
same wrong answer), none are recomposition slips — the mitigation class
stays absent cross-family — and the failures are
reasoning-over-representation:

* `cross-ref-2`/`cross-ref-3`: a confidently wrong file path — the join
  over two match sets fails when it must run through a large alias
  legend. The passed `cross-ref-1` has **9** legend entries; the failed
  ones have **45** and **43**.
* `decision-2`: answers "None" — the across-attempts aggregation
  collapses on the aliased retry log.

Cross-family picture, stated with exact scores and scopes (corrected —
an earlier wording quoted Sonnet's raw arm as if it were encoded):

* Sonnet on **squeeze**: 21/23 cells in `g5-sonnet-v1` (both misses
  stochastic recomposition slips, since mitigated), including 5/5 on the
  cross-ref family — but those were *pre-mitigation* artifacts; codex
  ran the current post-mitigation generation, so the cross-ref
  comparison is same-tasks, not byte-same artifacts. On decision+state
  the comparison is same-generation: Sonnet `g5-sonnet-v2-mitigated`
  squeeze 12/12 vs codex failing decision-2 deterministically.
* Codex on *counting* (`panel-codex-v1`): **better encoded than raw** —
  16/16 on deep/paper/squeeze including the paper trap that broke
  Sonnet at p≈2e-5, vs a consistent 5/6 on raw.

Comprehension of compressed context looks strongly model-family- and
task-dependent: legend-driven counting suits codex; high-alias-density
join/aggregation defeats it deterministically. `qodec risk`'s
hazard-not-oracle framing now has live evidence on both sides, and
alias *density* is a measurable hazard axis the metric does not yet
score — a concrete next item and the right axis for a bigger battery
that could actually power a significance claim.

## Alias-density dose-response — `density-codex-v1`

The bigger battery the codex results called for: the same cross-file join
task (`gen_density.py`, ground truth by construction) at five controlled
doses, three instances each, measured squeeze legend sizes as the dose
variable. Codex reader, raw + squeeze, 2 repeats — 60/60 valid calls:

| dose | legend entries (measured) | raw cells | squeeze cells |
|---|---|---|---|
| d06 | 6–7 | 6/6 | **6/6** |
| d12 | 15 | 6/6 | 3/6 |
| d20 | 22–23 | 6/6 | 5/6 |
| d30 | 31–34 | 6/6 | 5/6 |
| d40 | 42–45 | 6/6 | 3/6 |

**Primary analysis (paired)**: across 15 paired task-dose cells, raw
passed 15/15 and squeeze 9/15; all six discordant cells favored raw.
Exact two-sided McNemar **p=0.03125**. (Fisher on the collapsed table
gives 0.0169, kept as a supplementary independent-table calculation
only — raw and squeeze ran on the same tasks, so the observations are
paired and McNemar is the normative test. The run's `summary.md` line
predates this correction; `record.json` is the data, and the runner now
prints McNemar as primary.)

**Unit of independence, stated exactly**: the 15 cells are 15 freshly
sampled instances (each with its own seed, path sample and answer) at
five dose levels — independent in content, but all drawn from ONE
semantic task family (cross-file join) and one generator. Inference is
at the task-dose-cell level for THIS task shape; the paired analysis is
significant, but broader cross-task-family replication remains open.

**Threshold, stated exactly**: clean at 6–7 entries, failures already
present at the first next tested dose (15), no further monotone
worsening to 45. The observed onset therefore lies in the interval
**(7, 15]** — 15 is the first *tested* legend load at which failures
appeared, not a precisely estimated causal breakpoint. The shape is
compatible with a step/plateau, but six calls per dose cannot establish
that form conclusively. The prior 9-pass/43-fail anchors were
consistent with this and put the onset far too high.

Raw stays perfect at every dose while costing 2.6× the tokens at d40
(3176 vs 1222) — the failure is representational, not task difficulty.
Encoded in `qodec risk` as the info-level `legend-load` line:
`LEGEND_LOAD_STEP = 15` is an operational, conservative anchor at the
first tested onset (hazard-not-oracle: lookups and counting survived at
every dose; the hazard is specifically cross-entry join/aggregation,
and it is family-dependent — Sonnet held 5/5 on this task shape).

### Uncontrolled axis: reasoning effort

Recorded, not yet varied. What the panels actually ran with:

* claude reader: `claude-sonnet-5` via `claude -p`, **no thinking
  requested** — the closed-world flag set carries no effort knob and the
  envelope records no thinking configuration.
* codex reader: `gpt-5.6-sol` with **`reasoning effort: none`** (the
  `codex exec` default under `--ignore-user-config`; the session header
  states it — captured 2026-07-26).

So every comprehension number above — Sonnet's paper-trap failures AND
codex's 16/16 encoded counting AND codex's deterministic
high-alias-density join failures — was produced at the readers' floor
effort. Mentally dealiasing a 45-entry legend is multi-step work, so the
hypothesis that effort level interacts with codec comprehension (e.g.
`-c model_reasoning_effort=high` recovering the cross-ref joins) is
plausible in both directions and cheap to test: codex exposes the knob
per call; `claude -p` has no equivalent flag, so the claude side of such
a matrix needs a different mechanism and should be scoped honestly. An
open measurement, deliberately not run yet.
