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
