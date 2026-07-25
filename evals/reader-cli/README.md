# reader-cli — comprehension A/B through agent-CLI subscriptions

The model rung without a served endpoint: Claude Code (and later Codex)
subscriptions already put an authenticated model behind a CLI, and
[PhysShell/007](https://github.com/PhysShell/007) proved the closed-world
invocation discipline for exactly this shape of call. This stand drives
qodec's existing deterministic A/B ends (`qodec ab emit` → paired prompts,
`qodec ab grade` → dumb substring grading, no LLM judge) through `claude -p`
with 007's judge flag set: `--tools ""`, `--strict-mcp-config`,
`--setting-sources ""`, `--permission-mode default`,
`--no-session-persistence`, `--max-budget-usd`. No built-in tools, no
ambient MCP, no ambient CLAUDE.md — the reader sees exactly the emitted
prompt.

```bash
cargo build --release            # the runner shells the qodec binary
python3 evals/reader-cli/run.py --name panel-v1
python3 evals/reader-cli/run.py --name quick --cases stacktrace --codecs deep --repeats 1
```

Arms per case: `raw` (payload verbatim) and one encoded arm per codec
(`--codecs`, default `deep,paper` — the production miner vs the
arXiv:2604.13066 baseline). `ab emit` fails closed when a codec falls back
to raw, and the runner records the arm as `emit-refused` instead of running
a fake A/B.

Every run directory keeps: the emitted prompts, each repeat's raw answer
text and the **full CLI envelope** (exact model id, input/cache/output
tokens, cost), grade transcripts, and `record.json` with hashes of the
binary, payloads and questions. `summary.md` is the human view.

## Honest scope

* The CLI wraps every arm in Claude Code's own system prompt (visible as
  cache-creation tokens in the envelope). It is identical across arms, so
  paired deltas isolate the payload representation; absolute scores mean
  "reader inside Claude Code", not bare-model performance.
* `claude -p` exposes no temperature/seed; nondeterminism is handled by
  repeats and the paired design, with every envelope recorded verbatim.
* The committed corpus is our own — the closed world is discipline, not a
  claim that these payloads are hostile. For untrusted payloads the flag
  set is load-bearing (see 007's `docs/security-layers.md`).
* Scores here are comprehension evidence on small payloads, not the G5
  agentic gate; `evals/interop/` Level 2/3 remains the decision harness.
  This stand's edge is the *tokenizer*: the envelope reports Claude's real
  token counts, which no local meter can produce.
