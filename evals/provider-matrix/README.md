# Provider matrix: ModelHubby discovery intake

This vertical uses ModelHubby only as an **untrusted discovery source**. It does
not make ModelHubby a runtime dependency, does not use `model: auto`, and does
not silently fall back between providers. Qodec freezes a reviewed catalog
snapshot, plans explicit `provider × model` targets, then records one probe
receipt per target.

## Trust boundary

```text
ModelHubby/exported notes (untrusted, mutable)
        ↓ import
canonical catalog snapshot + raw SHA-256
        ↓ plan
fail-closed policy filters + explicit target IDs
        ↓ probe
one endpoint, one requested model, no fallback
        ↓
PASS / AUTH_FAILURE / RATE_LIMITED / MODEL_NOT_FOUND /
PROVIDER_5XX / TIMEOUT / TRANSPORT_FAILURE / INVALID_OUTPUT /
PROVIDER_SUBSTITUTED
```

`unknown` never satisfies `--free-only`, `--no-card`, or `--no-training`.
Provider-reported usage is retained as provider evidence, not normalized into a
cross-provider token truth.

## Import and freeze

Export or transcribe the useful ModelHubby rows into JSON using
`example-modelhubby-export.json` as the input contract. The observed timestamp
is supplied explicitly so repeating the command is byte-deterministic.

```bash
python3 evals/provider-matrix/provider_matrix.py import \
  --source /tmp/modelhubby-export.json \
  --observed-at 2026-07-28T00:00:00Z \
  --out /tmp/catalog.json

python3 evals/provider-matrix/provider_matrix.py plan \
  --catalog /tmp/catalog.json \
  --free-only --no-card --no-training \
  --out /tmp/plan.json
```

Review and commit the resulting catalog/plan when a benchmark scope is frozen.
Never fetch a live catalog during an acceptance run: discovery may change, the
benchmark identity may not.

## Probe selected targets

Set only the key variables named by selected targets, then:

```bash
python3 evals/provider-matrix/provider_matrix.py probe \
  --plan /tmp/plan.json \
  --out-dir /tmp/probes
```

The canary asks for exactly `QODEC_PROBE_OK` with temperature zero and records
the request/response hashes, endpoint, latency, requested model, reported
model, classification, and provider usage when present. A different reported
model is `PROVIDER_SUBSTITUTED`, never a pass.

## Qualification: does the target speak the C1 protocol?

An availability probe sends no tools. A target can pass it and still be unable
to run C1's forced-query arm at all, so `PASS` there means "alive and not
substituted", not "usable". The arm needs four tool declarations accepted,
forcing honoured, a multi-turn loop with results returned under their call ids,
and a terminal answer whose arguments parse. Nothing in a bare completion
predicts any of that.

`qualify` runs the structural contract of the arm — the same four tools, the
same schemas, the same forcing, the same loop — against one `provider × model`
target:

```bash
cargo run --example emit_panel_surface > evals/provider-matrix/c1-panel-surface.json

python3 evals/provider-matrix/provider_matrix.py qualify \
  --plan /tmp/plan.json \
  --surface evals/provider-matrix/c1-panel-surface.json \
  --out-dir /tmp/qualification
```

The schemas are **not restated here**. They come from `c1-panel-surface.json`,
generated from `panel::tool_schemas()` and `panel::answer_schema()` — the one
place that defines them. Qualifying a provider against a paraphrase of the C1
surface qualifies a request the adapter will never send. `check_surface.py`
regenerates and diffs, so the artifact cannot drift from the crate in silence.

The operation results are canned. The canary qualifies the wire protocol, not
qodec: a real store would add a second thing that can fail while telling us
nothing more about whether the provider speaks this dialect.

### Causes are kept apart

```
UNAVAILABLE  AUTH_FAILED  RATE_LIMITED  PROVIDER_REJECTED  MODEL_MISSING
PROVIDER_SUBSTITUTED  TOOL_CHOICE_UNSUPPORTED  TOOL_RESULT_REJECTED
MALFORMED_TOOL_ARGUMENTS  PROTOCOL_VIOLATION  NO_TERMINAL_ANSWER  PASS
```

`TOOL_CHOICE_UNSUPPORTED` earns its own name because a 400 from an incompatible
dialect and a model that does not exist are the same status code and completely
different problems — one is a request we can fix, the other a target to drop.
The turn matters too: a rejection of the first request is about the tools or the
forcing, while a rejection of the first request that carries `role: tool`
messages is about the result shape.

`PROVIDER_SUBSTITUTED` outranks a protocol pass. A run that satisfied every
structural rule against a model nobody asked for has established the protocol
and nothing about the target.

### A target is a provider × model pair

`groq × gpt-oss-120b → PASS` and `groq × gpt-oss-20b → PROTOCOL_VIOLATION` are
both ordinary outcomes and neither is a verdict on Groq. Receipts are written
per `target_id` for that reason.

This is intentionally the thin discovery/probe layer. Full Qodec A/B runs stay
in their existing eval harnesses and should consume only targets whose frozen
receipts are `PASS` for **both** probes.

## Tests

```bash
cd evals/provider-matrix
python3 -m unittest -v test_provider_matrix.py

# the frozen surface still matches the crate that defines it
python3 evals/provider-matrix/check_surface.py
```

Every classification above is reachable from the stand-in tests, without a
network. A qualification whose failure paths can only be exercised against a
real provider is a qualification whose failure paths are never exercised.
