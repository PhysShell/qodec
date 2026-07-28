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

This is intentionally the thin discovery/probe layer. Full Qodec A/B runs stay
in their existing eval harnesses and should consume only targets whose frozen
probe receipt is `PASS`.

## Tests

```bash
cd evals/provider-matrix
python3 -m unittest -v test_provider_matrix.py
```
