# qodec project (v0) — generic relation-aware projection

`qodec project` reads one `qodec-project-request-v0` JSON and emits one
`qodec-project-result-v0` JSON. It gives Qodec a **projection** capability that is
distinct from its **representation** (encode/decode) capability, and it keeps that
capability generic: the protocol carries no domain meaning.

```
qodec project --request request.json --out result.json
```

No implicit file discovery, no environment-derived semantics, no network. Output is
published atomically (temp + rename); on any error nothing is written.

## Ownership boundary

The caller owns *meaning*; Qodec owns *closure*. Domain notions — staleness,
authority classes, "current"/"pending", topics — never enter Qodec. Each record
arrives with a bare `eligible: bool` (the caller's admission decision) plus opaque
`caller_evidence` (validated-present, never interpreted). Qodec **enforces** the
supplied decision and never redefines it. A source-scan test forbids any
caller-domain / observation / question / B1-namespace literal in `src/project.rs`.

## Recomputed, never trusted

Qodec recomputes from the request bytes: the request canonical digest (over a
normalized form with set-valued arrays sorted and the caller-supplied `input_digest`
excluded), every payload's canonical byte length, the exact `(from, kind)` target
sets, the selected count, and the semantic byte usage. Caller-supplied byte counts
and aggregate digests are ignored for authority.

## Algorithm v0 — closure, not optimization

1. Validate records, relations, requirements (`direction=outgoing`, `depth=1`, `match=all`).
2–4. Reject duplicate record ids, duplicate exact relation triples, unknown endpoints.
5–6. Recompute each requirement's exact target set and require equality with
`expected_targets` (rejects fabricated and missing targets).
7. Start from every `base_selected` record. 8. Add every `required_record_id` (must be eligible).
9. `edge_witness`: materialize the (eligible) source; emit the exact edges; keep an
ineligible target **relation-only**. 10. `all_current_targets_materialized`:
materialize the source and every expected target, failing closed if any is ineligible/absent.
11. Never add an edge absent from the request graph. 12. Never materialize an ineligible record.
13. Preserve payloads byte-exact. 14. Deterministic ordering (sorted selected /
relations / omitted / requirements). 15. Fail closed if the mandatory closure
overflows either budget.

v0 never evicts a baseline record; budget-aware replacement is a later feature with
its own contract.

## Reason codes (closed)

- selection: `base_selected`, `required_record`, `edge_witness_source`,
  `edge_witness_target`, `all_current_source`, `all_current_target`.
- omission: `not_selected`, `relation_only_target`, `ineligible`.

Prose `detail` may supplement a code but never replaces it.

## Determinism

Reordering `records` / `relations` / `relation_requirements` yields a **byte-identical**
result. `execution_commit` / `execution_tree` come from the invoker via
`QODEC_EXECUTION_COMMIT` / `QODEC_EXECUTION_TREE` (or `"unknown"`); the receipt binds
the exact Qodec commit/tree separately.

Schemas: `schemas/qodec-project-request-v0.schema.json`,
`schemas/qodec-project-result-v0.schema.json`. Qualification: `tests/project.rs`.
