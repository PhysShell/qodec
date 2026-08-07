# GCX1 wire-format evaluation

Status: deferred research proposal

## Context

The Gortex project publishes GCX1, a compact round-trippable wire format for MCP-style structured responses. Its upstream benchmark reports a median token reduction versus JSON, but that result is self-reported and is not the reason to adopt anything in Qodec.

The useful question for Qodec is narrower:

> Does the GCX1 design contain representation techniques worth adopting, adapting, or rejecting under Qodec's stricter requirements for round-trip fidelity, determinism, and independently reproducible measurement?

This proposal records the experiment only. It does not change Qodec's current implementation or roadmap priority.

## Scope

Compare GCX1 against JSON and any relevant Qodec/native compact representation using the same fixed fixture corpus.

Measure at least:

- exact encode → decode round-trip fidelity;
- canonicalization and deterministic re-encoding;
- byte size;
- token count across selected tokenizers;
- parse and serialize cost;
- behavior on malformed/truncated input;
- delimiter/escaping/pathological-string cases;
- nested, sparse, repeated, and high-cardinality structures;
- schema evolution and unknown-field behavior.

Token economy is conditional on correctness. A smaller representation that loses information, has unstable canonical form, or admits ambiguous parses is not a successful compression result.

## Required experimental shape

Use a versioned, frozen corpus rather than examples selected after seeing results. Record representation identity, tokenizer identity/version, fixture identity, byte count, token count, encode/decode result, and timing evidence.

Where practical, include adversarial fixtures that attack assumptions likely to make compact text formats look better than they are:

```text
empty values
embedded tabs/newlines/delimiters
unicode and normalization variants
large repeated keys
very long scalar values
heterogeneous arrays
unknown fields
field reordering
truncated records
malformed escapes
```

Round-trip should be checked structurally and, where the representation claims canonicalization, byte-for-byte after canonical re-encoding.

## Non-goals

- No decision to replace JSON in Qodec is implied.
- No dependency on Gortex itself is implied.
- Passing Gortex's code-graph admissibility evaluation is not a prerequisite.
- This proposal must not interrupt current higher-priority Qodec work.

## Relationship to 007

This experiment originated while evaluating Gortex for `PhysShell/007`, but it is intentionally separated from that work. The 007 track evaluates whether code-graph observations are admissible evidence. This Qodec track evaluates representation fidelity and economy. Combining them would make two clean experiments harder to interpret for no benefit.

## Activation condition

Begin this experiment only when explicitly scheduled in Qodec work. Until then this file is the durable bookmark for the idea and its measurement contract.
