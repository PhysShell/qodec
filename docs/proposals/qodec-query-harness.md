# Qodec Query Harness: proposal for model-safe use of compressed context

> **Status:** proposal, not an accepted architecture.
>
> **Scope:** how to make Qodec artifacts reliably usable by coding agents and LLM readers when the task requires lookup, join, intersection, or aggregation across compressed entries.
>
> **Non-goal:** changing Qodec's byte-lossless contract or silently replacing model-facing evidence with an opaque answer oracle.

## 1. Problem statement

Qodec already proves a strong machine property:

```text
D(E(P)) = P
```

The encoder is lossless and the original bytes can be recovered exactly. That does **not** imply that a language model can reliably reason directly over every encoded representation.

The live reader evaluations established a narrower but important failure mode:

- RAW remained correct on the tested join tasks;
- squeeze sometimes failed on cross-entry joins even when lookup and counting remained usable;
- the direction of the hazard replicated across two independently generated join families;
- failure frequency and onset did not transfer cleanly between families;
- `LEGEND_LOAD_STEP = 15` is therefore a conservative warning anchor, not a universal breakpoint;
- increased reasoning effort produced both rescues and regressions, so effort escalation is not a reliable correction by itself;
- permissive grading can mistake a hedged multi-candidate answer for a rescue.

The most revealing failure was reader-side recomposition: the model returned a plausible identifier assembled from pieces associated with other entries. Encoder-side token-boundary protections cannot prevent a model from carrying out the same unsafe recomposition internally.

The engineering question is therefore not:

> How do we persuade the model to decode our compact language more carefully?

It is:

> Which operations should the model decide, and which operations should a deterministic harness execute?

## 2. Architectural thesis

Qodec should support three distinct consumption modes.

### 2.1 Direct reader mode

The model receives the encoded artifact and reasons over it directly.

Suitable for:

- local lookup;
- counting with an explicit request;
- inspection of a small legend;
- tasks whose evidence remains within one entry or one compact block.

This mode preserves maximum simplicity, but it must remain guarded by measured risk rather than assumed readability.

### 2.2 Reader-safe representation

The model still receives compressed text, but the codec preserves semantic entities as indivisible units.

Examples of indivisible units:

- full identifiers;
- full paths or path components;
- complete numbers and timestamps;
- error codes;
- canonical entity keys used by joins.

Unsafe decompositions include splitting a key into reusable stems, prefixes, separators, and numeric suffixes when the downstream task must reconstruct the complete key.

This mode trades some compression ratio for a smaller space of plausible but false recombinations.

### 2.3 Queryable representation

The compressed artifact is treated as a deterministic data store. The model chooses an operation; Qodec executes it and returns a small exact result with provenance.

This is the preferred mode for:

- joins;
- set intersections;
- aggregation across entries;
- cross-file correlation;
- any task flagged as requiring semantic recomposition.

The model remains responsible for understanding the user's request and selecting the operation. The harness is responsible for deterministic data manipulation.

## 3. Proposed tool interface

A minimal tool surface should stay small and typed.

```text
qodec_open(artifact_id)
  -> schema, sections, counts, risk flags, supported operations

qodec_lookup(artifact_id, query)
  -> exact matching records

qodec_intersect(artifact_id, sets, key)
  -> exact set intersection

qodec_join(artifact_id, left_filter, right_filter, key)
  -> exact joined rows

qodec_aggregate(artifact_id, filter, group_by, measures)
  -> exact aggregates

qodec_materialize(artifact_id, record_ids)
  -> selected RAW fragments

qodec_verify(artifact_id, proposed_answer, evidence_ids, operation)
  -> valid, invalid, ambiguous, or unverifiable
```

The initial implementation does not need all operations. A defensible first slice is:

1. `open`;
2. `lookup`;
3. `intersect`;
4. `materialize`;
5. `verify`.

That set directly covers the currently observed join failures without pretending to be a general database engine because apparently one distributed system per repository is not enough for humanity.

## 4. Tool result contract

Tool results should be structured and bounded.

Example:

```json
{
  "artifact_id": "sha256:...",
  "operation": "intersection",
  "key": "test_id",
  "matches": ["cli::reader_17"],
  "candidate_count": 1,
  "evidence_record_ids": ["r17", "r48", "r91"],
  "complete": true
}
```

Required properties:

- stable artifact identity;
- explicit operation;
- canonical entity identity;
- exact candidate count;
- evidence record IDs;
- completeness bit;
- machine-readable error categories;
- bounded preview with full material persisted outside the prompt when necessary.

An oversized result should return a preview and a retrievable handle, not dump the entire store back into the context window and thereby recreate the original problem with more ceremony.

## 5. Proof-carrying answers

For risky operations, the final model answer should be checked against evidence.

Suggested answer schema:

```json
{
  "answer": "cli::reader_17",
  "operation": "intersection",
  "evidence_record_ids": ["r17", "r48", "r91"],
  "candidate_count": 1
}
```

The harness verifies:

- the answer exists in the artifact;
- every evidence ID exists;
- the declared operation over those records yields the answer;
- the candidate count is correct;
- the answer contains exactly one canonical candidate.

This also closes the grading hole exposed by effort experiments. The primary categories should be:

```text
exact-correct
exact-wrong
hedged-includes-truth
hedged-without-truth
unparseable
backend-failed
```

Only `exact-correct` counts as correct in the normative gate.

## 6. Harness policy

`qodec risk` should remain a hazard detector, not impersonate an oracle. Its output can nevertheless guide the harness.

Proposed policy:

```text
join_hazard = false
  -> direct encoded reading allowed

join_hazard = true and query tool available
  -> deterministic query path required

join_hazard = true and query tool unavailable
  -> materialize the relevant RAW subset

verification ambiguous or incomplete
  -> RAW fallback
```

No production encoder branch should be changed in the first implementation. The policy should begin in diagnostic or shadow mode and record:

- whether the model attempted a direct answer;
- whether the required tool was called;
- operation and arguments;
- verification result;
- fallback reason;
- visible-token cost;
- latency;
- final exact correctness.

## 7. Reader skill and prompt contract

A small `qodec-reader` skill can teach the agent when and how to use the query interface without loading a large manual on every turn.

Catalog description:

```text
qodec-reader: use for qodec envelopes; load before reasoning over encoded artifacts.
```

Core instructions:

1. Inspect artifact metadata and risk flags first.
2. Never construct a canonical entity from parts belonging to multiple legend entries.
3. Direct reading is permitted for local lookup and explicit counting when the risk contract allows it.
4. Join, intersection, and cross-entry aggregation must use the Qodec query tool.
5. Return exactly one canonical answer unless the tool reports ambiguity.
6. Verify evidence before the final response.

The stable codec contract belongs in a cacheable prompt prefix. Artifact identity, current risk flags, and available operations belong in a dynamic tail or context message.

## 8. Representation experiments worth running

The query interface is the highest-leverage direction, but several representation changes deserve controlled ablations.

### 8.1 Entity-preserving aliases

Compare the current squeeze format with a mode that never splits canonical join keys.

```text
unsafe:
  A = cli
  B = ::reader_
  C = 17

reader-safe:
  TEST_17 = cli::reader_17
```

### 8.2 Typed aliases

Compare opaque aliases with type-bearing aliases:

```text
¿7;

<P17>
<TEST_18>
<NUM_4>
```

Types may reduce cross-category confusion and make output validation easier. They may also cost more tokens. Measurement decides, not aesthetic attachment to punctuation.

### 8.3 Local legends

Partition the dictionary by block and place each micro-legend adjacent to the block it decodes.

Expected trade-off:

- worse global compression;
- better spatial locality;
- lower legend navigation load;
- no guarantee for cross-block joins, which should still use the deterministic query path.

### 8.4 Prompt-only decoder contract

A cheap ablation may test:

- codec contract in the system prompt;
- one worked cross-entry join example;
- one explicit counterexample showing unsafe recomposition;
- mandatory candidate extraction before final answer;
- exact-one output schema.

This remains a mitigation experiment, not an architectural guarantee.

## 9. Proposed evaluation

Run the next experiment on the already frozen fixtures. Do not generate a new task universe while changing the interface.

Arms:

```text
RAW
current squeeze direct
squeeze + decoder system contract
squeeze + forced qodec query tool
reader-safe squeeze direct
```

Task families:

- cross-ref join;
- decision-join;
- lookup control.

Use the same reader identity and reasoning effort within each paired comparison.

Primary metrics:

- exact task correctness;
- rescued and broken transitions;
- reader-side recomposition failures;
- hedging rate;
- tool-call compliance;
- verification success;
- RAW fallback rate.

Secondary metrics:

- model-visible input tokens;
- output tokens where available;
- latency;
- number of materialized RAW records;
- query execution overhead;
- cost where the backend exposes a trustworthy usage envelope.

Primary gate:

```text
forced qodec query reaches RAW-like correctness
while exposing materially fewer tokens to the model
```

The exact threshold for "RAW-like" and "materially fewer" must be preregistered before live calls.

## 10. Acceptance slices

### Slice A: offline query engine

- frozen artifact format;
- deterministic `open`, `lookup`, `intersect`, `materialize`, and `verify`;
- exact replay;
- malformed input rejected fail-closed;
- bounded results;
- complete provenance.

### Slice B: agent tool integration

- typed tool schemas;
- forced tool path for join-hazard fixtures;
- full call envelopes;
- exact-one answer grader;
- no hidden manual decoding in the harness.

### Slice C: live paired panel

- frozen reader identity and effort;
- complete cells only;
- paired analysis by task;
- hedging reported separately;
- RAW control;
- no product routing change from one panel.

### Slice D: shadow routing

- risk-driven recommendation only;
- direct, query, and RAW fallback decisions recorded;
- realized correctness and cost compared against the recommendation;
- no automatic production block until the shadow record is accepted.

## 11. Non-goals

This proposal does not claim:

- that encoded artifacts are generally unreadable;
- that every join over compressed text fails;
- that legend load alone predicts failure;
- that reasoning effort reliably repairs failures;
- that one reader family's behavior transfers to another;
- that query tools eliminate all model error;
- that Qodec should become a general SQL engine;
- that the current codecs should be removed.

The narrow claim is architectural:

> deterministic relational work over compressed evidence should be performed by deterministic code when the model only needs to select and interpret the operation.

## 12. Sources and prior art

The following sources motivated the harness design, not the empirical claims above:

- Claude Code source archive and clean-room reconstructions: <https://github.com/chauncygu/collection-claude-code-source-code>
- Awesome Agent Architecture, especially tool runtime, skills, context management, system prompt assembly, and evaluation: <https://github.com/hardness1020/awesome-agent-architecture>
- Anthropic documentation on tool use and strict schemas: <https://platform.claude.com/docs/en/agents-and-tools/tool-use/overview>
- Anthropic documentation on programmatic tool calling: <https://platform.claude.com/docs/en/agents-and-tools/tool-use/programmatic-tool-calling>
- Model Context Protocol tool schemas and structured content: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

The architecture repositories are useful for mechanism discovery. The Claude Code collection includes reconstructed and leaked-source material and must not be treated as an official current product contract.

## 13. Recommended next action

Do not spend the next budget tranche on a full cross-provider effort matrix yet.

First implement the smallest offline `qodec_query` slice and run a frozen Codex panel comparing direct squeeze against forced deterministic intersection. If that recovers RAW-like correctness without surrendering the token advantage, then repeat the new interface across reader families.

That experiment tests a real architectural alternative. Another prompt incantation mainly tests whether the model is feeling cooperative that afternoon.
