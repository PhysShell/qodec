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

#### What "treated as a data store" means concretely

The artifact is not queried in its compressed form, and no operation
re-derives records from legend entries per call. `qodec_open` performs a
**single full decode** — `decode_once` — and builds two things from it:

```text
decode_once(artifact)
  -> canonical store : record_id -> exact RAW bytes of that record
     canonical index : key       -> sorted, deduplicated [record_id]
```

Four properties matter, and each exists to close a failure this program
has already measured:

- **Canonical keys are built by the decoder, never by the model.** The
  recomposition slip that PR #12/#13 measured is a reader reassembling a
  key from stems belonging to different legend entries. If the key set is
  produced by the decode path, that class of error has nowhere to occur;
  it is not mitigated, it is structurally absent.
- **The store holds bytes, not a re-encoding.** `qodec_materialize`
  returns exact RAW fragments from the store, so byte-equality with the
  original payload is checkable rather than asserted.
- **Decode happens once per artifact, not once per query.** Query latency
  and query cost are therefore properties of the index, and repeated
  queries cannot silently multiply decode work.
- **The index is the only thing operations read.** `lookup`, `intersect`,
  `join` and `aggregate` are set operations over `record_id` lists. They
  cannot see the compressed representation at all, which is what makes
  their results independent of codec choice — and what makes a codec
  ablation (§10, Slice C2) a separate question from whether the interface
  works.

The store and index are derived state, never a second source of truth: a
mismatch between the store and the artifact digest is an
`artifact-mismatch`, not a repairable condition.

## 3. Proposed tool interface

A minimal tool surface should stay small and typed.

One canonical operation enum is used in every request, result and
verification schema. The spelling is the imperative verb — `lookup`,
`intersect`, `join`, `aggregate` — and `intersection` is not an alias for
`intersect` anywhere.

```text
operation := lookup | intersect | join | aggregate
```

Every query returns an **immutable query result**, addressed by
`query_result_id`, which is what later verification binds to. The model
never gets to re-state what the query was.

```text
qodec_open(artifact_id)
  -> schema, sections, counts, risk flags, supported operations

qodec_lookup(artifact_id, query)
  -> query_result_id, matches, candidate_count, complete, digests

qodec_intersect(artifact_id, sets, key)
  -> query_result_id, matches, candidate_count, complete, digests

qodec_join(artifact_id, left_filter, right_filter, key)
  -> query_result_id, matches, candidate_count, complete, digests

qodec_aggregate(artifact_id, filter, group_by, measures)
  -> query_result_id, groups, complete, digests

qodec_materialize(artifact_id, record_ids)
  -> selected RAW fragments

qodec_verify(artifact_id, query_result_id, proposed_answer)
  -> valid | invalid | ambiguous | incomplete | unverifiable
     | stale-result-handle | artifact-mismatch | query-digest-mismatch
```

`qodec_verify` deliberately does **not** accept an evidence list, an
operation name, or query arguments from the model. See §5.

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
  "query_result_id": "sha256:...",
  "schema_id": "qodec.query.v1",
  "artifact_digest": "sha256:...",
  "canonical_query": {"operation": "intersect", "key": "test_id", "sets": ["..."]},
  "canonical_query_digest": "sha256:...",
  "complete_result": ["cli::reader_17"],
  "complete_result_digest": "sha256:...",
  "matches": ["cli::reader_17"],
  "candidate_count": 1,
  "evidence_record_ids": ["r17", "r48", "r91"],
  "complete": true
}
```

Required properties:

- `schema_id` — the result schema this record was produced under;
- `artifact_digest` — which artifact was queried;
- `canonical_query` — the **executable** normalised operation and
  arguments, stored in full, not only as a fingerprint;
- `canonical_query_digest` — `sha256(canonical_query_bytes)`, so a later
  verification cannot be pointed at a different question;
- `complete_result` — the full canonical result, persisted outside the
  prompt when large;
- `complete_result_digest` — `sha256(canonical_result_bytes)`, computed
  before any preview truncation, so a bounded preview can never be
  mistaken for the whole answer;
- `matches` — a possibly-truncated preview of `complete_result`, never
  the basis of any decision;
- exact candidate count **over the full result**, not over the preview;
- evidence record IDs — explanatory only (§5);
- completeness bit;
- machine-readable error categories.

### 4.1 Result identity is content-addressed, not a random handle

An opaque random handle and a content-addressed deterministic identity
are not the same thing, and Slice A requires the latter: it demands
deterministic results and exact replay, neither of which an allocator
counter can provide. So the identity **is** the content:

```text
canonical_query_digest  = sha256(canonical_query_bytes)
complete_result_digest  = sha256(canonical_result_bytes)

query_result_id = sha256(
      schema_id
   || artifact_digest
   || canonical_query_digest
   || complete_result_digest
)
```

Two consequences follow, and both are wanted. Re-running the same
canonical query over the same artifact under the same schema yields the
**same** `query_result_id` — replay is checkable by construction rather
than by bookkeeping. And any change to the artifact, the question, the
result, or the schema yields a different ID, so a handle can never
silently come to mean something else.

The alternative — declaring the ID an opaque immutable handle — is
defensible only if the `content-addressed` claim is dropped *and* exact
replay is redefined to compare result content and digests while ignoring
the handle. That is a coherent contract, but a weaker one, and it fits
badly with a project whose whole discipline is exact identities.

Query results are immutable. A handle whose stored result no longer
matches `complete_result_digest`, or which refers to a different
`artifact_digest` than the one presented, is `stale-result-handle` or
`artifact-mismatch` respectively — never silently re-executed.

An oversized result should return a preview and a retrievable handle, not dump the entire store back into the context window and thereby recreate the original problem with more ceremony.

## 5. Proof-carrying answers

For risky operations, the final model answer should be checked against evidence.

Suggested answer schema:

```json
{
  "answer": "cli::reader_17",
  "query_result_id": "sha256:...",
  "evidence_record_ids": ["r17", "r48", "r91"]
}
```

**Verification is bound to the full query result, never to the evidence
the model chose to cite.** This is the correction that matters most: if
truth were established over a model-supplied subset of records, the
model could satisfy `exact-one` by simply omitting the records that
support the other candidate.

```text
full intersect over the artifact  -> {A, B}
model cites evidence only for A
verify(evidence_for_A)            -> candidate_count = 1   # formally fine
                                                           # actually bypassed
```

So `qodec_verify` takes a `query_result_id` and re-derives truth from the
**stored complete result**. It never accepts an operation name, query
arguments, or a record set from the model.

An earlier draft said verification could equivalently "re-execute the
stored `canonical_query_digest`". It cannot: a digest is a fingerprint of
a query, not a query. `sha256` does not inverse-map to an AST, and the
two procedures it conflated are not equivalent even once the executable
`canonical_query` is stored alongside it. They are separated here.

### 5.1 Runtime verification and acceptance replay are different procedures

```text
runtime qodec_verify:
  verifies the immutable STORED complete result
  never re-executes anything
  a stale or mismatched handle is a terminal state, not a repair trigger

independent acceptance replay:
  re-executes the stored canonical_query
  over the pinned artifact_digest
  and compares the recomputed complete_result_digest
  (and therefore the recomputed query_result_id)
```

The distinction is not pedantry. If runtime verification were allowed to
re-execute a stale handle, it would replace missing evidence with freshly
manufactured evidence at exactly the moment the system had detected that
its evidence was untrustworthy — converting a fail-closed state into a
silent recovery. That is case 3 of the Slice A negative matrix.

Acceptance replay does re-execute, deliberately, but it is an offline
verifier over a pinned artifact answering a different question: *is this
stored result reproducible?* It never runs in the answer path, so it can
never rescue a live query, and a replay mismatch is a defect in the
engine rather than a fallback for the model.

The harness verifies:

- the handle resolves, is not stale, and its `artifact_digest` matches;
- the stored `canonical_query_digest` equals `sha256` of the stored
  `canonical_query`, and matches the query being claimed;
- the recomputed `query_result_id` equals the handle presented;
- the stored result is `complete`;
- `candidate_count == 1` **over the full result**;
- the answer equals that single canonical candidate exactly;
- the response contains no additional canonical candidate of the same
  entity shape;
- every cited evidence ID exists and is contained in the full result's
  supporting set.

`evidence_record_ids` remain useful for explanation and for auditing the
model's reasoning, and they are checked for existence and consistency —
but they do **not** define the data over which truth is established.
Otherwise the tail wags the dog and the evidence steers the oracle.

This also closes the grading hole exposed by effort experiments. The primary categories should be:

```text
exact-correct
exact-wrong
hedged-includes-truth
hedged-without-truth
unparseable
backend-failed
```

Only `exact-correct` counts as correct in the normative gate, and
`hedged-includes-truth` never becomes a pass — it is a separate
diagnostic outcome and is reported separately.

**`exact-one` must be enforced in four places, or the hole simply
relocates.** The effort experiment demonstrated the failure mode
concretely: a hedged answer naming two candidates scored 1/1 under
substring grading, identical to the single correct answer.

1. **Query result contract** — `candidate_count` is computed over the
   full result set; an ambiguous query reports `candidate_count > 1` and
   is not silently narrowed.
2. **`qodec_verify`** — as above, bound to the full query result.
3. **Normative evaluator** — the panel gate is the deterministic
   verifier, *not* `qodec ab grade`'s substring match. The substring
   grader may be reported alongside for continuity with the frozen runs,
   clearly labelled, but it does not decide pass/fail.
4. **Final answer parser** — a response containing more than one
   canonical candidate of the answer's entity shape is `hedged-*`,
   regardless of whether the truth is among them.

Formally, normative correctness requires all of:

```text
candidate_count == 1
AND answer == canonical_result[0]
AND no additional canonical candidates in the response
AND query result is complete
```

## 6. Harness policy

`qodec risk` should remain a hazard detector, not impersonate an oracle. Its output can nevertheless guide the harness.

Proposed policy:

**Routing keys off the requested operation, not off the risk flag.** An
earlier draft of this document said both "`join_hazard = false` → direct
encoded reading allowed" and "join, intersection and cross-entry
aggregation must use the query tool", which cannot both hold. The
contradiction resolves in one direction only: `qodec risk` is by its own
charter a conservative *hazard detector*, so the absence of a flag is not
evidence that a join is safe. A detector that has never been shown to
have high recall must not be allowed to authorise the very operation it
was built to warn about.

```text
local lookup / explicit count
  -> direct encoded reading permitted under the reader contract

join / intersect / cross-entry aggregate
  -> deterministic query path required

query path unavailable
  -> materialize the relevant RAW subset

any negative verification state
  -> RAW fallback
```

The risk flag keeps a real but narrower job: it informs recommendations,
prioritises which artifacts to route first, and is recorded in shadow
mode. It never widens the normative path.

The full negative set that triggers RAW fallback — not merely "ambiguous
or incomplete":

```text
invalid
ambiguous
incomplete
unverifiable
stale-result-handle
artifact-mismatch
query-digest-mismatch
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
current squeeze + forced qodec query tool
```

The prompt-only decoder contract may be kept as a cheap diagnostic
control arm **if it is already implemented**; it is not a reason to delay
the panel.

`reader-safe squeeze direct` is deliberately **excluded from this
panel**. It changes the representation at the same time as the access
interface, and afterwards nobody could say which of the two produced the
result. It belongs to a later ablation (§10, Slice C2).

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

Cost is measured in **two independent groups**, because conflating them
is how this experiment would cheat itself.

Model cost — everything that consumes context or an API token:

```text
reader skill / tool instructions
+ tool schemas
+ query arguments
+ query results (including previews)
+ materialized RAW fragments
+ verification responses
+ retries
+ final answer
= total_model_visible_tokens
```

plus API input/output tokens, fallback-visible RAW tokens, and the number
of tool round trips. Every one of these must be counted; a forced-query
arm that "wins" by moving text out of the prompt and forgetting to count
the tool result has proved nothing.

System cost — deterministic work done in ordinary code:

```text
bytes decoded internally
index construction time
peak memory
query latency
verification latency
stored artifact size
```

**Internal decoding is deliberately NOT counted as model cost.** Moving
deterministic relational work out of the prompt and into ordinary code is
the architectural hypothesis of this proposal, not a way of hiding the
bill. Qodec is not obliged to pretend the CPU never read the data; it is
obliged not to make a probabilistic reader do a relational engine's job.

Primary gate:

```text
forced qodec query reaches RAW-like exact correctness
at materially lower total model-visible token exposure
and acceptable system cost
```

The exact thresholds for "RAW-like", "materially lower" and "acceptable"
must be preregistered before live calls.

## 10. Acceptance slices

### Slice A: offline query engine

Offline only: no model calls, no production routing, no codec change, no
new representation. The deliverable is `decode_once` plus the canonical
store and index (§2.3), and the operations `open`, `lookup`, `intersect`,
`materialize`, `verify` over them — with:

- frozen artifact format;
- deterministic results, and exact replay in the §5.1 sense — replaying
  the stored `canonical_query` over the pinned artifact reproduces
  `complete_result_digest` and hence `query_result_id`;
- content-addressed result identity per §4.1, not an allocator handle;
- bounded results;
- complete provenance.

#### The negative matrix is part of the slice, not follow-up work

A query interface earns trust by what it *refuses*. Slice A is not
accepted until each of these is a test with a named expected outcome —
and a case that cannot be expressed as a test means the contract, not the
test, is underspecified.

| # | case | expected |
|---|---|---|
| 1 | malformed artifact | `open` fails closed; no partial store |
| 2 | artifact digest mismatch | `artifact-mismatch`; never silently re-decoded |
| 3 | stale query result handle | `stale-result-handle`; handles are not revalidated by re-running the query |
| 4 | tampered query args in a verify call | rejected: `verify` takes no operation or args from the caller (§5) |
| 5 | **evidence subset attack** — answer cites evidence for a strict subset of a complete result | `incomplete`; verification binds to the full result, not the cited rows |
| 6 | falsified `candidate_count` | `query-digest-mismatch`; the count is recomputed, never trusted from input |
| 7 | full result genuinely has >1 candidate | `ambiguous` — never resolved by picking one |
| 8 | duplicate canonical IDs in the index | build fails; the index is deduplicated by construction |
| 9 | evidence ID absent from the artifact | `unverifiable` |
| 10 | materialization of record IDs from a different artifact | rejected before any bytes are returned |
| 11 | unbounded / oversized result | refused with the bound stated; never truncated silently |
| 12 | nondeterministic ordering across replays | build fails; ordering is total and sorted — otherwise `complete_result_digest`, and therefore `query_result_id`, is not stable and §4.1 identity collapses |
| 13 | incomplete result flagged `complete` | `query-digest-mismatch` |

Cases 5, 6 and 13 are the ones worth stating plainly: each is an answer
that looks *formally* verified while being wrong, which is precisely the
failure mode a verification layer exists to prevent and therefore the
easiest one to accidentally build.

### Slice B: agent tool integration

- typed tool schemas;
- forced tool path for join-hazard fixtures;
- full call envelopes;
- exact-one answer grader;
- no hidden manual decoding in the harness.

### Slice C1: live paired panel — does the interface work?

Arms: `RAW` / `current squeeze direct` / `current squeeze + forced qodec
query tool`. The codec is held **fixed** across arms so the only thing
varying is how the model is allowed to reach the data.

- frozen reader identity and effort;
- complete cells only;
- paired analysis by task;
- hedging reported separately;
- RAW control;
- no product routing change from one panel.

### Slice C2: representation ablations — does a safer codec help?

Only after C1 returns a verdict. This is where `reader-safe squeeze`
(§2.2) and the §8 representation experiments belong, and the reason for
the ordering is that they answer a different question.

C1 asks whether deterministic execution removes the failure. C2 asks
whether a different encoding reduces it. Running them together would
confound the two: an arm that is both reader-safe **and** queryable
cannot attribute a gain to either, and the entity-preserving codecs cost
compression ratio, which is the thing the whole project is trying to buy.
If C1 shows deterministic execution recovers RAW-like correctness, C2
becomes an optimisation question about ratio rather than a correctness
question — which is a much cheaper experiment to design.

A reader-safe arm is therefore **excluded from C1 by construction**, not
omitted by oversight.

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

### 11.1 This is not Qodec Ingress Compression v1

The two efforts complement each other and must not be merged, because
they have different trust boundaries and different acceptance verticals.

| | Ingress Compression v1 | Query harness |
|---|---|---|
| trust boundary | encoder and decoder: `D(E(P)) = P` byte-exact | tool runtime: the model may only reach data through typed operations |
| what is accepted | the artifact roundtrips and fits the budget | the answer is uniquely determined by a complete query result |
| failure that matters | a byte differs after decode | a plausible answer that no query result supports |
| model's role | consumer of the artifact | selector of an operation, never a reconstructor of keys |
| measured by | roundtrip tests, ratio, tokenizer matrix | paired reader panels, exact-one gate, negative matrix |

Ingress compression can succeed completely — byte-exact, cheap,
tokenizer-stable — and the join hazard still exists, because that hazard
lives in what the *reader* does with a legal artifact. Conversely the
query harness could work over an artifact whose ratio is unremarkable.
Neither result substitutes for the other, and a shared acceptance gate
would let a win in one vertical mask a regression in the other.

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
