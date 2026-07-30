# Provider matrix: ModelHubby discovery intake

This vertical uses ModelHubby only as an **untrusted discovery source**. It does
not make ModelHubby a runtime dependency, does not use `model: auto`, and does
not silently fall back between providers. Qodec freezes a reviewed catalog
snapshot, plans explicit `provider × model` targets, then records one probe
receipt per target.

## Trust boundary

```text
ModelHubby/exported notes (untrusted, mutable)
        ↓ import, bound to trusted-providers.json
canonical catalog snapshot + raw SHA-256 + registry SHA-256
        ↓ plan
fail-closed policy filters + explicit target IDs
        ↓ probe
one endpoint, one requested model, no fallback
        ↓
PASS / AUTH_FAILURE / RATE_LIMITED / MODEL_NOT_FOUND /
PROVIDER_5XX / HTTP_FAILURE / TIMEOUT / TRANSPORT_FAILURE / INVALID_OUTPUT /
PROVIDER_SUBSTITUTED / MODEL_IDENTITY_MISSING / ENDPOINT_REJECTED /
REDIRECT_NOT_FOLLOWED / RESPONSE_CAPTURE_FAILED / INTERNAL_ERROR
```

`unknown` never satisfies `--free-only`, `--no-card`, or `--no-training`.
Provider-reported usage is retained as provider evidence, not normalized into a
cross-provider token truth.

## Discovery does not get to name the endpoint

The sharp edge of treating discovery as untrusted is that a catalog row decides
where a credential is sent. This row satisfies every URL rule below — https, a
real host, no userinfo, no query, no fragment, no redirect:

```json
{"provider": "groq", "model": "openai/gpt-oss-120b",
 "api_base": "https://steal.example/v1", "key_env": "GROQ_API_KEY"}
```

TLS then delivers the key to `steal.example` confidentially and intact. A
certificate proves who answered; it never proves they are Groq.

So origin, key name and dialect are **not the catalog's to supply**. They live
in `trusted-providers.json`, which changes only by reviewed commit:

```json
{"schema": "qodec-provider-registry-v1",
 "providers": {"groq": {"api_base": "https://api.groq.com/openai/v1",
                        "api_style": "openai-chat", "key_env": "GROQ_API_KEY"}}}
```

Discovery contributes `provider`, `model`, the free-tier metadata and its own
provenance — nothing that carries authority. The rule for each of `api_base`,
`key_env` and `api_style` is:

| the row says | outcome |
| --- | --- |
| nothing | the registry supplies it |
| exactly the trusted string | accepted, and kept as tamper evidence |
| a different string | refused |
| a non-string value | refused |

The last line is not pedantry: checking `isinstance(claimed, str)` before
comparing meant `"api_base": {"host": "steal.example"}` was read as "not a
string, therefore no disagreement" and quietly overruled — the exact silence the
rule exists to prevent. A provider absent from the registry never becomes a
target at all.

A registry supplied as an object takes the same validation path as the file:
schema, unknown fields, types, lowercase provider names, plausible `key_env` and
URL rules. The result is a freshly built object, so nothing downstream holds a
reference the caller can still mutate.

### Duplicate JSON keys are refused while parsing, and only there

`json.loads` keeps the last of two identical keys and says nothing. That is a
tamper channel:

```json
{"provider": "groq", "model": "m",
 "api_base": "https://steal.example/v1",
 "api_base": "https://api.groq.com/openai/v1"}
```

The hostile claim is gone before `bind_to_registry` can refuse it, so "every
authority value that is present is checked" holds only because the check never
sees it. The same trick hides a duplicated field in a hand-edited plan.

The line is *decides* versus *describes*, not ours versus theirs. On that test a
successful provider completion is firmly on the deciding side — its `model`
settles identity and therefore whether a target may `PASS`, and its
`function.arguments` **are** the tool call being qualified:

```json
{"model": "wrong-model", "model": "openai/gpt-oss-120b", "choices": [...]}
{"handle": "invented", "handle": "sha256:0000…"}
```

Both resolve to the second value, and the run would report `verified` about a
generation whose origin the response stated twice and differently, or grade a
tool call the schema validator and the observed-only grading never saw whole.

One `strict_json_loads` therefore parses **everything that decides something** —
source export, catalog, plan, surface, registry, every successful 2xx completion,
and the JSON string inside `function.arguments`. A repeated key is
`INVALID_OUTPUT` in a completion and `MALFORMED_TOOL_ARGUMENTS` in a tool call.

What stays lenient is the **HTTP error body**, and only that: it is read to pick
a local reason code, never becomes a tool call, and cannot earn a `PASS`.
Refusing to read a sloppy error would turn the provider's untidiness into our
transport failure.

### The JSON dialect is the consumer's, measured rather than imitated

`json.loads` is not a JSON parser; it is a parser for a superset. It admits
`NaN`, `Infinity` and `-Infinity` as bare constants, turns `1e400` into `inf`,
and accepts an unpaired `\ud800` escape as a lone surrogate. `serde_json` —
which the adapter runs over the **whole body** before reading a single field —
refuses all of them. So this parses here and yields a model and tool calls:

```json
{"model": "openai/gpt-oss-120b", "choices": [...], "unread": NaN}
```

...and the consumer rejects the entire response before it ever sees the model.
Nothing in the canary reads `unread`. That is a `PASS` for a target the adapter
cannot talk to — the sixth appearance of one defect: **a canary more liberal
than its consumer**.

By this point another hand-written approximation of `serde_json` would have been
a ritual. So there is an oracle instead:

```bash
# ask the real parser, then require the gate to admit nothing more
python3 evals/provider-matrix/check_json_admission.py
```

`examples/json_admission_oracle.rs` runs `serde_json::from_slice::<Value>` over
`json-admission-corpus.json` — cases carried as hex, so a case can be any
byte sequence — and the checker compares its verdicts against the Python gate.
Each case also carries a **frozen** `consumer_admits`, so the unit suite checks
parity without a Rust toolchain while CI re-measures it and refuses a frozen
value that has rotted.

The rule is **one-directional**: everything the gate admits, the consumer must
admit. The reverse is allowed and used exactly once — `serde_json` accepts
duplicate object keys and this gate refuses them, because a repeated key is a
tamper channel. Being stricter is a choice; being more liberal is a false PASS.

One measurement corrected a plan: integers past `u64::MAX` were to be rejected,
and the oracle says `serde_json` admits them, falling back to `f64`. The gate
therefore does not reject them either. Inventing a rule the consumer does not
have is only free when it is deliberate.

The same measurement then found the rest of the rule. `serde_json` keeps an
integer while it fits `u64`/`i64`, falls back to `f64` past that, and refuses
only when *the fallback overflows*. `parse_float` had been replaced and
`parse_int` had not, so a 400-digit literal parsed here and sank the whole body
there. The boundary is the fallback's finiteness, **not** a digit count:

| literal | digits | consumer |
| --- | --- | --- |
| `18446744073709551616` (`u64::MAX + 1`) | 20 | admits, as `f64` |
| 308 nines | 308 | admits |
| `1` then 308 zeros | 309 | admits |
| 309 nines | 309 | refuses |

`float` runs before `int` in the gate, because Python refuses `int()` past
`sys.get_int_max_str_digits()` with a bare `ValueError` — not a
`JSONDecodeError`, so it would escape every except tuple and be filed as
`INTERNAL_ERROR`. Anything that long overflows `f64` anyway.

#### Nesting depth, which a corpus of hand-picked cases had missed

A finite corpus is a sample, not a proof, and the first thing the sample missed
was structural depth. `serde_json`'s deserializer starts with a remaining depth
of 128 and refuses when it runs out; the oracle puts the boundary at **127
admitted, 128 refused**, for arrays and objects alike. Python's decoder admits
far more and then raises `RecursionError` — which is not a `ValueError`, so it
would escape every except tuple and be filed as `INTERNAL_ERROR`, blaming the
matrix for a body the provider sent.

So the depth is measured **before** parsing, by scanning the text with an
iterative bracket count that ignores brackets inside strings. That refuses
exactly what the consumer refuses, and means the decoder is never handed
anything deep enough to overflow. The surrogate walk is iterative for the same
reason: a check that itself overflows has swapped one uncaught failure for
another.

The corpus carries the boundary on both sides, and the false PASS it closes:

```json
{"model": "openai/gpt-oss-120b", "choices": [...], "unread": [[[[…128 deep…]]]]}
```

### The encoding is the consumer's, not a taste

`json.loads` accepts *bytes* and sniffs UTF-8, UTF-16 and UTF-32, and tolerates
a UTF-8 BOM. The adapter that will consume a `PASS` reads bodies with
`serde_json::from_slice`, which was measured against all four:

| body | `serde_json::from_slice` |
| --- | --- |
| UTF-8 | `Ok` |
| UTF-8 + BOM | `Err(expected value at line 1 column 1)` |
| UTF-16LE | `Err(expected value at line 1 column 1)` |
| broken UTF-8 | `Err(invalid unicode code point)` |

So the rule is **UTF-8, no BOM, nothing else** — RFC 8259 requires UTF-8 for
JSON exchanged between systems, and a receiver *may* ignore a BOM but is not
obliged to. Sniffing here would qualify a body the mapper refuses: the same
liberality as the padded byte envelope, moved from structure to encoding.

A body that breaks the rule is `INVALID_OUTPUT` — the provider sent it, and that
is not a defect in this tool. Before this, `UnicodeDecodeError` was in no except
tuple, so a broken 2xx surfaced as `INTERNAL_ERROR` and blamed the matrix for
what arrived on the wire.

This check cannot be repeated on a value that is already a `dict`. By then
Python has discarded the losing value, so an earlier claim that a
caller-supplied registry was validated "including duplicate JSON keys" was not
something any code could do.

Checked at `import`, and again immediately before the key is attached — a plan
is a reviewed file that still sits on disk afterwards. The catalog records the
`registry_sha256` its origins came from, so it cannot be replayed later against
a different registry invisibly.

## The transport itself

`probe` and `qualify` share **one** transport, and it refuses the endpoint
before the key is attached. `urllib`'s defaults will send a bearer token over
plaintext `http`, to a host smuggled in as userinfo, or to wherever a `302`
points — that last one silently, after the key has already left the process.

| rule | rejected |
| --- | --- |
| scheme | anything but `https` |
| host | absent |
| userinfo | any `user:password@` |
| query, fragment | any |
| redirects | all — the handler cannot follow one |
| response body | bounded; the bound is on the `read`, not on a complaint after it |

A failure is also classified by *when* it stopped. Nothing arrived before the
headers → the request may never have been served, and `UNAVAILABLE` invites a
retry. The body was lost after the headers → the generation exists and is on the
bill, so it is `RESPONSE_CAPTURE_FAILED` and retrying it is a decision somebody
makes on purpose.

`status is None` means one thing only: **no headers were ever received.** A body
lost after the headers keeps its status, its `request_id` and how many bytes were
seen — losing a `401` and filing it as a nameless capture failure would discard
the most useful fact in the exchange. The stage is a table, not an inference:

| status | body    | stage                                          |
| ------ | ------- | ---------------------------------------------- |
| `None` | `None`  | `before-response` — nothing arrived; retryable  |
| int    | `None`  | `after-headers` — the body was lost; billed     |
| int    | `bytes` | `completed`                                     |
| `None` | `bytes` | rejected: a body without a status is impossible |

Enforced on **every** `SendResult`, not only on the inferred ones. Validating
just the legacy three-tuple left the explicit form unchecked, so
`(503, None, "lost", "completed")` promoted a billed after-headers loss to a
success through the front door instead of the back. A stage written by hand is a
claim like any other and gets no more credit for being written down than for
being deduced.

And the table says `status=int, body=bytes`, so that is what is checked — not
merely whether the fields are present. `("503", None, …)` would otherwise fail
later on a status comparison and `(200, "not bytes", …)` on hashing; `True`
passes `isinstance(x, int)` and equals `1`, with the confidence usually reserved
for bad APIs. `status` must be an `int` in 100..599, `body` exactly `bytes`,
`body_bytes_observed` a non-negative `int`, `request_id` a `str`.

`b""` is a **complete empty body**, not a lost one. Inferring the stage from
"is there a status" alone promoted `(503, None)` to `completed`, so a billed
after-headers loss was reported as retryable `UNAVAILABLE`.

### Nothing untrusted, and no credential, reaches an artifact

Receipts are committed and read by more people than the secret is. So a receipt
records **facts, not the provider's prose**: HTTP status, request id, capture
stage, body byte count, body digest, and one reason code from a fixed local
vocabulary. The provider's error body is *read* — that is how a dialect
rejection is told from a missing model — and then dropped. Scrubbing arbitrary
provider text with a regex is a losing game: a key can come back base64'd,
JSON-escaped, or split across fields.

The credential is validated *before* an `Authorization` header exists, because
`http.client` reports a bad header value by putting it in the exception message,
and `main` prints exceptions to stderr. A whole-pipeline sentinel test runs every
failure path with a unique fake key and asserts it appears in no receipt, no
stdout, no stderr and no exception text.

### One malformed target costs one receipt

`[]`, `null` and `5` are valid JSON, and `payload.get` on any of them raises
`AttributeError`. Nothing caught it, so a single provider returning a bare array
ended the whole matrix and every later target lost its receipt — the least
informative outcome, from the least interesting cause. Each target is now
wrapped individually: a crash becomes an `INTERNAL_ERROR` receipt naming the
exception *type* and not its message, and the run continues.

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
the request/response hashes, endpoint, latency, requested model, reported model,
three-valued model status, classification, and provider usage when present. A
different reported model is `PROVIDER_SUBSTITUTED`; **no** reported model is
`MODEL_IDENTITY_MISSING`. Neither is a pass — the exact text plus an unnamed
model is still a response whose origin was never established.

## Qualification: does the target speak the C1 protocol?

An availability probe sends no tools. A target can pass it and still be unable
to run C1's forced-query arm at all, so `PASS` there means "alive and not
substituted", not "usable". The arm needs four tool declarations accepted,
forcing honoured, a multi-turn loop with results returned under their call ids,
and a terminal answer whose arguments validate. Nothing in a bare completion
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

### A PASS requires the whole cycle, not one forced call

```text
operation observed
  → the provider's own tool_calls array echoed back by reference
  → role: tool results returned under their call ids
  → the provider answered that request successfully
  → and only now may qodec_answer terminate the run
```

A target that opens with `qodec_answer` has emitted one forced tool call — which
the RAW arm also does — and has run no operation and never seen a `role: tool`
message. That is `PROTOCOL_VIOLATION`, *terminal answer before any
operation/tool-result roundtrip*, not a pass. The roundtrip counts when the
**provider accepts** the request carrying the results; a 400 on that request is
`TOOL_RESULT_REJECTED` and the roundtrip did not happen.

### The response contract is the adapter's, not a lenient superset

This vertical qualifies `api_style: openai-chat`, and the adapter that will
consume a `PASS` is `OpenAiChatCompletions`. A canary that accepted a looser
shape than the adapter would hand out a `PASS` for a response the adapter
rejects — the same defect as paraphrasing the schemas, moved to the response
side. So the contract is exactly what a strict mapper requires:

```text
message.role == "assistant"
tool_calls is a non-empty array
every tool_call.type == "function"
every id is a non-empty string, and unique within the response
function.arguments is a JSON *string*, decoding to an object
```

`arguments` arriving as an object is Anthropic's dialect, not a sloppy OpenAI
response, so it is `DIALECT_MISMATCH` and not quietly repaired: the fix is a
different adapter, not a better prompt. The provider's own `tool_calls` array is
then echoed back **by reference** rather than rebuilt from the parsed view —
rebuilding drops fields the parser does not model and re-encodes the arguments,
so a provider that only accepts its own emission back would fail for a reason
this canary invented.

### Only a verified model identity may pass

```text
model_status == verified  → PASS
model_status == drifted   → PROVIDER_SUBSTITUTED
model_status == missing   → MODEL_IDENTITY_MISSING
```

`missing` is not a milder `drifted`. A successful response that names no model
leaves the origin of the generation unestablished, and a target whose identity
was never established must not satisfy the gate that decides what the adapter
may be pointed at. This is distinct from `MODEL_MISSING`, which is HTTP 404 —
the provider has no such model. Different fact, different name.

### Arguments are checked against the declared schemas

Not against their required keys. `{"index": 123, "sections": "not-a-list",
"extra": true}` has every required key and is nonsense; accepting it would report
PASS for a target the arm cannot use. Every tool call is validated against the
schema the request actually declared — types, enums, patterns, minimums,
`minItems`, nested objects, `additionalProperties: false`, and local `$ref` —
using the frozen `jsonschema_mini` already shared by the corpus tools and the N2
registries. Violations are recorded in the receipt as `argument_errors`.

Beyond the schema, the terminal answer is graded against the canned data, which
fixes exactly one correct answer: the bytes must be `alpha`, the handle must be
one an operation returned, and every citation must be in that result's support.
Failing that is `CANARY_ANSWER_MISMATCH` — deliberately **not** a protocol cause.
A target that speaks the dialect perfectly and cites a handle it was never given
has qualified the wire and failed the task, and the two call for opposite
actions.

### Causes are kept apart

```text
ENDPOINT_REJECTED  UNAVAILABLE  RESPONSE_CAPTURE_FAILED  REDIRECT_NOT_FOLLOWED
AUTH_FAILED  RATE_LIMITED  PROVIDER_REJECTED  MODEL_MISSING
MODEL_IDENTITY_MISSING  PROVIDER_SUBSTITUTED  TOOL_CHOICE_UNSUPPORTED
TOOL_RESULT_REJECTED  DIALECT_MISMATCH  MALFORMED_TOOL_ARGUMENTS
PROTOCOL_VIOLATION  INVALID_OUTPUT  NO_TERMINAL_ANSWER
CANARY_ANSWER_MISMATCH  INTERNAL_ERROR  PASS
```

`TOOL_CHOICE_UNSUPPORTED` earns its own name because a 400 from an incompatible
dialect and a model that does not exist are the same status code and completely
different problems — one is a request we can fix, the other a target to drop.
The turn matters too: a rejection of the first request is about the tools or the
forcing, while a rejection of the first request that carries `role: tool`
messages is about the result shape.

`PROVIDER_SUBSTITUTED` outranks both a protocol pass and a wrong answer. A run
that satisfied every structural rule against a model nobody asked for has
established the protocol and nothing about the target.

Which model drifted is the finding, so it survives the fold. Every name the
provider reported is kept per turn and collected into `reported_models`; the
top-level `reported_model` is filled in only when a single consistent value
exists. A run that drifted on the first turn and was correct on the second folds
to `drifted` — and a single overwritten scalar would have made its detail line
read "requested X, provider reported X", losing the substituted model entirely.

### A target is a provider × model pair

`groq × gpt-oss-120b → PASS` and `groq × gpt-oss-20b → PROTOCOL_VIOLATION` are
both ordinary outcomes and neither is a verdict on Groq. Receipts are written
per `target_id` for that reason.

This is intentionally the thin discovery/probe layer. Full Qodec A/B runs stay
in their existing eval harnesses and should consume only targets whose frozen
receipts are `PASS` for **both** probes — which is exactly why neither may pass
on an unestablished identity.

## Adding a provider

Edit `trusted-providers.json` in a reviewed commit. Nothing else grants a
provider an origin or a key name, and the file is validated on load: every entry
must carry `api_base`, `api_style` and `key_env`, and its `api_base` must survive
the same URL rules as any other endpoint.

```json
{"schema": "qodec-provider-registry-v1",
 "providers": {
   "groq":     {"api_base": "https://api.groq.com/openai/v1",
                "api_style": "openai-chat", "key_env": "GROQ_API_KEY"},
   "<new>":    {"api_base": "https://…", "api_style": "openai-chat",
                "key_env": "<PROVIDER>_API_KEY"}}}
```

`--registry` points the commands at a different file; that is an explicit local
act, the same kind of act as editing this one, and it is recorded in the
catalog's `registry_sha256`.

## Tests

```bash
cd evals/provider-matrix
python3 -m unittest -v test_provider_matrix.py

# the frozen surface still matches the crate that defines it
python3 evals/provider-matrix/check_surface.py

# the JSON gate admits nothing serde_json refuses
python3 evals/provider-matrix/check_json_admission.py

# the checkout is byte-clean, and the check can prove it would say otherwise
python3 evals/provider-matrix/check_clean_tree.py
python3 evals/provider-matrix/check_clean_tree.py --self-test

# both ways of running the suite find the same tests
python3 evals/provider-matrix/check_test_discovery.py
python3 evals/provider-matrix/check_test_discovery.py --self-test

# and the tests would notice if the contracts were removed
python3 evals/provider-matrix/mutations.py
```

`mutations.py` states each contract as its own negation — accept an immediate
terminal answer, degrade validation to required keys, let a catalog row choose
the origin or the key, follow a redirect, pass a run whose model was never
named, discard a status when its body is lost, accept object arguments, rebuild
the replayed tool calls — and requires the suite to turn red for every one. It
verifies that each substitution actually applied before believing the result: an
anchor that no longer matches runs a green suite and reports "not caught", which
is the most convincing way to be wrong about a test.

Every classification above except `NO_TERMINAL_ANSWER` is reached in one table
in `test_every_classification_is_declared`, and that one has its own
budget-exhaustion test; the table asserts the remainder is exactly
`{NO_TERMINAL_ANSWER}`, so adding a cause without reaching it turns the suite
red. A qualification whose failure paths can only be exercised against a real
provider is a qualification whose failure paths are never exercised.
