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
cross-provider token truth — but only the counters, and only within bounds
derived from the request that was sent. See the projection boundary below.

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

There is a third answer, and the first two cannot express it. `BadStatusLine`
and `LineTooLong` out of the opener mean the request was sent and the reply was
not a parseable HTTP response at all. No headers ever parsed, so it is not
`after-headers`; but the request *was* served, so calling it `before-response`
would assert that nothing was generated and nothing will be billed — a claim
this transport cannot support, and the claim that invites paying twice. That is
`response-framing`: no status, no body, no response-derived fields, and
`RESPONSE_CAPTURE_FAILED` on both the qualification and the probe path.

The family matters more than any member of it. `IncompleteRead` was caught by
name first, which left `LineTooLong` and the rest exactly where they were: every
one of them derives from `http.client.HTTPException`, which is neither an
`OSError` nor a `ValueError`, and urllib re-raises them rather than wrapping
them in `URLError`. So the base class is what both body reads catch, because the
class is what "the provider broke the framing" means.

What gets written down is never `str(exc)`: `BadStatusLine`'s message *is* the
bytes the peer chose to send, and this string goes into a turn record and then
into a receipt on disk. A failed exchange crosses as `reason` — a member of a
closed vocabulary, assigned where the failure happens — and `failure_kind`
beside it, with the concrete exception class as a digest. `detail` never crosses
at all; see the projection boundary above for why "it is a Python class name"
was not, on its own, an argument that a field is local.

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

That table is the *inference* for a legacy three-tuple, so `response-framing`
does not appear in it: nothing about `(status, body)` distinguishes a reply that
never came from a reply that came back unreadable. Only `send_json` knows the
difference, and only `send_json` produces that stage.

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

Receipts are committed and read by more people than the secret is, and the
provider has already seen the bearer token — so every string it sends back is a
way to hand it over. Scrubbing that text with a regex is a losing game: a key
can come back base64'd, JSON-escaped, split across fields, or as an integer.

So the rule is not about fields, it is about a boundary:

```text
raw provider response
        ↓
ephemeral protocol state    — whatever the loop needs, in memory only
        ↓
typed, sanitised evidence
        ↓
durable receipt
```

Four shapes may cross, and nothing else:

| what it is | what crosses |
| --- | --- |
| a value that matched a trusted local one | the local value |
| a value from a local enum | the enum member |
| a bounded numeric scalar | the number, after a type *and range* check |
| an arbitrary identifier or text | a digest, a length, a local classification |

An unrecognised object or list does not cross at all — not even as a digest of
itself, since hashing one would be the boundary quietly making an exception for
its own rule.

Digests are domain-separated: `sha256("qodec-provider-request-id-v1\0" ‖ value)`.
Without the prefix, a request id and a tool call id that happen to be the same
string hash identically, and the receipt reveals that the provider reflected one
into the other. Small, and free to close. The prefixes are public constants, so
anyone holding a value can still recompute its digest.

**Why the boundary and not a list of `if`s.** Two review rounds found this as two
separate bugs: `usage` copied whole into a receipt, so a gateway answering
`{"prompt_tokens": 12, "echo": "Bearer …"}` writes the credential to disk on a
`PASS`; and `request_id_of()` returning a provider-controlled header verbatim.
Either could have been closed with an `if`. The next review would then have
found the tool call id, then the substituted model name, then `role`, then
`tool_call.type`, one per round, forever — because the receipt was still being
built by copying decoded provider values into it.

**Bounded means bounded at both ends.** `type(n) is int and n >= 0` is an
arbitrary-precision integer with a type check in front of it:
`int.from_bytes(secret.encode(), "big")` in `prompt_tokens` is a perfectly
well-typed non-negative count, and a sweep for a *string* sentinel walks
straight past it. Usage counters are bounded by the request this module sent —
the prompt by the number of bytes we transmitted, since no tokenizer emits more
than one token per byte, and the completion by the `max_tokens` we asked for.
Nothing in the response decides how large a number the response may write down.
Usage is descriptive telemetry and never reaches a verdict.

**Local means the vocabulary is local, not the address that produced it.** The
transport's `detail` is free text and stays in memory: an
`SSLCertVerificationError` message carries fields the peer chose. What crosses
is `reason`, from a closed vocabulary, assigned where the failure happens.

### The producer reports; the consumer projects

The boundary above says which *shapes* may cross. It does not by itself say
**who decides** that a value has one of them, and that second question took its
own round to answer, because `SendResult` is not only built by `send_json` — it
is also whatever an injected `send` returns.

```text
externally constructible input
        ↓
validation against local facts and local bounds
        ↓
consumer-owned classification / projection
        ↓
durable evidence, or a typed FAIL
```

Two fields had it backwards.

`body_bytes_observed` was the numeric channel `usage` closed, one field over. On
`after-headers` there is no body, so nothing local contradicts the count — which
is exactly what made it an opening: `int.from_bytes(secret, "big")` is a
non-negative integer and went into a receipt. One `response_limit` now runs from
the caller through the sender, `send_json`, `as_send_result` and
`validate_send_result` to `transport_target.max_response_bytes`, so the artifact
names the number every count was checked against instead of a second copy of a
constant that would eventually lead its own life. The allowance is `limit + 1`,
because `read_bounded` reads one past the limit deliberately to prove overflow;
past that, a count is not something this contract can produce. The refusal never
repeats the number it refused.

`failure_class` was the third time a shape check was mistaken for a statement
about origin. First the field held a class name and the argument was that a peer
cannot choose a Python class name. Then it held a digest and the check was
sixty-four hex characters — and a sixty-four-character hex credential satisfies a
sixty-four-character hex check. A producer that submits finished evidence leaves
the boundary nothing to verify but spelling. So the raw class name stays
ephemeral and locally bounded, and `project_transport_failure` computes the
domain-separated digest at the boundary for the probe and qualification paths
alike, which also stops the two from drifting. `BadStatusLine` and `LineTooLong`
remain distinguishable to anyone who can hash a class name they suspect.

The same ownership question applies to a subprocess. `subprocess.run(...,
text=True)` decodes with the host locale and raises `UnicodeDecodeError` — a
`ValueError` — from inside the call, where neither the timeout nor the `OSError`
handler covered it. A child's bytes were deciding whether a gate could return a
verdict. Output is read as bytes and decoded here; a failure to decode is
`UnreadableTestOutput`, reported without its own message, because the only
detail that message carries is the bytes that caused it.

The credential is validated *before* an `Authorization` header exists, because
`http.client` reports a bad header value by putting it in the exception message,
and `main` prints exceptions to stderr.

**The regression is recursive, not a checklist.** A sentinel is planted in
`usage`, the request id, a call id, a tool name, a model name, the assistant
`content`, `role`, `tool_call.type`, a cited handle, an error body and the
transport detail — and the assertion walks the entire serialised artifact for
it, in text form *and* as an integer, across every qualification and probe
scenario. It earned its keep immediately: it found `SendResult.detail` being
copied into the receipt, which no reviewer had named and no field list would
have caught. A list of known places ages faster than milk on a radiator; the
next field is always the one that is not on it.

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
message.content is absent, null, or a string
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

`role` and `type` are on that list twice over: the contract switches on them,
*and* they are strings the provider fills in. Reporting a violation as
`f"role {role!r}"` reads like a harmless diagnostic and is a copy — either field
can be the bearer token, and `detail` goes to disk. A discriminator that matched
one of ours is named outright, because it is a value we already had; anything
else is named by reference, and a non-string by its JSON type.

`content` is on that list because it was the one field replay sent back without
anyone having looked at it. The parser read `role` and `tool_calls`; replay then
reached past the parser into the original message for `content`, so `{"role":
"assistant", "content": 123, "tool_calls": [...]}` satisfied the contract, went
into the next request, and a run could finish `PASS` for a message a strict
mapper deserializes into nothing. Any other type — number, bool, object, array —
is `PROTOCOL_VIOLATION`, and the verdict lands before an operation runs, before
a roundtrip is acknowledged, and before the message can be replayed.

The parser therefore returns the value it checked, and replay uses *that*, not a
second read of the original dict. With the guard in place the two are equal, so
no test can tell them apart — which is exactly why it is written down here
rather than defended by a mutation that could never die. The reason to read the
checked value anyway is that the guard is what makes them equal: a consumer that
reaches past its own validator stops being covered the moment the validator
changes.

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
named, discard a status when its body is lost, accept object arguments, accept a
numeric assistant `content`, narrow the framing catch back to one exception,
write a malformed status line into a receipt, rebuild the replayed tool calls —
and requires the suite to turn red for every one. It verifies that each
substitution actually applied before believing the result: an anchor that no
longer matches runs a green suite and reports "not caught", which is the most
convincing way to be wrong about a test.

A mutated **gate** is answered by that gate's own `--self-test`, not by the
suite, so a contract a self-test does not exercise cannot be killed. Both
positive controls were extended rather than left to depend on that: the
discovery check runs a module that prints exactly one newline, and the
clean-tree check builds itself a HOME configured to break it — commit signing
on, a hook that exits 1, and `*.tmp` in `core.excludesFile`. The last of those
is the dangerous facet, because without isolation the untracked-file case goes
*quiet* rather than red, and a control that silently stops testing is worse than
one that fails. Every setup command in that self-test goes through `must_git`:
a preparation that did not happen used to surface as "a freshly committed tree
was reported dirty", which is the gate diagnosing its own failure as a defect in
the property it was checking.

Checks that no single mutation can reach are listed in that file as
**deliberately unmutated**, each with its own reason: a second guard holds the
same fact, the mutated behaviour is provably identical, or the difference only
shows on a machine CI is not. Writing a mutation that can never die is a worse
outcome than admitting the gap — it reads as coverage.

That is also why a new rule goes into the control rather than beside it. When
the discovery gate learned to refuse output it cannot decode, the arm that
proves it went into `--self-test` — a synthetic case that writes a raw `\xff` to
its own file descriptor — and the failure-to-verdict mapping became a function
so the control can reach that branch too. A decoding rule proved only by a test
the harness never runs would have been a certificate on a wall. Deleting an arm
outright is the one thing no control can catch about itself, and it is listed
with the others.

Every classification above except `NO_TERMINAL_ANSWER` is reached in one table
in `test_every_classification_is_declared`, and that one has its own
budget-exhaustion test; the table asserts the remainder is exactly
`{NO_TERMINAL_ANSWER}`, so adding a cause without reaching it turns the suite
red. A qualification whose failure paths can only be exercised against a real
provider is a qualification whose failure paths are never exercised.
