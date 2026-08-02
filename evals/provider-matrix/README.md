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

**"Exactly" is per field, because the three are not the same kind of string.**
One normalisation was applied to all of them — `claimed.strip().rstrip("/")` —
which is right for a URL, where a trailing slash is not part of the identity,
and wrong for the other two. `key_env` is the *name of an environment
variable*, and the run that follows reads the name the plan supplied:

```json
{"provider": "groq", "model": "m", "key_env": "GROQ_API_KEY/"}
```

compared equal to the registry, was admitted as agreeing, and then looked up a
variable the registry never named. `api_style` had the same hole. The generous
reading — that trailing punctuation is a typo — belongs to whoever writes the
file, not to the gate that verifies it: **a gate that repairs its input has
stopped comparing the input.** `AUTHORITY_COMPARISON` now names a rule for each
field and is indexed rather than `.get()`-ed, so a field added without one stops
the program instead of inheriting whichever rule happens to be first.

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

And the family has one more member, found the same way one round later. urllib
wraps a failure to *connect* in `URLError`; it does not wrap a failure that
happens once the socket is already up. A peer that resets the connection while
the status line is being read raises `ConnectionResetError` — a plain `OSError`
— straight out of `open`. Both body reads had caught `OSError` since round nine;
this boundary had not, so the one place the peer could still break the exchange
without being named was the first line of its reply. The broad clause sits
*below* `URLError`, which is itself an `OSError` and carries a `reason` this
module reads: a wide catch above a narrow one swallows the narrow one in
silence. The regression is a local listener that answers with half a status line
and closes with `SO_LINGER 0`, which is what a peer dropping a connection
actually does.

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

A `str` — and nothing about how long. The check also refused a `request_id`
past the local evidence bound, which turned a provider's choice of identifier
length into a crash on this side. Length is not a well-formedness property: the
producer is entitled to send an identifier of any size, and what this module
owes is a bounded record of it, which `opaque_text` already produces —
`request_id_bytes` with `request_id_oversize` beside it. A validator that
refuses what the contract can represent is not stricter, it is narrower, and
the difference shows up as a target that cannot be qualified for a reason that
has nothing to do with the protocol.

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

The three usage counters then wanted the opposite correction. One shared
`usage_ceiling` was computed from `response_limit`, which is a fact about the
*response*, while `usage_bounds` bounds the counters by the size of the
**request** this module sent — so a caller passing a small response limit made
the auditor refuse a `prompt_tokens` the producer had every reason to admit.
The same shared bound was slack for the other two: `completion_tokens` cannot
exceed the `max_tokens` this module asked for, and a bound that says only "some
number under the total" throws that away. Each counter now carries the bound
that produced it — `prompt_ceiling` from `MAX_REQUEST_BYTES`,
`completion_ceiling` from the per-kind generation limit, `usage_ceiling` their
sum — so the auditor's ceiling is the producer's ceiling rather than a second
number that happens to be larger.

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
verdict. That fix landed in one gate, and a reviewer found the same defect in a
second gate a round later, wearing the same clothes — which is not two bugs but
a boundary with no owner. `process_boundary.py` is that owner now; see below.

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

## Ownership is inventoried, not reviewed

Five rounds closed five instances of one defect, one per round: a value the
provider chose reached a durable artifact. Each repair above was correct. The
*method* was not — a contract enforced at the sites a reviewer happened to visit
has exactly as many exceptions as there are sites nobody visited. What was
missing is not another `if`. It is the statement that the set is **closed**, and
a machine that checks it.

Four things now have exactly one owner apiece, and each ownership claim is a
gate rather than a paragraph.

### 1. Every durable field

`receipt_policy.py` names **124 policies**, one per node and one per leaf either
receipt kind may contain. A path no policy names is a finding, not a skip —
which is the whole difference between an inventory and a spot check, because it
means a field added next round stops the gate on the commit that adds it.

| policy kind | what it admits |
| --- | --- |
| `Local(source)` | exactly the value the plan or the trusted registry already had |
| `Enum(name, values)` | a member of a closed local vocabulary |
| `BoundedInt(low, high)` | an integer, **both** ends bounded, `bool` refused |
| `Digest(domain)` | 64 hex under a domain declared in `EVIDENCE_DOMAINS` |
| `Shape(kind)` | a container — an object or an array, empty or not |
| `Flag()` | exactly `True` or `False`, never an integer wearing one |
| `BoundedNumber(low, high)` | a finite number, both ends bounded, `bool` refused |
| `Prose(max_bytes)` | a rendered line — as defence in depth; see §3 |

Provider-chosen material crosses only as a typed projection, never as itself.

Running it found three things five rounds of review had not:

* `transport_target.endpoint` was copied from the plan row *before* anything
  verified it, so a receipt that correctly classified `ENDPOINT_REJECTED` still
  carried the rejected host as a durable field.
* `transport_reason` could hold a member of either of two enums depending on
  which sender produced it — its fallback answered in the *turn outcome*
  vocabulary — so one field had two vocabularies and therefore none.
* `request_bytes` was unbounded, on the grounds that this module composed it
  itself. Provenance is not a bound.

The context the audit checks against is assembled from the plan, the registry
and the caller's own claim about which receipt it asked for — never from the
receipt. A context read out of the artifact under audit confirms whatever the
artifact says, and every `Local` policy degrades to *this value equals itself*.

**A path is structure, not notation.** While a path was a dotted string,
`"turns[].detail"` was two different things at once: what the path
`(Key("turns"), Each(), Key("detail"))` renders as, and what a single
provider-chosen top-level key spelled `turns[].detail` renders as. The second
therefore matched the policy written for the first and audited clean. Escaping
`.` and `[]` would have been the third patch on a representation problem, so the
representation changed instead:

```python
Path = tuple[Key | Each | BadKey, ...]
```

`Key` is one object member, `Each` is any array element, and `BadKey` is a
dictionary key that is not a string — which `str(key)` would otherwise have
laundered into something indistinguishable from a declared component. No policy
can name a `BadKey`, so it always stops the gate, and its rendering carries the
key's *type* and never its value. Strings appear when a finding is printed and
nowhere else.

**A container is a path, and a key is durable.** The first version of `flatten`
yielded leaves only, and said so as a principle: an empty list or object *has*
no leaves, so inventing one would report on something the artifact does not
contain. That was wrong, and a reviewer produced the counterexample to the
round's own theorem —

```python
receipt["provider_said"] = {"sk-live-secret": {}}
```

— which yielded nothing at all, so the closed-world audit answered `[]` for an
artifact carrying a provider-chosen **key**. A JSON key is written to the file
exactly as a JSON value is; calling it "not a leaf" removed it from the check
and not from disk. Every container is now a node with a path and a policy, so
the table describes the *shape* of the artifact rather than only its scalars.

Following from the same counterexample: an unknown-path finding projects every
component the table does not declare, because a gate that prints the key it is
refusing to persist has moved the leak into the CI log. That projection walks
the declared paths as a tree and is **prefix-sensitive**: it first asked only
whether a component appeared *anywhere* in the table, so
`provider_said.detail.name.ordinal` printed three provider-chosen keys verbatim
— each of them a real component somewhere else in the tree, none of them
declared there. A name known in another branch is not a name known here, and
once a step is unrecognised every step below it is foreign too.

**Coverage is asked of the table, not of the verdicts.** The first version
asserted that the scenarios reached every classification and treated that as
coverage. It is not: a classification is a verdict and a policy is a place.
Twelve of the then hundred and nine policies were never produced by any
generated receipt — `reported_model_type`, the per-turn failure-class
projection, two of the three usage counters — so weakening any of the twelve
left every gate green. Each policy now declares which receipt kinds it applies
to, and `coverage_gaps()` subtracts the paths a real run produced from the paths
that kind must be able to produce. The suite requires the difference to be empty
**per receipt kind**: a qualification-only path satisfied by a qualification
scenario says nothing about the probe, and a union would hide exactly that.

The scenarios were then added until the gate stopped listing gaps, in that
order — the other order is a sixth reviewed-site repair in a new jacket. The
gate found something on its first run too: five top-level identity paths were
declared for both receipt kinds when only the probe can produce them, so each
was passing on the other's evidence.

**And it subtracts in both directions**, because one direction cannot see a
declaration that is simply false. `required - reached` finds a policy no run
exercises; `reached - declared` finds a path a real run *did* produce for a kind
whose policy says that kind does not produce it. Marking a shared policy
probe-only leaves qualification writing the field with nothing missing and the
gate perfectly green — so `Coverage` reports `missing` and `wrong_schema`
separately.

`coverage_required=False` is the escape hatch from all of this, so it costs a
sentence: a policy excused from coverage must carry a stated reason, and
`policy_problems` refuses one that does not. `mutations.py` has required a
written reason for every deliberately unmutated check since round nine; the same
rule belongs here, before somebody reaches for the hatch with a label reading
"internal use".

There was a second hatch, reachable by typo rather than by intent.
`schemas=("proeb",)` put a policy in *neither* universe — demanded of no receipt
kind, declared for no receipt kind — so both directions of the coverage proof
went green by the policy simply vanishing from each. The vocabulary is a closed
type now, `ReceiptKind`, and membership is checked at runtime rather than left
to the annotation, which stands beside a program and offers moral support while
it does as it pleases.

**The check has one site, and that is not a stylistic preference.** It was first
written at all four public queries, which looks like defence in depth and is
not: `coverage` calls `applicable_paths` and `coverage_gaps` calls `coverage`,
so any three of the four could be deleted one at a time with nothing going red.
The mutation table said so out loud — a mutation removing the guard from
`coverage_gaps` survived, because the guard below it caught the same string. A
check no proof can distinguish from its own absence is not a check; it is a
comment with a runtime cost, and it makes the next reader believe a property is
enforced in four places when it is enforced in one. Selection is the door now
— `policies_for` — every query goes through it, and *bypassing* it is a
mutation each query can be caught committing.

### 2. Every verdict

Eighteen `receipt.update(classification=...)` calls became one writer:

```text
facts (typed, all local)  →  reduce_*  →  Decision  →  apply_decision
```

`apply_decision` is the only function that writes `classification`,
`decision_reason`, `detail_template` or `detail`, and an AST gate enforces that
rather than trusting it. Both classification vocabularies are closed and keyed
by schema — the probe's had never been written down, so a typo there would have
produced a receipt with a verdict no consumer knows. `EndpointRejected` carries
a reason from a closed vocabulary, so `str(exc)` no longer decides what a
durable field says. The reducers read typed facts: `reduce_transport` reads
`sent.reason`, never `sent.detail`, which the probe path was still doing a full
round after the qualification path stopped.

### 3. Every rendered line

The first version of this inventory shipped one check that overstated what it
proved, and the correction is worth stating plainly:

> `Prose` established that a line belonged to the module's lexical language. It
> did not establish that the module had produced *that particular line* from
> locally owned facts.

A provider can send `"timeout"`, or `"the completion carried the probe token"`,
or sixteen hex characters. Every one of those is made of local words and local
bytes. This vertical had already withdrawn that argument twice — for
`str.isidentifier()` on a failure class, then for sixty-four hex characters on a
digest — and the third withdrawal would have been inside the auditor built to
retire it.

So a detail is not text at the layer that decides it. `Decision.detail` is a
`LocalDetail`: a template from a closed table plus **typed** arguments, where
provider-chosen material can only appear as an `OpaqueRef` — a domain, a digest
and a bounded length, with no way to spell anything else. Validation lives in
`__post_init__`, so an inadmissible line cannot be constructed at all.

Then the proof: every durable `detail` travels with the `detail_template` it was
rendered from, and the audit **rebuilds** the line's grammar from that
template's declared slots — each slot's own vocabulary, the reference grammar,
the bounded counts, and trusted local values taken from the audit context rather
than from the receipt. An `OpaqueRef` must be computed from the value it stands
for, so a wrapper around the empty string is refused too: a reference that
digests something else is evidence about nothing. `Prose` stays as a lexical
defence in depth and no longer pretends to be a provenance proof.

Converting the message producers to typed values closed three **live** leaks
that no reviewer had named and the lexical check had never been shown, all three
in the byte-envelope oracle, all three reaching `detail` through the canary's
grading of a terminal answer:

* the character a strict base64 decoder rejected, interpolated as `{ch!r}`;
* the name of an unknown envelope field, interpolated as `{key!r}`;
* the provider's own `data` spelling, interpolated as `{data!r}`.

Five AST gates keep the construction path closed: no literal or f-string may
reach `Decision(..., detail)`; every `LocalDetail` must name a registered
template *and* every registered template must be built somewhere; only
`DigestRef.of` shortens a digest; only `OpaqueRef.render` spells a reference;
and only `apply_decision` and `record_detail` write a line into an artifact.

### 4. Every subprocess

`process_boundary.py` is the one place in this vertical that starts a process.
`run_bytes` returns bytes — `text=False` is the point, since a decode made
inside a library is a decode nobody caught — and decoding is a declared
per-call policy: `decode_output` for a child whose output contract is UTF-8, so
invalid bytes are a typed failure; `decode_path` for git, whose filenames are
arbitrary bytes by design. Failures never repeat what caused them, because
`UnicodeDecodeError`'s message contains the offending bytes and a child's stderr
is whatever the child chose to write. Children also get `stdin=DEVNULL` rather
than the parent's descriptor: a child that reads the terminal used to block
until its deadline, so a harness with a ten-minute timeout waited ten minutes
to learn nothing, and on a machine with no terminal it would have failed for a
third, unrelated reason. `DEVNULL` gives it an immediate EOF, which is the
honest answer to "was anything typed". All four gate consumers and the mutation
harness are migrated onto it; the test suite is the one stated exemption,
because it runs the CLI end to end and patches `subprocess.run` to prove the
gates report rather than raise.

The AST gate that enforces this began by matching the word `subprocess`, which
made it an assertion about a module name under a docstring claiming a property:
`os.system`, `os.popen`, `asyncio.create_subprocess_exec` and `pty.spawn` all
start processes and all stayed green. A theorem quietly renamed after a
counterexample is worth less than the counterexample, so the gate covers the
direct standard-library launch surface — `subprocess.*`, the `os` exec/spawn/
fork family, `asyncio.create_subprocess_*`, `multiprocessing`, `pty` — with a
negative specimen per class.

Two more things were asserted of a package and true of a directory. The
enumeration used `glob("*.py")` and never saw a nested module, so a future
`helpers/runner.py` could have called `subprocess.run` with the gate green; it
is recursive now, and exemptions are exact relative paths rather than bare
filenames, because `path.name` would hand a nested file wearing an exempt name
the same immunity as the real one. And import aliases were resolved while plain
assignment was not, so `launcher = os` walked past the check that caught
`import os as launcher`; assignment chains are followed to a fixed point.

Then the same lesson arrived once more, and this time as a rule rather than a
repair. Import aliases and plain assignment were resolved; tuple unpacking, a
walrus and a parameter default were not, and an `if` for each would have been
the next round's finding — `for launcher in [os]`, `run(os)`, `return os`,
`box = [os]`, `yield subprocess`. The list of ways to move a value in Python is
not a list anybody finishes.

So the gate states what is **allowed**. Outside `process_boundary.py` a launcher
may be imported, aliased by plain `name = name`, and inspected as an attribute.
Every other movement is a finding on its own — not because the value is proven
to reach a launch, but because it has left the grammar in which that could be
proven. Storing one on an attribute or in a mapping, passing it as an argument,
returning it, yielding it, putting it in a list: each is refused where it
happens, and no points-to analysis is attempted, because a gate that grows into
one quietly stops being a gate.

What a static check cannot reach at all, `importlib.import_module("subprocess")`
and a computed `getattr`, is listed in `mutations.py` with the other
deliberately unmutated gaps rather than left implied: closing it needs a runtime
audit hook, not a wider pattern.

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

### The bounded fields are a closed set, not a list of repaired ones

Round eighteen closed two fields where the policy stated a ceiling the producer
had never been told about. The next review found a third the same way it had
found the first two — which is not bad luck. It is the signal that repairing
the sites somebody points at was still the method in use, three rounds after
that method was supposedly retired.

So the class is closed rather than its third instance. Four claims, each
machine-checked:

**1. The set is closed in both directions.** `BOUND_ENFORCEMENT` names a
producer-side strategy for every policy that states a quantity — a byte bound,
an integer ceiling, a bounded number — and `enforcement_problems` reports a
bounded policy with no entry *and* an entry for a field that no longer has a
bound. One direction alone would let a ceiling be added without an owner, or an
owner outlive the ceiling it was written for. There are exactly three
strategies:

| | past the bound |
| --- | --- |
| `Refuse` | the verdict changes; the ordinary artifact is not built |
| `Project` | a bounded prefix is kept, with an explicit truncation flag |
| `Derive` | there is no past-the-bound case; the entry says what prevents it |

`Refuse` also carries a `source`, because who can reach the overrun decides
what a correct refusal looks like. A quantity a **provider** chooses must end in
a classification about the exchange; filing it as `INTERNAL_ERROR` says this
tool broke, which is the round-nine mistake in a new field. A quantity only an
injected **sender** can produce is a broken caller, and `INTERNAL_ERROR` is then
the honest answer.

**2. `Refuse` and `Project` carry witnesses, at the bound and one past it.**
Each is run through the real pipeline; the receipt must audit clean in both
cases, and a `Refuse` must actually have refused — the field absent *and* the
classification something other than our own crash. The second half of that
assertion found two defects the moment it was written.

**3. `Derive` carries no witness, and that is a stated gap rather than a
convenience.** Its claim is that no past-the-bound case exists, so there is
nothing to build. What it costs instead is a sentence naming what does the
bounding — "it is local" is not an answer, since round fourteen retired that
argument for `request_bytes`, which this module also composed. The risk that
somebody relabels a `Refuse` as a `Derive` to avoid writing a witness is real
and is **not** closed here. It is named, in the code and here, because a gap
that is written down is a gap somebody can find.

**4. The closure is a shipped gate, not a test.** `receipt_policy.py
--self-test` runs it, with positive controls for all three refusals, so a
quantitative bound with no owner turns CI red rather than waiting to be
noticed.

The gate found five things while it was being built, which is the argument for
building it rather than patching the third instance:

* **One request-size boundary, before the credential.** Only the qualification
  path checked the size of the body it was about to send, so a single oversized
  discovery row made the probe transmit an arbitrarily large *authenticated*
  request. Both paths compose through `bounded_request` now, and the refusal
  happens before `send` is reached.
* **An oversized request is an endpoint refusal, not our crash.** The
  qualification path called it "a defect in this tool" and raised it as
  `INTERNAL_ERROR`. The model id comes from the untrusted catalog, so an
  oversized body is something a row can *cause*; filing it as our own crash
  blames the matrix for bytes it did not choose. It is `ENDPOINT_REJECTED` with
  a reason from the closed vocabulary, in both paths, and inside the loop as
  well as before it.
* **The probe records the request it sent.** It had neither the bound nor the
  evidence — the asymmetry ran both ways.
* **A three-digit status is an observation.** `is_http_status` refused anything
  past 599, and `http.client` parses any three-digit status line, so
  `HTTP/1.1 600 Nope` from a hostile peer raised out of the transport and became
  `INTERNAL_ERROR`. An unassigned code is still something that happened; what it
  is not is a success, and `classify_http` files it as `HTTP_FAILURE`. Past
  three digits is a *sender* rather than a peer — `_read_status` raises
  `BadStatusLine` — and the entry says so as a premise that can be checked.
* **The canary diagnostics are a bounded projection.** The finding that opened
  the round: one rendered line per unsupported citation, joined whole into
  `detail`, so a hundred validly shaped citations produced a nine-kilobyte line
  past the `Prose` bound. The evidence is a prefix now, the kinds and the digest
  describe that same prefix, and `detail` carries a count instead of the
  findings — the provider's chosen multiplicity was crossing the durable
  boundary twice, and the second crossing is the one that broke the bound. Under
  truncation the line says **at least**, because a lower bound must not be
  mistakeable for an exact one.

### The producer applies the bounds the auditor checks

A ceiling declared in `receipt_policy.py` and nowhere else is not a bound; it
is an opinion the producer has never been told about. Two of them were exactly
that, and both were reachable with an unremarkable response — 1,026 well-formed
tool calls, or arguments violating 1,025 schema rules in three kilobytes, sit
inside every byte limit this module applies. The result was a receipt written
to disk that its own `audit()` then reported a finding against. An artifact
that fails the audit of the module that wrote it means there are two contracts,
and the one on disk is the one that loses.

The numbers live where enforcement happens, and the policy context reads them:

```text
MAX_TOOL_CALLS       the producer's cardinality bound
MAX_CALL_ORDINAL     MAX_TOOL_CALLS - 1
MAX_ARGUMENT_ERRORS  how many violations one turn may record
```

The second name exists because the two are **not the same number**.
`call_ceiling: 1024` bounded an *ordinal*, and ordinals start at zero, so it
admitted 1,025 calls — one more than the producer's own limit. Both numbers
were defensible in isolation and incompatible together, which is what a shared
name hides.

The two overruns are treated differently, because they are different kinds of
fact. **Too many tool calls is a protocol failure**, refused before a single
ordinal is assigned: enumerating first and discovering at audit time is the
defect, not the diagnosis. **Too many argument errors is not** — the arguments
are malformed whether there are twenty or eleven hundred, and the count is
description rather than verdict.

That second one is why `min(len(errors), MAX)` was the one repair unavailable:
the field would have kept the name `count` and stopped being one. So the
evidence describes a *prefix*, and every neighbouring field describes the same
prefix:

| field | with `truncated: false` | with `truncated: true` |
| --- | --- | --- |
| `argument_errors_count` | the number of violations | how many are recorded — a lower bound on how many there were |
| `argument_errors_kinds` | the kinds among them | the kinds among the recorded ones |
| `argument_errors_sha256` | a digest of them | a digest of the recorded ones |

A reader acting on a truncated receipt is told the arguments were malformed,
given a lower bound, and told it is a lower bound. What they are never given is
a number that looks exact and is not.

The invariant the round is about is asserted directly, at each boundary and one
past it:

```text
for every reachable provider response:
    audit(produce(response)) == clean
```

**One mutation was written, survived, and was right to.** Replacing
`pm.MAX_ARGUMENT_ERRORS` in the policy context with the literal `1024` changed
nothing observable, because it equals that constant today. The contract is that
the two numbers *agree*, so the mutation now makes them disagree. Worth being
explicit about what that does and does not cover: writing the literal back is
still invisible to the mutation table, and what catches it is the **test**,
which compares against `pm.MAX_ARGUMENT_ERRORS` rather than against 1024 — so
the day the constant changes, a stale literal fails. The coupling is enforced;
it is just not the mutation that enforces it.

### A receipt's file name is derived from an untrusted string

The model id comes from discovery, and it becomes part of a path. The first
version escaped three characters — `%`, `/`, `\` — because model ids routinely
carry a slash and `out_dir / f"{target_id}.json"` would turn that into a
directory. Three is the wrong number for the same reason a list of exception
names was: it is the set somebody thought of.

```json
{"model": "a\u0000b"}          → ValueError: embedded null byte
{"model": "aaaa…" × 300}  → OSError: File name too long
```

Both raise from *outside* every receipt boundary, so one row in a catalog ended
the run and denied every later target its evidence — which is precisely what
`guarded_receipt` exists to prevent, met one step further along. Two repairs,
because there were two defects:

* The name is total by construction. Every byte outside a declared alphabet is
  percent-escaped, `%` included, so the rule is the alphabet rather than a list
  of dangerous characters to keep current. The stem is bounded and a
  domain-separated digest of the whole id is appended, so truncation cannot make
  two ids share a path. The digest is not shortened — a file name is not
  evidence and has no budget to spend — and a gate that allows exactly two
  constructors to shorten a digest is what said so before this one could become
  the exception.
* The **write** moved inside the boundary. `guarded_receipt` wrapped the run and
  not the write, so the property it states held for everything a target could do
  except the last thing done with it. A failed write now costs that target and
  reports at the end; the run continues and still exits non-zero, because
  "continued" and "succeeded" are different claims and a partial matrix must not
  be readable as a complete one.

The problem line names the position and the exception class, never the path: the
path contains a model name the discovery source chose, and that line is printed.

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

**Identity is one sum type, and every reader is a projection of it.**

```python
model_identity(requested, reported)
    -> VerifiedModel | MissingModel | TextSubstitution | NonTextModel
```

Three readers used to answer that question separately and disagree.
`model_evidence` called `model: {}` *present* and wrote no digest beside it;
`model_status_of` called the same value *missing*; and the terminal-answer path
assumed every entry that was present-and-not-verified carried a digest, so a
provider putting an object in `model` raised `KeyError` and the crash was filed
as `INTERNAL_ERROR` — a run the provider broke, blamed on this tool.

`.get()` at the indexing site would have made the crash go away and left the
disagreement in place. *Present* and *digest-bearing string substitution* are
not the same fact, and the type is where that has to be said. The reducer now
receives typed `substituted_digests` and `substituted_types` accumulated in the
loop rather than reading the durable fold back — a consumer that owns its
boundary does not learn its facts from its own artifact — and drift renders in
three shapes: names only, non-names only, or both.

An empty `model` is `MissingModel` throughout, where it used to be
`present: True` from one function and `missing` from another at the same time.
The provider sent a value; it establishes no identity; both readers now say so.

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

# the durable-field policy is consistent, and can refuse a receipt
python3 evals/provider-matrix/receipt_policy.py --self-test

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
write a malformed status line into a receipt, rebuild the replayed tool calls,
skip a leaf no policy names, widen a slot pattern to anything, let a raw string
into a `Decision` — and requires an oracle to turn red for every one. It
verifies that each substitution actually applied before believing the result: an
anchor that no longer matches runs a green suite and reports "not caught", which
is the most convincing way to be wrong about a test.

**A target names its oracles.** The harness used to run a dichotomy: a gate was
answered by its own `--self-test` and *only* by it, everything else by the suite
and only by it. That was disclosed as a known limit for five rounds, which is
another way of saying it had become a design decision — and it cost real
coverage, since a mutation to a gate that the suite would have caught was
reported as killed by a control that never looked. `MUTATION_TARGETS` now maps
each mutable file to the oracles that may object to it, **every** one of them is
asked, and the harness reports which ones did. `process_boundary.py` answers to
both gate self-tests *and* the suite; before the table it had exactly one
oracle, chosen by nothing but which `if` its filename fell into.

**A kill is evidence only if the mutant was a program.** `DF9` referred to a
name that no longer existed in the function it mutated, so every oracle died of
`NameError` before a single policy compared anything — and "210/210 mutations
killed" was arithmetically true and evidentially false, with one corpse a
passer-by.

The first repair listed the exception names to refuse, which was the wrong
shape: `NameError` was on the list because a mutation had died of one, and
tomorrow's `RuntimeError` would have been the next neighbouring defect found one
at a time. Coherence is structural now. An `OracleResult` carries its label,
kind, output and discovered test count, and **a suite run that never says how
many tests it found did not get far enough to run any**, whatever it died of.
Anything incoherent is reported as `INVALID` rather than as a kill.

The rule is asked of the suite alone, and by oracle *kind* rather than by
scanning all the output together. Several gate mutations exist precisely to make
a gate die of a traceback instead of printing a report, so demanding a verdict
line from a gate would refuse the very kill that proves the contract. Every
target must therefore name a suite oracle to anchor coherence on, which
`target_problems` checks.

**Where the claim is about ownership, the kill is attributed.** `EXPECTED_KILL`
names, for each such mutation, a test that must appear in **the failing
oracle's own output** — not in a concatenation of every oracle's, where a test
id can arrive from a run that passed. Anything else is `MISATTRIBUTED`. That
check earned itself immediately: five mutations were killed by something other
than the contract they name, one of them because a coverage gate that reports
nothing keeps its own green assertion green — so the test that proves it is the
positive control, not the assertion that shares its subject.

**Five ways to prove the wrong thing, found in one round.** The nine repairs
this round arrived with nine new proofs, and the mutation table killed only
five of them on the first pass. The four survivors — plus one more on the
second pass — were not weak tests. Each asserted something true, and each held
for a reason other than the property it was named after:

* *A freshly built object instead of the shipped table.* The usage-ceiling test
  constructed a `BoundedInt(0, "completion_ceiling")` and asked it to refuse an
  oversized count. It does. That proves `BoundedInt` works; it says nothing
  about which ceiling `completion_tokens` was *declared* with, so collapsing
  the three ceilings back into one changed nothing the test looked at.
* *One guard smeared across several mutually covering places.* Described above:
  four checks, three of them deletable one at a time in silence.
* *The parts instead of the caller that produces the verdict.* The clean-tree
  regression exercised `repo_root` and `dirt` with an isolated environment.
  Both accepted isolation before this round — `main`, the one caller that
  actually reports, did not, and that was the entire defect. A test aimed at
  the pieces cannot see a caller that fails to use them.
* *A liveness test the environment had already satisfied.* The child was run
  with whatever stdin the runner had, which under CI is already `/dev/null`,
  so it passed with the inherited descriptor restored. The parent now gets a
  pipe nobody writes to and nobody closes, which makes `DEVNULL` the difference
  between the two outcomes rather than a preference.
* *A mutation spec pointing at where the code used to be.* Moving the coverage
  filter into `policies_for` orphaned `CV2`'s anchor. This one the harness
  caught by itself — `anchor matched 0 times, not 1`, reported as unaccounted
  rather than counted as a kill.

The last is the reason the anchor check exists, and it is worth being explicit
about what it bought: the run could have reported 256 of 256 by quietly
counting a substitution that never happened. Refusing to improve its own
statistic is a low bar for a person and a reasonable one for a harness.

No earlier, faster anchor check was added alongside it. It would read the same
pristine source the run already reads, and could differ from its absence only
in how long the answer takes — which is precisely the objection this round
raised against the guard written four functions deep.

**A test can also be green because of how the kernel sliced a stream.** The
listener several transport regressions run against called `conn.recv(65536)`
once, which reads whatever has arrived rather than the request. Qualification
bodies carry the whole tool surface and run to kilobytes, so a split between
headers and body is ordinary; answering with unread bytes still queued can
provoke an RST on close, and the client then reports a transport failure where
the test asserts a 200. Nothing was wrong on any particular day, which is the
problem — the outcome depended on segmentation rather than on the contract.

`read_http_request` reads to the end of the headers, parses `Content-Length`,
and reads exactly that many bytes, failing closed on a peer that stops early, a
length that is not a number, and a length past a local bound. It is driven
through a socket that fragments on purpose, at three different points, because
a regression that waits for the real network to misbehave is a regression that
tests the network.

Both positive controls were extended rather than left to depend on the old
limit: the discovery check runs a module that prints exactly one newline, and the
clean-tree check builds itself a HOME configured to break it — commit signing
on, a hook that exits 1, and `*.tmp` in `core.excludesFile`. The last of those
is the dangerous facet, because without isolation the untracked-file case goes
*quiet* rather than red, and a control that silently stops testing is worse than
one that fails. Every setup command in that self-test goes through `must_git`:
a preparation that did not happen used to surface as "a freshly committed tree
was reported dirty", which is the gate diagnosing its own failure as a defect in
the property it was checking.

And the **real** verdict runs under the same isolation the control builds for
itself. It did not, and the asymmetry was the defect in miniature: the control
proved the check survives a hostile machine, while the invocation that actually
reports ran with ambient `os.environ`. An inherited `GIT_DIR` or `GIT_WORK_TREE`
points both `rev-parse` and `status` at somebody else's repository, and a global
`core.excludesFile` hides untracked leftovers — after which the gate prints `OK`
about a tree it never looked at. A committed `.gitignore` still applies; it is
part of the reviewed tree, which is exactly the difference. The regression for
it copies the gate into a dirty repository of its own and *runs* it under a
hostile `GIT_DIR`, asserting both that the verdict is about the right tree and
that the hijack it survives is real — a control that only proves the first half
cannot tell isolation from decoration.

`receipt_policy.py --self-test` is the third control, and it exists for the same
reason as the other two: a table that has never refused anything is a table
nobody has tested. It carries nine defective specimens — an unnamed leaf, an
unbounded integer, a foreign word in a line, a byte outside the local alphabet,
a boolean wearing an HTTP status, an invented decision reason, a value that is
not the local one, a line whose words are local but which this module never
renders, and a line that disagrees with its own template — and requires every
one to be refused, plus a duplicated policy and a digest policy naming an
undeclared domain to be reported against the table itself.

**A specimen must stand on the contract, not on the interpreter.** `U4` removes
the depth pre-scan from the one deliberately lenient parse, and its regression
used to rely on a forty-thousand-level body raising `RecursionError`. CPython
3.14 parses that body, so on a newer interpreter the mutation stopped changing
the answer and survived — it had been dying of a platform accident rather than
of the contract it names. The specimen now stands on the declared boundary:
one level past `MAX_JSON_DEPTH` the body is not interpreted and the rejection is
the ordinary one, one level inside it the same body is read and the cause is the
specific one. The two classifications differ on any interpreter, and a second
test asserts the specimen is *readable*, so it cannot quietly go back to testing
the stack.

Checks that no single mutation can reach are listed in that file as
**deliberately unmutated**, each with its own reason: a second guard holds the
same fact, the mutated behaviour is provably identical, or the difference only
shows on a machine CI is not. Writing a mutation that can never die is a worse
outcome than admitting the gap — it reads as coverage.

The seventeenth round added one by withdrawing a mutation that had already been
written and had already survived: the `isinstance(claimed, str)` guard in
`verify_against_registry`. A plan reaches it from `strict_json_loads`, so the
value is a JSON type, and no JSON non-string renders as `"GROQ_API_KEY"` — the
guard therefore refuses exactly what the previous `str(claimed)` comparison
refused, on every input that can arrive. The alternative was a specimen with a
hand-written `__str__`, which is a test for a program that cannot exist.

The reason is phrased as *"a plan arrives from the strict JSON reader"* rather
than *"such an input cannot occur"*, and the difference is load-bearing. The
first names a premise that can be checked and can later become false; the second
is unfalsifiable, and an unfalsifiable reason in this list is how a stated gap
turns into a forgotten one. If a path ever puts an object into a plan without
crossing that reader, this entry is wrong — and nothing would report it, because
there is no mutation there to die.

That is also why a new rule goes into the control rather than beside it. When
the discovery gate learned to refuse output it cannot decode, the arm that
proves it went into `--self-test` — a synthetic case that writes a raw `\xff` to
its own file descriptor — and the failure-to-verdict mapping became a function
so the control can reach that branch too. A decoding rule proved only by a test
the harness never runs would have been a certificate on a wall. Deleting an arm
outright is the one thing no control can catch about itself, and it is listed
with the others.

**A spec whose anchor stops matching happened twice, and stayed a build failure
both times.** `CV2` in the sixteenth round and `E1` in the seventeenth were the
same shape: a refactor moved the line a spec pointed at, so the substitution
never applied. The run reported each as `anchor matched 0 times, not 1`,
declined to count it among the killed, and exited non-zero — CI went red on
`ed2eacd` and on `eb958e0` for exactly this. No second, earlier anchor check was
added either time: it would read the same pristine source the run already reads
and could differ from its absence only in how long the answer takes. What
changed instead is how a run is started — every anchor is verified once before
a twenty-minute run rather than after it, which is a fix to the procedure, not
to the check.

The counts, from CI on the head this describes: **413 tests**, found identically
by `python3 test_provider_matrix.py` and by `python3 -m unittest`; **288 of 288
mutations killed**, none of them invalid, misattributed or unanchored; **124 durable-field
policies**, of which **36 state a quantity and every one names the producer that
applies it** with **9 defective specimens refused** and no coverage gaps in either
direction on either receipt kind; **49 JSON admission cases** against the live
`serde_json` oracle, one of them refused here on purpose; and a byte-clean
checkout asserted by a check that proves it can say otherwise.

Every classification above except two is reached in one table in
`test_every_classification_is_declared`; the table asserts the remainder is
exactly `{NO_TERMINAL_ANSWER, INTERNAL_ERROR}`, so adding a cause without
reaching it turns the suite red. Both exceptions are reached elsewhere —
`NO_TERMINAL_ANSWER` by the budget-exhaustion test, `INTERNAL_ERROR` by
`MatrixIsolationTests` — because the table drives the loop with a scripted
sender and neither cause comes from a reply.

This paragraph named one of the two for several rounds while the assertion
named both, and it read exactly like a true one. It is checked now:
`ReadmeContractTests` compares the set spelled here against the set the suite
asserts, and the two classification blocks above against the tuples the code
emits from. A qualification whose failure paths can only be exercised against a real
provider is a qualification whose failure paths are never exercised.
