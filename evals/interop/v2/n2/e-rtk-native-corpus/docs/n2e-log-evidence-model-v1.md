# N2-E Loghub evidence model (log-evidence-capsule-v1)

Frozen design contract for the ninth vertical (`loghub::HDFS::log`, `rtk_command_oracle`,
oracle `rtk-log-hdfs-oracle-v1`, canon `log-v1` → this model's `log-hdfs-v1`). Authored BEFORE
any CI qualification run. The full RAW stream (`cat HDFS.log`, ~1.5 GB uncompressed from the
Zenodo `HDFS.zip`, 321 944 794 B compressed, `md5:f23880dd4938379a535ab71a8d27a798`) is NEVER
committed. It is represented by a compact, deterministic, independently-verifiable
**evidence capsule**.

## Why the pilot is not the model

`n2e-log-qualification-pilot-v1.json` and today's `acquire_loghub` read the whole archive +
whole log into memory and then slice to the first 1500 lines, discarding the rest. That is
elegantly-formatted data loss, not bounded evidence. This model replaces BOTH the memory
profile (streaming, O(1)+O(templates) memory) and the truncation (the full stream is read to
EOF and hashed; only the *record* and *memory* are bounded, never the verified data region).

## Bounded ≠ truncated — the two-path invariant

The full stream is consumed EXACTLY ONCE, in fixed-size chunks, through two paths that both
reach EOF:

1. **Full-byte hash path** — every byte flows through `sha256`; a running byte counter; and a
   per-chunk hash list whose Merkle root is pinned. Memory: O(chunk) + O(chunk_count·32B); the
   capsule stores only the root + inclusion proofs for excerpt chunks, so the capsule size is
   independent of stream size.
2. **Bounded semantic extractor** — line-framed (newline, residual buffer across chunk
   boundaries), each line parsed by the declared `log-hdfs-v1` canon into
   `(severity, template_id)`; updates a severity counter and a per-template table
   `{count, first_occurrence, last_occurrence}`. The table is capped at `TEMPLATE_CAP`
   distinct templates; **overflow fails closed** (`DISQUALIFIED_TEMPLATE_CARDINALITY`) — a log
   whose masking yields unbounded "templates" is a canon inadequacy, never a silent pass.

Bounded memory guarantees: chunk hashing is O(1) rolling + a bounded root; the template table
is capped; excerpts are capped in count and window size.

## The `log-hdfs-v1` canon (declared, ordered)

- **Framing**: split on `\n`; the trailing partial line at a chunk boundary is carried in a
  residual buffer; a final unterminated line is a real line. No truncation for hashing.
- **Encoding**: bytes; decode per-line `utf-8` with `replace` ONLY for template derivation; the
  hash is over raw bytes.
- **Line grammar**: HDFS `YYMMDD HHMMSS PID LEVEL COMPONENT: MESSAGE`. `LEVEL ∈
  {INFO,WARN,WARNING,ERROR,FATAL,DEBUG}` (others → `other`). A line that does not match is
  `severity=unparsed`, `template=<unparsed>` (counted, never dropped).
- **Template masking** (ordered, exact grammar only): `blk_-?\d+ → blk_<*>`; IPv4[:port] `→
  <ip>`; `/`-rooted paths `→ <path>`; standalone integers `→ <num>`. `template_id =
  sha256(component + "\x00" + masked_message)[:16]`. Masking touches only these forms; a real
  message difference survives (mutation-tested).

## Capsule schema (`n2e-log-evidence-capsule`)

```
stream:  { role, invoked_argv, exit_status, bytes, sha256, read_to_eof,
           chunking: { chunk_bytes, chunk_count, merkle_root } }
canon:   { dialect: "log-hdfs-v1", module_sha256, framing, encoding, masking_rules,
           template_cap, truncation_policy: "none-for-hashing" }
summary: { outcome, total_lines, severity_counts, unique_template_count,
           unique_template_ids[sorted], occurrence_counts, first_last_occurrence,
           overflow, summary_sha256 }
excerpts:[ { stream, template_id, byte_start, byte_end, chunk_index, chunk_sha256,
             merkle_proof[], sha256, content } ]   # ≤ MAX_EXCERPTS, each ≤ MAX_EXCERPT_BYTES
identities: { rtk_binary_sha256, source_revision, environment }
```

`summary_sha256` covers the semantic summary bytes; `stream.sha256` is the full-stream digest.

## RAW ↔ RTK semantic contract

Both arms produce a capsule. RAW (`cat HDFS.log`) is the huge stream → full streaming capsule.
RTK (`rtk log HDFS.log`) is itself a compact summary → small stream, same capsule shape, but
its `summary` is parsed from rtk's reported output by `rtk-log-hdfs-oracle-v1`. Equivalence is
decided on the FROZEN criterion fields — `severity_counts`, `unique_template_ids` (as a set),
`occurrence_counts` (per id), `first_last_occurrence` — NOT any text overlap. The oracle
compares only the fields rtk actually reports; a field rtk does not preserve makes the case
fail equivalence, never silently pass. The RAW capsule is the reference the RTK summary is
judged against.

## Independent verifiability (verifier replay obligations)

Given the capsule + the two frozen streams (RAW is retained as the source archive identity +
the capsule; RTK's small output is retained verbatim), the independent verifier re-derives and
MUST confirm:

- the full stream was read to EOF (`read_to_eof` true AND re-streamed byte count == `bytes`);
- `stream.sha256` == streaming re-hash; every chunk hash + Merkle root re-derive;
- `summary` == re-extraction through the pinned `log-hdfs-v1` canon module (`module_sha256`
  matches current code — frozen-code drift is fail-closed);
- each excerpt's `content` == the bytes at `[byte_start,byte_end)`, its `chunk_sha256` covers
  that range, and its `merkle_proof` re-roots to `merkle_root`;
- RAW↔RTK compared through the frozen semantic contract above.

For the >1 GB RAW stream the verifier replays from the acquisition (re-fetch by pinned
Zenodo checksum + stream), NOT from a committed 1.5 GB blob: the committed evidence is the
capsule + the checksum-pinned source identity, and the streaming re-derivation is the proof.

## Work order (this scope)

1. RED tests for the evidence model. ← starting here
2. Streaming collector with full-byte hashing (bounded memory).
3. Bounded semantic capsule (capped template table, capped excerpts).
4. Independent verifier replay.
5. Aggregator integration (as a gen-3 native case; one declared change, like Lucene).
6. Only then the real two-arm qualification run.
7. Artifact + record in a separate commit, after independent re-verification.

Frozen policy / cq / verifier identities / bridge semantics are NOT changed for Loghub; the
vertical enters as ONE declared gen-3 case change.
