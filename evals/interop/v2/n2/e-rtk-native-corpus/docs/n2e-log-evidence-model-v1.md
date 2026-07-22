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

## Template identity: the published Loghub set is the authority

`unique_template_ids` is defined by the PUBLISHED Loghub-2.0 HDFS template set, NOT by our own
masking. The pinned reference `n2e-loghub-hdfs-reference-v1` carries the committed
`n2e-loghub-hdfs-templates.csv` (extracted from the checksum-pinned Zenodo `HDFS.zip` member
`HDFS/HDFS_full.log_templates.csv`, sha256
`0a105b8dd2f8d3784faada4443c726e6e4aec76f9c8a14298d5e3b8295b4aa63`, 4181 B, 46 templates) — each
`EventId`, its `EventTemplate`, and its published `Occurrences`. The published Occurrences sum to
11 167 740 == the exact full-log line count (the set covers every line).

- **Line grammar**: HDFS `YYMMDD HHMMSS PID LEVEL COMPONENT: CONTENT`. `LEVEL ∈
  {INFO,WARN,WARNING,ERROR,FATAL,DEBUG}` (others → `other`).
- **EventId assignment**: each line's `CONTENT` is matched against the published `EventTemplate`s
  (each `<*>` → `.*?`, anchored full-match) with the EXACTLY-ONE-MATCH rule — one match → that
  published EventId; **zero → reject (`<unmatched>`); more than one → reject (`<ambiguous>`)**.
  Any unmatched/ambiguous line makes the summary
  `outcome=DISQUALIFIED_UNMATCHED_OR_AMBIGUOUS`, never a silent pass.
- **Occurrence-count authority**: the published `Occurrences`. The single streamed pass counts
  per-EventId occurrences and they MUST equal the published values for the full stream
  (`occurrence_counts_match_published`); a partial/sub stream is `outcome=streamed_partial`
  (valid, not the full published log); the full-log acceptance requires `outcome=parsed`.
- **severity_counts / first_last_occurrence**: from the same streamed pass (Level field; first &
  last line + byte offset per EventId).
- **Masking is diagnostic ONLY**: an ordered masking cross-check (`blk_<*>`/`<ip>`/`<path>`/`<num>`)
  records a distinct-masked count in `masking_cross_check` with `authority=false`. It may
  summarize or validate; it never defines identity. (A full masked↔published bijection is separate
  research and not required for qualification.)
- **Framing**: split on `\n`; residual buffer across chunk boundaries; a final unterminated line is
  a real line. No truncation for hashing; the hash is over raw bytes.

The 1.7 GB per-line `HDFS_full.log_structured.csv` is pinned by identity for optional future per-line
escalation; the base qualification does not stream it — the exactly-one-match rule + the published
occurrence-count equality already bind our per-line assignment to the published labeling in
aggregate.

## Capsule schema (`n2e-log-evidence-capsule`)

```
stream:  { role, invoked_argv, exit_status, bytes, sha256, read_to_eof,
           chunking: { chunk_bytes, chunk_count, merkle_root } }
canon:   { dialect: "log-hdfs-v1", module_sha256, identity_authority,
           reference_sha256, framing, encoding, masking_cross_check,
           truncation_policy: "none-for-hashing" }
summary: { reference_sha256, reference_template_count, outcome, total_lines,
           severity_counts, observed_event_ids[sorted], unique_template_count,
           streamed_occurrence_counts, published_occurrence_counts,
           occurrence_counts_match_published, first_last_occurrence,
           unmatched_lines, ambiguous_lines,
           masking_cross_check{ authority:false }, summary_sha256 }
excerpts:[ { event_id, byte_start, byte_end, chunk_index, chunk_sha256,
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
