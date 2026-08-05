# case-0002 source blobs

This branch carries data, not code. Its first commit has no parent and shares no
history with `main`. Nothing here is built, imported, or tested; it exists so
that a fixture can be bound to bytes instead of to a container's mood.

`SOURCE-LOCK-v3.yaml` is the authoritative document. `MANIFEST.yaml` lists every
digest. Read those two; this file is the map.

## Contents

| file | what it is |
|---|---|
| `claude-session.window-r21.jsonl.gz` | the R21.0 arc of the coder session, 527 records |
| `claude-session.prefix-r21.jsonl.gz` | the whole coder session through record 17111 |
| `SOURCE-LOCK-v3.yaml` | windows, authority rules, corrections, what is still missing |
| `MANIFEST.yaml` | digests, sizes, anchors, verification commands |
| `window_invariant.py` | proves the window is the anchored slice of the prefix |
| `source_profiler.py` | the frozen measurement filter |
| `window-invariant.json` | that proof's output |
| `coder-profile.json` | that filter's output |
| `history/` | both documents that were called revision 2 |

Digests of the uncompressed blobs, which are the ones a fixture should bind:

- window: `7b74dd3a521b7e999ef794450f1b0e15d563421a03cfa1ad499f8c7600adc023`, 1 873 570 bytes
- prefix: `8392de803d600b19ac8273a43b2b766951d2eaf9a9197e1d8d43e97f541fca1c`, 87 564 394 bytes

## Bind to objects, not to this branch

A branch ref moves. Round 0 should name:

    repository  PhysShell/qodec
    commit      d4decebd5cebaf04920f9bd6f2a5eba26866a1ed   (first commit)
    tree        7fbe15bdad41843b3f6a7647ecba4c8612ac02dc
    prefix_gz   6d8a09a7012a0d0aada905967fcd146dc10c445e
    window_gz   58e3875d10d2e647333f0652c260f7bbb8cae59e

The branch name is a locator and nothing more.

## Verifying

    gunzip -c claude-session.window-r21.jsonl.gz | sha256sum
    gunzip -c claude-session.prefix-r21.jsonl.gz | sha256sum

Two blobs that are each individually well-formed do not establish the relation
claimed between them, so the relation is computed:

    python3 window_invariant.py \
      --prefix claude-session.prefix-r21.jsonl \
      --window claude-session.window-r21.jsonl \
      --start-uuid 3a0760a5-e751-4ece-81e8-c9aea36a4ad4 \
      --end-uuid 3794550b-a82a-4f52-a785-9a599894d6ea \
      --expect-records 527 \
      --expect-window-sha256 7b74dd3a521b7e999ef794450f1b0e15d563421a03cfa1ad499f8c7600adc023

It checks that each anchor occurs exactly once, that the start precedes the end,
that exactly 527 records are extracted, and that the slice is byte-identical to
the window blob. It exits 1 on an altered digest, an off-by-one record count, or
swapped anchors; all three were exercised.

## Why a prefix and not the file

The coder session file was still being appended to while these blobs were cut.
It measured 87 629 277 bytes early on, 87 858 714 at the first freeze, and
88 002 155 half an hour later. The file is append-only, so a digest over a
record prefix is stable while a digest over the whole file is not. The prefix
was frozen at 02:07 UTC and recomputed at 02:34 UTC across a container reset and
31 further appended records; both length and digest reproduced exactly.

## Contents disclosure

These are unredacted session logs, published byte-exact so the digests stay
meaningful. They contain ordinary working detail — file paths, commit SHAs, CI
run ids — and the participants' correspondence, including one personal email
address.

They were scanned for credentials before publication and the patterns searched
for (`sk-`, `sk-ant-`, `ghp_`, `gho_`, `github_pat_`, `AKIA`, `xox*`, PEM
private key headers, `api_key=`-style assignments) produced no matches; the
OAuth and proxy strings present are environment variable *names* with no values.
That scan proves the absence of the patterns it looked for and nothing more, and
it was run by the agent whose own output is in the logs. It has not been
independently replayed.

Whether unredacted logs belong in a public repository at all is recorded as an
open controller decision in `SOURCE-LOCK-v3.yaml`, not as settled. A digest
binds a private blob exactly as well as a public one.

## What is not here

The third source plane. Repository, CI and evidence artifacts for the R21.0 arc
are not frozen, and until they are, the two chat planes corroborate each other
only because a human relayed the same text between them. See
`finding_relay_coupling` in `SOURCE-LOCK-v3.yaml`.

The reviewer plane's own export is also absent — supplied as an attachment and
lost with the container's upload directory. Its digest is recorded so a
re-supplied copy can be bound rather than trusted.
