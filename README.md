# case-0002 source blobs

This branch carries data, not code. Its first commit has no parent and shares no
history with `main`. Nothing here is built, imported, or tested; it exists so
that a fixture can be bound to bytes instead of to a container's mood.

`SOURCE-LOCK-v6.yaml` is the authoritative document. `MANIFEST.yaml` lists every
digest. Read those two; this file is the map.

## Contents

| file | what it is |
|---|---|
| `claude-session.window-r21.jsonl.gz` | the R21.0 arc of the coder session, 527 records |
| `claude-session.prefix-r21.jsonl.gz` | the whole coder session through record 17111 |
| `SOURCE-LOCK-v6.yaml` | windows, authority rules, corrections, what is still missing |
| `reviewer-profile.json` | the reviewer plane's extraction ladder, as measured |
| `MANIFEST.yaml` | digests, sizes, anchors, verification commands |
| `window_invariant.py` | proves the window is the anchored slice of the prefix |
| `source_profiler.py` | the frozen measurement filter |
| `window-invariant.json` | that proof's output |
| `coder-profile.json` | that filter's output |
| `history/` | both documents called revision 2, and revisions 3, 4 and 5 |

Digests of the uncompressed blobs, which are the ones a fixture should bind:

- window: `7b74dd3a521b7e999ef794450f1b0e15d563421a03cfa1ad499f8c7600adc023`, 1 873 570 bytes
- prefix: `8392de803d600b19ac8273a43b2b766951d2eaf9a9197e1d8d43e97f541fca1c`, 87 564 394 bytes

## Bind to objects, not to this branch — and bind twice

A branch ref moves. Two different things need binding, and an earlier revision
of this file conflated them.

The **source data** originates in the first commit and has not moved since:

    repository  PhysShell/qodec
    commit      d4decebd5cebaf04920f9bd6f2a5eba26866a1ed
    tree        7fbe15bdad41843b3f6a7647ecba4c8612ac02dc
    prefix_gz   6d8a09a7012a0d0aada905967fcd146dc10c445e
    window_gz   58e3875d10d2e647333f0652c260f7bbb8cae59e

That tree contains the two gzip blobs and the first lock. It holds no current
lock, no tools and no outputs, so naming it binds the data honestly and the
metadata not at all.

The **metadata bundle** — the authoritative lock, both tools, their outputs and
the superseded locks — lives at a later head. Its exact commit must be recorded
by the Round 0 fixture manifest, outside these files: a document cannot contain
the hash of the commit that contains it.

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

It checks that every non-blank line of both blobs parses as a JSON object, that
each anchor occurs exactly once, that the start precedes the end, that exactly
527 records are extracted, and that the slice is byte-identical to the window
blob. It exits 1 on an altered digest, an off-by-one record count, swapped
anchors, a malformed line, and a JSON scalar in place of a record; all five were
exercised.

The parser strictness is not decorative. An earlier implementation skipped lines
it could not read, so the record count it reported came from a universe it had
silently edited. Given a pair of blobs with the same unreadable line in both — so
the slice comparison cannot notice — and the record count that implementation
itself reported, it exited 0 with `byte_identical: true` and no problems. The
current one refuses at prefix line 16588. Hardening changed nothing for
well-formed input: both tools reproduce their recorded outputs byte for byte, so
no published count moved.

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

Publishing byte-exact is a risk the controller accepted explicitly, after being
shown the repository's public visibility, the personal address, the limits of
the scan, and the fact that redaction voids every digest. The reviewer's
contrary position — that a digest binds a private blob exactly as well as a
public one, so publication is not required by the freeze design — is recorded
alongside it in `SOURCE-LOCK-v6.yaml`, because a decision taken against a stated
objection should carry the objection with it.

## What is not here

The third source plane. Repository, CI and evidence artifacts for the R21.0 arc
are not frozen, and until they are, the two chat planes corroborate each other
only because a human relayed the same text between them. See
`finding_relay_coupling` in `SOURCE-LOCK-v6.yaml`.

The reviewer plane's own export. It was re-supplied, verified against its
recorded digest, and profiled by the frozen tool; the resulting
`reviewer-profile.json` is here, and it is byte-identical to an independent
replay. The corpus itself is deliberately not here — the controller's
publication decision covered the coder-session blobs, and this is a different
corpus carrying unrelated conversations — and publishing it is not a Round 0
requirement.

That leaves the reviewer plane measured but not stored. The export has already
vanished twice from the ephemeral container that held it. The coder blobs
survive those resets only because they are committed here; the export is not,
and has no durable object id. A digest attests a future copy without producing
one, so reviewer-plane durability has to be settled before a fixture is locked,
even though nothing in Round 0 waits on it.
