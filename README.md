# case-0002 source blobs

This branch carries data, not code. It has no parent commit and shares no
history with `main`. Nothing here is built, imported, or tested; it exists so
that a fixture can be bound to bytes instead of to a container's mood.

## What is here

| file | what it is | bytes | sha256 |
|---|---|---|---|
| `claude-session.window-r21.jsonl.gz` | the R21.0 arc of the coder session, 527 records | 526 718 | `132c359fb9cc0de7c19f58a223d1f01309bb0a9235ab29d1ceccb64a77e59381` |
| `claude-session.prefix-r21.jsonl.gz` | the whole coder session through record 17111 | 21 239 298 | `950dcd4af8c43f478aa92b32d58974289eb00a23e8b051ae441a33655893cb5d` |
| `MANIFEST.yaml` | digests, window anchors, verification steps | — | — |
| `SOURCE-LOCK-v2.yaml` | window definitions, authority rules, what is still missing | — | — |

Digests of the uncompressed contents, which are the ones a fixture should bind:

- window: `7b74dd3a521b7e999ef794450f1b0e15d563421a03cfa1ad499f8c7600adc023`, 1 873 570 bytes
- prefix: `8392de803d600b19ac8273a43b2b766951d2eaf9a9197e1d8d43e97f541fca1c`, 87 564 394 bytes

## Verifying

    gunzip -c claude-session.window-r21.jsonl.gz | sha256sum
    gunzip -c claude-session.prefix-r21.jsonl.gz | sha256sum

The window's first record is uuid `3a0760a5-e751-4ece-81e8-c9aea36a4ad4`
(2026-08-02T16:06:26.130Z) and its last is `3794550b-a82a-4f52-a785-9a599894d6ea`
(2026-08-03T18:00:08.189Z). Anchors are uuids rather than indices, so a
re-derived index cannot silently move the boundary.

## Why a prefix and not the file

The coder session file was still being appended to while these blobs were cut.
It measured 87 629 277 bytes early on, 87 858 714 at the first freeze, and
88 002 155 half an hour later. The file is append-only, so a digest over a
record prefix is stable while a digest over the whole file is not. The prefix
was frozen at 02:07 UTC and recomputed at 02:34 UTC across a container reset
and 31 further appended records; both length and digest reproduced exactly.

## Contents disclosure

These are unredacted session logs, published byte-exact so the digests stay
meaningful. They were scanned for credentials before publication — key patterns
(`sk-`, `sk-ant-`, `ghp_`, `gho_`, `github_pat_`, `AKIA`, `xox*`, PEM private
key headers, `api_key=`-style assignments) produced no matches, and the OAuth
and proxy strings that do appear are environment variable *names* with no
values. They do contain ordinary working detail: file paths, commit SHAs, CI run
ids, and the participants' correspondence, including one personal email address.
Publishing byte-exact was a deliberate choice: redaction would change the bytes
and void every digest above.

## What is not here

The third source plane. Repository, CI and evidence artifacts for the R21.0 arc
are not yet frozen, and until they are, the two chat planes corroborate each
other only because a human relayed the same text between them. See
`finding_relay_coupling` in `SOURCE-LOCK-v2.yaml`.
