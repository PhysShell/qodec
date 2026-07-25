# reader-cli A/B — run `panel-sonnet5-stability-v4`

date 2026-07-25T20:14:41Z · 2.1.220 (Claude Code) · qodec `ec98074d0765` · repeats 8 · closed-world flags as in 007 judge

| case | arm | scores | mean | prompt tok (o200k) | fresh input tok (envelope) | model |
|---|---|---|---:|---:|---:|---|
| findings | raw | 6/6 6/6 6/6 6/6 6/6 6/6 6/6 6/6 | 6.0 | 808 | 201 | claude-sonnet-5 |
| findings | paper | 5/6 5/6 5/6 5/6 5/6 5/6 5/6 5/6 | 5.0 | 1082 | 243 | claude-sonnet-5 |

`fresh input tok` = envelope inputTokens + cacheCreation for the main model (what a cold request pays, incl. the CLI's own system prompt — identical across arms, so deltas isolate the payload). Full envelopes, answers and hashes live next to this file.
