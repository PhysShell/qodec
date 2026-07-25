# reader-cli A/B — run `panel-sonnet5-stability-v3`

date 2026-07-25T20:07:06Z · 2.1.220 (Claude Code) · qodec `2d47221a1a07` · repeats 4 · closed-world flags as in 007 judge

| case | arm | scores | mean | prompt tok (o200k) | fresh input tok (envelope) | model |
|---|---|---|---:|---:|---:|---|
| findings | raw | 6/6 6/6 6/6 6/6 | 6.0 | 808 | 2 | claude-sonnet-5 |
| findings | paper | 6/6 6/6 5/6 5/6 | 5.5 | 1082 | 484 | claude-sonnet-5 |

`fresh input tok` = envelope inputTokens + cacheCreation for the main model (what a cold request pays, incl. the CLI's own system prompt — identical across arms, so deltas isolate the payload). Full envelopes, answers and hashes live next to this file.
