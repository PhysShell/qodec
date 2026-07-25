# reader-cli A/B — run `panel-sonnet5-count-v2`

date 2026-07-25T20:03:31Z · 2.1.220 (Claude Code) · qodec `036929d080c6` · repeats 2 · closed-world flags as in 007 judge

| case | arm | scores | mean | prompt tok (o200k) | fresh input tok (envelope) | model |
|---|---|---|---:|---:|---:|---|
| findings-count | raw | 5/6 5/6 | 5.0 | 808 | 1572 | claude-sonnet-5 |
| findings-count | deep | 6/6 6/6 | 6.0 | 842 | 712 | claude-sonnet-5 |
| findings-count | paper | 6/6 6/6 | 6.0 | 1082 | 956 | claude-sonnet-5 |
| findings-count | squeeze | 6/6 6/6 | 6.0 | 762 | 1298 | claude-sonnet-5 |

`fresh input tok` = envelope inputTokens + cacheCreation for the main model (what a cold request pays, incl. the CLI's own system prompt — identical across arms, so deltas isolate the payload). Full envelopes, answers and hashes live next to this file.
