# reader-cli A/B — run `panel-sonnet5-riskprobe-v5`

date 2026-07-25T20:17:02Z · 2.1.220 (Claude Code) · qodec `ec98074d0765` · repeats 2 · closed-world flags as in 007 judge

| case | arm | scores | mean | prompt tok (o200k) | fresh input tok (envelope) | model |
|---|---|---|---:|---:|---:|---|
| findings-risk-probe | raw | 2/2 2/2 | 2.0 | 791 | 786 | claude-sonnet-5 |
| findings-risk-probe | deep | 2/2 2/2 | 2.0 | 825 | 712 | claude-sonnet-5 |
| findings-risk-probe | paper | 2/2 2/2 | 2.0 | 1065 | 957 | claude-sonnet-5 |

`fresh input tok` = envelope inputTokens + cacheCreation for the main model (what a cold request pays, incl. the CLI's own system prompt — identical across arms, so deltas isolate the payload). Full envelopes, answers and hashes live next to this file.
