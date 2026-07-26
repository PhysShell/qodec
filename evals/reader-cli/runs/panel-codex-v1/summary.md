# reader-cli A/B — run `panel-codex-v1`

date 2026-07-26T12:58:28Z · codex codex-cli 0.145.0 · qodec `859fcba8546d` · repeats 2 · closed-world flags as in 007 judge

| case | arm | scores | mean | prompt tok (o200k) | fresh input tok (envelope) | model |
|---|---|---|---:|---:|---:|---|
| findings-count | raw | 5/6 5/6 | 5.0 | 808 | ? | ? |
| findings-count | deep | 6/6 6/6 | 6.0 | 848 | ? | ? |
| findings-count | paper | 6/6 6/6 | 6.0 | 1082 | ? | ? |
| findings-count | squeeze | 6/6 6/6 | 6.0 | 814 | ? | ? |
| findings-risk-probe | raw | 2/2 2/2 | 2.0 | 791 | ? | ? |
| findings-risk-probe | deep | 2/2 2/2 | 2.0 | 831 | ? | ? |
| findings-risk-probe | paper | 2/2 2/2 | 2.0 | 1065 | ? | ? |
| findings-risk-probe | squeeze | 2/2 2/2 | 2.0 | 797 | ? | ? |

`fresh input tok` = envelope inputTokens + cacheCreation for the main model (what a cold request pays, incl. the CLI's own system prompt — identical across arms, so deltas isolate the payload). Full envelopes, answers and hashes live next to this file.
