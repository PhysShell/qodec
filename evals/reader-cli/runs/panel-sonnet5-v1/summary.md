# reader-cli A/B — run `panel-sonnet5-v1`

date 2026-07-25T19:46:31Z · 2.1.220 (Claude Code) · qodec `6666de5f2dc8` · repeats 2 · closed-world flags as in 007 judge

| case | arm | scores | mean | prompt tok (o200k) | fresh input tok (envelope) | model |
|---|---|---|---:|---:|---:|---|
| stacktrace | raw | 6/6 6/6 | 6.0 | 691 | 2 | claude-sonnet-5 |
| stacktrace | deep | 6/6 6/6 | 6.0 | 825 | 2 | claude-sonnet-5 |
| stacktrace | paper | 6/6 6/6 | 6.0 | 885 | 868 | claude-sonnet-5 |
| build-log | raw | 6/6 6/6 | 6.0 | 809 | 764 | claude-sonnet-5 |
| build-log | deep | 6/6 6/6 | 6.0 | 765 | 1300 | claude-sonnet-5 |
| build-log | paper | 6/6 6/6 | 6.0 | 946 | 828 | claude-sonnet-5 |
| rg-output | raw | 6/6 6/6 | 6.0 | 697 | 787 | claude-sonnet-5 |
| rg-output | deep | 6/6 6/6 | 6.0 | 762 | 692 | claude-sonnet-5 |
| rg-output | paper | 6/6 6/6 | 6.0 | 977 | 965 | claude-sonnet-5 |
| findings | raw | 6/6 6/6 | 6.0 | 808 | 794 | claude-sonnet-5 |
| findings | deep | 6/6 6/6 | 6.0 | 842 | 720 | claude-sonnet-5 |
| findings | paper | 5/6 5/6 | 5.0 | 1082 | 965 | claude-sonnet-5 |

`fresh input tok` = envelope inputTokens + cacheCreation for the main model (what a cold request pays, incl. the CLI's own system prompt — identical across arms, so deltas isolate the payload). Full envelopes, answers and hashes live next to this file.
