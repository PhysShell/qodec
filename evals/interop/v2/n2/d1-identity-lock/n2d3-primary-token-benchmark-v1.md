# N2-D3 Primary Token Benchmark (model-free)

total corpus cases = 18
token-measurable cases = 16
non-UTF-8 measurement refusals = 2

All token aggregate denominators below are n=16 (measured text-domain subset). Failure/refusal rates use denominator 18.

| case_id | status | raw | qodec | rtk | rtk+qodec |
|---|---|---:|---:|---:|---:|
| bot-dependabot-black-5206 | MEASURED | 10532 | 7318 | 10532 | 7318 |
| bot-syzbot-do-mkdirat | MEASURED | 55720 | 44533 | 55720 | 44533 |
| ci-log-jansson | MEASURED | 17226 | 9335 | 17226 | 9335 |
| ci-log-nlog | MEASURED | 51609 | 35053 | 51609 | 35053 |
| ci-log-spdlog | MEASURED | 12790 | 5742 | 12790 | 5742 |
| dataset-loghub-v8 | UNMEASURABLE_NON_UTF8 | - | - | - | - |
| dataset-rtn-traffic-ids | MEASURED | 19974469 | 7858011 | 19974469 | 7858011 |
| n2a-miner-canary | MEASURED | 8184 | 8184 | 8184 | 8184 |
| repo-docker-java-parser | MEASURED | 3886 | 3692 | 3886 | 3692 |
| repo-dockerfile-parser-rs | MEASURED | 896 | 806 | 10 | 10 |
| repo-helm-values | MEASURED | 336 | 282 | 336 | 282 |
| repo-hyperfine | MEASURED | 9 | 9 | 9 | 9 |
| repo-kubeops-generator | MEASURED | 736 | 736 | 736 | 736 |
| repo-moshi | MEASURED | 2937 | 1729 | 2937 | 1729 |
| repo-pyflakes | MEASURED | 0 | 0 | 0 | 0 |
| repo-requests | MEASURED | 1213 | 1118 | 1213 | 1118 |
| repo-rustlings | MEASURED | 198 | 190 | 10 | 10 |
| research-corpus-loghub2 | UNMEASURABLE_NON_UTF8 | - | - | - | - |

## Token aggregates (measured text-domain subset, n=16)

| arm | total tokens | weighted savings % | macro savings % | median savings % | bootstrap 95% CI |
|---|---:|---:|---:|---:|---|
| QODEC | 7976738 | 60.395 | 20.5224 | 13.058 | [11.0024, 30.8732] (n=10000, seed=20260716) |
| RTK | 20139667 | 0.0053 | 12.1146 | 0.0 | [0.0, 30.1635] (n=10000, seed=20260716) |
| RTK+QODEC | 7975762 | 60.3999 | 31.7567 | 25.2968 | [17.334, 47.8933] (n=10000, seed=20260716) |
