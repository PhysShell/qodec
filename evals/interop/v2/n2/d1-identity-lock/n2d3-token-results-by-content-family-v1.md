# N2-D3 Token Results by Content Family (post-hoc, exploratory)

## Scope and limitations

This report is a **post-hoc, exploratory, non-canonical** derived view. It does not rerun N2-D2/N2-D3, does not change canonical input bytes, QODEC/RTK/tokenizer/workflow/measurement tooling, and does not alter the existing canonical N2-D3 record (`sha256:c00d2ff8f4883c964fbd05d46840763826806ea73357511e6f38a882aaf0e1cd`). Every number below is derived directly from that committed record and from the committed content taxonomy (`sha256:c7272585cc44c4bb308ccd49095f4af62228b38cf28330a1ef30098d68735de4`) -- never from this report's own Markdown/PR body.

Cases are classified by what was **actually measured** (frozen command + selected stream + actual canonical payload format), never by source-repository name, implementation language, or file extension.

## Taxonomy table

| case | content family | origin kind | producer | payload kind | rationale |
|---|---|---|---|---|---|
| bot-dependabot-black-5206 | dependency-bot-report | bot-output | bot | utf8-text | static content acquisition (no frozen command); canonical input is the archived 'bot-dependabot-black-5206/normalized-source.tar' member described in evals/interop/v2/n2/d0-durable-evidence/durable-input-manifest.json. Classified as dependency-bot-report (bot-output/bot). |
| bot-syzbot-do-mkdirat | kernel-bug-report | bot-output | bot | utf8-text | static content acquisition (no frozen command); canonical input is the archived 'bot-syzbot-do-mkdirat/normalized-source.tar' member described in evals/interop/v2/n2/d0-durable-evidence/durable-input-manifest.json. Classified as kernel-bug-report (bot-output/bot). |
| ci-log-jansson | ci-build-log | ci-log | generic-ci | utf8-text | static content acquisition (no frozen command); canonical input is the archived 'ci-log-jansson/normalized-source.tar' member described in evals/interop/v2/n2/d0-durable-evidence/durable-input-manifest.json. Classified as ci-build-log (ci-log/generic-ci). |
| ci-log-nlog | ci-build-log | ci-log | generic-ci | utf8-text | static content acquisition (no frozen command); canonical input is the archived 'ci-log-nlog/normalized-source.tar' member described in evals/interop/v2/n2/d0-durable-evidence/durable-input-manifest.json. Classified as ci-build-log (ci-log/generic-ci). |
| ci-log-spdlog | ci-build-log | ci-log | generic-ci | utf8-text | static content acquisition (no frozen command); canonical input is the archived 'ci-log-spdlog/normalized-source.tar' member described in evals/interop/v2/n2/d0-durable-evidence/durable-input-manifest.json. Classified as ci-build-log (ci-log/generic-ci). |
| dataset-loghub-v8 | binary-archive-container | static-dataset | dataset | binary-container | static content acquisition (no frozen command); canonical input is the archived 'dataset-loghub-v8/normalized-source.tar' member described in evals/interop/v2/n2/d0-durable-evidence/durable-input-manifest.json. The case's own primary source-freeze manifest recorded an extraction_recipe intending to extract a named plain-text archive member, but the committed canonical_benchmark_input is the un-extracted original compressed archive re-wrapped in normalized-source.tar (utf8_valid=False) -- a genuine binary archive container, not a semantic judgment about the underlying logs, which is why this case is a typed UNMEASURABLE_NON_UTF8 refusal rather than a measured row. |
| dataset-rtn-traffic-ids | static-log-dataset | static-dataset | dataset | utf8-text | static content acquisition (no frozen command); canonical input is the archived 'dataset-rtn-traffic-ids/normalized-source.tar' member described in evals/interop/v2/n2/d0-durable-evidence/durable-input-manifest.json. Classified as static-log-dataset (static-dataset/dataset). |
| n2a-miner-canary | canary-ci-log | canary | dotnet | utf8-text | frozen canary command ['dotnet', 'build', 'EncryptAesApp/EncryptAesApp.csproj', '--configuration', 'Release', '--no-restore', '--nologo', '--verbosity', 'normal', '-p:UseSharedCompilation=false', '--disable-build-servers', '-m:1', '-p:BuildInParallel=false', '-p:RunAnalyzersInParallel=false'] (stdout), per evals/interop/v2/n2/canary/source-manifest.json. Classified as canary-ci-log (canary/dotnet). |
| repo-docker-java-parser | maven-test-output | repository-command-output | maven | utf8-text | frozen command ['mvn', 'test'] (stdout), per evals/interop/v2/n2/d1-identity-lock/stage2-full-matrix-acceptance.json. Classified as maven-test-output (repository-command-output/maven). |
| repo-dockerfile-parser-rs | cargo-test-output | repository-command-output | cargo | utf8-text | frozen command ['cargo', 'test'] (stdout), per evals/interop/v2/n2/d1-identity-lock/stage2-full-matrix-acceptance.json. Classified as cargo-test-output (repository-command-output/cargo). |
| repo-helm-values | gradle-test-output | repository-command-output | gradle | utf8-text | frozen command ['./gradlew', ':helm-values-shared:test'] (stdout), per evals/interop/v2/n2/d1-identity-lock/stage2-full-matrix-acceptance.json. Classified as gradle-test-output (repository-command-output/gradle). |
| repo-hyperfine | cli-tool-output | repository-command-output | generic-cli | utf8-text | frozen command ['cargo', 'run', '--', '--version'] (stdout), per evals/interop/v2/n2/d1-identity-lock/stage2-full-matrix-acceptance.json. Classified as cli-tool-output (repository-command-output/generic-cli). |
| repo-kubeops-generator | dotnet-test-output | repository-command-output | dotnet | utf8-text | frozen command ['dotnet', 'test', 'test/KubeOps.Generator.Test/KubeOps.Generator.Test.csproj'] (stdout), per evals/interop/v2/n2/d1-identity-lock/stage2-full-matrix-acceptance.json. Classified as dotnet-test-output (repository-command-output/dotnet). |
| repo-moshi | gradle-test-output | repository-command-output | gradle | utf8-text | frozen command ['./gradlew', 'test'] (stdout), per evals/interop/v2/n2/d1-identity-lock/stage2-full-matrix-acceptance.json. Classified as gradle-test-output (repository-command-output/gradle). |
| repo-pyflakes | cli-tool-output | repository-command-output | generic-cli | utf8-text | frozen command ['python', '-m', 'pyflakes', 'src/'] (stdout), per evals/interop/v2/n2/d1-identity-lock/stage2-full-matrix-acceptance.json. Classified as cli-tool-output (repository-command-output/generic-cli). |
| repo-requests | pytest-output | repository-command-output | pytest | utf8-text | frozen command ['pytest'] (stdout), per evals/interop/v2/n2/d1-identity-lock/stage2-full-matrix-acceptance.json. Classified as pytest-output (repository-command-output/pytest). |
| repo-rustlings | cargo-test-output | repository-command-output | cargo | utf8-text | frozen command ['cargo', 'test'] (stdout), per evals/interop/v2/n2/d1-identity-lock/stage2-full-matrix-acceptance.json. Classified as cargo-test-output (repository-command-output/cargo). |
| research-corpus-loghub2 | binary-archive-container | research-corpus | none | binary-container | static content acquisition (no frozen command); canonical input is the archived 'research-corpus-loghub2/normalized-source.tar' member described in evals/interop/v2/n2/d0-durable-evidence/durable-input-manifest.json. The case's own primary source-freeze manifest recorded an extraction_recipe intending to extract a named plain-text archive member, but the committed canonical_benchmark_input is the un-extracted original compressed archive re-wrapped in normalized-source.tar (utf8_valid=False) -- a genuine binary archive container, not a semantic judgment about the underlying logs, which is why this case is a typed UNMEASURABLE_NON_UTF8 refusal rather than a measured row. |

## Main table by content family

| group | n (total/measured/refusal) | sample size | raw tokens | raw share % | QODEC weighted % | RTK weighted % | RTK+QODEC weighted % | dominant case | dominated? |
|---|---|---|---:|---:|---:|---:|---:|---|---|
| binary-archive-container | 2/0/2 | non-measurable-group | 0 | 0.0 | - | - | - | - | False |
| canary-ci-log | 1/1/0 | descriptive-case-study | 8184 | 0.0406 | 0.0 | 0.0 | 0.0 | n2a-miner-canary | True |
| cargo-test-output | 2/2/0 | exploratory-small-group | 1094 | 0.0054 | 8.958 | 98.1718 | 98.1718 | repo-dockerfile-parser-rs | True |
| ci-build-log | 3/3/0 | exploratory-group | 81625 | 0.4053 | 38.585 | 0.0 | 38.585 | ci-log-nlog | False |
| cli-tool-output | 2/2/0 | exploratory-small-group | 9 | 0.0 | 0.0 | 0.0 | 0.0 | repo-hyperfine | True |
| dependency-bot-report | 1/1/0 | descriptive-case-study | 10532 | 0.0523 | 30.5165 | 0.0 | 30.5165 | bot-dependabot-black-5206 | True |
| dotnet-test-output | 1/1/0 | descriptive-case-study | 736 | 0.0037 | 0.0 | 0.0 | 0.0 | repo-kubeops-generator | True |
| gradle-test-output | 2/2/0 | exploratory-small-group | 3273 | 0.0163 | 38.5579 | 0.0 | 38.5579 | repo-moshi | True |
| kernel-bug-report | 1/1/0 | descriptive-case-study | 55720 | 0.2767 | 20.0772 | 0.0 | 20.0772 | bot-syzbot-do-mkdirat | True |
| maven-test-output | 1/1/0 | descriptive-case-study | 3886 | 0.0193 | 4.9923 | 0.0 | 4.9923 | repo-docker-java-parser | True |
| pytest-output | 1/1/0 | descriptive-case-study | 1213 | 0.006 | 7.8318 | 0.0 | 7.8318 | repo-requests | True |
| static-log-dataset | 1/1/0 | descriptive-case-study | 19974469 | 99.1744 | 60.6597 | 0.0 | 60.6597 | dataset-rtn-traffic-ids | True |

## Secondary table: by origin kind

| group | n (total/measured/refusal) | sample size | raw tokens | raw share % | QODEC weighted % | RTK weighted % | RTK+QODEC weighted % | dominant case | dominated? |
|---|---|---|---:|---:|---:|---:|---:|---|---|
| bot-output | 2/2/0 | exploratory-small-group | 66252 | 0.3289 | 21.7367 | 0.0 | 21.7367 | bot-syzbot-do-mkdirat | True |
| canary | 1/1/0 | descriptive-case-study | 8184 | 0.0406 | 0.0 | 0.0 | 0.0 | n2a-miner-canary | True |
| ci-log | 3/3/0 | exploratory-group | 81625 | 0.4053 | 38.585 | 0.0 | 38.585 | ci-log-nlog | False |
| repository-command-output | 9/9/0 | exploratory-group | 10211 | 0.0507 | 16.1493 | 10.5181 | 25.7076 | repo-docker-java-parser | False |
| research-corpus | 1/0/1 | non-measurable-group | 0 | 0.0 | - | - | - | - | False |
| static-dataset | 2/1/1 | descriptive-case-study | 19974469 | 99.1744 | 60.6597 | 0.0 | 60.6597 | dataset-rtn-traffic-ids | True |

## Secondary table: by producer family

| group | n (total/measured/refusal) | sample size | raw tokens | raw share % | QODEC weighted % | RTK weighted % | RTK+QODEC weighted % | dominant case | dominated? |
|---|---|---|---:|---:|---:|---:|---:|---|---|
| bot | 2/2/0 | exploratory-small-group | 66252 | 0.3289 | 21.7367 | 0.0 | 21.7367 | bot-syzbot-do-mkdirat | True |
| cargo | 2/2/0 | exploratory-small-group | 1094 | 0.0054 | 8.958 | 98.1718 | 98.1718 | repo-dockerfile-parser-rs | True |
| dataset | 2/1/1 | descriptive-case-study | 19974469 | 99.1744 | 60.6597 | 0.0 | 60.6597 | dataset-rtn-traffic-ids | True |
| dotnet | 2/2/0 | exploratory-small-group | 8920 | 0.0443 | 0.0 | 0.0 | 0.0 | n2a-miner-canary | True |
| generic-ci | 3/3/0 | exploratory-group | 81625 | 0.4053 | 38.585 | 0.0 | 38.585 | ci-log-nlog | False |
| generic-cli | 2/2/0 | exploratory-small-group | 9 | 0.0 | 0.0 | 0.0 | 0.0 | repo-hyperfine | True |
| gradle | 2/2/0 | exploratory-small-group | 3273 | 0.0163 | 38.5579 | 0.0 | 38.5579 | repo-moshi | True |
| maven | 1/1/0 | descriptive-case-study | 3886 | 0.0193 | 4.9923 | 0.0 | 4.9923 | repo-docker-java-parser | True |
| none | 1/0/1 | non-measurable-group | 0 | 0.0 | - | - | - | - | False |
| pytest | 1/1/0 | descriptive-case-study | 1213 | 0.006 | 7.8318 | 0.0 | 7.8318 | repo-requests | True |

## Secondary table: by payload kind

| group | n (total/measured/refusal) | sample size | raw tokens | raw share % | QODEC weighted % | RTK weighted % | RTK+QODEC weighted % | dominant case | dominated? |
|---|---|---|---:|---:|---:|---:|---:|---|---|
| binary-container | 2/0/2 | non-measurable-group | 0 | 0.0 | - | - | - | - | False |
| utf8-text | 16/16/0 | exploratory-group | 20140741 | 100.0 | 60.395 | 0.0053 | 60.3999 | dataset-rtn-traffic-ids | True |

## Dominance diagnostics

`dataset-rtn-traffic-ids` is 99.1744% of total measured RAW tokens (n=16) and accounts for 99.6091% of total corpus-wide QODEC token savings.

## With/without dataset-rtn sensitivity

| subset | n | RAW total | QODEC total | RTK total | hybrid total | QODEC weighted % | RTK weighted % | hybrid weighted % |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| canonical (n=16) | 16 | 20140741 | 7976738 | 20139667 | 7975762 | 60.395 | 0.0053 | 60.3999 |
| excluding dataset-rtn (n=15) | 15 | 166272 | 118727 | 165198 | 117751 | 28.5947 | 0.6459 | 29.1817 |

This sensitivity block does not replace the canonical result; it exists to make the corpus-weighted total's dependence on a single dominant case visible.

## Equal-family exploratory summary

**exploratory equal-content-family summary** -- post-hoc exploratory metric, not a canonical benchmark result, and does not replace the corpus-weighted or case-macro results. gives every measured content family equal weight regardless of case count or token mass, then averages each family's own weighted savings percentage. Families with a single measured case receive the same family weight as families with more cases, so this metric is sensitive to taxonomy granularity. Not a leaderboard; not a substitute for the corpus-weighted or case-macro canonical results.

Families included (n=11): canary-ci-log, cargo-test-output, ci-build-log, cli-tool-output, dependency-bot-report, dotnet-test-output, gradle-test-output, kernel-bug-report, maven-test-output, pytest-output, static-log-dataset
Families excluded (zero measured cases): binary-archive-container

Mean family weighted savings % -- QODEC: 19.1071, RTK: 8.9247, RTK+QODEC: 27.2175

No leaderboard is constructed.

## Small-sample warnings

- `binary-archive-container`: non-measurable-group (measured_case_count=0); no bootstrap CI, no strong statistical conclusion drawn.
- `canary-ci-log`: descriptive-case-study (measured_case_count=1); no bootstrap CI, no strong statistical conclusion drawn.
- `cargo-test-output`: exploratory-small-group (measured_case_count=2); no bootstrap CI, no strong statistical conclusion drawn.
- `cli-tool-output`: exploratory-small-group (measured_case_count=2); no bootstrap CI, no strong statistical conclusion drawn.
- `dependency-bot-report`: descriptive-case-study (measured_case_count=1); no bootstrap CI, no strong statistical conclusion drawn.
- `dotnet-test-output`: descriptive-case-study (measured_case_count=1); no bootstrap CI, no strong statistical conclusion drawn.
- `gradle-test-output`: exploratory-small-group (measured_case_count=2); no bootstrap CI, no strong statistical conclusion drawn.
- `kernel-bug-report`: descriptive-case-study (measured_case_count=1); no bootstrap CI, no strong statistical conclusion drawn.
- `maven-test-output`: descriptive-case-study (measured_case_count=1); no bootstrap CI, no strong statistical conclusion drawn.
- `pytest-output`: descriptive-case-study (measured_case_count=1); no bootstrap CI, no strong statistical conclusion drawn.
- `static-log-dataset`: descriptive-case-study (measured_case_count=1); no bootstrap CI, no strong statistical conclusion drawn.

## Non-UTF-8 domain boundary

**binary-container is a measurement-domain classification, not evidence that the underlying archived logs are semantically binary.** The canonical measured bytes for `dataset-loghub-v8` and `research-corpus-loghub2` are archive containers (their `normalized-source.tar` wraps the originally-downloaded compressed archive un-extracted) and are therefore invalid for the current UTF-8 text meter. This is why both remain typed `UNMEASURABLE_NON_UTF8` refusals rather than measured rows.

## Interpretation

- Observed token behavior differs across content families.
- QODEC savings are concentrated in some log-like families.
- RTK savings are concentrated in `cargo-test-output`.
- Weighted totals are dominated by `dataset-rtn-traffic-ids`.
- Hybrid incremental savings vary by family.

No claims are made about semantic quality, model task success, production superiority, a universal winner, or general behavior on all Dockerfiles/Rust files/Java projects/etc. For example, `repo-dockerfile-parser-rs` did not measure Dockerfile content or Rust source; its measured payload is the `cargo test` stdout captured from that repository. Any such claim would be a claim this benchmark never measured.
