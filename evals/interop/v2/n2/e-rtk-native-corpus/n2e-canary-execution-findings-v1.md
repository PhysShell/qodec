# N2-E canary execution findings (local run, evidence-backed)

A real local execution of the frozen 12-case canary (pinned RTK+QODEC binaries,
Docker daemon, full toolchains) produced these findings. It is NOT the §28
acceptance canary (that requires 12/12 deterministic PASS); it is honest
evidence of what passes and what the remaining test-runner work is. No partial
result is committed as acceptance evidence.

## Deterministic PASS (real o200k, RAW x3 byte-identical)
| case | RAW o200k | RTK o200k | savings |
|---|---:|---:|---:|
| container::redis::docker::images | 122 | 33 | 72.95% |
| loghub::HDFS::log | 80034 | 35 | 99.96% |
| gin-gonic/gin go vet | 18 | 7 | 61.11% |
| preactjs/preact files_search read | 4223 | 4223 | 0.00% |
| projectlombok/lombok files_search read | 254 | 254 | 0.00% |

Zero-saving cases (read) are shown, not hidden (§19). The daemonless + light
strata (docker, log, files, go-vet, git) execute end-to-end with the identity-
matched binaries and are byte-deterministic across 3 reps.

## Evidence-backed remaining work (test-runner strata)
1. jvm build system: apache/lucene uses Gradle, not Maven; the jvm adapter now
   detects pom.xml vs gradlew/build.gradle and resolves `./gradlew <sub>` /
   `rtk gradlew <sub>` (fixed in run_canary_case.py). lucene's first run used
   `mvn test` -> exit 1, non-deterministic.
2. git dirty state: git add/commit cases need a patch-created dirty state (§6.2).
   The current git adapter checks out clean, so `git commit` exits 128 (nothing
   to commit). The adapter must apply the instance test_patch to create the
   dirty state before add/commit/status/diff.
3. test-runner determinism: cargo/go test/pytest/vitest RAW output carries timing,
   ordering, temp paths and (on failure) memory addresses. Byte-determinism x3
   requires per-tool canonicalization policies (as N2-D3 built for a subset),
   beyond the current bounded duration/tmpdir normalization. This is the core
   §15 engineering task for the test strata.
4. heavy builds: tokio/lucene/vue/scrapy/caddy clone + build + test are multi-GB
   and minutes each; the CI matrix (one job per case) is the intended executor.

## CI dispatch
The workflow_dispatch canary cannot be triggered from this session:
- the GitHub integration token lacks actions:write (run_workflow -> HTTP 403
  "Resource not accessible by integration");
- workflow_dispatch workflows must be registered on the default branch, and this
  workflow is intentionally only on the unmerged feature branch.
The owner (with actions:write) can dispatch it, or it runs once the branch's
workflow reaches the default branch.
