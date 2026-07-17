# N2-E §5/§16 acquisition-method reconnaissance (evidenced)

This records how each selected stratum's environment is acquired and executed,
from real probes in the bootstrapped substrate. It is the input to the per-instance
acquisition + RAW qualification phases. No stratum below is blocked; the remaining
work is execution volume, not a §27 condition.

## Substrate (proven, committed)
- `.#rtk-pinned` reproduced bit-for-bit (`41f316ad…`) and `.#qodec` built via the
  git-transport bootstrap under the Nix sandbox. Docker daemon running; daemonless
  OCI digest resolution + verify-by-digest proven; user-namespace isolation available.
- Disk headroom at reconnaissance: ~23 GiB free (/), Nix store ~6.6 GiB.

## Logs + files_search — Loghub-2.0 (PROVEN end-to-end)
- Acquire: Zenodo record 8275861, per-file publisher md5 verified; safety-scan +
  extract; deterministic line slice.
- Execute: RAW (`cat`/`grep`) and RTK (`rtk log`/`rtk grep`) run under the mandated
  env; byte-deterministic across 3 reps; o200k via qodec. See
  `n2e-log-qualification-pilot-v1.json` (RAW 67875 → RTK 34 o200k tokens, both
  deterministic).
- Finding: `rtk log` on severity-less formats (Proxifier) collapses to a content-
  free summary → the §14 log oracle must select severity-bearing Loghub systems
  (e.g. Apache/OpenSSH/HDFS) for meaningful cases.

## Test runners — SWE-bench Multilingual (harness-built images)
- Finding (evidenced): SWE-bench Multilingual does NOT publish pre-built eval
  images. 6 pages / 600 repos of the `swebench` Docker Hub namespace contain only
  classic (Python) `sweb.eval.x86_64.*` images; no caddy/tokio/gin/preact/lombok/
  ruff/hugo/axios/gson/druid images exist. §2.2 explicitly permits a "reproducible
  image recipe" for exactly this case.
- Acquire (recipe): per instance, build the environment via the SWE-bench harness
  (clone repo at `base_commit` over the working git smart-HTTP transport, install
  the language toolchain + deps during the network acquisition phase, apply
  `test_patch`), then pin the resulting LOCAL image digest and run offline. The
  pinned RTK binary is injected (bind-mount) and `rtk cargo test` / `rtk go test` /
  `rtk jest|vitest` / `rtk mvn|gradlew test` run inside; qodec meters the captured
  output outside the container.
- Cost: multi-GB and minutes per instance build → sequential build/run/prune under
  the ~23 GiB budget; well within §9 per-unit limits when pruned between cases.

## Git — SWE-bench patches (no Docker)
- Acquire: `git fetch` the instance repo at `base_commit` (git transport works
  cross-owner); apply upstream `patch`/`test_patch` to create real dirty states.
  Push cases target a disposable local bare remote (§6.2). No Docker required.

## Python — BugsInPy (reserve, raw CDN reachable)
- SWE-bench Multilingual contains no Python (confirmed: 0 Python repos among the 41).
  Python/pytest + ruff cases come from BugsInPy; its repo + per-bug metadata are
  reachable via `raw.githubusercontent.com` (open cross-owner). Enumeration pending.

## Containers — local disposable, digest-pinned (Terminal-Bench optional)
- Terminal-Bench 2.0 HF endpoints return 401 (auth/gated) at reconnaissance. The
  §6.9 requirement — several running containers, multiple images, repetitive +
  mixed normal/error logs, all LOCAL and DISPOSABLE — is satisfiable directly:
  resolve+pin real public image digests via the OCI resolver, run them as local
  disposable containers on the running daemon, and capture `rtk docker ps/images/
  logs`. Terminal-Bench task environments may be promoted if an unauthenticated,
  digest-pinnable source is confirmed; otherwise digest-pinned public images meet
  the stratum deterministically.

## Network split (§4/§16)
- Acquisition (network): dataset revisions, Zenodo archives, git fetches, image
  builds, dependency caches — all reachable (HF, Zenodo, crates.io/pypi/npm/go
  proxies in noProxy, git smart-HTTP, docker.io/ghcr via token).
- Measurement (network-denied): fresh workdirs, fixed locale/timezone/terminal,
  no color/progress, user-namespace `unshare -n` isolation for offline execution.
