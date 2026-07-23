# N2-E text-compression benchmark — RAW vs RTK vs Qodec vs RTK→Qodec

Reporting slice over the already-qualified twelve-case N2-E corpus (`resolved_canary_pass=true`). No frozen evidence, qualification record, aggregator, dispatch, or promotion flag was touched.

- **Qodec**: `target/release/qodec` sha256 `100fd35a18a9447f…`, v0.1.0, config codec_arm=`deep` / tokenize=`identity`, alphabet=auto, `--json` envelope.
- **Tokenizers**: primary **o200k_base**, secondary **cl100k_base** (tiktoken-rs 0.7.0 (embedded BPE, offline)). Exact BPE, no char/4.
- **Command**: `python3 benchmarks/n2e-text-compression/run_benchmark.py`
- **compression_ratio = arm_tokens / raw_tokens** (smaller is better); **saving% = 100·(1 − ratio)**. Primary meter = o200k.

## Per-case headline (primary o200k tokens)

| case | family | RAW | RTK | Qodec | RTK→Qodec | winner | RTK sem | notes |
|---|---|--:|--:|--:|--:|:--:|:--:|---|
| coreutils | Test output | 344 | 19 (+94.5%) | 290 (+15.7%) | 29 (+91.6%) | rtk | pass | RAW=canon |
| caddy | Test output | 63 | 78 (-23.8%) | 73 (-15.9%) | 88 (-39.7%) | qodec | pass | RAW=canon, RTK↑ |
| lucene | Test output | 6,251 | 6,251 (+0.0%) | 3,661 (+41.4%) | 3,661 (+41.4%) | qodec | pass | RAW=canon |
| vue | Test output | 2,318 | 2,318 (+0.0%) | 1,022 (+55.9%) | 1,022 (+55.9%) | qodec | pass | RAW=canon |
| scrapy | Test output | 500 | 7 (+98.6%) | 452 (+9.6%) | 17 (+96.6%) | rtk | pass | RAW=canon |
| gin | Diagnostics | 0 | 1 | 10 | 10 | rtk | pass | RAW=canon, RTK↑ |
| preact | File content | 4,223 | 4,223 (+0.0%) | 1,929 (+54.3%) | 1,929 (+54.3%) | qodec | pass | RAW=canon |
| lombok | File content | 254 | 254 (+0.0%) | 233 (+8.3%) | 233 (+8.3%) | qodec | pass | RAW=canon |
| loghub | Large structured logs | — | 606 | — | 375 | rtk_then_qodec | pass | RAW capsule |
| rubocop | Git output | 128 | 84 (+34.4%) | 138 (-7.8%) | 94 (+26.6%) | rtk | pass |  |
| php-cs-fixer | Git output | 35 | 6 (+82.9%) | 45 (-28.6%) | 16 (+54.3%) | rtk | pass |  |
| redis | Docker inventory | 10 | 21 (-110.0%) | 20 (-100.0%) | 31 (-210.0%) | qodec | pass | RTK↑ |

## Per-case detail

### coreutils · Test output

- **RAW**: 1,229 B, 28 lines, 344 o200k / 340 cl100k tok; 434 ms, 0.0 MiB/s
- **RTK**: 59 B, 1 lines, 19 o200k / 19 cl100k tok; vs RAW 325 tok / +94.48%; semantic=pass; 455 ms, 0.0 MiB/s
- **Qodec**: 983 B, 37 lines, 290 o200k / 293 cl100k tok; vs RAW 54 tok / +15.70%; vs RTK -271 tok / -1426.32%; semantic=pass (lossless=True); 386 ms, 0.0 MiB/s
- **RTK → Qodec**: 76 B, 3 lines, 29 o200k / 29 cl100k tok; vs RAW 315 tok / +91.57%; vs RTK -10 tok / -52.63%; semantic=pass (lossless=True); 334 ms, 0.0 MiB/s
- **ranking** (fewest o200k tokens, semantic-ok only): rtk < rtk_then_qodec < qodec

### caddy · Test output

- **RAW**: 206 B, 6 lines, 63 o200k / 63 cl100k tok; 451 ms, 0.0 MiB/s
- **RTK**: 232 B, 6 lines, 78 o200k / 77 cl100k tok; vs RAW -15 tok / -23.81%; semantic=pass; 424 ms, 0.0 MiB/s
- **Qodec**: 223 B, 8 lines, 73 o200k / 73 cl100k tok; vs RAW -10 tok / -15.87%; vs RTK +5 tok / +6.41%; semantic=pass (lossless=True); 302 ms, 0.0 MiB/s
- **RTK → Qodec**: 249 B, 8 lines, 88 o200k / 87 cl100k tok; vs RAW -25 tok / -39.68%; vs RTK -10 tok / -12.82%; semantic=pass (lossless=True); 321 ms, 0.0 MiB/s
- **ranking** (fewest o200k tokens, semantic-ok only): qodec < rtk < rtk_then_qodec

### lucene · Test output

- **RAW**: 24,660 B, 472 lines, 6,251 o200k / 6,303 cl100k tok; 508 ms, 0.0 MiB/s
- **RTK**: 24,660 B, 472 lines, 6,251 o200k / 6,303 cl100k tok; vs RAW 0 tok / +0.00%; semantic=pass; 452 ms, 0.1 MiB/s
- **Qodec**: 12,870 B, 538 lines, 3,661 o200k / 3,877 cl100k tok; vs RAW 2,590 tok / +41.43%; vs RTK +2,590 tok / +41.43%; semantic=pass (lossless=True); 9446 ms, 0.0 MiB/s
- **RTK → Qodec**: 12,870 B, 538 lines, 3,661 o200k / 3,877 cl100k tok; vs RAW 2,590 tok / +41.43%; vs RTK +2,590 tok / +41.43%; semantic=pass (lossless=True); 9313 ms, 0.0 MiB/s
- **ranking** (fewest o200k tokens, semantic-ok only): qodec < rtk_then_qodec < rtk

### vue · Test output

- **RAW**: 9,789 B, 112 lines, 2,318 o200k / 2,320 cl100k tok; 572 ms, 0.0 MiB/s
- **RTK**: 9,789 B, 112 lines, 2,318 o200k / 2,320 cl100k tok; vs RAW 0 tok / +0.00%; semantic=pass; 501 ms, 0.0 MiB/s
- **Qodec**: 4,115 B, 131 lines, 1,022 o200k / 1,067 cl100k tok; vs RAW 1,296 tok / +55.91%; vs RTK +1,296 tok / +55.91%; semantic=pass (lossless=True); 1055 ms, 0.0 MiB/s
- **RTK → Qodec**: 4,115 B, 131 lines, 1,022 o200k / 1,067 cl100k tok; vs RAW 1,296 tok / +55.91%; vs RTK +1,296 tok / +55.91%; semantic=pass (lossless=True); 1083 ms, 0.0 MiB/s
- **ranking** (fewest o200k tokens, semantic-ok only): qodec < rtk_then_qodec < rtk

### scrapy · Test output

- **RAW**: 2,001 B, 28 lines, 500 o200k / 491 cl100k tok; 502 ms, 0.0 MiB/s
- **RTK**: 17 B, 1 lines, 7 o200k / 7 cl100k tok; vs RAW 493 tok / +98.60%; semantic=pass; 486 ms, 0.0 MiB/s
- **Qodec**: 1,854 B, 34 lines, 452 o200k / 450 cl100k tok; vs RAW 48 tok / +9.60%; vs RTK -445 tok / -6357.14%; semantic=pass (lossless=True); 420 ms, 0.0 MiB/s
- **RTK → Qodec**: 34 B, 3 lines, 17 o200k / 17 cl100k tok; vs RAW 483 tok / +96.60%; vs RTK -10 tok / -142.86%; semantic=pass (lossless=True); 314 ms, 0.0 MiB/s
- **ranking** (fewest o200k tokens, semantic-ok only): rtk < rtk_then_qodec < qodec

### gin · Diagnostics

- **RAW**: 0 B, 0 lines, 0 o200k / 0 cl100k tok; 469 ms
- **RTK**: 1 B, 1 lines, 1 o200k / 1 cl100k tok; semantic=pass; 454 ms, 0.0 MiB/s
- **Qodec**: 17 B, 2 lines, 10 o200k / 10 cl100k tok; vs RTK -9 tok / -900.00%; semantic=pass (lossless=True); 355 ms, 0.0 MiB/s
- **RTK → Qodec**: 18 B, 3 lines, 10 o200k / 10 cl100k tok; vs RTK -9 tok / -900.00%; semantic=pass (lossless=True); 341 ms, 0.0 MiB/s
- **ranking** (fewest o200k tokens, semantic-ok only): rtk < qodec < rtk_then_qodec

### preact · File content

- **RAW**: 14,778 B, 187 lines, 4,223 o200k / 4,108 cl100k tok; 537 ms, 0.0 MiB/s
- **RTK**: 14,778 B, 187 lines, 4,223 o200k / 4,108 cl100k tok; vs RAW 0 tok / +0.00%; semantic=pass; 541 ms, 0.0 MiB/s
- **Qodec**: 6,824 B, 210 lines, 1,929 o200k / 1,990 cl100k tok; vs RAW 2,294 tok / +54.32%; vs RTK +2,294 tok / +54.32%; semantic=pass (lossless=True); 1949 ms, 0.0 MiB/s
- **RTK → Qodec**: 6,824 B, 210 lines, 1,929 o200k / 1,990 cl100k tok; vs RAW 2,294 tok / +54.32%; vs RTK +2,294 tok / +54.32%; semantic=pass (lossless=True); 1850 ms, 0.0 MiB/s
- **ranking** (fewest o200k tokens, semantic-ok only): qodec < rtk_then_qodec < rtk

### lombok · File content

- **RAW**: 1,050 B, 20 lines, 254 o200k / 243 cl100k tok; 458 ms, 0.0 MiB/s
- **RTK**: 1,050 B, 20 lines, 254 o200k / 243 cl100k tok; vs RAW 0 tok / +0.00%; semantic=pass; 439 ms, 0.0 MiB/s
- **Qodec**: 910 B, 26 lines, 233 o200k / 231 cl100k tok; vs RAW 21 tok / +8.27%; vs RTK +21 tok / +8.27%; semantic=pass (lossless=True); 329 ms, 0.0 MiB/s
- **RTK → Qodec**: 910 B, 26 lines, 233 o200k / 231 cl100k tok; vs RAW 21 tok / +8.27%; vs RTK +21 tok / +8.27%; semantic=pass (lossless=True); 336 ms, 0.0 MiB/s
- **ranking** (fewest o200k tokens, semantic-ok only): qodec < rtk_then_qodec < rtk

### loghub · Large structured logs

- **RAW**: unsupported — RAW is the full ~1.5 GB HDFS.log member; not committed. Reacquisition is impractical in the session disk allowance and exact streaming BPE tokenization is out of scope for this slice, so RAW/Qodec-on-RAW token counts are UNSUPPORTED. (published lines ≈ 11,167,740, member `e8987f909b97…`)
- **RTK**: 1,877 B, 25 lines, 606 o200k / 606 cl100k tok; semantic=pass; 450 ms, 0.0 MiB/s
- **Qodec**: unsupported — RAW bytes not local (bounded capsule)
- **RTK → Qodec**: 1,055 B, 33 lines, 375 o200k / 383 cl100k tok; vs RTK +231 tok / +38.12%; semantic=pass (lossless=True); 407 ms, 0.0 MiB/s
- **ranking** (fewest o200k tokens, semantic-ok only): rtk_then_qodec < rtk

### rubocop · Git output

- **RAW**: 394 B, 9 lines, 128 o200k / 127 cl100k tok; 474 ms, 0.0 MiB/s
- **RTK**: 267 B, 3 lines, 84 o200k / 83 cl100k tok; vs RAW 44 tok / +34.38%; semantic=pass; 449 ms, 0.0 MiB/s
- **Qodec**: 411 B, 11 lines, 138 o200k / 137 cl100k tok; vs RAW -10 tok / -7.81%; vs RTK -54 tok / -64.29%; semantic=pass (lossless=True); 311 ms, 0.0 MiB/s
- **RTK → Qodec**: 284 B, 5 lines, 94 o200k / 93 cl100k tok; vs RAW 34 tok / +26.56%; vs RTK -10 tok / -11.90%; semantic=pass (lossless=True); 321 ms, 0.0 MiB/s
- **ranking** (fewest o200k tokens, semantic-ok only): rtk < rtk_then_qodec < qodec

### php-cs-fixer · Git output

- **RAW**: 94 B, 3 lines, 35 o200k / 35 cl100k tok; 462 ms, 0.0 MiB/s
- **RTK**: 11 B, 1 lines, 6 o200k / 6 cl100k tok; vs RAW 29 tok / +82.86%; semantic=pass; 478 ms, 0.0 MiB/s
- **Qodec**: 111 B, 5 lines, 45 o200k / 45 cl100k tok; vs RAW -10 tok / -28.57%; vs RTK -39 tok / -650.00%; semantic=pass (lossless=True); 530 ms, 0.0 MiB/s
- **RTK → Qodec**: 28 B, 3 lines, 16 o200k / 16 cl100k tok; vs RAW 19 tok / +54.29%; vs RTK -10 tok / -166.67%; semantic=pass (lossless=True); 316 ms, 0.0 MiB/s
- **ranking** (fewest o200k tokens, semantic-ok only): rtk < rtk_then_qodec < qodec

### redis · Docker inventory

- **RAW**: 17 B, 1 lines, 10 o200k / 10 cl100k tok; 464 ms, 0.0 MiB/s
- **RTK**: 46 B, 2 lines, 21 o200k / 21 cl100k tok; vs RAW -11 tok / -110.00%; semantic=pass; 474 ms, 0.0 MiB/s
- **Qodec**: 34 B, 3 lines, 20 o200k / 20 cl100k tok; vs RAW -10 tok / -100.00%; vs RTK +1 tok / +4.76%; semantic=pass (lossless=True); 330 ms, 0.0 MiB/s
- **RTK → Qodec**: 63 B, 4 lines, 31 o200k / 31 cl100k tok; vs RAW -21 tok / -210.00%; vs RTK -10 tok / -47.62%; semantic=pass (lossless=True); 306 ms, 0.0 MiB/s
- **ranking** (fewest o200k tokens, semantic-ok only): qodec < rtk < rtk_then_qodec

## Family summaries

| family | cases | RTK median saving | Qodec median saving | Qodec range | sem fail | sem unsup | note |
|---|---|--:|--:|--:|--:|--:|---|
| Diagnostics | gin | — | — | — | 0 | 0 | single-case family -- not a statistical average |
| Docker inventory | redis | -110.00% | -100.00% | -100.0…-100.0% | 0 | 0 | single-case family -- not a statistical average |
| File content | preact, lombok | +0.00% | +31.29% | 8.3…54.3% | 0 | 0 | highly case-dependent |
| Git output | rubocop, php-cs-fixer | +58.62% | -18.19% | -28.6…-7.8% | 0 | 0 | consistent across cases |
| Large structured logs | loghub | — | — | — | 0 | 1 | single-case family -- not a statistical average |
| Test output | coreutils, caddy, lucene, vue, scrapy | +0.00% | +15.70% | -15.9…55.9% | 0 | 0 | highly case-dependent |

## Aggregates (secondary — read after the per-case detail)

### All twelve cases

| arm | measured | weighted saving | macro-median | min | max | increased text |
|---|--:|--:|--:|--:|--:|--:|
| rtk | 11 | +6.12% | +0.00% | -110.00% | +98.60% | 2 |
| qodec | 11 | +44.34% | +8.93% | -100.00% | +55.91% | 4 |
| rtk_then_qodec | 11 | +49.60% | +47.86% | -210.00% | +96.60% | 2 |

- winners: RTK=5, Qodec=6, RTK→Qodec=1, none=0
- semantic tally (arm-instances): pass=35, fail=0, unsupported=1, reference=12

### Eleven cases excluding Loghub

| arm | measured | weighted saving | macro-median | min | max | increased text |
|---|--:|--:|--:|--:|--:|--:|
| rtk | 11 | +6.12% | +0.00% | -110.00% | +98.60% | 2 |
| qodec | 11 | +44.34% | +8.93% | -100.00% | +55.91% | 4 |
| rtk_then_qodec | 11 | +49.60% | +47.86% | -210.00% | +96.60% | 2 |

- winners: RTK=5, Qodec=6, RTK→Qodec=0, none=0
- semantic tally (arm-instances): pass=33, fail=0, unsupported=0, reference=11

**Micro (weighted) vs macro (median).** The weighted aggregate is dominated by the largest inputs; the macro median treats every case equally. They can disagree sharply, so both are shown, and the without-Loghub view sits beside the all-twelve view — no single 'average saving' headline stands alone.

## Limitations & honesty notes

- 8 cases (coreutils, caddy, lucene, vue, scrapy, gin, preact, lombok) expose **canonicalized** bytes as their frozen RAW authority, not true raw stdout — labeled `RAW=canon`.
- **Loghub** RAW is a ~1.5 GB reacquirable member (bounded capsule committed); its RAW/Qodec token counts are **unsupported** here (not loaded into memory; exact streaming BPE out of scope). RTK and RTK→Qodec are exact.
- 4 cases (lucene, vue, preact, lombok) have **RTK ≡ RAW** (faithful preservation → 0 token saving).
- **caddy** and **redis** show RTK **increasing** tokens vs their frozen authority (redis RAW = the `--format` projection; the user-facing default `docker images` table lives only in the CI artifact).
- **gin** RAW is empty (0 tokens) → compression ratio undefined; absolute values reported.
- Qodec arms are **byte-lossless** (decode==input verified per arm); semantic preservation is total, so a lossy 'OK'-style output can never rank as a winner.
- **Qodec is UTF-8-only**: it errors on invalid UTF-8 input (documented limitation). All twelve corpus streams are valid UTF-8, so no arm hit this; an invalid-UTF-8 input would be recorded as `failed`, never approximated.

_Total measured runtime 44.9s; peak child RSS not available on this host (/usr/bin/time absent). Inputs are ≤25 KiB (loghub RTK 1.9 KiB), so per-arm wall time is dominated by process startup and MiB/s throughput rounds to ~0; timing is reported for completeness, not as a performance claim._

