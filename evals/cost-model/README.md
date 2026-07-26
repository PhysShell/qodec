# Mosaic cost model — learned edge costs for the all-span DP

The Griff-lab hybrid pattern instantiated where qodec is uniquely
positioned: **labels are free, exact and objective** (encode a span, count
its tokens), so the experiment funnel runs without human preferences.
The model prices a mosaic DAG edge in fourteen multiplications where the
measured router pays four full encodes — which is what makes the exhaustive
all-span graph affordable beyond its 300-line cap (predicted routing goes
to 2000).

The contract is the probe ranker's, verbatim: **ordering only**. The DP
runs on predicted weights, real encodes happen only for the selected path,
and the assembled artifact is arbitrated against the whole-payload
single-codec baseline by the exact meter. A wrong model wastes probes,
never bytes and never tokens (`tests/cost.rs` pins the guarantee).

## Reproduce

```bash
cargo build --release
python3 evals/cost-model/gen_fixtures.py          # byte-identical fixtures
./target/release/qodec cost harvest --corpus corpus -o evals/cost-model/dataset-corpus.json
./target/release/qodec cost harvest --corpus evals/cost-model/train-synth -o evals/cost-model/dataset-synth.json   # ~9 min: 54k spans, exact labels
python3 -c "import json; json.dump(json.load(open('evals/cost-model/dataset-corpus.json'))+json.load(open('evals/cost-model/dataset-synth.json')), open('evals/cost-model/dataset-all.json','w'))"
./target/release/qodec cost fit -i evals/cost-model/dataset-all.json --holdout build-log.txt,rg-output.txt -o evals/cost-model/model.json
./target/release/qodec cost bench --corpus evals/cost-model/demo --model evals/cost-model/model.json
```

The harvested datasets are deterministic; the synthetic one is too large
to commit (11 MB), so its identity is pinned instead — regeneration must
reproduce these exact bytes:

```
dataset-corpus.json  sha256  b9f4b37e13126c325608678de6c5ccd8e49d3f3c8ea646948bf18f4be8bd3849
dataset-synth.json   sha256  666d644cfec40c3ef7315000f74b3ec505836c6a8b0e6ebe11fa26c1a6216c50
```

`model.json` (committed, 4 KB) is the fitted v2 model;
`dataset-corpus.json` (committed, 404 KB) is the corpus harvest.

## The funnel, as it actually ran (2026-07-26, o200k)

1. **v1 — 12 additive features, corpus-only training.** Reproduced the
   measured all-span verdicts token-for-token on all 6 corpus files at
   8–21 ms vs 194–1890 ms, and 0.109 s vs **499 s** on a 250-line
   off-grid fixture (4577×). But on multi-regime fixtures it trailed
   measured quality by 18%: structural codecs are *multiplicative* in
   content mix (fold collapses a run of identical lines to one line), and
   an additive model cannot express `bytes × dup_frac`.
2. **+ interaction features (DIM 12→14) + long-span synthetics, absolute
   target.** Training on 54k long-span rows drove the effective per-byte
   slope negative for grep-dense content: a held-out file's ordering came
   back **inverted** (Spearman −0.97). Textbook extrapolation failure,
   caught by the by-file holdout.
3. **v2 — ratio target.** The model predicts a clamped *compressibility
   ratio* `cost/size`; the prediction is `clamp(ratio, 0.02, 1.2) × size`,
   so cost is structurally increasing in size — the model chooses how
   compressible content is, never whether more bytes cost less. Holdout
   Spearman: build-log 0.917, rg-output 0.994.

## Results (v2)

| fixture | raw tok | measured all-span | predicted | geometric |
|---|---:|---:|---:|---:|
| offgrid-250 (250 lines) | 4599 | **2013** · 489 s | 2108 · **0.097 s** | 2119 · 10.4 s |
| offgrid-900 (864 lines) | 16015 | refuses (>300) | 7555 · **0.34 s** | **7445** · 38.8 s |
| corpus ×6 | — | = predicted | token-identical, 4–16 ms | = predicted |

Honest reading: predicted routing lands within **4.7%** of the measured
truth where truth is computable (beating the geometric router there), and
within **1.5%** of geometric at 113× less search time where truth is not.
On the 6 real corpus files all three agree token-for-token. The measured
meter remains the only authority — this model never accepts anything.

## Scope guards

* Training is offline and explicit; nothing accumulates from production
  runs (`docs/secondary-calibration.md` applies — this is the permitted
  reorder/shortlist layer, built after the measurement infrastructure).
* The bench fixtures and training synthetics come from one generator
  family with disjoint seeds and files; the corpus holdouts are real
  files the model never saw. Cross-family generalization (real CI logs,
  real diffs at 1000+ lines) is the next measurement, not a claim.
* `encode_predicted` is not wired into any production codec path;
  `mosaic` production routing is unchanged.
