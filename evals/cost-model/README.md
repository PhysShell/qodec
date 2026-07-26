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
python3 -c "
import json
a=json.load(open('evals/cost-model/dataset-corpus.json'))
b=json.load(open('evals/cost-model/dataset-synth.json'))
assert a['meter']==b['meter'] and a['format']==b['format']
json.dump({'format':a['format'],'meter':a['meter'],'rows':a['rows']+b['rows']}, open('evals/cost-model/dataset-all.json','w'))"
./target/release/qodec cost fit -i evals/cost-model/dataset-all.json --holdout build-log.txt,rg-output.txt -o evals/cost-model/model.json
./target/release/qodec cost bench --corpus evals/cost-model/demo --model evals/cost-model/model.json
```

The harvested datasets are deterministic; the synthetic one is too large
to commit (11 MB), so its identity is pinned instead — regeneration must
reproduce these exact bytes:

```
dataset-corpus.json  sha256  4e632988162b959e36e70d304a2240af051daed3a6aa857a90bdf5c4335023d9
dataset-synth.json   sha256  6173177e156577cdebd69e21f20d6e908d0955fb17351202597afd9e53201775
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
   ratio* `cost/size`; the prediction is `clamp(ratio, 0.02, 1.2) × size`.
   Precisely stated (the first wording overclaimed, caught by Codex review
   with a live counterexample): the clamp bounds any two predictions to
   `cost(A)/cost(B) ≥ (0.02/1.2)·(size_A/size_B)` — excluding the global
   slope inversion — but does **not** make cost monotonic under span
   extension, since the ratio reads size-dependent features. The physical
   law "extending a span never makes its artifact cheaper" is enforced in
   the DP instead: the predicted router applies a running max over each
   start's extensions, O(1) per edge. Holdout Spearman: build-log 0.918,
   rg-output 0.994 (refit after the dup-boundary feature fix from review).

## Results (v2)

| fixture | raw tok | measured all-span | predicted | geometric |
|---|---:|---:|---:|---:|
| offgrid-250 (250 lines) | 4599 | **2013** · 349 s | **2013** · **0.071 s** | 2119 · 6.8 s |
| offgrid-900 (864 lines) | 16015 | refuses (>300) | 7613 · **0.23 s** | **7445** · 23.7 s |
| corpus ×6 | — | = predicted | token-identical, 3–9 ms | = predicted |

Honest reading: after the review-driven dup-boundary feature fix, predicted
routing reproduces the measured truth **token-for-token** where truth is
computable (4900× faster, beating the geometric router there), and lands
within **2.3%** of geometric at 102× less search time where truth is not.
On the 6 real corpus files all three agree token-for-token. The measured
meter remains the only authority — this model never accepts anything.

## Drift tracking

The model is a static artifact, so the question "when has the world moved
out from under it?" has three answers, each with its own mechanism:

1. **Codec drift** (someone improves `fold`/`grep`/`diag`/`tmpl`, shifting
   the ground truth the labels encode): caught in CI by the label canary
   (`tests/cost.rs::ground_truth_canary_pins_span_labels`), which harvests a
   small multi-regime text with the exact o200k meter and compares every
   span label against a pinned string. When it fails, the committed
   datasets and `model.json` no longer describe the code — re-harvest,
   refit, update the pins here and in the test.
2. **Tokenizer drift** (a model trained under one meter asked to rank for
   another): fail-closed stamps through the whole chain. `cost harvest`
   writes the meter *identity* into the dataset envelope
   (`qodec-cost-dataset-v2`) — for bundled BPEs that is the name, for
   `hf:` meters it includes a content digest of the `tokenizer.json`, so a
   file swapped in place under the same path still trips the check (Codex
   review on PR #9). `cost fit` copies the stamp into the model
   (`qodec-cost-model-v2`), and `encode_predicted` skips predicted routing
   entirely on mismatch — baseline ships, `PredictReport::meter_mismatch`
   says why. Unstamped legacy files refuse to load; `cost bench` makes the
   mismatch a hard error.
3. **Domain drift** (real inputs stop resembling the training corpus):
   monitored from work arbitration already pays for — zero extra encodes.
   `encode_predicted_report` returns the DP's predicted path cost, the
   exact realized tokens of that path, and whether arbitration fell back
   to the baseline. Capacity skips (empty input, over the line cap) are
   reported separately and never count toward the fallback rate — only a
   *realized* path that lost arbitration is a model verdict (Codex review
   on PR #9). `cost bench` prints the two indicators (`resid`, `fb`
   columns and a `drift:` summary line); a mean relative residual or
   fallback rate that climbs on a new corpus is the re-harvest signal.
   This is the `docs/secondary-calibration.md` shadow mode: measurement
   only, nothing feeds back into the model at runtime.

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
