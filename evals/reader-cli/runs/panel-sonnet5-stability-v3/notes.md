# panel-sonnet5-stability-v3 — the three-panel picture

Same mixed question battery as v1 (`ab/findings.json`), raw vs paper,
4 repeats each. raw: 6/6 × 4. paper: 6/6, 6/6, 5/6, 5/6 — the two losses
are again q4 (suspect_fp=true count), again answered exactly **4**.

## Combined evidence across all three panels (Sonnet 5, findings.json)

The suspect_fp count question on the *mixed* battery, all repeats pooled:

| arm | repeats | q4 failures | wrong answer when failing |
|---|---:|---:|---|
| raw | 6 (v1 2 + v3 4) | 0 | — |
| deep | 2 (v1) | 0 | — |
| paper | 8 (v1 2 + v3 4 + v2 2*) | 4 | always exactly 4 |

\* v2 asked the same count inside a dedicated counting battery — paper
passed there (and so did deep and squeeze on their risk-flagged severity
counts), while v2's stable miss was **raw** undercounting severity=medium.

## What survives, what does not

* **The mechanistic signature is strong.** Paper's every wrong answer is
  exactly the artifact-visible count (3 literal in body + 1 legend
  definition = 4) — never 3, never 6. Four independent failures, one
  number, and `qodec risk` computes that number without running a model.
* **The attribution is suggestive, not concluded.** 4/8 failures on paper
  vs 0/6 on raw (Fisher exact p ≈ 0.09) — below any respectable bar.
  What v2 adds: the failure is modulated by question framing (a dedicated
  counting battery elicits careful counting; a mixed battery does not),
  and counting fragility exists on plain JSON too (raw's severity miss).
* **The risk report is a hazard flag, not a failure predictor.** Its
  split-span flags mark where a *plausible-but-wrong* count exists for the
  reader to fall into; whether the reader falls depends on framing and
  attention. v2 falsified its point predictions; v3 re-confirmed the
  hazard is real. Diagnostic, not a gate — as shipped.

## Next increments this suggests

More repeats on the paper/mixed cell to tighten the interval; the same
battery through a second reader (codex CLI when available) to separate
model-specific from representation-specific fragility; and a `risk`-driven
question generator (ask the visible-count number as a distractor probe).
