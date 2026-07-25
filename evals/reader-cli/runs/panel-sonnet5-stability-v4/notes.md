# panel-sonnet5-stability-v4 — the attribution closes

Mixed battery, raw vs paper, 8 repeats each: raw 6/6 × 8, paper 5/6 × 8 —
every single loss is q4 (suspect_fp=true count), every single wrong answer
is exactly **4**.

## Pooled mixed-battery evidence (v1 + v3 + v4)

| arm | repeats | q4 failures |
|---|---:|---:|
| raw | 14 | 0 |
| deep | 2 | 0 |
| paper | 16 | **12** |

Fisher exact (paper 12/16 vs raw 0/14, one-sided): **p ≈ 2.1×10⁻⁵**.

All 12 wrong answers are the number `qodec risk` precomputes without a
model (3 literal body occurrences + 1 legend definition = 4). The v3
"suggestive, not concluded" caveat is now resolved: on this battery, this
payload, this reader, the paper baseline's split representation causes a
stable, mechanistically-predicted undercount, and qodec's `deep` does not.

Scope guards that stay: one payload, one reader, one question — a decisive
demonstration of the mechanism, not a general codec ranking; v2/v5 show
the trap is framing-dependent (explicit count batteries elicit careful
counting and everyone passes).
