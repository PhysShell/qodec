# Full-request matrix — chat template applied, brief + dictionary paid

date 2026-07-25 · qodec `d8d17b4a2883` · cold one-shot: encoded arm = template(task + notation brief + artifact). Per family, corpus-total request tokens; saving vs the raw request.

| tokenizer | raw req | squeeze cold | Δ | squeeze warm | Δ | paper cold | Δ | paper warm | Δ |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| deepseek-v3 | 3450 | 3912 | -13.4% | 2280 | +33.9% | 4916 | -42.5% | 3284 | +4.8% |
| gemma2 | 3736 | 4054 | -8.5% | 2446 | +34.5% | 5141 | -37.6% | 3533 | +5.4% |
| glm4 | 3143 | 3713 | -18.1% | 2141 | +31.9% | 4587 | -45.9% | 3015 | +4.1% |
| llama3.1 | 3151 | 3726 | -18.2% | 2154 | +31.6% | 4598 | -45.9% | 3026 | +4.0% |
| mistral0.3 | 4110 | 4358 | -6.0% | 2648 | +35.6% | 5607 | -36.4% | 3897 | +5.2% |
| phi4 | 3133 | 3714 | -18.5% | 2142 | +31.6% | 4580 | -46.2% | 3008 | +4.0% |
| qwen2.5 | 3400 | 3958 | -16.4% | 2386 | +29.8% | 4837 | -42.3% | 3265 | +4.0% |

cold = the brief travels in every request (one-shot worst case; on payloads this small it eats the gain — the truth, not a bug). warm = brief amortized in a cached prefix, artifact still carries its own dictionary. Both are *full requests*: chat template applied, task line included.
