# Tokenizer matrix — corpus-total savings per family

date: 2026-07-25 · qodec commit `8bf12fe62bf4` · corpus: the 6 committed samples · cold = full artifact (dictionary included), warm = body only (legend amortized in a cached prefix). Counts are payload-level (no chat template); every cell is re-encoded under that family's tokenizer, never rescaled from o200k.

## Cold (net, dictionary travels in-message)

| tokenizer | RAW tok | fold | toon | grep | diag | tmpl | paper | mine | deep | squeeze | mosaic |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| o200k | 3115 | +5.5% | +2.8% | +1.3% | -1.0% | +16.0% | +4.1% | +19.2% | +30.0% | +33.0% | +30.9% |
| cl100k | 3050 | +5.4% | +2.8% | +1.6% | -1.0% | +15.6% | +4.1% | +17.6% | +28.8% | +32.4% | +30.3% |
| qwen2.5 | 3184 | +5.6% | +2.7% | +1.5% | -0.9% | +15.9% | +4.2% | +17.4% | +28.0% | +31.8% | +30.3% |
| llama3.1 | 3050 | +5.4% | +2.8% | +1.7% | -1.0% | +15.6% | +4.1% | +19.0% | +29.6% | +32.6% | +30.5% |
| deepseek-v3 | 3390 | +5.8% | +1.1% | +1.7% | -0.8% | +17.3% | +4.9% | +21.3% | +32.3% | +34.5% | +33.3% |
| glm4 | 3071 | +5.6% | +2.8% | +1.6% | -1.0% | +15.8% | +4.2% | +19.3% | +29.7% | +32.6% | +30.7% |
| phi4 | 3050 | +5.4% | +2.8% | +1.6% | -1.0% | +15.6% | +4.1% | +17.6% | +28.8% | +32.4% | +30.3% |
| mistral0.3 | 4038 | +6.0% | +1.7% | +2.0% | -0.2% | +18.4% | +5.3% | +22.6% | +33.5% | +36.2% | +35.8% |
| gemma2 | 3640 | +6.0% | +3.0% | +1.6% | -0.6% | +17.9% | +5.6% | +22.7% | +32.6% | +35.4% | +34.0% |

## Warm (body only, legend amortized)

| tokenizer | RAW tok | fold | toon | grep | diag | tmpl | paper | mine | deep | squeeze | mosaic |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| o200k | 3115 | +7.5% | +4.9% | +3.5% | +3.5% | +39.4% | +24.0% | +41.3% | +56.8% | +49.5% | +45.4% |
| cl100k | 3050 | +7.5% | +5.0% | +3.8% | +3.5% | +39.0% | +23.0% | +37.3% | +53.6% | +46.9% | +42.8% |
| qwen2.5 | 3184 | +7.5% | +4.8% | +3.6% | +3.5% | +38.9% | +23.1% | +36.5% | +52.5% | +46.1% | +42.7% |
| llama3.1 | 3050 | +7.5% | +5.0% | +3.9% | +3.5% | +39.0% | +23.0% | +39.4% | +54.5% | +47.2% | +43.1% |
| deepseek-v3 | 3390 | +7.7% | +3.0% | +3.7% | +3.4% | +40.5% | +23.0% | +43.6% | +59.0% | +50.6% | +47.4% |
| glm4 | 3071 | +7.6% | +5.0% | +3.7% | +3.5% | +39.3% | +23.0% | +38.8% | +54.5% | +47.1% | +43.2% |
| phi4 | 3050 | +7.5% | +5.0% | +3.8% | +3.5% | +39.0% | +23.0% | +37.3% | +53.6% | +46.9% | +42.8% |
| mistral0.3 | 4038 | +7.5% | +3.4% | +3.7% | +4.5% | +40.5% | +23.4% | +45.4% | +59.8% | +52.6% | +50.6% |
| gemma2 | 3640 | +7.7% | +4.9% | +3.4% | +3.4% | +40.6% | +22.4% | +44.3% | +58.8% | +51.5% | +49.0% |

families not fetched (no tokenizer.json / drift / offline): kimi-k2 (moonshotai/Kimi-K2-Instruct)

⚠ marks a family where any sample failed byte roundtrip under that codec — investigate before trusting the number.

Full per-sample rows, provenance and hashes: `results.json`.
