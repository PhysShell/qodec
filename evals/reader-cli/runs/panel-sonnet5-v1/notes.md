# panel-sonnet5-v1 — reading of the results

24 calls, zero reader/grade failures, model `claude-sonnet-5` throughout.

## Headline

Comprehension held at 6/6 in **every arm of every case except one**: the
`paper` baseline on `findings` lost the *count* question (q4 "how many
findings are marked suspect_fp = true?" — truth 5, answered 4) in **both**
repeats, while `raw` and `deep` stayed 6/6 on the same payload.

## Mechanism (verified against the artifact, not guessed)

`qodec encode --codec paper -i corpus/findings.json` puts the counted
predicate *inside a dictionary value*:

```
<M3>=subscription without matching unsubscribe in Dispose","suspect_fp":true},
```

so some `"suspect_fp":true` occurrences appear in the body only as `<M3>`.
Counting then requires mentally expanding the legend and summing alias
occurrences with literal ones — the reader undercounts by exactly one. This
is the same failure class as the interop L2 `n-warnings` loss
(notation-ambiguity on counts) and the model-readability risk the program
document predicts for dictionary codecs; `deep`'s measured, token-aware
aliasing did not trip it here.

Combined with the tokenizer matrix (paper is net-*negative* on
findings.json under every meter), the baseline is doubly condemned on
structured JSON: it pays tokens *and* loses a count. qodec's contribution
is visible in both dimensions at once.

## Caveats

* `fresh input tok` is polluted by prompt caching across runs: arms whose
  identical prompt was sent earlier (e.g. stacktrace raw/deep after the
  smoke run) show cache-*read* instead of cache-creation, collapsing the
  column to ~2. The o200k column is the deterministic size evidence;
  envelope reads are per-call truth, comparable only within a cold run.
* Six questions per case is comprehension smoke, not the G5 gate — the
  value of the stable paper/findings loss is that it reproduces the
  interop L2 failure class through a completely different reader stack
  (Claude Code CLI vs served vLLM, Sonnet 5 vs Qwen 7B).
