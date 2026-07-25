# Tokenizer matrix — does the win survive the tokenizer?

Token savings are a claim about a *specific* tokenizer. This stand runs the
whole codec table (including the `paper` arXiv:2604.13066 baseline) under
many real open tokenizers, re-encoding under each one through the crate's
fail-closed `hf:` meter — aliases and acceptance are chosen per tokenizer,
nothing is rescaled from the o200k proxy. No GPU, no inference, no API keys:
one `tokenizer.json` download per family, then fully offline.

```bash
cargo build --release
python3 evals/tokenizer-matrix/run.py             # fetch + verify + bench + report
python3 evals/tokenizer-matrix/run.py --offline   # cache only, refuse downloads
```

Downloads are pinned: the first fetch records url/sha256/bytes in
`tokenizers.lock.json`; later runs re-verify the cached file and refuse on
drift. Gated repos (meta-llama, mistralai, google) are represented by
well-known ungated mirrors, marked as such in the provenance — what is
pinned is the tokenizer bytes, not the repo pedigree. Results (committed):
`results/matrix.md` + full per-sample rows and hashes in
`results/results.json`. Tokenizer files live in `.cache/` (gitignored).

## Honest scope

* Counts are payload-level (`add_special_tokens=false`), not full-request.
  The chat-template wrapping is identical in both arms, so it cancels in the
  absolute saving and only dilutes the percentage; exact chat-template
  full-request accounting is a later increment.
* This proves **net token reduction** per tokenizer — gate G2 of the
  program. It proves nothing about comprehension; that is Level 2's job
  (`evals/interop/`).

## Findings (2026-07-25 run, 8 families + o200k/cl100k)

* **The relative ordering transfers.** `deep` > `squeeze`/`mosaic` > `mine` >
  `tmpl` > `paper` > `fold` on every one of the 10 meters — the lab's
  "relative ordering transfers across BPE tokenizers" rule is now measured,
  not assumed.
* **Absolute savings move only a few points across families** (cold corpus
  total: `squeeze` +31.8%…+36.2%; warm `deep` +52.5%…+59.8%). Tokenizers
  that spend more tokens on the raw corpus (mistral0.3, gemma2, deepseek-v3)
  save the most — redundancy the codec removes is redundancy the tokenizer
  was paying for.
* **The paper baseline stays an order behind qodec everywhere** (cold
  +4.1%…+5.6% vs qodec's +31.8%…+36.2%): the comparison-ladder gap is
  tokenizer-robust, not an o200k artifact.
* **Zero roundtrip failures** across all families × codecs × samples.
* llama3.1 and phi4 count this ASCII corpus identically to cl100k —
  cl100k-lineage vocabularies agree on plain ASCII; the matrix keeps them as
  separate pinned meters anyway.
* kimi-k2 publishes no `tokenizer.json` (tiktoken-style model file) — noted
  as not fetched rather than silently dropped.
