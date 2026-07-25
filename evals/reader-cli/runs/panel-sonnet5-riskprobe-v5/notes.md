# panel-sonnet5-riskprobe-v5 — traps don't spring when named

The `gen_questions.py` battery: exact-occurrence probes for the two
risk-flagged split spans of paper/findings, each with a precomputed trap
(the artifact-visible count — 9 and 1 against truths 12 and 3).

Result: raw, deep and paper all 2/2 in both repeats. Nobody answered a
trap number — even the paper arm, whose representation *is* the trap.

Read together with v2 (dedicated semantic-count battery: every codec
passed, raw stumbled on severity) and v4 (mixed battery: paper fails the
semantic count 12/16 with exactly the trap number):

* The split representation is a **latent hazard**, not a deterministic
  failure: it materializes when a count is asked *incidentally* among
  other questions, and vanishes when the question explicitly demands
  counting — the reader then decodes and counts carefully.
* That makes `qodec risk` exactly what it claims to be: a hazard flag
  whose number tells you what the wrong answer will be *if* it happens —
  not a predictor of when. Gate-grade use would need framing-matched
  panels, which is what this stand now automates end-to-end
  (risk → gen_questions → panel → trap comparison).
