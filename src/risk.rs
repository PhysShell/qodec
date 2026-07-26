//! `risk` — model-readability risk report for an encoded artifact.
//!
//! Byte-lossless to the decoder is not legible to the model, and the failure
//! classes are now *measured*, not hypothetical: the interop L2 run lost
//! count questions under fold×alias (`n-warnings`), and the reader-cli panel
//! reproduced the same class through a different stack (Sonnet 5 undercounted
//! `suspect_fp=true` on the `paper` baseline while `deep` held). The verified
//! mechanism: an encoding gives one repeated source span *two different
//! surface forms* — some occurrences literal, some swallowed into dictionary
//! values — so a count over what the model sees no longer equals the truth.
//!
//! This module classifies how each repeated source span is represented in
//! the artifact the model actually reads (header + legend + body):
//!
//! * **uniform-literal** — every occurrence is verbatim in the artifact; a
//!   naive count is correct. No risk.
//! * **split** — some occurrences literal, some hidden inside legend values
//!   (the artifact-visible count is wrong but plausible). HIGH risk: this is
//!   the exact measured killer — in the panel the reader answered the
//!   artifact-visible count (4) instead of the truth (5).
//! * **heterogeneous-hidden** — no literal occurrence, hidden across ≥2
//!   distinct legend entries; counting means summing across different
//!   aliases. MEDIUM risk.
//! * **uniform-hidden** — hidden inside exactly one legend entry; the alias
//!   count times its in-value multiplicity recovers the truth. LOW risk.
//! * **boundary-recomposed** — zero literal occurrences and no legend value
//!   contains the whole span: the span is uniformly reassembled from an
//!   alias expansion plus adjacent literal bytes (deep's `节true` shape).
//!   The panel reader handled this; reported as info, not a flag.
//!
//! `fold`'s `%q1 xN` markers also land in **split** (one literal line, N−1
//! hidden behind an explicit counter) — deliberately so: the L2 evidence
//! says readers miscount folded runs too, explicit counter or not.
//!
//! Scope: spans are single-line (the SAM candidate filter drops
//! newline-crossing repeats) and the legend attribution reads the outermost
//! container layer; nested pipeline layers contribute to visibility counts
//! but not to per-entry attribution. A diagnostic report, not a gate — it
//! flags, the A/B stands decide.

use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::container;
use crate::sam;

/// SAM candidate window: spans shorter than this are noise (single tokens),
/// longer ones are clipped — the risk is about predicates, not paragraphs.
const MIN_SPAN: usize = 6;
const MAX_SPAN: usize = 48;
const SAM_TOP: usize = 400;
/// Near-duplicate legend values: normalized edit distance at or below this.
const NEAR_DUP: f64 = 0.3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanClass {
    UniformLiteral,
    Split,
    HeterogeneousHidden,
    UniformHidden,
    BoundaryRecomposed,
}

impl SpanClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::UniformLiteral => "uniform-literal",
            Self::Split => "split",
            Self::HeterogeneousHidden => "heterogeneous-hidden",
            Self::UniformHidden => "uniform-hidden",
            Self::BoundaryRecomposed => "boundary-recomposed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpanRisk {
    pub span: String,
    /// Non-overlapping occurrences in the decoded source — the truth.
    pub total: usize,
    /// Non-overlapping occurrences in the encoded *body* — what a naive
    /// count over the payload returns. Legend definitions are counted
    /// separately: one definition per alias is the *expected* shape, and
    /// the measured panels show readers handle it (deep 6/6) — the danger
    /// is literal body occurrences mixing with hidden ones.
    pub body_visible: usize,
    /// Occurrences inside legend values (definitions the model also sees —
    /// the panel's wrong answer was body_visible + legend_visible).
    pub legend_visible: usize,
    /// Distinct legend entries whose value contains the span.
    pub hiding_entries: usize,
    pub class: SpanClass,
    /// Byte ranges of every source occurrence — used to collapse sliding
    /// SAM windows over the same underlying repeat into one report line.
    occupied: Vec<(usize, usize)>,
}

#[derive(Debug, Clone)]
pub struct RiskReport {
    pub codec: String,
    pub legend_entries: usize,
    /// Alias occurrences in the body per 100 chars (0 for legend-less codecs).
    pub alias_density: f64,
    pub split: Vec<SpanRisk>,
    pub heterogeneous_hidden: Vec<SpanRisk>,
    pub uniform_hidden: usize,
    pub boundary_recomposed: usize,
    pub uniform_literal: usize,
    /// Legend value pairs within NEAR_DUP normalized edit distance.
    pub near_duplicate_pairs: Vec<(String, String)>,
    /// Legend values whose digit fraction is ≥ 0.3.
    pub numeric_heavy_entries: usize,
}

/// Legend-load onset (`evals/agent-g5/runs/density-codex-v1`, 60
/// closed-world calls at five controlled doses): the codex reader's
/// cross-file join stayed **6/6** at 6-7 legend entries and dropped to
/// 16/24 cells across 15-45 entries, while raw stayed perfect at every
/// dose. Primary paired analysis: 15/15 vs 9/15 task-dose cells, all six
/// discordant cells favoring raw, exact two-sided McNemar p=0.03125.
///
/// Precisely what this constant is: **the first tested legend load at
/// which failures appeared**, not an estimated causal breakpoint — the
/// observed onset lies in (7, 15], and six calls per dose cannot pin the
/// curve's shape beyond "compatible with a step/plateau". All cells share
/// one semantic task family (cross-file join), so cross-family
/// replication remains open. The Sonnet reader held 5/5 on the same task
/// shape in `g5-sonnet-v1`. Family-dependent hazard, not an oracle: at or
/// above this many entries, reasoning that must *join across* the legend
/// becomes unreliable for at least one reader family, and an operational
/// threshold this low means most non-trivial mine/deep artifacts carry
/// the flag — which is exactly what an info-level hazard is for.
pub const LEGEND_LOAD_STEP: usize = 15;

impl RiskReport {
    pub fn high_risk(&self) -> bool {
        !self.split.is_empty()
    }

    /// Legend large enough that join/aggregation *across* entries has a
    /// measured reliability step for at least one reader family. See
    /// [`LEGEND_LOAD_STEP`]. Info-level: lookups and counting survived at
    /// every measured dose; the hazard is specifically multi-entry
    /// reasoning.
    pub fn legend_load(&self) -> bool {
        self.legend_entries >= LEGEND_LOAD_STEP
    }
}

/// True when placing a representation boundary between `before` and `after`
/// would split an identifier or number run — the `boundary-recomposed`
/// failure made live by the G5 panel: a reader reassembling
/// `codec` + `::pool_` + `28` answered `codecpool_28`, and one recomposing
/// slot `819200` + template literal `0` answered `819200` for `8192000`.
/// Task logic was correct both times; the surface reconstruction failed.
///
/// Unsafe cuts, each pinned to evidence: inside a `[A-Za-z0-9_]` run (both
/// G5 misses), and against `::` path glue on either side (the dropped `::`).
/// A *single* `:` is deliberately a safe cut: the counting panels measured
/// readers holding 6/6 on `"key":`-shaped aliases and G5 root-cause held
/// 6/6 through `path:`-prefix aliases — and refusing those cuts fragments
/// previously uniform representations into the `split` class, a worse
/// hazard than the one avoided. Text edges never split. Used by `mine` and
/// `tmpl` to keep alias and slot edges on whole-token boundaries — a
/// representational mitigation, not "compress less": the same content may
/// still be aliased whole.
pub fn splits_token(before: &str, after: &str) -> bool {
    let w = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let l = before.chars().next_back();
    let r = after.chars().next();
    match (l, r) {
        (Some(l), Some(r)) => {
            (w(l) && w(r))
                || (w(l) && after.starts_with("::"))
                || (before.ends_with("::") && w(r))
                // Cutting between the two colons of `::` splits the glue
                // itself (`auth:` + `:cursor_01`) — same class, seen in the
                // first mitigated artifacts.
                || (l == ':' && r == ':')
        }
        _ => false,
    }
}

/// Analyze an encoded artifact. The artifact must decode (fails on pinned
/// extern keys — supply the decoded source path instead by re-encoding).
pub fn analyze(artifact: &str) -> Result<RiskReport> {
    let c = container::parse(artifact)?;
    if c.codec == "raw" || c.codec == "identity" {
        return Ok(RiskReport {
            codec: c.codec,
            legend_entries: 0,
            alias_density: 0.0,
            split: Vec::new(),
            heterogeneous_hidden: Vec::new(),
            uniform_hidden: 0,
            boundary_recomposed: 0,
            uniform_literal: 0,
            near_duplicate_pairs: Vec::new(),
            numeric_heavy_entries: 0,
        });
    }
    let source = crate::decode(artifact)?;

    // Legend of the outermost layer: alias = text before the first '='.
    let entries: Vec<(String, String)> = c
        .legend
        .iter()
        .filter_map(|line| {
            line.split_once('=')
                .map(|(a, v)| (a.to_string(), v.to_string()))
        })
        .collect();

    let alias_occurrences: usize = entries
        .iter()
        .filter(|(a, _)| !a.is_empty())
        .map(|(a, _)| c.body.matches(a.as_str()).count())
        .sum();
    let alias_density = if c.body.is_empty() {
        0.0
    } else {
        100.0 * alias_occurrences as f64 / c.body.chars().count() as f64
    };

    let mut split: Vec<SpanRisk> = Vec::new();
    let mut hetero: Vec<SpanRisk> = Vec::new();
    let mut uniform_hidden = 0usize;
    let mut boundary_recomposed = 0usize;
    let mut uniform_literal = 0usize;

    for cand in sam::repeated_substrings(&source, MIN_SPAN, MAX_SPAN, SAM_TOP) {
        let span = cand.text;
        let occupied: Vec<(usize, usize)> = source
            .match_indices(span.as_str())
            .map(|(i, m)| (i, i + m.len()))
            .collect();
        let total = occupied.len();
        if total < 2 {
            continue;
        }
        let body_visible = c.body.matches(span.as_str()).count();
        let legend_visible: usize = entries
            .iter()
            .map(|(_, v)| v.matches(span.as_str()).count())
            .sum();
        let hiding_entries = entries
            .iter()
            .filter(|(_, v)| v.contains(span.as_str()))
            .count();
        let class = if body_visible >= total {
            SpanClass::UniformLiteral
        } else if body_visible > 0 {
            SpanClass::Split
        } else if hiding_entries >= 2 {
            SpanClass::HeterogeneousHidden
        } else if hiding_entries == 1 {
            SpanClass::UniformHidden
        } else {
            SpanClass::BoundaryRecomposed
        };
        let risk = SpanRisk {
            span,
            total,
            body_visible,
            legend_visible,
            hiding_entries,
            class,
            occupied,
        };
        match class {
            SpanClass::Split => split.push(risk),
            SpanClass::HeterogeneousHidden => hetero.push(risk),
            SpanClass::UniformHidden => uniform_hidden += 1,
            SpanClass::BoundaryRecomposed => boundary_recomposed += 1,
            SpanClass::UniformLiteral => uniform_literal += 1,
        }
    }

    // SAM emits sliding windows over the same underlying repeat; collapse
    // them by source-position overlap — biggest miscount first, then the
    // longest span, and a candidate whose occurrences overlap an already
    // kept span's occurrences is the same finding said smaller.
    let dedupe = |mut list: Vec<SpanRisk>| -> Vec<SpanRisk> {
        list.sort_by_key(|r| {
            std::cmp::Reverse((r.total.saturating_sub(r.body_visible), r.span.len()))
        });
        let mut kept: Vec<SpanRisk> = Vec::new();
        for r in list {
            let overlaps = kept.iter().any(|k| {
                k.occupied
                    .iter()
                    .any(|&(ks, ke)| r.occupied.iter().any(|&(s, e)| s < ke && ks < e))
            });
            if !overlaps {
                kept.push(r);
            }
        }
        kept
    };
    let split = dedupe(split);
    let hetero = dedupe(hetero);

    let mut near_duplicate_pairs = Vec::new();
    for (i, (_, a)) in entries.iter().enumerate() {
        for (_, b) in entries.iter().skip(i + 1) {
            if a.len() < MIN_SPAN || b.len() < MIN_SPAN {
                continue;
            }
            let dist = levenshtein(a, b) as f64 / a.len().max(b.len()) as f64;
            if dist <= NEAR_DUP {
                near_duplicate_pairs.push((a.clone(), b.clone()));
            }
        }
    }
    let numeric_heavy_entries = entries
        .iter()
        .filter(|(_, v)| {
            let digits = v.chars().filter(char::is_ascii_digit).count();
            let len = v.chars().count();
            len >= 4 && digits as f64 / len as f64 >= 0.3
        })
        .count();

    Ok(RiskReport {
        codec: c.codec,
        legend_entries: entries.len(),
        alias_density,
        split,
        heterogeneous_hidden: hetero,
        uniform_hidden,
        boundary_recomposed,
        uniform_literal,
        near_duplicate_pairs,
        numeric_heavy_entries,
    })
}

pub fn render(r: &RiskReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "risk: codec={} legend_entries={} alias_density={:.2}/100ch\n",
        r.codec, r.legend_entries, r.alias_density
    ));
    if r.split.is_empty() {
        out.push_str("split spans: none\n");
    } else {
        out.push_str(&format!(
            "split spans (count-splitting, HIGH): {}\n",
            r.split.len()
        ));
        for s in r.split.iter().take(10) {
            out.push_str(&format!(
                "  {:?} truth={} body-visible={} legend-visible={} hiding_entries={}\n",
                s.span, s.total, s.body_visible, s.legend_visible, s.hiding_entries
            ));
        }
    }
    if !r.heterogeneous_hidden.is_empty() {
        out.push_str(&format!(
            "heterogeneous-hidden spans (MEDIUM): {}\n",
            r.heterogeneous_hidden.len()
        ));
        for s in r.heterogeneous_hidden.iter().take(5) {
            out.push_str(&format!(
                "  {:?} truth={} across {} entries\n",
                s.span, s.total, s.hiding_entries
            ));
        }
    }
    out.push_str(&format!(
        "info: uniform-literal={} uniform-hidden={} boundary-recomposed={}\n",
        r.uniform_literal, r.uniform_hidden, r.boundary_recomposed
    ));
    out.push_str(&format!(
        "legend: near-duplicate value pairs={} numeric-heavy values={}\n",
        r.near_duplicate_pairs.len(),
        r.numeric_heavy_entries
    ));
    if r.legend_load() {
        out.push_str(&format!(
            "legend-load: {} entries >= {} — cross-entry join/aggregation is \
             unreliable for the codex reader family at this size \
             (density-codex-v1; family-dependent hazard, not an oracle)\n",
            r.legend_entries, LEGEND_LOAD_STEP
        ));
    }
    out.push_str(if r.high_risk() {
        "verdict: HIGH-RISK representation present (count questions may fail)\n"
    } else {
        "verdict: no high-risk spans\n"
    });
    out
}

pub fn to_json(r: &RiskReport) -> Value {
    let spans = |list: &[SpanRisk]| -> Value {
        Value::Array(
            list.iter()
                .map(|s| {
                    json!({
                        "span": s.span,
                        "truth": s.total,
                        "body_visible": s.body_visible,
                        "legend_visible": s.legend_visible,
                        "hiding_entries": s.hiding_entries,
                        "class": s.class.label(),
                    })
                })
                .collect(),
        )
    };
    json!({
        "codec": r.codec,
        "legend_entries": r.legend_entries,
        "alias_density_per_100ch": r.alias_density,
        "split": spans(&r.split),
        "heterogeneous_hidden": spans(&r.heterogeneous_hidden),
        "uniform_hidden": r.uniform_hidden,
        "boundary_recomposed": r.boundary_recomposed,
        "uniform_literal": r.uniform_literal,
        "near_duplicate_pairs": r.near_duplicate_pairs.len(),
        "numeric_heavy_entries": r.numeric_heavy_entries,
        "legend_load": {
            "entries": r.legend_entries,
            "step": LEGEND_LOAD_STEP,
            "flagged": r.legend_load(),
        },
        "high_risk": r.high_risk(),
    })
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        if let Some(slot) = cur.first_mut() {
            *slot = i + 1;
        }
        for (j, cb) in b.iter().enumerate() {
            let sub = prev.get(j).copied().unwrap_or(usize::MAX);
            let del = prev.get(j + 1).copied().unwrap_or(usize::MAX);
            let ins = cur.get(j).copied().unwrap_or(usize::MAX);
            let cost = if ca == cb { sub } else { sub.saturating_add(1) };
            let best = cost.min(del.saturating_add(1)).min(ins.saturating_add(1));
            if let Some(slot) = cur.get_mut(j + 1) {
                *slot = best;
            }
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev.last().copied().unwrap_or(0)
}

/// Guard against analyzing something that is not an artifact at all.
pub fn ensure_container(text: &str) -> Result<()> {
    if container::parse(text).is_err() {
        bail!("input is not a %q1 container — pass an artifact or use --codec to encode first");
    }
    Ok(())
}
