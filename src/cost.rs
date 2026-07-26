//! `cost` — a learned edge-cost model for mosaic's DP.
//!
//! Mosaic's expensive step is `best_span`: four full structural encodes plus
//! meter calls **per DAG edge**. The geometric production graph affords it;
//! the exhaustive all-span graph is `O(N²)` edges and is therefore capped at
//! 300 lines. This module learns to *predict* an edge's measured cost from
//! cheap byte-level features, so the exhaustive DP can run on predicted
//! weights and spend real encodes only on the path it selects.
//!
//! The contract mirrors the probe ranker (`rank.rs`) exactly:
//! * the model **orders and shortlists, never decides** — the chosen path is
//!   assembled with real encodes and arbitrated against the whole-payload
//!   baseline by the exact meter (`mosaic::routed_or_baseline`), so a wrong
//!   model wastes probes, never bytes and never tokens;
//! * labels are the *exact measured* `best_span` cost — the free objective
//!   ground truth this lab uniquely has (no human labels, no usage data);
//! * training is offline and explicit (`qodec cost harvest` / `fit`), split
//!   by file; nothing accumulates from production runs (the
//!   `docs/secondary-calibration.md` boundary).
//!
//! Features are computed in **O(1) per span** from per-line prefix sums —
//! anything slower would put an `O(N³)` byte scan back into the `O(N²)`
//! graph — and use **no tokenizer calls**, the same discipline as the
//! ranker's features.

use std::fmt::Write as _;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::meter::TokenMeter;
use crate::mosaic;
use crate::rank::ridge_solve;

/// Feature dimension, bias included. Bump only together with the model-file
/// format note below: models of a different dimension refuse to load.
///
/// v2 (12 → 14): two interaction terms. Structural codecs make span cost
/// *multiplicative* in content mix — fold collapses a run of identical
/// lines to one line + a marker, grep strips repeated paths — and a purely
/// additive model cannot express `bytes × dup_frac`. Measured before the
/// change: predicted routing trailed measured by 18% on off-grid
/// multi-regime fixtures while matching it on single-regime files.
pub const DIM: usize = 14;

/// Ridge regularizer on standardized features.
const LAMBDA: f64 = 1.0;
/// Below this many training rows the fit is refused.
const MIN_SAMPLES: usize = 256;

/// The model predicts a *compressibility ratio* — `cost / size` where size is
/// the char-token estimate — and the prediction is `clamp(ratio) × size`.
/// Measured reason: fitting absolute cost on long-span synthetics drove the
/// effective per-byte slope negative for grep-dense content, and a held-out
/// file's span ordering came back **inverted** (Spearman −0.97).
///
/// Precisely what the clamp guarantees, and what it does not (Codex review
/// on PR #8 exhibited the gap with a live counterexample): it bounds any two
/// predictions to `cost(A)/cost(B) ≥ (RATIO_MIN/RATIO_MAX)·(size_A/size_B)`,
/// which excludes the global slope inversion above — but it does **not**
/// make cost monotonic under span extension, because the ratio itself reads
/// size-dependent features. The physical law "extending a span never makes
/// its artifact cheaper" is instead enforced where it matters, in the DP:
/// [`crate::mosaic`]'s predicted router applies a running max over each
/// start's extensions.
const RATIO_MIN: f64 = 0.02;
const RATIO_MAX: f64 = 1.2;

/// Per-line counters, prefix-summed so any span's features cost O(1).
pub struct SpanStats {
    /// Byte offset where each line starts; `offsets[n]` = text length.
    offsets: Vec<usize>,
    bytes: Vec<u64>,
    digits: Vec<u64>,
    punct: Vec<u64>,
    ws: Vec<u64>,
    upper: Vec<u64>,
    grep_shaped: Vec<u64>,
    /// 1 when the line equals the previous line — the fold signal.
    dup_prev: Vec<u64>,
}

impl SpanStats {
    pub fn build(text: &str) -> Self {
        let units: Vec<&str> = text.split_inclusive('\n').collect();
        let n = units.len();
        let mut offsets = Vec::with_capacity(n + 1);
        offsets.push(0usize);
        let zeros = || {
            let mut v = Vec::with_capacity(n + 1);
            v.push(0u64);
            v
        };
        let (mut bytes, mut digits, mut punct, mut ws) = (zeros(), zeros(), zeros(), zeros());
        let (mut upper, mut grep_shaped, mut dup_prev) = (zeros(), zeros(), zeros());

        let mut acc = 0usize;
        let mut prev: Option<&str> = None;
        let push = |v: &mut Vec<u64>, add: u64| {
            let last = v.last().copied().unwrap_or(0);
            v.push(last + add);
        };
        for u in &units {
            acc += u.len();
            offsets.push(acc);
            push(&mut bytes, u.len() as u64);
            push(
                &mut digits,
                u.bytes().filter(u8::is_ascii_digit).count() as u64,
            );
            push(
                &mut punct,
                u.bytes()
                    .filter(|b| {
                        matches!(
                            b,
                            b'/' | b'\\'
                                | b'.'
                                | b':'
                                | b';'
                                | b','
                                | b'('
                                | b')'
                                | b'['
                                | b']'
                                | b'{'
                                | b'}'
                        )
                    })
                    .count() as u64,
            );
            push(
                &mut ws,
                u.bytes().filter(u8::is_ascii_whitespace).count() as u64,
            );
            push(
                &mut upper,
                u.bytes().filter(u8::is_ascii_uppercase).count() as u64,
            );
            push(&mut grep_shaped, u64::from(is_grep_shaped(u)));
            push(&mut dup_prev, u64::from(prev == Some(*u)));
            prev = Some(*u);
        }
        Self {
            offsets,
            bytes,
            digits,
            punct,
            ws,
            upper,
            grep_shaped,
            dup_prev,
        }
    }

    pub fn lines(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    pub fn byte_range(&self, i: usize, j: usize) -> Option<(usize, usize)> {
        Some((self.offsets.get(i).copied()?, self.offsets.get(j).copied()?))
    }

    fn sum(v: &[u64], i: usize, j: usize) -> f64 {
        let hi = v.get(j).copied().unwrap_or(0);
        let lo = v.get(i).copied().unwrap_or(0);
        hi.saturating_sub(lo) as f64
    }

    /// Features of the span `[i, j)` in line units. O(1).
    pub fn features(&self, i: usize, j: usize) -> [f64; DIM] {
        let lines = j.saturating_sub(i).max(1) as f64;
        let bytes = Self::sum(&self.bytes, i, j).max(1.0);
        // `dup_prev` at line `i` compares against line `i-1`, which is
        // OUTSIDE `[i, j)` — start the sum at `i+1` so only comparisons
        // wholly inside the span count (Codex review on PR #8: a singleton
        // span opening mid-run otherwise scored dup_frac=1 while fold sees
        // one line and returns raw, underpricing boundary spans).
        let dup_frac = Self::sum(&self.dup_prev, (i + 1).min(j), j) / lines;
        let grep_frac = Self::sum(&self.grep_shaped, i, j) / lines;
        [
            1.0,                                   // bias
            bytes / 3.5,                           // linear size (≈ char-token estimate)
            lines,                                 // linear per-line costs (headers, rows)
            bytes.ln(),                            // sub-linear size effects
            bytes / lines,                         // average line length
            dup_frac,                              // fold signal: adjacent duplicates
            grep_frac,                             // grep signal: path:line: lines
            Self::sum(&self.digits, i, j) / bytes, // numeric density
            Self::sum(&self.punct, i, j) / bytes,  // path/punct density
            Self::sum(&self.ws, i, j) / bytes,     // whitespace density
            Self::sum(&self.upper, i, j) / bytes,  // identifier casing
            (lines).ln(),                          // sub-linear line effects
            (bytes / 3.5) * dup_frac,              // foldable mass: bytes a run collapses
            (bytes / 3.5) * grep_frac,             // grep mass: bytes path-grouping shrinks
        ]
    }
}

/// The `path:123` shape at line start — a one-pass heuristic for matcher
/// output, deliberately cruder than `grep`'s real parser (it is a feature,
/// not a router).
fn is_grep_shaped(line: &str) -> bool {
    let Some(colon) = line.find(':') else {
        return false;
    };
    colon > 0
        && line
            .get(colon + 1..)
            .and_then(|rest| rest.chars().next())
            .is_some_and(|c| c.is_ascii_digit())
}

/// One harvested observation: a span of a named file, its features and the
/// exact measured `best_span` cost.
#[derive(Debug, Clone)]
pub struct Row {
    pub file: String,
    pub i: usize,
    pub j: usize,
    pub features: [f64; DIM],
    pub target: f64,
}

/// Measure every span of `text` (all `[i, j)` up to `max_lines` total lines)
/// with the exact meter — the expensive, offline, ground-truth pass.
pub fn harvest(
    file: &str,
    text: &str,
    meter: &dyn TokenMeter,
    templates: &[Vec<String>],
    max_lines: usize,
) -> Vec<Row> {
    let stats = SpanStats::build(text);
    let n = stats.lines();
    if n == 0 || n > max_lines {
        return Vec::new();
    }
    let mut rows = Vec::new();
    for i in 0..n {
        for j in (i + 1)..=n {
            let Some((start, end)) = stats.byte_range(i, j) else {
                continue;
            };
            let Some(span) = text.get(start..end) else {
                continue;
            };
            let (_, weight) = mosaic::best_span(span, meter, templates);
            rows.push(Row {
                file: file.to_string(),
                i,
                j,
                features: stats.features(i, j),
                target: weight as f64,
            });
        }
    }
    rows
}

/// Fitted model: standardization + ridge weights over standardized features.
#[derive(Debug, Clone)]
pub struct CostModel {
    mean: Vec<f64>,
    std: Vec<f64>,
    weights: Vec<f64>,
    pub trained_on: Vec<String>,
}

impl CostModel {
    pub fn predict(&self, x: &[f64; DIM]) -> f64 {
        let mut acc = 0.0;
        for k in 0..DIM {
            let xi = x.get(k).copied().unwrap_or(0.0);
            let m = self.mean.get(k).copied().unwrap_or(0.0);
            let s = self.std.get(k).copied().unwrap_or(1.0);
            let z = if k == 0 { xi } else { (xi - m) / s };
            acc += self.weights.get(k).copied().unwrap_or(0.0) * z;
        }
        let size = x.get(1).copied().unwrap_or(1.0).max(1.0);
        (acc.clamp(RATIO_MIN, RATIO_MAX) * size).max(1.0)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "format": "qodec-cost-model-v1",
            "d": DIM,
            "mean": self.mean,
            "std": self.std,
            "weights": self.weights,
            "trained_on": self.trained_on,
        })
    }

    pub fn from_json(v: &Value) -> Result<Self> {
        let d = v.get("d").and_then(Value::as_u64).unwrap_or(0) as usize;
        if d != DIM {
            bail!("cost model dimension {d} != {DIM} (feature set changed)");
        }
        let read = |key: &str| -> Result<Vec<f64>> {
            let arr = v
                .get(key)
                .and_then(Value::as_array)
                .with_context(|| format!("cost model missing {key}"))?;
            let out: Option<Vec<f64>> = arr.iter().map(Value::as_f64).collect();
            let out = out.with_context(|| format!("non-numeric value in {key}"))?;
            if out.len() != DIM {
                bail!("{key} has {} entries, want {DIM}", out.len());
            }
            Ok(out)
        };
        let trained_on = v
            .get("trained_on")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            mean: read("mean")?,
            std: read("std")?,
            weights: read("weights")?,
            trained_on,
        })
    }
}

/// Fit a standardized ridge model on `rows`. Refuses on too few samples or a
/// degenerate system — the caller keeps using measured mosaic.
pub fn fit(rows: &[Row]) -> Option<CostModel> {
    if rows.len() < MIN_SAMPLES {
        return None;
    }
    // Standardization moments (bias column excluded).
    let n = rows.len() as f64;
    let mut mean = vec![0.0f64; DIM];
    let mut var = [0.0f64; DIM];
    for r in rows {
        for k in 0..DIM {
            if let (Some(m), Some(&x)) = (mean.get_mut(k), r.features.get(k)) {
                *m += x / n;
            }
        }
    }
    for r in rows {
        for k in 0..DIM {
            let m = mean.get(k).copied().unwrap_or(0.0);
            let x = r.features.get(k).copied().unwrap_or(0.0);
            if let Some(v) = var.get_mut(k) {
                *v += (x - m) * (x - m) / n;
            }
        }
    }
    let std: Vec<f64> = var
        .iter()
        .map(|v| if v.sqrt() > 1e-9 { v.sqrt() } else { 1.0 })
        .collect();

    let standardize = |x: &[f64; DIM]| -> Vec<f64> {
        (0..DIM)
            .map(|k| {
                let xi = x.get(k).copied().unwrap_or(0.0);
                if k == 0 {
                    xi
                } else {
                    (xi - mean.get(k).copied().unwrap_or(0.0)) / std.get(k).copied().unwrap_or(1.0)
                }
            })
            .collect()
    };

    let mut xtx = vec![0.0f64; DIM * DIM];
    let mut xty = vec![0.0f64; DIM];
    for r in rows {
        let z = standardize(&r.features);
        // Ratio target, matching `predict`'s clamp(ratio) × size shape.
        let size = r.features.get(1).copied().unwrap_or(1.0).max(1.0);
        let ratio = (r.target / size).clamp(RATIO_MIN, RATIO_MAX);
        for (a, &za) in z.iter().enumerate() {
            if let Some(slot) = xty.get_mut(a) {
                *slot += za * ratio;
            }
            for (b, &zb) in z.iter().enumerate() {
                if let Some(slot) = xtx.get_mut(a * DIM + b) {
                    *slot += za * zb;
                }
            }
        }
    }
    let weights = ridge_solve(DIM, &xtx, &xty, LAMBDA)?;
    let mut trained_on: Vec<String> = rows.iter().map(|r| r.file.clone()).collect();
    trained_on.sort();
    trained_on.dedup();
    Some(CostModel {
        mean,
        std,
        weights,
        trained_on,
    })
}

/// Prediction-quality metrics over one set of rows.
pub struct Metrics {
    pub n: usize,
    pub mae: f64,
    pub mean_target: f64,
    pub spearman: f64,
}

pub fn evaluate(model: &CostModel, rows: &[Row]) -> Metrics {
    let n = rows.len();
    let preds: Vec<f64> = rows.iter().map(|r| model.predict(&r.features)).collect();
    let targets: Vec<f64> = rows.iter().map(|r| r.target).collect();
    let mae = preds
        .iter()
        .zip(&targets)
        .map(|(p, t)| (p - t).abs())
        .sum::<f64>()
        / n.max(1) as f64;
    let mean_target = targets.iter().sum::<f64>() / n.max(1) as f64;
    Metrics {
        n,
        mae,
        mean_target,
        spearman: spearman(&preds, &targets),
    }
}

/// Spearman rank correlation — the DP cares about ordering, not scale.
fn spearman(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() || a.len() < 2 {
        return 0.0;
    }
    let ra = ranks(a);
    let rb = ranks(b);
    let n = ra.len() as f64;
    let mean = (n - 1.0) / 2.0;
    let (mut cov, mut va, mut vb) = (0.0, 0.0, 0.0);
    for (x, y) in ra.iter().zip(&rb) {
        cov += (x - mean) * (y - mean);
        va += (x - mean) * (x - mean);
        vb += (y - mean) * (y - mean);
    }
    if va <= 0.0 || vb <= 0.0 {
        return 0.0;
    }
    cov / (va.sqrt() * vb.sqrt())
}

/// Fractional ranks with ties averaged — required for Spearman; sequential
/// ranks would let a constant prediction inherit the dataset's input order
/// and report a fake correlation of 1.0 (Codex review on PR #8).
fn ranks(v: &[f64]) -> Vec<f64> {
    let mut idx: Vec<usize> = (0..v.len()).collect();
    idx.sort_by(|&x, &y| {
        let a = v.get(x).copied().unwrap_or(0.0);
        let b = v.get(y).copied().unwrap_or(0.0);
        a.total_cmp(&b)
    });
    let mut out = vec![0.0f64; v.len()];
    let mut pos = 0usize;
    while pos < idx.len() {
        let value = idx
            .get(pos)
            .and_then(|&orig| v.get(orig))
            .copied()
            .unwrap_or(0.0);
        let mut end = pos;
        while idx
            .get(end)
            .and_then(|&orig| v.get(orig))
            .is_some_and(|&x| x == value)
        {
            end += 1;
        }
        let avg = (pos + end - 1) as f64 / 2.0;
        for k in pos..end {
            if let Some(&orig) = idx.get(k) {
                if let Some(slot) = out.get_mut(orig) {
                    *slot = avg;
                }
            }
        }
        pos = end;
    }
    out
}

/// Serialize rows deterministically (JSON lines inside one array).
pub fn rows_to_json(rows: &[Row]) -> String {
    let mut out = String::from("[\n");
    for (k, r) in rows.iter().enumerate() {
        let features: Vec<String> = r.features.iter().map(|f| format!("{f:.6}")).collect();
        // Rust's `{:?}` escaping is not JSON (non-ASCII, control chars);
        // serde_json's string encoder is.
        let _ = write!(
            out,
            "{{\"file\":{},\"i\":{},\"j\":{},\"target\":{},\"features\":[{}]}}",
            Value::String(r.file.clone()),
            r.i,
            r.j,
            r.target,
            features.join(",")
        );
        out.push_str(if k + 1 == rows.len() { "\n" } else { ",\n" });
    }
    out.push(']');
    out
}

pub fn rows_from_json(text: &str) -> Result<Vec<Row>> {
    let v: Value = serde_json::from_str(text).context("parsing cost dataset")?;
    let arr = v.as_array().context("cost dataset must be a JSON array")?;
    let mut rows = Vec::with_capacity(arr.len());
    for item in arr {
        let feats = item
            .get("features")
            .and_then(Value::as_array)
            .context("row missing features")?;
        if feats.len() != DIM {
            bail!("row has {} features, want {DIM}", feats.len());
        }
        let mut features = [0.0f64; DIM];
        for (slot, fv) in features.iter_mut().zip(feats) {
            *slot = fv.as_f64().context("non-numeric feature")?;
        }
        rows.push(Row {
            file: item
                .get("file")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            i: item.get("i").and_then(Value::as_u64).unwrap_or(0) as usize,
            j: item.get("j").and_then(Value::as_u64).unwrap_or(0) as usize,
            features,
            target: item.get("target").and_then(Value::as_f64).unwrap_or(0.0),
        });
    }
    Ok(rows)
}
