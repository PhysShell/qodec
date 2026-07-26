//! `cost` — the learned edge-cost model must honor the ranker contract:
//! prefix-sum features are exact, the fit is deterministic and refuses tiny
//! samples, and predicted routing can never ship an artifact worse than the
//! whole-payload baseline (arbitration is the exact meter's, not the model's).

use anyhow::Result;

use qodec::cost::{
    dataset_from_json, dataset_to_json, evaluate, fit, harvest, CostModel, SpanStats,
};
use qodec::meter::{Approx, Bpe, TokenMeter};
use qodec::{decode, mosaic};

fn synthetic_log() -> String {
    // Three regimes so segmentation has something to find: a foldable run,
    // a grep-shaped block, and unique prose.
    let mut text = String::new();
    for _ in 0..14 {
        text.push_str("warning: connection pool exhausted, retrying with backoff\n");
    }
    for i in 0..14 {
        text.push_str(&format!(
            "src/app/handler.rs:{}:9: unused variable `ctx`\n",
            40 + i
        ));
    }
    text.push_str("Meanwhile the release notes describe a wholly unrelated feature.\n");
    text.push_str("Nothing in this paragraph repeats, so raw should win here.\n");
    text
}

fn feat(f: &[f64], k: usize) -> f64 {
    f.get(k).copied().unwrap_or(f64::NAN)
}

#[test]
fn features_are_exact_over_prefix_sums() -> Result<()> {
    // The O(1) span features must equal a naive recount on the raw slice.
    let text = synthetic_log();
    let stats = SpanStats::build(&text);
    let n = stats.lines();
    for (i, j) in [(0usize, 3usize), (2, 17), (10, n), (0, n)] {
        let f = stats.features(i, j);
        let (start, end) = stats
            .byte_range(i, j)
            .ok_or_else(|| anyhow::anyhow!("byte_range({i},{j})"))?;
        let span = text.get(start..end).unwrap_or("");
        let bytes = span.len().max(1) as f64;
        let lines = (j - i).max(1) as f64;
        let digits = span.bytes().filter(u8::is_ascii_digit).count() as f64;
        anyhow::ensure!((feat(&f, 1) - bytes / 3.5).abs() < 1e-9, "size ({i},{j})");
        anyhow::ensure!((feat(&f, 2) - lines).abs() < 1e-9, "lines ({i},{j})");
        anyhow::ensure!(
            (feat(&f, 7) - digits / bytes).abs() < 1e-9,
            "digit frac ({i},{j})"
        );
    }
    Ok(())
}

#[test]
fn fit_refuses_tiny_samples_and_is_deterministic() -> Result<()> {
    let text = synthetic_log();
    let rows = harvest("synthetic", &text, &Approx, &[], 300);
    anyhow::ensure!(rows.len() > 256, "harvest yields all spans");
    let tiny: Vec<_> = rows.iter().take(10).cloned().collect();
    anyhow::ensure!(
        fit(&tiny, "approx").is_none(),
        "tiny sample must be refused"
    );

    let a = fit(&rows, "approx").ok_or_else(|| anyhow::anyhow!("fit failed"))?;
    let b = fit(&rows, "approx").ok_or_else(|| anyhow::anyhow!("fit failed"))?;
    anyhow::ensure!(
        serde_json::to_string(&a.to_json())? == serde_json::to_string(&b.to_json())?,
        "fit must be deterministic"
    );
    // Roundtrip through JSON preserves predictions.
    let back = CostModel::from_json(&a.to_json())?;
    let f = SpanStats::build(&text).features(0, 5);
    anyhow::ensure!((a.predict(&f) - back.predict(&f)).abs() < 1e-9);
    Ok(())
}

#[test]
fn model_learns_ordering_within_a_file() -> Result<()> {
    // Not a generalization claim — just that on in-domain data the linear
    // model orders span costs far better than chance (the DP consumes
    // ordering). Threshold is deliberately loose.
    let text = synthetic_log();
    let rows = harvest("synthetic", &text, &Approx, &[], 300);
    let model = fit(&rows, "approx").ok_or_else(|| anyhow::anyhow!("fit failed"))?;
    let m = evaluate(&model, &rows);
    anyhow::ensure!(
        m.spearman > 0.9,
        "in-domain rank correlation too weak: {}",
        m.spearman
    );
    Ok(())
}

#[test]
fn predicted_routing_roundtrips_and_never_loses_to_baseline() -> Result<()> {
    let meter = Bpe::o200k()?;
    let text = synthetic_log();
    let rows = harvest("synthetic", &text, &meter, &[], 300);
    let model = fit(&rows, meter.name()).ok_or_else(|| anyhow::anyhow!("fit failed"))?;

    let (artifact, report) = mosaic::encode_predicted_report(&text, &meter, &model, &[]);
    let back = decode(&artifact)?;
    anyhow::ensure!(back == text, "predicted mosaic must stay byte-exact");
    anyhow::ensure!(
        !report.meter_mismatch,
        "stamps match, mismatch must be false"
    );
    anyhow::ensure!(
        report.predicted_cost.is_some() && report.realized_tokens.is_some(),
        "matching meters must produce the shadow residual pair"
    );

    // The exact-meter arbitration guarantee: whatever the model picked, the
    // shipped artifact is never worse than the whole-payload single-codec
    // baseline (min over the structural codecs and raw — the same set
    // `best_span` measures). Predicted vs geometric routing is NOT ordered:
    // both are clamped to this baseline, either may beat the other.
    let baseline_tokens = [
        qodec::container::raw(&text),
        qodec::fold::encode(&text, &meter),
        qodec::grep::encode(&text, &meter),
        qodec::diag::encode(&text, &meter),
        qodec::encode(
            &text,
            qodec::CodecKind::Tmpl,
            &meter,
            qodec::alias::Alphabet::Auto,
        ),
    ]
    .iter()
    .map(|artifact| meter.count(artifact))
    .min()
    .ok_or_else(|| anyhow::anyhow!("no baseline"))?;
    anyhow::ensure!(
        meter.count(&artifact) <= baseline_tokens,
        "predicted routing lost to the whole-payload baseline: {} > {}",
        meter.count(&artifact),
        baseline_tokens
    );
    Ok(())
}

#[test]
fn dup_frac_counts_only_inside_span_comparisons() -> Result<()> {
    // Codex review on PR #8: a singleton span opening mid-run must not
    // inherit the boundary comparison against a line outside the span.
    let stats = SpanStats::build("same line here\nsame line here\n");
    let f = stats.features(1, 2);
    anyhow::ensure!(
        feat(&f, 5).abs() < 1e-9,
        "singleton span [1,2) must have dup_frac 0, got {}",
        feat(&f, 5)
    );
    // The full two-line span has exactly one interior comparison.
    let f_full = stats.features(0, 2);
    anyhow::ensure!((feat(&f_full, 5) - 0.5).abs() < 1e-9);
    Ok(())
}

#[test]
fn spearman_averages_tied_ranks() -> Result<()> {
    // Codex review on PR #8: constant predictions must not inherit the
    // dataset's input order — build rows where targets are already sorted,
    // hand the evaluator a model that predicts a constant (all features
    // zeroed except bias -> same standardized input -> same output), and
    // require correlation ~0, not 1.
    let text = synthetic_log();
    let rows = harvest("synthetic", &text, &Approx, &[], 300);
    let model = fit(&rows, "approx").ok_or_else(|| anyhow::anyhow!("fit failed"))?;
    let mut sorted: Vec<_> = rows.clone();
    sorted.sort_by(|a, b| a.target.total_cmp(&b.target));
    let constant_rows: Vec<_> = sorted
        .iter()
        .map(|r| {
            let mut r2 = r.clone();
            r2.features = [0.0; qodec::cost::DIM];
            if let Some(bias) = r2.features.get_mut(0) {
                *bias = 1.0;
            }
            r2
        })
        .collect();
    let m = evaluate(&model, &constant_rows);
    anyhow::ensure!(
        m.spearman.abs() < 0.05,
        "constant predictions must score ~0 correlation, got {}",
        m.spearman
    );
    Ok(())
}

#[test]
fn dataset_json_roundtrips() -> Result<()> {
    let text = synthetic_log();
    let mut rows = harvest("synthetic", &text, &Approx, &[], 300);
    // CodeRabbit review on PR #8: file names must survive as valid JSON —
    // non-ASCII, quotes, backslashes and tabs all appear in real paths.
    if let Some(hostile) = rows.first_mut() {
        hostile.file = "логи/\"β\"\tback\\slash.txt".to_string();
    }
    let json = dataset_to_json("approx", &rows);
    anyhow::ensure!(
        serde_json::from_str::<serde_json::Value>(&json).is_ok(),
        "dataset_to_json must emit valid JSON"
    );
    let (meter, back) = dataset_from_json(&json)?;
    anyhow::ensure!(meter == "approx", "meter stamp must roundtrip");
    anyhow::ensure!(rows.len() == back.len());
    let a = rows.first().ok_or_else(|| anyhow::anyhow!("empty rows"))?;
    let b = back.first().ok_or_else(|| anyhow::anyhow!("empty back"))?;
    anyhow::ensure!(a.file == b.file, "hostile file name must roundtrip");
    anyhow::ensure!((a.target - b.target).abs() < 1e-9);
    // Fail closed on unstamped inputs: a legacy bare-array dataset and a
    // model JSON without a meter field must both refuse to load.
    anyhow::ensure!(
        dataset_from_json("[]").is_err(),
        "legacy v1 dataset must be refused"
    );
    let model = fit(&rows, "approx").ok_or_else(|| anyhow::anyhow!("fit failed"))?;
    let mut unstamped = model.to_json();
    if let Some(obj) = unstamped.as_object_mut() {
        obj.remove("meter");
    }
    anyhow::ensure!(
        CostModel::from_json(&unstamped).is_err(),
        "model without a meter stamp must be refused"
    );
    Ok(())
}

#[test]
fn meter_mismatch_fails_closed_to_baseline() -> Result<()> {
    // A model stamped for one tokenizer must never order spans for another:
    // predicted routing is skipped, the report says why, and the shipped
    // artifact is exactly the measured whole-payload baseline — byte-exact.
    let meter = Bpe::o200k()?;
    let text = synthetic_log();
    let rows = harvest("synthetic", &text, &Approx, &[], 300);
    let model = fit(&rows, "approx").ok_or_else(|| anyhow::anyhow!("fit failed"))?;

    let (artifact, report) = mosaic::encode_predicted_report(&text, &meter, &model, &[]);
    anyhow::ensure!(report.meter_mismatch, "approx model under o200k must trip");
    anyhow::ensure!(
        report.skipped && !report.fell_back,
        "a mismatch is a skip, not an arbitration verdict"
    );
    anyhow::ensure!(
        report.predicted_cost.is_none() && report.realized_tokens.is_none(),
        "no predicted path may run under a mismatched meter"
    );
    anyhow::ensure!(decode(&artifact)? == text, "fallback stays byte-exact");
    Ok(())
}

#[test]
fn over_cap_input_skips_without_counting_as_fallback() -> Result<()> {
    // Codex review on PR #9: a file over MAX_PREDICTED_LINES is a capacity
    // skip, not a model misordering — it must not inflate the drift rate.
    let text = synthetic_log();
    let rows = harvest("synthetic", &text, &Approx, &[], 300);
    let model = fit(&rows, "approx").ok_or_else(|| anyhow::anyhow!("fit failed"))?;
    let mut big = String::new();
    for i in 0..2100 {
        big.push_str(&format!("unique line number {i} with no structure\n"));
    }
    let (artifact, report) = mosaic::encode_predicted_report(&big, &Approx, &model, &[]);
    anyhow::ensure!(!report.meter_mismatch, "stamps match");
    anyhow::ensure!(
        report.skipped && !report.fell_back,
        "over-cap input must be a skip, not a fallback"
    );
    anyhow::ensure!(decode(&artifact)? == big, "skip path stays byte-exact");
    Ok(())
}

/// The label canary: pinned exact o200k ground truth for one multi-regime
/// text. Any change to a structural codec (fold/grep/diag/tmpl), the meter,
/// or `best_span` arbitration that shifts span economics breaks this pin —
/// which is the point. On failure: the committed `evals/cost-model` datasets
/// and `model.json` no longer describe the code; re-harvest, refit, update
/// the README's SHA-256 pins, then update this pin from the test output.
#[test]
fn ground_truth_canary_pins_span_labels() -> Result<()> {
    let meter = Bpe::o200k()?;
    let mut text = String::new();
    for _ in 0..4 {
        text.push_str("error: lock timeout on shard 7, retrying\n");
    }
    for i in 0..3 {
        text.push_str(&format!(
            "src/db/pool.rs:{}:5: connection dropped\n",
            88 + i
        ));
    }
    text.push_str("A unique closing line that no codec can compress.\n");
    let rows = harvest("canary", &text, &meter, &[], 300);
    let got: Vec<String> = rows
        .iter()
        .map(|r| format!("{}-{}:{}", r.i, r.j, r.target))
        .collect();
    let pinned = "0-1:22 0-2:34 0-3:31 0-4:31 0-5:44 0-6:57 0-7:70 0-8:80 1-2:22 1-3:34 \
                  1-4:31 1-5:44 1-6:57 1-7:69 1-8:79 2-3:22 2-4:34 2-5:47 2-6:60 2-7:73 \
                  2-8:83 3-4:22 3-5:35 3-6:48 3-7:61 3-8:71 4-5:23 4-6:36 4-7:49 4-8:59 \
                  5-6:23 5-7:36 5-8:46 6-7:23 6-8:33 7-8:20";
    anyhow::ensure!(
        got.join(" ") == pinned,
        "ground-truth labels moved — codec/meter change shifted span economics.\n\
         Re-harvest datasets, refit model.json, update README pins, then update this pin to:\n{}",
        got.join(" ")
    );
    Ok(())
}
