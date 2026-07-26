//! `cost` — the learned edge-cost model must honor the ranker contract:
//! prefix-sum features are exact, the fit is deterministic and refuses tiny
//! samples, and predicted routing can never ship an artifact worse than the
//! whole-payload baseline (arbitration is the exact meter's, not the model's).

use anyhow::Result;

use qodec::cost::{evaluate, fit, harvest, rows_from_json, rows_to_json, CostModel, SpanStats};
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
    anyhow::ensure!(fit(&tiny).is_none(), "tiny sample must be refused");

    let a = fit(&rows).ok_or_else(|| anyhow::anyhow!("fit failed"))?;
    let b = fit(&rows).ok_or_else(|| anyhow::anyhow!("fit failed"))?;
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
    let model = fit(&rows).ok_or_else(|| anyhow::anyhow!("fit failed"))?;
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
    let model = fit(&rows).ok_or_else(|| anyhow::anyhow!("fit failed"))?;

    let artifact = mosaic::encode_predicted(&text, &meter, &model, &[]);
    let back = decode(&artifact)?;
    anyhow::ensure!(back == text, "predicted mosaic must stay byte-exact");

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
fn dataset_json_roundtrips() -> Result<()> {
    let text = synthetic_log();
    let rows = harvest("synthetic", &text, &Approx, &[], 300);
    let json = rows_to_json(&rows);
    let back = rows_from_json(&json)?;
    anyhow::ensure!(rows.len() == back.len());
    let a = rows.first().ok_or_else(|| anyhow::anyhow!("empty rows"))?;
    let b = back.first().ok_or_else(|| anyhow::anyhow!("empty back"))?;
    anyhow::ensure!(a.file == b.file);
    anyhow::ensure!((a.target - b.target).abs() < 1e-9);
    Ok(())
}
