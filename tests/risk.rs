//! `risk` — the model-readability report must reproduce the *measured*
//! panel finding mechanically: the paper baseline's count-splitting on
//! findings.json is flagged HIGH, deep's uniform recomposition of the same
//! predicate is not, and the artifact-visible count the report computes is
//! the wrong answer the reader actually gave.

use anyhow::Result;

use qodec::alias::Alphabet;
use qodec::meter::Bpe;
use qodec::risk::{analyze, SpanClass};
use qodec::{encode, CodecKind};

fn findings() -> Result<String> {
    Ok(std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/findings.json"),
    )?)
}

#[test]
fn paper_count_splitting_is_flagged_high() -> Result<()> {
    let meter = Bpe::o200k()?;
    let text = findings()?;
    let artifact = encode(&text, CodecKind::Paper, &meter, Alphabet::Auto);
    let report = analyze(&artifact)?;
    anyhow::ensure!(report.high_risk(), "paper on findings must be HIGH risk");
    let hit = report
        .split
        .iter()
        .find(|s| s.span.contains("suspect_fp"))
        .ok_or_else(|| anyhow::anyhow!("suspect_fp split span not flagged"))?;
    // The panel reader answered a count below the truth because part of the
    // occurrences are hidden in dictionary values — the report must show a
    // genuine literal/hidden mix for the counted predicate's region.
    anyhow::ensure!(
        hit.body_visible >= 1 && hit.body_visible < hit.total,
        "expected a literal/hidden mix, got truth={} body-visible={}",
        hit.total,
        hit.body_visible
    );
    Ok(())
}

#[test]
fn deep_same_predicate_is_not_split() -> Result<()> {
    let meter = Bpe::o200k()?;
    let text = findings()?;
    let artifact = encode(&text, CodecKind::Deep, &meter, Alphabet::Auto);
    let report = analyze(&artifact)?;
    anyhow::ensure!(
        !report.split.iter().any(|s| s.span.contains("suspect_fp")),
        "deep held 6/6 in the panel — the suspect_fp predicate must not be split"
    );
    Ok(())
}

#[test]
fn legend_load_flags_at_the_measured_step() -> Result<()> {
    // density-codex-v1 (60 calls, five doses): the codex reader's join was
    // clean at 6-7 legend entries and unreliable from 15 up — a step. The
    // flag anchors there and must trip on a >=15-entry artifact and stay
    // silent on a small one. Uses the density fixtures themselves, whose
    // measured legend sizes are recorded in the run.
    let meter = Bpe::o200k()?;
    let small = std::fs::read_to_string("evals/agent-g5/tasks-density/xref-d06-1.txt")?;
    let large = std::fs::read_to_string("evals/agent-g5/tasks-density/xref-d12-1.txt")?;
    let small_report = analyze(&encode(&small, CodecKind::Squeeze, &meter, Alphabet::Auto))?;
    let large_report = analyze(&encode(&large, CodecKind::Squeeze, &meter, Alphabet::Auto))?;
    anyhow::ensure!(
        !small_report.legend_load(),
        "6-7 entries measured clean — must not flag ({} entries)",
        small_report.legend_entries
    );
    anyhow::ensure!(
        large_report.legend_load(),
        "15 entries is the measured step — must flag ({} entries)",
        large_report.legend_entries
    );
    Ok(())
}

#[test]
fn fold_run_hiding_is_split_by_design() -> Result<()> {
    // fold's `%q1 xN` hides N-1 copies behind an explicit counter. The L2
    // evidence says readers miscount folded runs anyway, so the report
    // deliberately classifies this as split.
    let meter = Bpe::o200k()?;
    let line = "identical diagnostic line repeated many times over and over\n";
    let text = line.repeat(9) + "unique tail line to anchor the file\n";
    let artifact = encode(&text, CodecKind::Fold, &meter, Alphabet::Auto);
    let report = analyze(&artifact)?;
    anyhow::ensure!(
        report.high_risk(),
        "folded runs must be flagged as count-splitting"
    );
    Ok(())
}

#[test]
fn raw_artifact_reports_no_risk() -> Result<()> {
    let meter = Bpe::o200k()?;
    let text = "one two three four five six seven eight nine ten.\n";
    let artifact = encode(text, CodecKind::Paper, &meter, Alphabet::Auto);
    let report = analyze(&artifact)?;
    anyhow::ensure!(report.codec == "raw");
    anyhow::ensure!(!report.high_risk());
    Ok(())
}

#[test]
fn classes_cover_the_mechanism_taxonomy() -> Result<()> {
    // Sanity on the enum labels the JSON output exposes.
    for (class, label) in [
        (SpanClass::UniformLiteral, "uniform-literal"),
        (SpanClass::Split, "split"),
        (SpanClass::HeterogeneousHidden, "heterogeneous-hidden"),
        (SpanClass::UniformHidden, "uniform-hidden"),
        (SpanClass::BoundaryRecomposed, "boundary-recomposed"),
    ] {
        anyhow::ensure!(class.label() == label);
    }
    Ok(())
}
