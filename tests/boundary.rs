//! Boundary-recomposition mitigation (G5 panel, run `g5-sonnet-v1`): alias
//! edges and template/slot cuts must land on whole-token boundaries. The two
//! live failures pinned here: a reader reassembling `codec` + `::pool_` + `28`
//! answered `codecpool_28`, and one recomposing slot `819200` + template
//! literal `0` answered `819200` for `8192000`. Task logic was right both
//! times — the representation made the surface reconstruction fail.

use anyhow::Result;

use qodec::meter::Bpe;
use qodec::risk::splits_token;
use qodec::{container, decode, encode, CodecKind};

#[test]
fn splits_token_table() {
    // Inside identifier/number runs (both G5 misses).
    assert!(splits_token("pool", "_28"));
    assert!(splits_token("pool_", "28"));
    assert!(splits_token("819200", "0;"));
    // `::` path glue: either side, and between its own two colons.
    assert!(splits_token("codec", "::pool_28"));
    assert!(splits_token("codec::", "pool_28"));
    assert!(splits_token("auth:", ":cursor_01"));
    // A single `:` is a SAFE cut — measured: counting panels held 6/6 on
    // `"key":`-shaped aliases, G5 root-cause held 6/6 through `path:`
    // prefixes, and refusing these cuts fragments uniform representations
    // into the worse `split` risk class.
    assert!(!splits_token("\"suspect_fp\":", "true"));
    assert!(!splits_token("pool.rs:", "141"));
    assert!(!splits_token("warning", ": unused"));
    // Whitespace, punctuation, separators, text edges.
    assert!(!splits_token("a ", "phrase"));
    assert!(!splits_token("src/", "pool"));
    assert!(!splits_token("App.dll", " done"));
    assert!(!splits_token("", "x"));
    assert!(!splits_token("x", ""));
}

/// The decision-family shape: aliased fragments of `mod::file_NN` names must
/// never be carved out of the identifiers (`::pool_` from `codec::pool_28`).
/// Legend values are checked at their occurrences in the decoded text; nested
/// entries containing alias glyphs simply have no occurrence there and the
/// roundtrip guarantee covers them.
#[test]
fn mine_keeps_alias_edges_on_token_boundaries() -> Result<()> {
    let meter = Bpe::o200k()?;
    let mut text = String::new();
    for attempt in 1..=3 {
        text.push_str(&format!("--- attempt {attempt} ---\n"));
        for k in 0..24 {
            let status = if k == 7 { "FAILED" } else { "ok" };
            text.push_str(&format!("test codec::pool_{k:02} ... {status}\n"));
        }
    }
    for kind in [CodecKind::Deep, CodecKind::Squeeze] {
        let artifact = encode(&text, kind, &meter, qodec::alias::Alphabet::Auto);
        anyhow::ensure!(decode(&artifact)? == text, "roundtrip");
        let c = container::parse(&artifact)?;
        for entry in &c.legend {
            let Some((_, phrase)) = entry.split_once('=') else {
                continue;
            };
            let mut from = 0usize;
            while let Some(rel) = text.get(from..).and_then(|s| s.find(phrase)) {
                let pos = from + rel;
                let before = text.get(..pos).unwrap_or_default();
                let after = text.get(pos + phrase.len()..).unwrap_or_default();
                anyhow::ensure!(
                    !splits_token(before, phrase) && !splits_token(phrase, after),
                    "{kind:?} legend value {phrase:?} cuts a token at byte {pos}"
                );
                from = pos + phrase.len().max(1);
            }
        }
    }
    Ok(())
}

/// Codex review on PR #10: profile/extern templates bypass
/// `choose_template`'s snapping — a pre-mitigation legend can carry parts
/// that cut inside a number. The matcher (`glob_match`, the one funnel all
/// frozen templates go through) must refuse such a match: lines travel
/// verbatim, the template stays usable wherever its boundaries are clean.
#[test]
fn frozen_templates_cannot_recompose_carved_tokens() -> Result<()> {
    let meter = Bpe::o200k()?;
    let legend = qodec::legend::TemplateLegend::parse(
        "# qodec extern templates v1 slot=quest\nT1=+    pub const ¿: u64 = ¿0;\n",
    )?;
    let mut text = String::new();
    for (name, value) in [
        ("WAL_SEGMENT_BYTES", "8192000"),
        ("RETRY_BUDGET_MS", "327680"),
        ("POOL_CAP_HINT", "1024000"),
    ] {
        text.push_str(&format!("+    pub const {name}: u64 = {value};\n"));
    }
    let artifact = qodec::tmpl::encode_extern(&text, &meter, &legend);
    anyhow::ensure!(
        !artifact.contains("ext="),
        "a template whose slot boundary carves a number must never match: {artifact:?}"
    );
    anyhow::ensure!(decode(&artifact)? == text, "roundtrip");
    for value in ["8192000", "327680", "1024000"] {
        anyhow::ensure!(
            artifact.contains(value),
            "value {value} must survive contiguous in the artifact"
        );
    }
    Ok(())
}

/// The state-family shape: numeric slot values sharing a trailing digit must
/// not have that digit pulled into the template literal. With the snap, the
/// full number survives contiguously somewhere in the artifact; before it,
/// `8192000` was emitted only as `819200` + literal `0`.
#[test]
fn tmpl_never_splits_numbers_at_slot_boundaries() -> Result<()> {
    let meter = Bpe::o200k()?;
    let mut text = String::new();
    for (name, value) in [
        ("WAL_SEGMENT_BYTES", "8192000"),
        ("RETRY_BUDGET_MS", "327680"),
        ("POOL_CAP_HINT", "1024000"),
        ("FSYNC_EVERY_OPS", "512000"),
    ] {
        text.push_str(&format!("+    pub const {name}: u64 = {value};\n"));
    }
    let artifact = encode(&text, CodecKind::Tmpl, &meter, qodec::alias::Alphabet::Auto);
    anyhow::ensure!(decode(&artifact)? == text, "roundtrip");
    if container::parse(&artifact)?.codec == "tmpl" {
        for value in ["8192000", "327680", "1024000", "512000"] {
            anyhow::ensure!(
                artifact.contains(value),
                "number {value} was split across a template/slot boundary"
            );
        }
    }
    Ok(())
}
