//! `paper` baseline (arXiv:2604.13066 reproduction) — the properties the
//! faithful re-implementation must hold: byte-exact roundtrip, the paper's
//! per-pattern acceptance (Equation 1), no nesting, no overlap, deterministic
//! output, fail-closed alias collision.

use anyhow::Result;
use proptest::prelude::*;

use qodec::alias::Alphabet;
use qodec::meter::{Approx, Bpe, TokenMeter};
use qodec::{container, decode, encode, CodecKind};

fn roundtrip_bytes(text: &str, meter: &dyn TokenMeter) -> Result<String> {
    let encoded = encode(text, CodecKind::Paper, meter, Alphabet::Auto);
    let back = decode(&encoded)?;
    anyhow::ensure!(
        back == text,
        "paper byte roundtrip failed: {:?} -> {:?}",
        text,
        back
    );
    Ok(encoded)
}

#[test]
fn compresses_repetitive_text_and_roundtrips() -> Result<()> {
    let meter = Bpe::o200k()?;
    // The paper's home turf: a batch of near-identical log lines.
    let mut text = String::new();
    for i in 0..12 {
        text.push_str(&format!(
            "worker thread pool executor rejected task {i} because queue capacity was exhausted\n"
        ));
    }
    let encoded = roundtrip_bytes(&text, &meter)?;
    anyhow::ensure!(
        encoded.starts_with("%q1 paper"),
        "expected paper container, got {:?}",
        encoded.lines().next()
    );
    anyhow::ensure!(
        meter.count(&encoded) < meter.count(&text),
        "paper must reduce tokens on repetitive logs"
    );
    Ok(())
}

#[test]
fn dictionary_entries_pass_equation_1_and_never_nest() -> Result<()> {
    let meter = Bpe::o200k()?;
    let mut text = String::new();
    for i in 0..10 {
        text.push_str(&format!(
            "open ticket search customer database entry {i}\nclick open ticket search customer {i}\n"
        ));
    }
    let encoded = roundtrip_bytes(&text, &meter)?;
    let c = container::parse(&encoded)?;
    anyhow::ensure!(c.codec == "paper", "expected paper container");
    anyhow::ensure!(!c.legend.is_empty(), "expected dictionary entries");
    for line in &c.legend {
        let (alias, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("malformed legend line {line:?}"))?;
        // Aliases are ASCII <M#>; values never contain a meta-token (that
        // would be nesting, which the paper's Algorithm 2 forbids).
        anyhow::ensure!(alias.starts_with("<M") && alias.ends_with('>'));
        anyhow::ensure!(
            !value.contains("<M"),
            "nested meta-token in dictionary value {value:?}"
        );
        // Equation 1 on the committed entry, recomputed independently:
        // (1+f)·ntoken(M) + ntoken(S) < f·ntoken(S).
        let f = c.body.matches(alias).count() as i64;
        let m_tok = meter.count(alias) as i64;
        let s_tok = meter.count(&value.replace("\\n", "\n").replace("\\\\", "\\")) as i64;
        anyhow::ensure!(
            (1 + f) * m_tok + s_tok < f * s_tok,
            "committed entry {alias} violates Equation 1 (f={f}, m={m_tok}, s={s_tok})"
        );
    }
    Ok(())
}

#[test]
fn falls_back_on_unique_prose() -> Result<()> {
    let meter = Bpe::o200k()?;
    let text = "one two three four five six seven eight nine ten.\n";
    let encoded = roundtrip_bytes(text, &meter)?;
    anyhow::ensure!(encoded.starts_with("%q1 raw"), "expected raw fallback");
    Ok(())
}

#[test]
fn fails_closed_on_meta_token_collision() -> Result<()> {
    let meter = Bpe::o200k()?;
    // Input that already speaks <M#> — replacements would be ambiguous at
    // decode time, so the encoder must refuse, not gamble.
    let mut text = String::from("legend says <M1> maps to something else entirely\n");
    for _ in 0..8 {
        text.push_str("repeated payload line with plenty of shared words here\n");
    }
    let encoded = roundtrip_bytes(&text, &meter)?;
    anyhow::ensure!(
        encoded.starts_with("%q1 raw"),
        "alias collision must fail closed to raw"
    );
    // `<M` without the closing shape is not a collision — compression may run.
    let mut benign = String::from("comparison a <Marker without digits> stays fine\n");
    for _ in 0..8 {
        benign.push_str("repeated payload line with plenty of shared words here\n");
    }
    let benign_encoded = roundtrip_bytes(&benign, &meter)?;
    anyhow::ensure!(
        benign_encoded.starts_with("%q1 paper"),
        "non-colliding angle brackets must not disable the codec"
    );
    Ok(())
}

#[test]
fn preserves_exact_interior_whitespace() -> Result<()> {
    let meter = Bpe::o200k()?;
    // Same words, different interior whitespace: these are *different*
    // patterns here (byte-exact grouping), and whichever is committed must
    // reproduce its exact bytes — tabs, double spaces and all.
    let mut text = String::new();
    for _ in 0..6 {
        text.push_str("alpha  beta\tgamma delta epsilon zeta eta theta\n");
    }
    for _ in 0..6 {
        text.push_str("alpha beta gamma delta epsilon zeta eta theta\n");
    }
    roundtrip_bytes(&text, &meter)?;
    Ok(())
}

#[test]
fn multiline_patterns_survive_legend_escaping() -> Result<()> {
    let meter = Bpe::o200k()?;
    // A repeated pattern spanning a newline: its dictionary value must travel
    // escaped through the line-framed legend and come back byte-exact —
    // including a backslash sitting right next to the line break.
    let block = "first status line of the report block c:\\temp\\path\\\nsecond status line of the report block\n";
    let text = block.repeat(8);
    let encoded = roundtrip_bytes(&text, &meter)?;
    anyhow::ensure!(
        encoded.starts_with("%q1 paper"),
        "expected paper container on a repeated multi-line block"
    );
    Ok(())
}

#[test]
fn deterministic_encoding() -> Result<()> {
    let meter = Bpe::o200k()?;
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/build-log.txt"),
    )?;
    let a = encode(&text, CodecKind::Paper, &meter, Alphabet::Auto);
    let b = encode(&text, CodecKind::Paper, &meter, Alphabet::Auto);
    anyhow::ensure!(a == b, "paper encoding must be deterministic");
    Ok(())
}

#[test]
fn corpus_roundtrips_byte_exact() -> Result<()> {
    let meter = Bpe::o200k()?;
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    for entry in std::fs::read_dir(corpus)? {
        let path = entry?.path();
        if !path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&path)?;
        roundtrip_bytes(&text, &meter)
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    }
    Ok(())
}

#[test]
fn decode_refuses_unknown_alias() {
    // A hand-corrupted artifact whose body uses an alias the dictionary does
    // not define must fail, never silently pass the alias through as text.
    let artifact = "%q1 paper n=1 lmax=20 fmin=2\n<M1>=known value\n%q1 body\n<M1> and then <M2> appears\n";
    let err = decode(artifact);
    assert!(err.is_err(), "unknown alias must refuse to decode");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_paper_roundtrip(text in "[ -~\n\t§¤码引']{0,400}") {
        // The alphabet includes '<', 'M', digits and '>', so collision inputs
        // (falling back to raw) and near-miss shapes are both generated.
        let meter = Approx;
        let encoded = encode(&text, CodecKind::Paper, &meter, Alphabet::Auto);
        let back = decode(&encoded)
            .map_err(|e| TestCaseError::fail(format!("paper decode error: {e}")))?;
        prop_assert_eq!(&back, &text);
    }
}
