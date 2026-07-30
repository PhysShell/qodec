//! Report what `serde_json::from_slice::<Value>` admits — eval-only, no model.
//!
//! The canary's JSON gate must never be more liberal than the consumer that
//! reads a qualified target's bodies. "Never more liberal" is a claim about two
//! parsers, and the only honest way to hold it is to ask one of them. So this
//! is the oracle: it takes the frozen admission corpus, runs the *real*
//! `serde_json` over each case, and prints a verdict per case.
//!
//! Deliberately dumb, for the same reason `emit_panel_surface` is: the moment
//! this file starts reasoning about which inputs *ought* to be admitted, there
//! are two opinions about the consumer's behaviour and one of them is fiction.
//!
//! ```text
//! cargo run --example json_admission_oracle -- evals/provider-matrix/json-admission-corpus.json
//! ```
//!
//! Cases carry their bytes as lowercase hex so a corpus entry can name any byte
//! sequence, including ones that are not valid UTF-8 and could not survive
//! being written as a JSON string.

use anyhow::{bail, Context, Result};

fn unhex(text: &str) -> Result<Vec<u8>> {
    if text.len() % 2 != 0 {
        bail!("hex string has an odd length");
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16).context("not a hex digit")?;
        let lo = (pair[1] as char).to_digit(16).context("not a hex digit")?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

fn main() -> Result<()> {
    let path = std::env::args().nth(1).context("usage: json_admission_oracle <corpus.json>")?;
    let corpus: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).context("reading the corpus")?)
            .context("the corpus itself is not valid JSON")?;

    let cases = corpus["cases"].as_array().context("corpus needs a `cases` array")?;
    let mut verdicts = serde_json::Map::new();
    for case in cases {
        let name = case["name"].as_str().context("every case needs a name")?;
        let raw = unhex(case["hex"].as_str().context("every case needs hex bytes")?)?;
        // The whole point: the consumer parses the *entire* body into a Value
        // before it looks at any field, so a rejected constant three fields
        // away from anything the canary reads still sinks the response.
        let admitted = serde_json::from_slice::<serde_json::Value>(&raw).is_ok();
        if verdicts.insert(name.to_string(), admitted.into()).is_some() {
            bail!("duplicate case name {name:?}");
        }
    }

    let mut root = serde_json::Map::new();
    root.insert("schema".into(), "qodec-json-admission-verdicts-v1".into());
    root.insert("verdicts".into(), serde_json::Value::Object(verdicts));
    println!("{}", serde_json::Value::Object(root));
    Ok(())
}
