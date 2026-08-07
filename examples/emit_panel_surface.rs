//! Emit the C1 panel surface as canonical JSON — eval-only, no model.
//!
//! The forced-query arm's four model-visible declarations, written out so a
//! tool outside this crate can send exactly them. Qualifying a provider against
//! *approximately* the C1 surface qualifies nothing: the question a canary
//! answers is whether a given `provider × model` accepts these schemas and this
//! forcing, and a paraphrase of them has a different answer.
//!
//! Deliberately dumb. It reads [`qodec::panel::tool_schemas`] and
//! [`qodec::panel::answer_schema`] and prints them. It performs no
//! provider-specific transformation, because the moment this file knows what
//! OpenAI or Anthropic want, there are two places that decide the wire shape
//! and they begin to drift on the same afternoon.
//!
//! ```text
//! cargo run --example emit_panel_surface > evals/provider-matrix/c1-panel-surface.json
//! ```

use anyhow::Result;
use qodec::panel::{answer_schema, tool_schemas, PanelToolSchema};

fn main() -> Result<()> {
    let mut root = serde_json::Map::new();
    root.insert("schema".into(), "qodec-c1-panel-surface-v1".into());
    root.insert(
        "operations".into(),
        tool_schemas()
            .iter()
            .map(PanelToolSchema::to_json)
            .collect::<Vec<_>>()
            .into(),
    );
    root.insert("terminal_answer".into(), answer_schema().to_json());

    // Canonical: sorted keys (serde_json's default map ordering) and a trailing
    // newline, so regenerating and diffing is a byte comparison rather than a
    // judgement call about formatting.
    println!("{}", serde_json::Value::Object(root));
    Ok(())
}
