//! Deterministic dry-run of the forced-query panel — eval-only, no model.
//!
//! A rehearsal of the C1 adapter rather than a test that prints. It walks the
//! whole cell path — metadata, query, materialize, answer — against a frozen
//! fixture and emits the transcript twice: canonical JSONL as the machine
//! source of truth, and a human rendering *derived from it*.
//!
//! Deliberately an example and not `qodec panel dry-run`. A public subcommand
//! would create a user-facing CLI surface before the interface is accepted, and
//! eval-only flags start counting as product compatibility the moment someone
//! writes them into a shell script. It is also deliberately not an ordinary
//! test: the test harness swallows stdout on success, dumping an artifact from
//! it is awkward, and a test makes a poor reproducible instrument even when it
//! makes a fine assertion.
//!
//! ```text
//! cargo run --example panel_dry_run -- \
//!   --case happy \
//!   --jsonl-out result/panel-transcript.jsonl \
//!   --text-out result/panel-transcript.txt
//! ```

use std::path::PathBuf;

use anyhow::{bail, Result};
use qodec::canon::{IndexName, KeyBytes, SchemaId, SetName, SCHEMA_QUERY_V1};
use qodec::panel::{PanelEvent, PanelSession};
use qodec::query::ExecutionLimits;
use qodec::store::{IndexSpec, KeyExtractor, Segmentation, StorePlan};

/// The frozen fixture. Held here rather than read from disk so the dry-run has
/// no input that could drift underneath the golden transcript.
const FIXTURE: &str = "%q1 raw\n%q1 body\n\
--- attempt_1 ---\nalpha\nbeta\n\
--- attempt_2 ---\nalpha\nbeta\n\
--- attempt_3 ---\nalpha\ngamma\n";

fn plan() -> Result<StorePlan> {
    StorePlan::new(
        1,
        Segmentation::MarkedSections {
            prefix: "--- ".into(),
            suffix: " ---".into(),
            preamble: SetName::parse("preamble")?,
        },
        vec![IndexSpec {
            name: IndexName::parse("line")?,
            extractor: KeyExtractor::WholeRecord,
        }],
    )
}

fn attempts() -> Result<Vec<SetName>> {
    Ok(vec![
        SetName::parse("attempt_1")?,
        SetName::parse("attempt_2")?,
        SetName::parse("attempt_3")?,
    ])
}

/// The happy path: metadata, intersect, materialize, answer.
fn happy(sess: &mut PanelSession) -> Result<()> {
    sess.metadata()?;
    let hit = sess.intersect(&IndexName::parse("line")?, &attempts()?)?;
    sess.materialize(&hit.handle, &hit.support)?;
    let answer = hit
        .preview
        .first()
        .cloned()
        .unwrap_or_else(|| KeyBytes::new(Vec::new()));
    sess.answer(&hit.handle, &answer, &hit.support);
    Ok(())
}

/// The refusal path: an out-of-scope materialize is attempted first.
///
/// Frozen as its own golden because `ok: false` is otherwise a field that
/// exists mainly in the documentation.
fn refusal(sess: &mut PanelSession) -> Result<()> {
    sess.metadata()?;
    let hit = sess.intersect(&IndexName::parse("line")?, &attempts()?)?;
    let beta = sess.lookup(&IndexName::parse("line")?, &KeyBytes::new(b"beta".to_vec()))?;
    // Real ids in this very store, and still outside *this* result's support.
    let _ = sess.materialize(&hit.handle, &beta.support);
    sess.materialize(&hit.handle, &hit.support)?;
    let answer = hit
        .preview
        .first()
        .cloned()
        .unwrap_or_else(|| KeyBytes::new(Vec::new()));
    sess.answer(&hit.handle, &answer, &hit.support);
    Ok(())
}

/// The human rendering, derived strictly from the canonical JSONL.
///
/// Two independently built transcripts would eventually disagree, and both
/// would look convincing. This one cannot disagree with the JSONL because it
/// has no other source.
fn render(jsonl: &str) -> Result<String> {
    let mut out = String::new();
    for line in jsonl.lines() {
        let event: serde_json::Value = serde_json::from_str(line)?;
        let kind = event.get("event").and_then(|v| v.as_str()).unwrap_or("?");
        match kind {
            "metadata" => {
                out.push_str("== metadata ==\n");
                let records = event
                    .pointer("/metadata/record_count")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                out.push_str(&format!("  records: {records}\n"));
                if let Some(sections) = event
                    .pointer("/metadata/sections")
                    .and_then(serde_json::Value::as_object)
                {
                    for (name, count) in sections {
                        out.push_str(&format!("  section {name}: {count}\n"));
                    }
                }
                if let Some(schemas) = event
                    .get("tool_schemas")
                    .and_then(serde_json::Value::as_array)
                {
                    for s in schemas {
                        let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                        let required = s
                            .pointer("/input_schema/required")
                            .and_then(serde_json::Value::as_array)
                            .map(|r| {
                                r.iter()
                                    .filter_map(|v| v.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .unwrap_or_default();
                        out.push_str(&format!("  tool: {name}({required})\n"));
                    }
                }
                if let Some(required) = event
                    .pointer("/answer_schema/schema/required")
                    .and_then(serde_json::Value::as_array)
                {
                    let fields = required
                        .iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    out.push_str(&format!("  answer: {{{fields}}}\n"));
                }
            }
            "tool_call" => {
                let seq = event
                    .get("sequence")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                let tool = event.get("tool").and_then(|v| v.as_str()).unwrap_or("?");
                let ok = event
                    .pointer("/outcome/ok")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                out.push_str(&format!(
                    "== [{seq}] {tool} {} ==\n",
                    if ok { "ok" } else { "REFUSED" }
                ));
                if let Some(reason) = event.pointer("/outcome/reason").and_then(|v| v.as_str()) {
                    out.push_str(&format!("  reason: {reason}\n"));
                }
                if let Some(count) = event
                    .pointer("/outcome/candidate_count")
                    .and_then(serde_json::Value::as_u64)
                {
                    out.push_str(&format!("  candidate_count: {count}\n"));
                }
                for (label, ptr) in [
                    ("preview", "/outcome/preview"),
                    ("record", "/outcome/records"),
                ] {
                    if let Some(items) = event.pointer(ptr).and_then(serde_json::Value::as_array) {
                        for item in items {
                            out.push_str(&format!("  {label}: {}\n", byte_summary(item)));
                        }
                    }
                }
                if let Some(support) = event
                    .pointer("/outcome/support")
                    .and_then(serde_json::Value::as_array)
                {
                    for id in support {
                        out.push_str(&format!("  support: {}\n", record_summary(id)));
                    }
                }
            }
            "final_answer" => {
                let verdict = event.get("verdict").and_then(|v| v.as_str()).unwrap_or("?");
                out.push_str("== final answer ==\n");
                out.push_str(&format!(
                    "  answer: {}\n",
                    event.get("answer").map(byte_summary).unwrap_or_default()
                ));
                out.push_str(&format!("  verdict: {verdict}\n"));
            }
            other => bail!("unknown transcript event {other:?}"),
        }
    }
    Ok(out)
}

/// Bytes as the reader should see them: the display form when it exists, the
/// base64url payload when it does not. Never a lossy conversion.
fn byte_summary(v: &serde_json::Value) -> String {
    if let Some(text) = v.get("display_utf8").and_then(|t| t.as_str()) {
        return format!("{text:?}");
    }
    format!(
        "base64url:{}",
        v.get("data").and_then(|d| d.as_str()).unwrap_or("?")
    )
}

fn record_summary(v: &serde_json::Value) -> String {
    format!(
        "{}#{}",
        v.get("section").and_then(|s| s.as_str()).unwrap_or("?"),
        v.get("ordinal")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    )
}

fn main() -> Result<()> {
    let mut case = "happy".to_owned();
    let mut jsonl_out: Option<PathBuf> = None;
    let mut text_out: Option<PathBuf> = None;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let flag = args.get(i).map(String::as_str).unwrap_or("");
        let value = args.get(i + 1).cloned();
        match flag {
            "--case" => case = value.ok_or_else(|| anyhow::anyhow!("--case needs a value"))?,
            "--jsonl-out" => {
                jsonl_out =
                    Some(PathBuf::from(value.ok_or_else(|| {
                        anyhow::anyhow!("--jsonl-out needs a path")
                    })?));
            }
            "--text-out" => {
                text_out = Some(PathBuf::from(
                    value.ok_or_else(|| anyhow::anyhow!("--text-out needs a path"))?,
                ));
            }
            other => bail!("unknown flag {other:?}"),
        }
        i += 2;
    }

    let plan = plan()?;
    let mut sess = PanelSession::open(
        FIXTURE,
        &plan,
        SchemaId::parse(SCHEMA_QUERY_V1)?,
        ExecutionLimits::modest(),
    )?;
    match case.as_str() {
        "happy" => happy(&mut sess)?,
        "refusal" => refusal(&mut sess)?,
        other => bail!("unknown case {other:?} (expected \"happy\" or \"refusal\")"),
    }

    // A sanity assertion the driver owes the reader: the artifact body must not
    // appear anywhere outside a materialize event, since materialize is the one
    // operation entitled to return record bytes.
    let jsonl = sess.transcript_jsonl();
    for event in sess.transcript() {
        if let PanelEvent::ToolCall { tool, .. } = event {
            if tool.name() == "qodec_materialize" {
                continue;
            }
        }
        let line = event.to_json().to_string();
        if line.contains("--- attempt_1 ---") {
            bail!("a non-materialize event leaked artifact text: {line}");
        }
    }

    let text = render(&jsonl)?;
    if let Some(path) = &jsonl_out {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, &jsonl)?;
    }
    if let Some(path) = &text_out {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, &text)?;
    }
    if jsonl_out.is_none() && text_out.is_none() {
        print!("{text}");
    }
    Ok(())
}
