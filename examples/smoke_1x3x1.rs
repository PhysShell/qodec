//! The 1×3×1 smoke: one case, three arms, one repeat.
//!
//! The first place the three arms stand next to each other and produce
//! comparable rows. Deliberately an example rather than a subcommand or a
//! test, for the same reasons as `panel_dry_run`: a public CLI surface would
//! become compatibility before the interface is accepted, and a test is a poor
//! instrument to emit an artifact from.
//!
//! Two transports:
//!
//! * `programmed` (default) — a deterministic stand-in, no network, what CI
//!   runs. It rehearses the plumbing and is **not evidence about a model**.
//! * `live` — a real provider call. Never run by CI, never used to write a
//!   golden, and refuses to start without an explicit endpoint and key.
//!
//! ```text
//! cargo run --example smoke_1x3x1 -- --jsonl-out out.jsonl --text-out out.txt
//! cargo run --example smoke_1x3x1 -- --transport live \
//!   --base-url https://api.anthropic.com --model <snapshot>
//! ```

use std::path::PathBuf;

use anyhow::{anyhow, bail, Result};
use qodec::alias::Alphabet;
use qodec::canon::{IndexName, KeyBytes, SchemaId, SetName, SCHEMA_QUERY_V1};
use qodec::cell::{run_direct_cell, run_forced_query_cell, CellRecord, CellSpec};
use qodec::meter::TokenMeter;
use qodec::panel::PanelSession;
use qodec::provider::{
    Arm, ContentBlock, FixtureIdentity, HttpTransport, ModelIdentity, ProgrammedTransport,
    ProviderKind, RawResponse, SamplingParams, SealedRequest,
};
use qodec::query::ExecutionLimits;
use qodec::store::{IndexSpec, KeyExtractor, Segmentation, StorePlan};
use qodec::CodecKind;

/// The frozen case. One `%q1` layer over three attempt sections.
///
/// Repetition inside each section is deliberate: without it `squeeze` refuses
/// and emits a raw container, the squeeze-direct arm becomes the RAW arm with
/// extra steps, and the smoke would show three rows of which two are the same
/// measurement wearing different labels.
const FIXTURE: &str = "%q1 raw\n%q1 body\n\
--- attempt_1 ---\n\
alpha\n\
warning: retry scheduled for worker 1\n\
warning: retry scheduled for worker 1\n\
warning: retry scheduled for worker 1\n\
beta\n\
--- attempt_2 ---\n\
alpha\n\
warning: retry scheduled for worker 2\n\
warning: retry scheduled for worker 2\n\
warning: retry scheduled for worker 2\n\
beta\n\
--- attempt_3 ---\n\
alpha\n\
warning: retry scheduled for worker 3\n\
warning: retry scheduled for worker 3\n\
warning: retry scheduled for worker 3\n\
gamma\n";

const TASK: &str = "Exactly one line appears in every attempt section. Which line is it?";
const EXPECTED: &[u8] = b"alpha";
const FIXTURE_NAME: &str = "attempts-v1";
const STAND_IN_MODEL: &str = "programmed-stand-in";

const SECTIONS: [&str; 3] = ["attempt_1", "attempt_2", "attempt_3"];

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

/// The RAW body: the fixture with its one container layer removed.
fn raw_body() -> Result<String> {
    qodec::decode_once(FIXTURE)
}

/// The squeeze arm's payload — the real production encoder, not a stand-in.
fn squeeze_payload(raw: &str, meter: &dyn TokenMeter) -> String {
    qodec::encode(raw, CodecKind::Squeeze, meter, Alphabet::Auto)
}

fn spec(arm: Arm, model: &ModelIdentity) -> Result<CellSpec> {
    Ok(CellSpec {
        arm,
        provider: ProviderKind::AnthropicMessages,
        model: model.clone(),
        sampling: SamplingParams::deterministic(1024)?,
        fixture: FixtureIdentity::of_source(FIXTURE_NAME, FIXTURE)?,
        task: TASK.to_owned(),
        expected: KeyBytes::new(EXPECTED.to_vec()),
        max_turns: 6,
        max_transport_attempts: 3,
    })
}

// ---------------------------------------------------------------------------
// The deterministic stand-in
// ---------------------------------------------------------------------------

fn reply(blocks: Vec<serde_json::Value>) -> Result<RawResponse> {
    Ok(RawResponse {
        status: 200,
        body: serde_json::to_vec(&serde_json::json!({
            "id": "msg_standin",
            "model": STAND_IN_MODEL,
            "stop_reason": "tool_use",
            "content": blocks,
            "usage": {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0},
        }))?,
        request_id: Some("req_standin".to_owned()),
    })
}

fn tool_use(id: &str, name: &str, input: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"type": "tool_use", "id": id, "name": name, "input": input})
}

fn direct_answer() -> Result<RawResponse> {
    reply(vec![tool_use(
        "call_answer",
        "qodec_answer",
        serde_json::json!({"answer": KeyBytes::new(EXPECTED.to_vec()).to_envelope()}),
    )])
}

/// The first query result already in the conversation, if any.
fn first_query_result(sealed: &SealedRequest) -> Option<serde_json::Value> {
    sealed
        .envelope()
        .messages
        .iter()
        .flat_map(|m| m.content.iter())
        .find_map(|b| match b {
            ContentBlock::ToolResult { content, .. } if content.get("handle").is_some() => {
                Some(content.clone())
            }
            _ => None,
        })
}

/// The forced-query stand-in: intersect, materialize the support, then answer.
///
/// Three turns rather than two on purpose — the materialize step is what makes
/// `materialized_raw_bytes` a real number in the smoke rather than a field
/// that is always zero.
fn forced_query_standin(sealed: &SealedRequest, turn: usize) -> Result<RawResponse> {
    match turn {
        0 => reply(vec![tool_use(
            "call_intersect",
            "qodec_intersect",
            serde_json::json!({"index": "line", "sections": SECTIONS}),
        )]),
        1 => {
            let result = first_query_result(sealed)
                .ok_or_else(|| anyhow!("no query result to materialize from"))?;
            let handle = result
                .get("handle")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("query result carried no handle"))?;
            let support = result
                .get("support")
                .cloned()
                .ok_or_else(|| anyhow!("query result carried no support"))?;
            reply(vec![tool_use(
                "call_materialize",
                "qodec_materialize",
                serde_json::json!({"handle": handle, "record_ids": support}),
            )])
        }
        _ => {
            let result = first_query_result(sealed)
                .ok_or_else(|| anyhow!("no query result to answer from"))?;
            let handle = result
                .get("handle")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("query result carried no handle"))?;
            let answer = result
                .pointer("/preview/0")
                .ok_or_else(|| anyhow!("query result carried no preview"))?
                .clone();
            let cited = result
                .get("support")
                .cloned()
                .unwrap_or(serde_json::Value::Array(Vec::new()));
            reply(vec![tool_use(
                "call_answer",
                "qodec_answer",
                serde_json::json!({"handle": handle, "answer": answer, "cited": cited}),
            )])
        }
    }
}

// ---------------------------------------------------------------------------
// Running the three arms
// ---------------------------------------------------------------------------

enum Chosen {
    Programmed,
    Live { base_url: String, api_key: String },
}

impl Chosen {
    fn direct(&self, spec: &CellSpec, payload: &str) -> Result<CellRecord> {
        match self {
            Chosen::Programmed => {
                let mut transport =
                    ProgrammedTransport::new(|_: &SealedRequest, _| direct_answer());
                run_direct_cell(spec, payload, &mut transport)
            }
            Chosen::Live { base_url, api_key } => {
                let mut transport = live(base_url, api_key)?;
                run_direct_cell(spec, payload, &mut transport)
            }
        }
    }

    fn forced(&self, spec: &CellSpec, session: &mut PanelSession) -> Result<CellRecord> {
        match self {
            Chosen::Programmed => {
                let mut transport = ProgrammedTransport::new(forced_query_standin);
                run_forced_query_cell(spec, session, &mut transport)
            }
            Chosen::Live { base_url, api_key } => {
                let mut transport = live(base_url, api_key)?;
                run_forced_query_cell(spec, session, &mut transport)
            }
        }
    }
}

fn live(base_url: &str, api_key: &str) -> Result<HttpTransport> {
    HttpTransport::new(base_url, api_key, "2023-06-01", 120)
}

fn run_all(chosen: &Chosen, model: &ModelIdentity) -> Result<Vec<CellRecord>> {
    let raw = raw_body()?;
    let meter = qodec::meter::by_name("o200k")?;
    let squeezed = squeeze_payload(&raw, meter.as_ref());

    let mut records = Vec::new();
    records.push(chosen.direct(&spec(Arm::Raw, model)?, &raw)?);
    records.push(chosen.direct(&spec(Arm::SqueezeDirect, model)?, &squeezed)?);

    let mut session = PanelSession::open(
        FIXTURE,
        &plan()?,
        SchemaId::parse(SCHEMA_QUERY_V1)?,
        ExecutionLimits::modest(),
    )?;
    records.push(chosen.forced(&spec(Arm::ForcedQuery, model)?, &mut session)?);
    Ok(records)
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// The human table, derived strictly from the canonical JSONL.
///
/// Same rule as the panel dry-run: two independently built renderings would
/// eventually disagree and both would look convincing.
fn render(jsonl: &str) -> Result<String> {
    let mut out = String::new();
    out.push_str(
        "arm             correct  verdict              model     cmp  prov_in  prov_out  \
visible_B  mat_B  calls\n",
    );
    for line in jsonl.lines() {
        let v: serde_json::Value = serde_json::from_str(line)?;
        let arm = v.get("arm").and_then(|x| x.as_str()).unwrap_or("?");
        let kind = v
            .pointer("/outcome/kind")
            .and_then(|x| x.as_str())
            .unwrap_or("?");
        let correct = v
            .pointer("/outcome/correct")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let verdict = v
            .pointer("/outcome/verdict")
            .and_then(|x| x.as_str())
            .unwrap_or(if kind == "answered" { "valid" } else { kind });
        let num = |ptr: &str| {
            v.pointer(ptr)
                .and_then(serde_json::Value::as_u64)
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".to_owned())
        };
        let status = v
            .get("model_status")
            .and_then(|x| x.as_str())
            .unwrap_or("?");
        let comparable = v
            .get("comparable")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        out.push_str(&format!(
            "{arm:<15} {:<8} {verdict:<20} {status:<9} {:<4} {:<8} {:<9} {:<10} {:<6} {}\n",
            if correct { "yes" } else { "no" },
            if comparable { "yes" } else { "NO" },
            num("/accounting/provider_reported/input_tokens"),
            num("/accounting/provider_reported/output_tokens"),
            num("/accounting/deterministic_local/model_visible_transcript_bytes"),
            num("/accounting/deterministic_local/materialized_raw_bytes"),
            num("/accounting/deterministic_local/tool_call_count"),
        ));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let mut transport_kind = "programmed".to_owned();
    let mut base_url = String::new();
    let mut model = STAND_IN_MODEL.to_owned();
    let mut jsonl_out: Option<PathBuf> = None;
    let mut text_out: Option<PathBuf> = None;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let flag = args.get(i).map(String::as_str).unwrap_or("");
        let value = args.get(i + 1).cloned();
        let need = |v: Option<String>| v.ok_or_else(|| anyhow!("{flag} needs a value"));
        match flag {
            "--transport" => transport_kind = need(value)?,
            "--base-url" => base_url = need(value)?,
            "--model" => model = need(value)?,
            "--jsonl-out" => jsonl_out = Some(PathBuf::from(need(value)?)),
            "--text-out" => text_out = Some(PathBuf::from(need(value)?)),
            other => bail!("unknown flag {other:?}"),
        }
        i += 2;
    }

    let chosen = match transport_kind.as_str() {
        "programmed" => Chosen::Programmed,
        "live" => {
            // No ambient defaults. A live run is a deliberate act and must look
            // like one at the command line.
            let api_key = std::env::var("ANTHROPIC_API_KEY")
                .map_err(|_| anyhow!("a live run needs ANTHROPIC_API_KEY in the environment"))?;
            if base_url.is_empty() {
                bail!("a live run needs an explicit --base-url");
            }
            if model == STAND_IN_MODEL {
                bail!("a live run needs an explicit --model snapshot");
            }
            Chosen::Live { base_url, api_key }
        }
        other => bail!("unknown transport {other:?} (expected \"programmed\" or \"live\")"),
    };
    if matches!(chosen, Chosen::Live { .. }) && (jsonl_out.is_some() || text_out.is_some()) {
        eprintln!(
            "note: this is a live run — its output is evidence about a model and \
             must not be committed as a model-free golden"
        );
    }

    let model = ModelIdentity::parse(&model)?;
    let records = run_all(&chosen, &model)?;

    let mut jsonl = String::new();
    for record in &records {
        jsonl.push_str(&record.to_json().to_string());
        jsonl.push('\n');
    }

    // The guard this driver owes the reader: the forced-query arm's requests
    // must not contain the artifact. Checked here as well as in the contracts,
    // because a driver that emits an artifact nobody re-checks is how a
    // leaking transcript gets published with a passing test suite behind it.
    let raw = raw_body()?;
    for record in &records {
        if record.arm != Arm::ForcedQuery {
            continue;
        }
        for turn in &record.turns {
            let body = String::from_utf8_lossy(turn.request.wire_bytes()).into_owned();
            let escaped = serde_json::to_string(&raw)?;
            let escaped = escaped
                .get(1..escaped.len().saturating_sub(1))
                .unwrap_or("");
            if body.contains(&raw) || (!escaped.is_empty() && body.contains(escaped)) {
                bail!(
                    "the forced-query arm put the RAW body on the wire at turn {}",
                    turn.ordinal
                );
            }
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
