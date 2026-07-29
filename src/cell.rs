//! One C1 cell: one arm, one fixture, one question, one model.
//!
//! Three arms differ in exactly one thing — how the model may reach the data —
//! and are held identical in every other respect: same model, same sampling,
//! same question, same frozen expected answer, same terminal answer channel.
//! Anything else that varied would be a second independent variable quietly
//! sharing a column.
//!
//! ## Why the direct arms also answer through a tool
//!
//! It would be more natural to let the RAW and squeeze arms reply in prose and
//! then check whether the answer "appears" in the reply. That measurement is
//! partly a measurement of the parser we wrote to grade it: a lenient matcher
//! flatters the arm, a strict one punishes formatting, and neither fact is
//! about the model. All three arms therefore end by calling a terminal answer
//! tool with a byte-exact `answer`. The arms still differ in exactly one thing;
//! grading is byte equality in all three.
//!
//! ## No hidden rescue
//!
//! [`run_forced_query_cell`] takes a [`PanelSession`] and **no payload
//! parameter**. It could not fall back to RAW if it wanted to: the text is not
//! in scope. That is deliberate and is the enforcement — a rule stated in a
//! comment is a rule that survives exactly until the first inconvenient
//! failure. Retrying a failed query cell against RAW would let the third arm
//! reach RAW-like correctness by the innovative method of becoming the first
//! arm.
//!
//! Transport retries are a different thing entirely and are permitted: the
//! *same sealed request*, delivered again after a socket died, recorded as
//! repeated attempts carrying one request digest. See
//! [`crate::provider::deliver`].

use anyhow::{bail, Context, Result};

use crate::canon::{IndexName, KeyBytes, QueryResultId, SetName};
use crate::panel::{
    byte_envelope_defs, byte_ref, obj, strings, CellOutcome, PanelAnswerSchema, PanelEvent,
    PanelSession, PanelTool,
};
use crate::provider::{
    exchange, Arm, ContentBlock, FixtureIdentity, Message, MessageRole, ModelIdentity,
    ModelTransport, NormalizedToolCall, ProviderKind, ProviderUsage, RequestEnvelope,
    RequestMapping, ResponseEnvelope, SamplingParams, SealedRequest, ANSWER_TOOL_NAME,
};
use crate::query::VerifyOutcome;
use crate::store::RecordId;

/// What the direct arms are told.
const DIRECT_INSTRUCTIONS: &str = "You are answering one question about a document that is \
    included in this conversation. Read it and answer. When you have the answer, call \
    qodec_answer exactly once with the answer bytes. Do not call it more than once.";

/// What the forced-query arm is told.
///
/// It does not *ask* the model to prefer the tools — there is nothing else to
/// prefer. The wording describes the situation rather than requesting
/// compliance, because an instruction to use the tools would make the arm a
/// measurement of instruction-following.
const FORCED_QUERY_INSTRUCTIONS: &str = "You are answering one question about a document you \
    cannot see. The document is not in this conversation and will not be shown to you. You have \
    tools that run deterministic queries against it and return results, and a tool that returns \
    the exact bytes of records backing a result you already obtained. Use them to establish the \
    answer, then call qodec_answer exactly once, citing the result handle it came from and the \
    record ids that support it.";

/// The terminal answer format for the direct arms.
///
/// The same mechanism as the panel's answer schema and deliberately not the
/// same schema: a direct arm has no result handle to cite and no support to
/// name, so requiring them would ask the model to invent identifiers, and an
/// invented handle is a failure mode belonging to the harness rather than to
/// the arm.
pub fn direct_answer_schema() -> PanelAnswerSchema {
    PanelAnswerSchema {
        description: "The final answer, as exact bytes.",
        schema: obj(vec![
            ("type", "object".into()),
            ("required", strings(&["answer"])),
            ("additionalProperties", false.into()),
            ("properties", obj(vec![("answer", byte_ref())])),
            ("$defs", byte_envelope_defs()),
        ]),
    }
}

/// Everything a cell needs that is not the data itself.
#[derive(Debug, Clone, PartialEq)]
pub struct CellSpec {
    pub arm: Arm,
    pub provider: ProviderKind,
    pub model: ModelIdentity,
    pub sampling: SamplingParams,
    pub fixture: FixtureIdentity,
    /// The one question, identical across the three arms.
    pub task: String,
    /// The one frozen expected answer, identical across the three arms.
    pub expected: KeyBytes,
    pub max_turns: u32,
    pub max_transport_attempts: u32,
}

impl CellSpec {
    fn validated(&self) -> Result<()> {
        if self.task.is_empty() {
            bail!("a cell needs a question");
        }
        if self.max_turns == 0 {
            bail!("max_turns must be at least 1");
        }
        if self.max_transport_attempts == 0 {
            bail!("max_transport_attempts must be at least 1");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Accounting
// ---------------------------------------------------------------------------

/// Counters computed locally, from bytes we hold.
///
/// Exact and reproducible: every field is a length or a count of something in
/// the record, so re-deriving them from a saved transcript gives the same
/// numbers on any machine, in any year, with no provider involved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeterministicLocalAccounting {
    /// Total sealed request bytes across all turns.
    pub request_bytes: u64,
    /// Total raw response body bytes across all turns.
    pub response_bytes: u64,
    /// Bytes of `system` + `messages` + `tools`, summed per turn.
    ///
    /// The conversation is re-sent every turn, so this grows the way a
    /// provider's input charge grows. It is a **byte** count and never a token
    /// count: the two are different quantities and the moment one is used as a
    /// proxy for the other, the table stops being falsifiable.
    pub model_visible_transcript_bytes: u64,
    /// Bytes handed back by `qodec_materialize`. Zero for the direct arms,
    /// where the payload arrives in the prompt instead and is counted above.
    pub materialized_raw_bytes: u64,
    /// Every tool call the model made on the wire, answer channel included.
    pub tool_call_count: u64,
    /// Panel operations only — the wire count minus the answer call.
    pub operation_call_count: u64,
}

/// The two planes, side by side and never added together.
///
/// They measure different things and are wrong in different directions.
/// Provider counters are authoritative for what the provider billed and are
/// useless for comparing providers, since each tokenizes and caches its own
/// way. Local byte counts are exactly reproducible and are not what anyone was
/// charged. There is deliberately no method returning "the total": a single
/// number here would have to pick one plane's units and silently reinterpret
/// the other's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CellAccounting {
    pub provider_reported: ProviderUsage,
    pub deterministic_local: DeterministicLocalAccounting,
}

impl CellAccounting {
    fn to_json(self) -> serde_json::Value {
        let l = self.deterministic_local;
        obj(vec![
            ("provider_reported", self.provider_reported.to_json()),
            (
                "deterministic_local",
                obj(vec![
                    ("request_bytes", l.request_bytes.into()),
                    ("response_bytes", l.response_bytes.into()),
                    (
                        "model_visible_transcript_bytes",
                        l.model_visible_transcript_bytes.into(),
                    ),
                    ("materialized_raw_bytes", l.materialized_raw_bytes.into()),
                    ("tool_call_count", l.tool_call_count.into()),
                    ("operation_call_count", l.operation_call_count.into()),
                ]),
            ),
        ])
    }
}

// ---------------------------------------------------------------------------
// Outcome and record
// ---------------------------------------------------------------------------

/// How an arm's cell ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArmOutcome {
    /// The model produced an answer, correct or not.
    Answered { correct: bool },
    /// Forced-query only: the answer failed deterministic verification.
    ///
    /// Never scored as a forced-query success, and never retried against RAW.
    QueryPathFailed {
        verdict: VerifyOutcome,
        correct: bool,
    },
    /// No answer was produced within the turn budget, or the model stopped.
    NoAnswer { reason: String },
}

impl ArmOutcome {
    /// Whether the cell answered correctly. A failed verdict is not correct
    /// even when the bytes match: an unverified right answer is a right answer
    /// the harness cannot tell from a lucky one.
    pub fn correct(&self) -> bool {
        matches!(self, ArmOutcome::Answered { correct: true })
    }

    fn to_json(&self) -> serde_json::Value {
        match self {
            ArmOutcome::Answered { correct } => obj(vec![
                ("kind", "answered".into()),
                ("correct", (*correct).into()),
            ]),
            ArmOutcome::QueryPathFailed { verdict, correct } => obj(vec![
                ("kind", "query-path-failed".into()),
                ("verdict", verdict_name(*verdict).into()),
                ("answer_bytes_matched", (*correct).into()),
                ("fallback_required", true.into()),
            ]),
            ArmOutcome::NoAnswer { reason } => obj(vec![
                ("kind", "no-answer".into()),
                ("reason", reason.clone().into()),
            ]),
        }
    }
}

fn verdict_name(v: VerifyOutcome) -> &'static str {
    match v {
        VerifyOutcome::Valid => "valid",
        VerifyOutcome::Invalid => "invalid",
        VerifyOutcome::Ambiguous => "ambiguous",
        VerifyOutcome::Incomplete => "incomplete",
        VerifyOutcome::Unverifiable => "unverifiable",
        VerifyOutcome::StaleResultHandle => "stale-result-handle",
        VerifyOutcome::ArtifactMismatch => "artifact-mismatch",
        VerifyOutcome::StorePlanMismatch => "store-plan-mismatch",
        VerifyOutcome::QueryDigestMismatch => "query-digest-mismatch",
    }
}

/// One round trip, both halves.
#[derive(Debug, Clone, PartialEq)]
pub struct TurnRecord {
    pub ordinal: u32,
    pub request: SealedRequest,
    pub response: ResponseEnvelope,
}

impl TurnRecord {
    fn to_json(&self) -> serde_json::Value {
        obj(vec![
            ("ordinal", self.ordinal.into()),
            ("request", self.request.to_json()),
            ("response", self.response.to_json()),
        ])
    }
}

/// Everything one cell produced.
#[derive(Debug, Clone, PartialEq)]
pub struct CellRecord {
    pub arm: Arm,
    pub fixture: FixtureIdentity,
    pub model_requested: ModelIdentity,
    /// What the provider said it ran, per turn.
    pub models_reported: Vec<Option<String>>,
    pub turns: Vec<TurnRecord>,
    pub outcome: ArmOutcome,
    pub accounting: CellAccounting,
    /// The panel transcript, for the forced-query arm. Empty otherwise.
    pub panel_transcript: Vec<PanelEvent>,
}

impl CellRecord {
    /// Whether any turn ran a model other than the one requested.
    ///
    /// Checked rather than assumed. An alias resolving to a new snapshot
    /// mid-experiment keeps every row looking like it names one model while
    /// the arms stop being comparable, which is the kind of defect that shows
    /// up as unexplained variance and gets attributed to the arms.
    pub fn model_drifted(&self) -> bool {
        self.models_reported.iter().any(|m| {
            m.as_deref()
                .is_some_and(|m| m != self.model_requested.as_str())
        })
    }

    pub fn to_json(&self) -> serde_json::Value {
        obj(vec![
            ("arm", self.arm.label().into()),
            ("fixture", self.fixture.name.clone().into()),
            (
                "fixture_source_digest",
                self.fixture.source_digest.to_canonical_text().into(),
            ),
            ("model_requested", self.model_requested.as_str().into()),
            (
                "models_reported",
                self.models_reported
                    .iter()
                    .map(|m| match m {
                        Some(s) => serde_json::Value::from(s.clone()),
                        None => serde_json::Value::Null,
                    })
                    .collect::<Vec<_>>()
                    .into(),
            ),
            ("model_drifted", self.model_drifted().into()),
            ("outcome", self.outcome.to_json()),
            ("accounting", self.accounting.to_json()),
            (
                "turns",
                self.turns
                    .iter()
                    .map(TurnRecord::to_json)
                    .collect::<Vec<_>>()
                    .into(),
            ),
            (
                "panel_transcript",
                self.panel_transcript
                    .iter()
                    .map(PanelEvent::to_json)
                    .collect::<Vec<_>>()
                    .into(),
            ),
        ])
    }
}

// ---------------------------------------------------------------------------
// The direct arms
// ---------------------------------------------------------------------------

/// Run a RAW or squeeze-direct cell: the whole payload goes in the prompt.
///
/// Refuses [`Arm::ForcedQuery`]. That arm has a different signature for a
/// reason, and accepting it here — with a payload in hand — would reintroduce
/// the exact bypass the third arm exists to rule out.
pub fn run_direct_cell(
    spec: &CellSpec,
    payload: &str,
    transport: &mut dyn ModelTransport,
) -> Result<CellRecord> {
    spec.validated()?;
    if spec.arm == Arm::ForcedQuery {
        bail!("the forced-query arm must not be run through the direct path");
    }
    let answer_schema = direct_answer_schema();
    let mapping = RequestMapping::direct(spec.provider, &answer_schema, &spec.sampling);
    let messages = vec![Message::user_text(format!(
        "{}\n\n--- document ---\n{}",
        spec.task, payload
    ))];

    // Exactly one turn. A direct arm has nothing to round-trip: the document
    // is already in the prompt, so a second turn could only be a nudge to
    // answer, and a nudge measures instruction-following in one arm and not in
    // the others. `max_turns` governs the forced-query loop, where extra turns
    // buy tool calls rather than pressure.
    let sealed = seal(spec, DIRECT_INSTRUCTIONS, &messages, &mapping)?;
    let response = exchange(transport, &sealed, spec.max_transport_attempts)?;
    let mut accounting = CellAccounting::default();
    charge(&mut accounting, &sealed, &response);
    let models_reported = vec![response.normalized.reported_model.clone()];
    let calls = response.normalized.tool_calls.clone();
    let turns = vec![TurnRecord {
        ordinal: 0,
        request: sealed,
        response,
    }];

    let outcome = match calls.iter().find(|c| c.name == ANSWER_TOOL_NAME) {
        None => ArmOutcome::NoAnswer {
            reason: "model produced no qodec_answer call".to_owned(),
        },
        Some(call) => ArmOutcome::Answered {
            correct: parse_direct_answer(&call.input)? == spec.expected,
        },
    };
    Ok(finish(
        spec,
        turns,
        accounting,
        models_reported,
        Vec::new(),
        outcome,
    ))
}

// ---------------------------------------------------------------------------
// The forced-query arm
// ---------------------------------------------------------------------------

/// Run a forced-query cell against an open session.
///
/// **There is no payload parameter, and that is the enforcement.** The function
/// cannot fall back to RAW because the RAW text is not in its scope, so the
/// prohibition is a property of the signature rather than of anyone's
/// discipline on a bad afternoon.
pub fn run_forced_query_cell(
    spec: &CellSpec,
    session: &mut PanelSession,
    transport: &mut dyn ModelTransport,
) -> Result<CellRecord> {
    spec.validated()?;
    if spec.arm != Arm::ForcedQuery {
        bail!("only the forced-query arm runs through the panel path");
    }
    let metadata = session.metadata()?;
    let mapping = RequestMapping::for_panel(
        spec.provider,
        session.tool_schemas(),
        session.answer_schema(),
        &spec.sampling,
    );
    let mut messages = vec![Message::user_text(format!(
        "{}\n\n--- artifact metadata ---\n{}",
        spec.task,
        metadata.render()
    ))];

    let mut turns = Vec::new();
    let mut accounting = CellAccounting::default();
    let mut models_reported = Vec::new();

    for ordinal in 0..spec.max_turns {
        let sealed = seal(spec, FORCED_QUERY_INSTRUCTIONS, &messages, &mapping)?;
        let response = exchange(transport, &sealed, spec.max_transport_attempts)?;
        charge(&mut accounting, &sealed, &response);
        models_reported.push(response.normalized.reported_model.clone());
        let calls = response.normalized.tool_calls.clone();
        let assistant = assistant_turn(&response);
        turns.push(TurnRecord {
            ordinal,
            request: sealed,
            response,
        });

        if calls.is_empty() {
            return Ok(finish(
                spec,
                turns,
                accounting,
                models_reported,
                session.transcript().to_vec(),
                ArmOutcome::NoAnswer {
                    reason: "model made no tool call".to_owned(),
                },
            ));
        }
        messages.push(assistant);

        let mut results = Vec::new();
        for call in &calls {
            if call.name == ANSWER_TOOL_NAME {
                let (handle, answer, cited) = parse_panel_answer(&call.input)?;
                let cell = session.answer(&handle, &answer, &cited);
                let correct = answer == spec.expected;
                let outcome = match cell {
                    CellOutcome::Accepted => ArmOutcome::Answered { correct },
                    // Not retried, not rescued, not scored as a success. A
                    // separate diagnostic may follow outside this cell.
                    CellOutcome::QueryPathFailed { verdict } => {
                        ArmOutcome::QueryPathFailed { verdict, correct }
                    }
                };
                return Ok(finish(
                    spec,
                    turns,
                    accounting,
                    models_reported,
                    session.transcript().to_vec(),
                    outcome,
                ));
            }
            let (content, is_error, materialized) = dispatch(session, call, &mut accounting);
            accounting.deterministic_local.materialized_raw_bytes = accounting
                .deterministic_local
                .materialized_raw_bytes
                .saturating_add(materialized);
            results.push(ContentBlock::ToolResult {
                tool_use_id: call.id.clone(),
                content,
                is_error,
            });
        }
        messages.push(Message {
            role: MessageRole::User,
            content: results,
        });
    }
    Ok(finish(
        spec,
        turns,
        accounting,
        models_reported,
        session.transcript().to_vec(),
        ArmOutcome::NoAnswer {
            reason: "turn budget exhausted".to_owned(),
        },
    ))
}

/// Execute one panel operation and render its result for the model.
///
/// A refusal is returned as a tool result with `is_error`, not as a Rust error:
/// the model asking for something out of scope is a normal event in this arm
/// and the session already recorded it. Aborting the cell instead would delete
/// the very measurement the refusal produces.
fn dispatch(
    session: &mut PanelSession,
    call: &NormalizedToolCall,
    accounting: &mut CellAccounting,
) -> (serde_json::Value, bool, u64) {
    let tool = match call.name.as_str() {
        n if n == PanelTool::Lookup.name() => PanelTool::Lookup,
        n if n == PanelTool::Intersect.name() => PanelTool::Intersect,
        n if n == PanelTool::Materialize.name() => PanelTool::Materialize,
        // Not a panel operation, so it is not counted as one. It stays in
        // `tool_call_count`, which counts what the model did on the wire.
        other => {
            return (
                obj(vec![("error", format!("unknown tool {other:?}").into())]),
                true,
                0,
            )
        }
    };
    accounting.deterministic_local.operation_call_count = accounting
        .deterministic_local
        .operation_call_count
        .saturating_add(1);
    match tool {
        PanelTool::Lookup => match parse_lookup(&call.input) {
            Err(e) => (obj(vec![("error", format!("{e}").into())]), true, 0),
            Ok((index, key)) => match session.lookup(&index, &key) {
                Err(e) => (obj(vec![("error", format!("{e}").into())]), true, 0),
                Ok(result) => (query_result_json(&result), false, 0),
            },
        },
        PanelTool::Intersect => match parse_intersect(&call.input) {
            Err(e) => (obj(vec![("error", format!("{e}").into())]), true, 0),
            Ok((index, sections)) => match session.intersect(&index, &sections) {
                Err(e) => (obj(vec![("error", format!("{e}").into())]), true, 0),
                Ok(result) => (query_result_json(&result), false, 0),
            },
        },
        PanelTool::Materialize => match parse_materialize(&call.input) {
            Err(e) => (obj(vec![("error", format!("{e}").into())]), true, 0),
            Ok((handle, ids)) => match session.materialize(&handle, &ids) {
                Err(e) => (obj(vec![("error", format!("{e}").into())]), true, 0),
                Ok(records) => {
                    let bytes = records
                        .iter()
                        .fold(0u64, |acc, r| acc.saturating_add(r.len() as u64));
                    (
                        obj(vec![(
                            "records",
                            records
                                .iter()
                                .map(|r| KeyBytes::new(r.clone()).to_envelope())
                                .collect::<Vec<_>>()
                                .into(),
                        )]),
                        false,
                        bytes,
                    )
                }
            },
        },
    }
}

fn query_result_json(result: &crate::panel::ToolResult) -> serde_json::Value {
    obj(vec![
        ("handle", result.handle.to_canonical_text().into()),
        ("candidate_count", result.candidate_count.into()),
        (
            "completion",
            match result.completion {
                crate::query::ExecutionCompletion::Exhausted => {
                    obj(vec![("state", "exhausted".into())])
                }
                crate::query::ExecutionCompletion::LimitReached { limit } => obj(vec![
                    ("state", "limit-reached".into()),
                    ("limit", limit.into()),
                ]),
            },
        ),
        (
            "preview",
            result
                .preview
                .iter()
                .map(KeyBytes::to_envelope)
                .collect::<Vec<_>>()
                .into(),
        ),
        (
            "support",
            result
                .support
                .iter()
                .map(record_json)
                .collect::<Vec<_>>()
                .into(),
        ),
    ])
}

fn record_json(id: &RecordId) -> serde_json::Value {
    obj(vec![
        ("store", id.store_id().to_canonical_text().into()),
        ("section", id.section().as_str().into()),
        ("ordinal", id.ordinal().into()),
    ])
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

fn parse_lookup(input: &serde_json::Value) -> Result<(IndexName, KeyBytes)> {
    let index = input
        .get("index")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("qodec_lookup needs a string `index`"))?;
    let key = input
        .get("key")
        .ok_or_else(|| anyhow::anyhow!("qodec_lookup needs a `key` byte envelope"))?;
    Ok((IndexName::parse(index)?, KeyBytes::from_envelope(key)?))
}

fn parse_intersect(input: &serde_json::Value) -> Result<(IndexName, Vec<SetName>)> {
    let index = input
        .get("index")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("qodec_intersect needs a string `index`"))?;
    let sections = input
        .get("sections")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("qodec_intersect needs an array `sections`"))?;
    let mut parsed = Vec::new();
    for section in sections {
        let name = section
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("each section must be a string"))?;
        parsed.push(SetName::parse(name)?);
    }
    Ok((IndexName::parse(index)?, parsed))
}

fn parse_materialize(input: &serde_json::Value) -> Result<(QueryResultId, Vec<RecordId>)> {
    let handle = input
        .get("handle")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("qodec_materialize needs a string `handle`"))?;
    let ids = input
        .get("record_ids")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("qodec_materialize needs an array `record_ids`"))?;
    let mut parsed = Vec::new();
    for id in ids {
        parsed.push(RecordId::from_envelope(id)?);
    }
    Ok((QueryResultId::parse_canonical_text(handle)?, parsed))
}

fn parse_direct_answer(input: &serde_json::Value) -> Result<KeyBytes> {
    let answer = input
        .get("answer")
        .ok_or_else(|| anyhow::anyhow!("qodec_answer needs an `answer` byte envelope"))?;
    KeyBytes::from_envelope(answer).context("parsing the final answer")
}

fn parse_panel_answer(
    input: &serde_json::Value,
) -> Result<(QueryResultId, KeyBytes, Vec<RecordId>)> {
    let handle = input
        .get("handle")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("qodec_answer needs a string `handle`"))?;
    let answer = input
        .get("answer")
        .ok_or_else(|| anyhow::anyhow!("qodec_answer needs an `answer` byte envelope"))?;
    let cited = input
        .get("cited")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("qodec_answer needs an array `cited`"))?;
    let mut ids = Vec::new();
    for id in cited {
        ids.push(RecordId::from_envelope(id)?);
    }
    Ok((
        QueryResultId::parse_canonical_text(handle)?,
        KeyBytes::from_envelope(answer)?,
        ids,
    ))
}

// ---------------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------------

fn seal(
    spec: &CellSpec,
    instructions: &str,
    messages: &[Message],
    mapping: &RequestMapping,
) -> Result<SealedRequest> {
    SealedRequest::seal(RequestEnvelope {
        provider: spec.provider,
        model: spec.model.clone(),
        arm: spec.arm,
        fixture: spec.fixture.clone(),
        instructions: instructions.to_owned(),
        messages: messages.to_vec(),
        mapping: mapping.clone(),
        sampling: spec.sampling.clone(),
    })
}

/// Rebuild the assistant turn from what the model actually returned.
fn assistant_turn(response: &ResponseEnvelope) -> Message {
    let mut content = Vec::new();
    if !response.normalized.text.is_empty() {
        content.push(ContentBlock::Text {
            text: response.normalized.text.clone(),
        });
    }
    for call in &response.normalized.tool_calls {
        content.push(ContentBlock::ToolUse {
            id: call.id.clone(),
            name: call.name.clone(),
            input: call.input.clone(),
        });
    }
    Message {
        role: MessageRole::Assistant,
        content,
    }
}

fn charge(accounting: &mut CellAccounting, sealed: &SealedRequest, response: &ResponseEnvelope) {
    let l = &mut accounting.deterministic_local;
    l.request_bytes = l
        .request_bytes
        .saturating_add(sealed.wire_bytes().len() as u64);
    l.response_bytes = l
        .response_bytes
        .saturating_add(response.raw.body.len() as u64);
    l.model_visible_transcript_bytes = l
        .model_visible_transcript_bytes
        .saturating_add(sealed.envelope().model_visible_bytes());
    l.tool_call_count = l
        .tool_call_count
        .saturating_add(response.normalized.tool_calls.len() as u64);
}

fn finish(
    spec: &CellSpec,
    turns: Vec<TurnRecord>,
    accounting: CellAccounting,
    models_reported: Vec<Option<String>>,
    panel_transcript: Vec<PanelEvent>,
    outcome: ArmOutcome,
) -> CellRecord {
    // Folded here, from the turns, rather than accumulated as they arrive.
    // An accumulator seeded with `ProviderUsage::default()` starts every field
    // at `None`, and `None` is contagious by design, so the first addition
    // annihilates the total and every cell reports "the provider said
    // nothing" — which is exactly what a provider outage looks like. `reduce`
    // seeds from the first real turn instead, so contagion still means what it
    // is supposed to mean: one turn actually failed to report.
    let mut accounting = accounting;
    accounting.provider_reported = turns
        .iter()
        .map(|t| t.response.normalized.usage)
        .reduce(ProviderUsage::plus)
        .unwrap_or_default();
    CellRecord {
        arm: spec.arm,
        fixture: spec.fixture.clone(),
        model_requested: spec.model.clone(),
        models_reported,
        turns,
        outcome,
        accounting,
        panel_transcript,
    }
}
