//! Provider mapping and the exact request/response envelopes.
//!
//! This is the boundary where C1's first external probabilistic component
//! enters. Everything below it is deterministic; everything above it is a
//! measurement of something we do not control. The module's whole job is to
//! make the crossing *legible*: what left the process, byte for byte, and what
//! came back, byte for byte, with no step that reconstructs either from
//! configuration afterwards.
//!
//! Three rules shape it, each closing a way a measurement layer can look
//! rigorous while quietly measuring itself.
//!
//! * **The recorded request is the sent request.** [`SealedRequest`] owns the
//!   serialized bytes and the transport takes *that object*. There is no path
//!   that serializes twice, so there is no pair of almost-identical bodies of
//!   which only one was charged for. Rebuilding the envelope from config after
//!   the call would be a recollection, and a recollection agrees with the
//!   config by construction rather than with the wire.
//! * **Raw and normalized never substitute for each other.** A
//!   [`ResponseEnvelope`] carries the provider's exact bytes *and* the parsed
//!   view. Keeping only the parse discards the evidence for the parse; keeping
//!   only the bytes makes every later reader re-derive it, slightly
//!   differently.
//! * **The provider-neutral schema is the meaning; the provider envelope is
//!   the fact.** [`crate::panel::PanelToolSchema`] stays normative for what an
//!   operation *is*. The mapping records what a specific provider was actually
//!   told — including, explicitly, the fields it was *not* told, because a
//!   silently dropped field is how an undercount becomes invisible.
//!
//! ## What the wire drops, and why that is recorded
//!
//! Two things do not survive the crossing to a Messages-style API:
//!
//! * `output_schema` — the API accepts no such field on a tool definition. It
//!   remains a real contract used to check semantic equivalence, but the model
//!   is never charged for it. Recorded in [`MappedTool::dropped`].
//! * `seed` — not a parameter this provider has. Recorded in
//!   [`RequestMapping::unsupported_parameters`] rather than omitted, so a run
//!   claiming determinism cannot rest on a knob that was never turned.
//!
//! ## The fourth tool
//!
//! [`crate::panel::PanelTool`] has three variants and always will: those are
//! the operations that touch the store. On the wire there are **four** tool
//! definitions, because a schema-constrained terminal answer needs a channel,
//! and on a tool-calling API that channel is a tool. The distinction is worth
//! keeping rather than smoothing over — `qodec_answer` reads nothing, executes
//! nothing, and ends the loop. Calling it a panel tool would put the answer
//! inside the set of operations it is supposed to conclude.
//!
//! Because the answer is a tool in *every* arm, every arm also carries the same
//! [`ToolChoice`] — the model must act rather than reply in prose. That keeps
//! the arms differing in which tools exist and in nothing else; left to the
//! default, a direct arm would answer in prose and its score would become a
//! measurement of the matcher written to read it.

use anyhow::{bail, Context, Result};

use crate::canon::{
    digest_provider_request_bytes, ArtifactDigest, KeyBytes, ProviderRequestDigest,
};
use crate::panel::{PanelAnswerSchema, PanelToolSchema};

/// The name of the terminal answer channel on the wire.
pub const ANSWER_TOOL_NAME: &str = "qodec_answer";

// ---------------------------------------------------------------------------
// Run identity
// ---------------------------------------------------------------------------

/// Which of C1's three arms a request belongs to.
///
/// Part of the request's recorded identity rather than a label applied by the
/// aggregator later. An arm assigned after the fact is assigned by whoever is
/// writing the table, and tables have opinions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Arm {
    /// Task plus the full RAW payload.
    Raw,
    /// Task plus the full squeeze text.
    SqueezeDirect,
    /// Task plus metadata and typed operations. No RAW, no full squeeze.
    ForcedQuery,
}

impl Arm {
    pub fn label(self) -> &'static str {
        match self {
            Arm::Raw => "raw",
            Arm::SqueezeDirect => "squeeze-direct",
            Arm::ForcedQuery => "forced-query",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "raw" => Some(Arm::Raw),
            "squeeze-direct" => Some(Arm::SqueezeDirect),
            "forced-query" => Some(Arm::ForcedQuery),
            _ => None,
        }
    }

    /// The three arms in canonical order.
    pub fn all() -> [Arm; 3] {
        [Arm::Raw, Arm::SqueezeDirect, Arm::ForcedQuery]
    }
}

/// Which fixture a request was built from.
///
/// `source_digest` is the digest of the **original source bytes**, shared by
/// all three arms of a cell. That sharing is the point: the arms differ in how
/// the same bytes are presented, so an identity that varied per arm would make
/// the comparison unfalsifiable — three runs over three inputs, reported as one
/// row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureIdentity {
    pub name: String,
    pub source_digest: ArtifactDigest,
}

impl FixtureIdentity {
    /// Build from the fixture's own source text.
    pub fn of_source(name: &str, source: &str) -> Result<Self> {
        if name.is_empty() {
            bail!("fixture name must not be empty");
        }
        Ok(FixtureIdentity {
            name: name.to_owned(),
            source_digest: ArtifactDigest::of_artifact_bytes(source.as_bytes()),
        })
    }

    fn to_json(&self) -> serde_json::Value {
        json_obj(vec![
            ("name", self.name.clone().into()),
            (
                "source_digest",
                self.source_digest.to_canonical_text().into(),
            ),
        ])
    }
}

/// Which model was asked for.
///
/// Held as the *requested* identifier. What the provider says it actually ran
/// lives in the response envelope, and the two are compared rather than
/// assumed equal: an alias that silently resolves to a different snapshot
/// mid-experiment breaks cross-arm comparability while every row still looks
/// like it names one model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelIdentity(String);

impl ModelIdentity {
    pub fn parse(s: &str) -> Result<Self> {
        if s.is_empty() || s.chars().any(char::is_whitespace) {
            bail!("model identity must be non-empty and free of whitespace, got {s:?}");
        }
        Ok(ModelIdentity(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Sampling
// ---------------------------------------------------------------------------

/// Decoding parameters, as requested.
///
/// Non-finite floats are refused at construction. Not defensive habit: the
/// envelope is serialized to bytes that are then digested, and `NaN` has no
/// JSON form, so a value that cannot be written down would fail at seal time
/// with a message about serialization rather than about the parameter that was
/// wrong.
#[derive(Debug, Clone, PartialEq)]
pub struct SamplingParams {
    pub max_output_tokens: u64,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    /// Extended-thinking budget, where the provider has one. Modelled as an
    /// exact token budget rather than a free-form "effort" string, so the
    /// mapping is a fact rather than an interpretation.
    pub thinking_budget_tokens: Option<u64>,
    /// Recorded even where unsupported — see
    /// [`RequestMapping::unsupported_parameters`].
    pub seed: Option<u64>,
}

impl SamplingParams {
    /// Greedy-as-possible defaults for a comparison run.
    pub fn deterministic(max_output_tokens: u64) -> Result<Self> {
        SamplingParams {
            max_output_tokens,
            temperature: Some(0.0),
            top_p: None,
            thinking_budget_tokens: None,
            seed: None,
        }
        .validated()
    }

    pub fn validated(self) -> Result<Self> {
        if self.max_output_tokens == 0 {
            bail!("max_output_tokens must be at least 1");
        }
        for (name, value) in [("temperature", self.temperature), ("top_p", self.top_p)] {
            if let Some(v) = value {
                if !v.is_finite() {
                    bail!("{name} must be finite, got {v}");
                }
                if v < 0.0 {
                    bail!("{name} must not be negative, got {v}");
                }
            }
        }
        Ok(self)
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRole {
    User,
    Assistant,
}

impl MessageRole {
    fn label(self) -> &'static str {
        match self {
            MessageRole::User => "user",
            MessageRole::Assistant => "assistant",
        }
    }
}

/// One block of message content.
///
/// Tool results carry `content` as a JSON value rather than a pre-rendered
/// string for the same reason the panel transcript holds typed arguments: one
/// place decides how a value becomes text, so there is no earlier lossy step to
/// go looking for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentBlock {
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    ToolResult {
        tool_use_id: String,
        content: serde_json::Value,
        is_error: bool,
    },
}

impl ContentBlock {
    fn to_wire(&self) -> serde_json::Value {
        match self {
            ContentBlock::Text { text } => {
                json_obj(vec![("type", "text".into()), ("text", text.clone().into())])
            }
            ContentBlock::ToolUse { id, name, input } => json_obj(vec![
                ("type", "tool_use".into()),
                ("id", id.clone().into()),
                ("name", name.clone().into()),
                ("input", input.clone()),
            ]),
            ContentBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
            } => json_obj(vec![
                ("type", "tool_result".into()),
                ("tool_use_id", tool_use_id.clone().into()),
                ("content", serde_json::Value::String(content.to_string())),
                ("is_error", (*is_error).into()),
            ]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub role: MessageRole,
    pub content: Vec<ContentBlock>,
}

impl Message {
    pub fn user_text(text: impl Into<String>) -> Self {
        Message {
            role: MessageRole::User,
            content: vec![ContentBlock::Text { text: text.into() }],
        }
    }

    fn to_wire(&self) -> serde_json::Value {
        json_obj(vec![
            ("role", self.role.label().into()),
            (
                "content",
                self.content
                    .iter()
                    .map(ContentBlock::to_wire)
                    .collect::<Vec<_>>()
                    .into(),
            ),
        ])
    }
}

// ---------------------------------------------------------------------------
// Provider mapping
// ---------------------------------------------------------------------------

/// The providers this build knows how to talk to.
///
/// One variant on purpose. A multi-provider matrix is a later increment, and an
/// enum with speculative variants would advertise coverage the mapping tests do
/// not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// Anthropic Messages API, `POST /v1/messages`.
    AnthropicMessages,
}

impl ProviderKind {
    pub fn label(self) -> &'static str {
        match self {
            ProviderKind::AnthropicMessages => "anthropic.messages",
        }
    }

    /// The path a request is sent to, relative to the base URL.
    pub fn path(self) -> &'static str {
        match self {
            ProviderKind::AnthropicMessages => "/v1/messages",
        }
    }
}

/// A tool definition exactly as it goes on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

impl ProviderToolDefinition {
    fn to_wire(&self) -> serde_json::Value {
        json_obj(vec![
            ("name", self.name.clone().into()),
            ("description", self.description.clone().into()),
            ("input_schema", self.input_schema.clone()),
        ])
    }
}

/// One neutral schema, translated — together with what translation cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedTool {
    pub definition: ProviderToolDefinition,
    /// Neutral fields with no wire representation for this provider.
    ///
    /// Present so the difference between "the model was told this" and "we
    /// believe this" stays visible in the record. Charging the model for a
    /// field the API has no slot for would overcount; dropping it silently
    /// would leave the reader to assume it was sent.
    pub dropped: Vec<&'static str>,
}

/// Translate a provider-neutral tool schema.
///
/// Deterministic and total: the same neutral schema always yields the same
/// definition, which is what makes the golden meaningful.
pub fn map_tool(schema: &PanelToolSchema, provider: ProviderKind) -> MappedTool {
    match provider {
        ProviderKind::AnthropicMessages => MappedTool {
            definition: ProviderToolDefinition {
                name: schema.name.name().to_owned(),
                description: schema.description.to_owned(),
                input_schema: schema.input_schema.clone(),
            },
            dropped: vec!["output_schema"],
        },
    }
}

/// Whether the model may reply without acting.
///
/// One variant, and it is used by every arm that has tools at all — which is
/// every arm. **Every arm must act through a tool; the arms differ only in
/// which tools exist.** A direct arm whose sole tool is the answer channel and
/// a forced-query arm with four tools therefore carry the *same* wire value
/// here, so nothing about the answer channel varies between them.
///
/// Left to the default, a direct arm would usually reply in prose and grading
/// would become a measurement of whatever matcher we wrote to read it — the
/// exact failure the byte-exact answer schema exists to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolChoice {
    /// The model must call one of the offered tools.
    Any,
}

impl ToolChoice {
    fn to_wire(self) -> serde_json::Value {
        match self {
            ToolChoice::Any => json_obj(vec![("type", "any".into())]),
        }
    }

    fn label(self) -> &'static str {
        match self {
            ToolChoice::Any => "any",
        }
    }
}

/// How the terminal answer is constrained on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderResponseFormat {
    /// The answer arrives as a call to a distinguished tool, schema-constrained
    /// by that tool's input schema.
    TerminalTool(ProviderToolDefinition),
}

impl ProviderResponseFormat {
    /// The wire tool definition this format contributes, if any.
    pub fn tool_definition(&self) -> &ProviderToolDefinition {
        match self {
            ProviderResponseFormat::TerminalTool(def) => def,
        }
    }
}

/// Translate the answer schema into a provider response format.
pub fn map_answer(schema: &PanelAnswerSchema, provider: ProviderKind) -> ProviderResponseFormat {
    match provider {
        ProviderKind::AnthropicMessages => {
            ProviderResponseFormat::TerminalTool(ProviderToolDefinition {
                name: ANSWER_TOOL_NAME.to_owned(),
                description: schema.description.to_owned(),
                input_schema: schema.schema.clone(),
            })
        }
    }
}

/// The full translation of one panel surface, with every loss recorded.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestMapping {
    pub provider: ProviderKind,
    pub tools: Vec<MappedTool>,
    pub response_format: Option<ProviderResponseFormat>,
    /// Whether the model may reply without calling a tool. Identical in every
    /// arm — see [`ToolChoice`].
    pub tool_choice: Option<ToolChoice>,
    /// Sampling knobs this provider has no wire slot for.
    ///
    /// A run that claims reproducibility while requesting a `seed` the API
    /// never received is claiming a property it does not have. Naming the gap
    /// is cheaper than discovering it in the variance.
    pub unsupported_parameters: Vec<&'static str>,
}

impl RequestMapping {
    /// Map the panel surface — three operations plus the terminal answer.
    pub fn for_panel(
        provider: ProviderKind,
        tool_schemas: &[PanelToolSchema],
        answer_schema: &PanelAnswerSchema,
        sampling: &SamplingParams,
    ) -> Self {
        RequestMapping {
            provider,
            tools: tool_schemas.iter().map(|s| map_tool(s, provider)).collect(),
            response_format: Some(map_answer(answer_schema, provider)),
            tool_choice: Some(ToolChoice::Any),
            unsupported_parameters: unsupported_for(provider, sampling),
        }
    }

    /// Map a direct arm: no operations, only the terminal answer channel.
    ///
    /// The answer channel is present in every arm on purpose. The arms are
    /// meant to differ in how the model reaches the data and in nothing else,
    /// so giving two of them a structured answer and the third a prose one
    /// would put the grader's leniency into the comparison.
    pub fn direct(
        provider: ProviderKind,
        answer_schema: &PanelAnswerSchema,
        sampling: &SamplingParams,
    ) -> Self {
        RequestMapping {
            provider,
            tools: Vec::new(),
            response_format: Some(map_answer(answer_schema, provider)),
            tool_choice: Some(ToolChoice::Any),
            unsupported_parameters: unsupported_for(provider, sampling),
        }
    }

    /// Every tool definition that goes on the wire, in canonical order.
    ///
    /// The panel operations first, the terminal answer channel last. Four
    /// entries for a three-variant [`crate::panel::PanelTool`] — see the module
    /// documentation.
    pub fn wire_tools(&self) -> Vec<ProviderToolDefinition> {
        let mut out: Vec<ProviderToolDefinition> =
            self.tools.iter().map(|t| t.definition.clone()).collect();
        if let Some(format) = &self.response_format {
            out.push(format.tool_definition().clone());
        }
        out
    }

    fn to_json(&self) -> serde_json::Value {
        json_obj(vec![
            ("provider", self.provider.label().into()),
            (
                "tools",
                self.tools
                    .iter()
                    .map(|t| {
                        json_obj(vec![
                            ("name", t.definition.name.clone().into()),
                            (
                                "dropped",
                                t.dropped
                                    .iter()
                                    .map(|d| serde_json::Value::from(*d))
                                    .collect::<Vec<_>>()
                                    .into(),
                            ),
                        ])
                    })
                    .collect::<Vec<_>>()
                    .into(),
            ),
            (
                "response_format",
                match &self.response_format {
                    None => serde_json::Value::Null,
                    Some(ProviderResponseFormat::TerminalTool(def)) => json_obj(vec![
                        ("kind", "terminal-tool".into()),
                        ("name", def.name.clone().into()),
                    ]),
                },
            ),
            (
                "tool_choice",
                match self.tool_choice {
                    Some(c) => c.label().into(),
                    None => serde_json::Value::Null,
                },
            ),
            (
                "unsupported_parameters",
                self.unsupported_parameters
                    .iter()
                    .map(|p| serde_json::Value::from(*p))
                    .collect::<Vec<_>>()
                    .into(),
            ),
        ])
    }
}

fn unsupported_for(provider: ProviderKind, sampling: &SamplingParams) -> Vec<&'static str> {
    match provider {
        // The Messages API has no seed parameter. Requesting one is not an
        // error worth refusing — it is a fact worth recording.
        ProviderKind::AnthropicMessages => {
            if sampling.seed.is_some() {
                vec!["seed"]
            } else {
                Vec::new()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The request envelope
// ---------------------------------------------------------------------------

/// Everything about one request, recorded before it is sent.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestEnvelope {
    pub provider: ProviderKind,
    pub model: ModelIdentity,
    pub arm: Arm,
    pub fixture: FixtureIdentity,
    pub instructions: String,
    pub messages: Vec<Message>,
    pub mapping: RequestMapping,
    pub sampling: SamplingParams,
}

impl RequestEnvelope {
    /// The exact JSON body, as the provider will receive it.
    ///
    /// Arm and fixture are deliberately absent: they identify the *experiment*,
    /// not the request, and inventing wire fields for them would change what
    /// the model is charged for in order to make bookkeeping convenient.
    pub fn to_wire_json(&self) -> serde_json::Value {
        let mut pairs: Vec<(&str, serde_json::Value)> = vec![
            ("model", self.model.as_str().into()),
            ("max_tokens", self.sampling.max_output_tokens.into()),
        ];
        if !self.instructions.is_empty() {
            pairs.push(("system", self.instructions.clone().into()));
        }
        pairs.push((
            "messages",
            self.messages
                .iter()
                .map(Message::to_wire)
                .collect::<Vec<_>>()
                .into(),
        ));
        let tools = self.mapping.wire_tools();
        if !tools.is_empty() {
            pairs.push((
                "tools",
                tools
                    .iter()
                    .map(ProviderToolDefinition::to_wire)
                    .collect::<Vec<_>>()
                    .into(),
            ));
            if let Some(choice) = self.mapping.tool_choice {
                pairs.push(("tool_choice", choice.to_wire()));
            }
        }
        if let Some(t) = self.sampling.temperature {
            pairs.push(("temperature", serde_json::Value::from(t)));
        }
        if let Some(p) = self.sampling.top_p {
            pairs.push(("top_p", serde_json::Value::from(p)));
        }
        if let Some(budget) = self.sampling.thinking_budget_tokens {
            pairs.push((
                "thinking",
                json_obj(vec![
                    ("type", "enabled".into()),
                    ("budget_tokens", budget.into()),
                ]),
            ));
        }
        json_obj(pairs)
    }

    /// The recorded form: the experiment's identity plus the wire body.
    pub fn to_json(&self) -> serde_json::Value {
        json_obj(vec![
            ("provider", self.provider.label().into()),
            ("path", self.provider.path().into()),
            ("arm", self.arm.label().into()),
            ("fixture", self.fixture.to_json()),
            ("model_requested", self.model.as_str().into()),
            ("mapping", self.mapping.to_json()),
            ("wire", self.to_wire_json()),
        ])
    }

    /// Bytes of the model-visible portion of the body.
    ///
    /// Exactly `system`, `messages` and `tools` as serialized in *this* body.
    /// Stated as a definition rather than an estimate: it is a byte count of
    /// named fields, not a guess at what a tokenizer will do with them, and the
    /// two must never be confused for one another.
    pub fn model_visible_bytes(&self) -> u64 {
        let wire = self.to_wire_json();
        let mut total = 0u64;
        for field in ["system", "messages", "tools"] {
            if let Some(value) = wire.get(field) {
                total = total.saturating_add(value.to_string().len() as u64);
            }
        }
        total
    }
}

/// A request whose bytes are fixed.
///
/// The only object a transport accepts. Serialization happens exactly once, at
/// [`SealedRequest::seal`], so the digest, the recorded body and the sent body
/// are three names for one buffer rather than three chances to differ.
#[derive(Debug, Clone, PartialEq)]
pub struct SealedRequest {
    envelope: RequestEnvelope,
    wire_bytes: Vec<u8>,
    digest: ProviderRequestDigest,
}

impl SealedRequest {
    pub fn seal(envelope: RequestEnvelope) -> Result<Self> {
        let wire_bytes = serde_json::to_vec(&envelope.to_wire_json())
            .context("serializing the provider request body")?;
        let digest = digest_provider_request_bytes(&wire_bytes);
        Ok(SealedRequest {
            envelope,
            wire_bytes,
            digest,
        })
    }

    /// The bytes that go on the wire — and the bytes that were recorded.
    pub fn wire_bytes(&self) -> &[u8] {
        &self.wire_bytes
    }

    pub fn envelope(&self) -> &RequestEnvelope {
        &self.envelope
    }

    pub fn digest(&self) -> ProviderRequestDigest {
        self.digest
    }

    /// The recorded form, including the exact bytes and their identity.
    pub fn to_json(&self) -> serde_json::Value {
        json_obj(vec![
            ("envelope", self.envelope.to_json()),
            ("wire_digest", self.digest.to_canonical_text().into()),
            ("wire_bytes_len", (self.wire_bytes.len() as u64).into()),
            (
                "wire_body",
                KeyBytes::new(self.wire_bytes.clone()).to_envelope(),
            ),
        ])
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// A provider response exactly as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// The provider's own correlation id, where it sends one.
    pub request_id: Option<String>,
}

impl RawResponse {
    fn to_json(&self) -> serde_json::Value {
        json_obj(vec![
            ("status", self.status.into()),
            ("body_len", (self.body.len() as u64).into()),
            (
                "request_id",
                match &self.request_id {
                    Some(id) => id.clone().into(),
                    None => serde_json::Value::Null,
                },
            ),
            ("body", KeyBytes::new(self.body.clone()).to_envelope()),
        ])
    }
}

/// Anything that can carry a sealed request to a model and bring bytes back.
///
/// Takes `&SealedRequest` rather than a body, a URL, or a struct to serialize.
/// A transport that built its own body could send something the record does not
/// describe, and the record would still look complete.
pub trait ModelTransport {
    fn send(&mut self, sealed: &SealedRequest) -> Result<RawResponse>;
}

/// What happened on one attempt to deliver one sealed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportAttempt {
    pub ordinal: u32,
    /// The identity of the body this attempt carried.
    ///
    /// Every attempt in a retry sequence must show the same value. That
    /// equality is what distinguishes a transport retry — the same question
    /// asked again after a socket died — from a semantic retry, which is a
    /// different question wearing the first one's clothes.
    pub request_digest: ProviderRequestDigest,
    pub outcome: AttemptOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptOutcome {
    Response { status: u16, body_len: u64 },
    TransportError { reason: String },
}

impl TransportAttempt {
    fn to_json(&self) -> serde_json::Value {
        let mut pairs = vec![
            ("ordinal", self.ordinal.into()),
            (
                "request_digest",
                self.request_digest.to_canonical_text().into(),
            ),
        ];
        match &self.outcome {
            AttemptOutcome::Response { status, body_len } => {
                pairs.push(("outcome", "response".into()));
                pairs.push(("status", (*status).into()));
                pairs.push(("body_len", (*body_len).into()));
            }
            AttemptOutcome::TransportError { reason } => {
                pairs.push(("outcome", "transport-error".into()));
                pairs.push(("reason", reason.clone().into()));
            }
        }
        json_obj(pairs)
    }
}

/// Deliver one sealed request, retrying transport failures only.
///
/// Takes a single `&SealedRequest` and never constructs another, so "retry the
/// same request" is a property of the signature rather than a promise in a
/// comment. A caller that wants to ask a *different* question must seal a new
/// request, which produces a new digest and a visibly new attempt sequence.
pub fn deliver(
    transport: &mut dyn ModelTransport,
    sealed: &SealedRequest,
    max_attempts: u32,
) -> Result<(RawResponse, Vec<TransportAttempt>)> {
    if max_attempts == 0 {
        bail!("max_attempts must be at least 1");
    }
    let mut attempts = Vec::new();
    let mut last_error: Option<anyhow::Error> = None;
    for ordinal in 0..max_attempts {
        match transport.send(sealed) {
            Ok(raw) => {
                attempts.push(TransportAttempt {
                    ordinal,
                    request_digest: sealed.digest(),
                    outcome: AttemptOutcome::Response {
                        status: raw.status,
                        body_len: raw.body.len() as u64,
                    },
                });
                return Ok((raw, attempts));
            }
            Err(e) => {
                attempts.push(TransportAttempt {
                    ordinal,
                    request_digest: sealed.digest(),
                    outcome: AttemptOutcome::TransportError {
                        reason: format!("{e}"),
                    },
                });
                last_error = Some(e);
            }
        }
    }
    let attempted = attempts.len();
    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("transport made no attempt"))
        .context(format!("all {attempted} transport attempts failed")))
}

// ---------------------------------------------------------------------------
// The response envelope
// ---------------------------------------------------------------------------

/// Token counters as the provider reported them.
///
/// Every field optional, because a provider that omits one has told us
/// something — and a zero would say the opposite.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProviderUsage {
    pub input_tokens: Option<u64>,
    pub cached_input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
}

impl ProviderUsage {
    /// The canonical JSON form. `null` where the provider said nothing.
    pub fn to_json(&self) -> serde_json::Value {
        json_obj(vec![
            ("input_tokens", opt_u64(self.input_tokens)),
            ("cached_input_tokens", opt_u64(self.cached_input_tokens)),
            ("output_tokens", opt_u64(self.output_tokens)),
            ("reasoning_tokens", opt_u64(self.reasoning_tokens)),
        ])
    }

    /// Add another turn's counters. `None` is contagious: a total that silently
    /// treats a missing counter as zero is a total that understates itself
    /// without ever saying so.
    pub fn plus(self, other: ProviderUsage) -> ProviderUsage {
        fn add(a: Option<u64>, b: Option<u64>) -> Option<u64> {
            match (a, b) {
                (Some(x), Some(y)) => Some(x.saturating_add(y)),
                _ => None,
            }
        }
        ProviderUsage {
            input_tokens: add(self.input_tokens, other.input_tokens),
            cached_input_tokens: add(self.cached_input_tokens, other.cached_input_tokens),
            output_tokens: add(self.output_tokens, other.output_tokens),
            reasoning_tokens: add(self.reasoning_tokens, other.reasoning_tokens),
        }
    }
}

/// One tool call, normalized out of the provider's shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedToolCall {
    pub id: String,
    pub name: String,
    pub input: serde_json::Value,
}

/// The parsed view of a response.
///
/// A *view*. It never replaces [`ResponseEnvelope::raw`], which stays beside it
/// for exactly the cases where the parse turns out to have been wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedResponse {
    pub response_id: Option<String>,
    pub reported_model: Option<String>,
    pub stop_reason: Option<String>,
    pub text: String,
    pub tool_calls: Vec<NormalizedToolCall>,
    pub usage: ProviderUsage,
}

impl NormalizedResponse {
    fn to_json(&self) -> serde_json::Value {
        json_obj(vec![
            ("response_id", opt_str(self.response_id.as_deref())),
            ("reported_model", opt_str(self.reported_model.as_deref())),
            ("stop_reason", opt_str(self.stop_reason.as_deref())),
            ("text", self.text.clone().into()),
            (
                "tool_calls",
                self.tool_calls
                    .iter()
                    .map(|c| {
                        json_obj(vec![
                            ("id", c.id.clone().into()),
                            ("name", c.name.clone().into()),
                            ("input", c.input.clone()),
                        ])
                    })
                    .collect::<Vec<_>>()
                    .into(),
            ),
            ("usage", self.usage.to_json()),
        ])
    }
}

/// Parse a provider response into the normalized view.
pub fn normalize(provider: ProviderKind, raw: &RawResponse) -> Result<NormalizedResponse> {
    match provider {
        ProviderKind::AnthropicMessages => normalize_anthropic(raw),
    }
}

fn normalize_anthropic(raw: &RawResponse) -> Result<NormalizedResponse> {
    let body: serde_json::Value =
        serde_json::from_slice(&raw.body).context("provider response body is not valid JSON")?;
    if raw.status < 200 || raw.status >= 300 {
        let message = body
            .pointer("/error/message")
            .and_then(|v| v.as_str())
            .unwrap_or("no error message");
        bail!("provider returned HTTP {}: {message}", raw.status);
    }
    let mut text = String::new();
    let mut tool_calls = Vec::new();
    if let Some(blocks) = body.get("content").and_then(serde_json::Value::as_array) {
        for block in blocks {
            match block.get("type").and_then(|v| v.as_str()) {
                Some("text") => {
                    if let Some(t) = block.get("text").and_then(|v| v.as_str()) {
                        text.push_str(t);
                    }
                }
                Some("tool_use") => {
                    let id = block
                        .get("id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("tool_use block without an id"))?;
                    let name = block
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("tool_use block without a name"))?;
                    tool_calls.push(NormalizedToolCall {
                        id: id.to_owned(),
                        name: name.to_owned(),
                        input: block
                            .get("input")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                    });
                }
                // Thinking and other block kinds carry no operation and no
                // answer. Skipped from the normalized view, never from `raw`.
                _ => {}
            }
        }
    }
    let usage = ProviderUsage {
        input_tokens: body.pointer("/usage/input_tokens").and_then(as_u64),
        cached_input_tokens: body
            .pointer("/usage/cache_read_input_tokens")
            .and_then(as_u64),
        output_tokens: body.pointer("/usage/output_tokens").and_then(as_u64),
        reasoning_tokens: body.pointer("/usage/reasoning_tokens").and_then(as_u64),
    };
    Ok(NormalizedResponse {
        response_id: body.get("id").and_then(|v| v.as_str()).map(str::to_owned),
        reported_model: body
            .get("model")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        stop_reason: body
            .get("stop_reason")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        text,
        tool_calls,
        usage,
    })
}

/// The complete record of one round trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseEnvelope {
    pub raw: RawResponse,
    pub normalized: NormalizedResponse,
    pub attempts: Vec<TransportAttempt>,
}

impl ResponseEnvelope {
    pub fn to_json(&self) -> serde_json::Value {
        json_obj(vec![
            ("raw", self.raw.to_json()),
            ("normalized", self.normalized.to_json()),
            (
                "attempts",
                self.attempts
                    .iter()
                    .map(TransportAttempt::to_json)
                    .collect::<Vec<_>>()
                    .into(),
            ),
        ])
    }
}

/// Send a sealed request and record both halves of the crossing.
pub fn exchange(
    transport: &mut dyn ModelTransport,
    sealed: &SealedRequest,
    max_attempts: u32,
) -> Result<ResponseEnvelope> {
    let (raw, attempts) = deliver(transport, sealed, max_attempts)?;
    let normalized = normalize(sealed.envelope().provider, &raw)?;
    Ok(ResponseEnvelope {
        raw,
        normalized,
        attempts,
    })
}

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------

/// A deterministic transport that never touches a network.
///
/// Eval-only, and the reason the whole path — mapping, sealing, delivery,
/// normalization, the tool loop, accounting — can be exercised in CI without a
/// model. It replies from a script and records what it was asked, so a test can
/// assert that the bytes the transport saw are the bytes the record claims.
#[derive(Debug, Default)]
pub struct ScriptedTransport {
    replies: Vec<Result<RawResponse, String>>,
    seen: Vec<Vec<u8>>,
    next: usize,
}

impl ScriptedTransport {
    pub fn new(replies: Vec<Result<RawResponse, String>>) -> Self {
        ScriptedTransport {
            replies,
            seen: Vec::new(),
            next: 0,
        }
    }

    /// The exact bodies this transport was handed, in order.
    pub fn seen_bodies(&self) -> &[Vec<u8>] {
        &self.seen
    }
}

impl ModelTransport for ScriptedTransport {
    fn send(&mut self, sealed: &SealedRequest) -> Result<RawResponse> {
        self.seen.push(sealed.wire_bytes().to_vec());
        let Some(reply) = self.replies.get(self.next) else {
            bail!(
                "scripted transport ran out of replies at call {}",
                self.next
            );
        };
        self.next = self.next.saturating_add(1);
        match reply {
            Ok(raw) => Ok(raw.clone()),
            Err(reason) => bail!("scripted transport error: {reason}"),
        }
    }
}

/// A deterministic stand-in that computes its reply from the request.
///
/// Eval-only, and a *stand-in*, not a model: it is a pure function of the
/// conversation so far. A fixed reply script cannot express the one thing the
/// forced-query loop requires — an answer citing a result handle that did not
/// exist when the script was written — so exercising that loop without a model
/// needs a reply that can read what the previous turn returned.
///
/// Nothing it produces is evidence about a model. It exists so the plumbing
/// around the model can be tested when there is no model, which is a different
/// claim and must stay one.
pub struct ProgrammedTransport<F> {
    reply: F,
    seen: Vec<Vec<u8>>,
    calls: usize,
}

impl<F> std::fmt::Debug for ProgrammedTransport<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgrammedTransport")
            .field("calls", &self.calls)
            .finish_non_exhaustive()
    }
}

impl<F> ProgrammedTransport<F>
where
    F: FnMut(&SealedRequest, usize) -> Result<RawResponse>,
{
    pub fn new(reply: F) -> Self {
        ProgrammedTransport {
            reply,
            seen: Vec::new(),
            calls: 0,
        }
    }

    /// The exact bodies this transport was handed, in order.
    pub fn seen_bodies(&self) -> &[Vec<u8>] {
        &self.seen
    }
}

impl<F> ModelTransport for ProgrammedTransport<F>
where
    F: FnMut(&SealedRequest, usize) -> Result<RawResponse>,
{
    fn send(&mut self, sealed: &SealedRequest) -> Result<RawResponse> {
        self.seen.push(sealed.wire_bytes().to_vec());
        let n = self.calls;
        self.calls = self.calls.saturating_add(1);
        (self.reply)(sealed, n)
    }
}

/// A live HTTP transport.
///
/// Never exercised by the test suite or by CI: every automated path uses
/// [`ScriptedTransport`]. This exists so the smoke can be run deliberately,
/// by a person, against a real endpoint — and so that when it is, the bytes
/// sent are the sealed bytes and nothing assembles a second body along the way.
#[derive(Debug)]
pub struct HttpTransport {
    base_url: String,
    api_key: String,
    api_version: String,
    timeout_secs: u64,
}

impl HttpTransport {
    /// Build from an explicit endpoint and key.
    ///
    /// No default base URL and no ambient key lookup: a transport that finds
    /// its own credentials can be constructed by accident, and the one thing
    /// this type must never do is send something nobody asked it to send.
    pub fn new(
        base_url: &str,
        api_key: &str,
        api_version: &str,
        timeout_secs: u64,
    ) -> Result<Self> {
        if base_url.is_empty() || api_key.is_empty() {
            bail!("live transport needs both a base URL and an API key");
        }
        Ok(HttpTransport {
            base_url: base_url.trim_end_matches('/').to_owned(),
            api_key: api_key.to_owned(),
            api_version: api_version.to_owned(),
            timeout_secs,
        })
    }
}

impl ModelTransport for HttpTransport {
    fn send(&mut self, sealed: &SealedRequest) -> Result<RawResponse> {
        let url = format!("{}{}", self.base_url, sealed.envelope().provider.path());
        let response = ureq::post(&url)
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .set("content-type", "application/json")
            .set("x-api-key", &self.api_key)
            .set("anthropic-version", &self.api_version)
            // The sealed buffer, unmodified. Not a re-serialization of the
            // envelope, which is the whole reason this type takes a
            // `SealedRequest` instead of a body.
            .send_bytes(sealed.wire_bytes());
        let (status, request_id, reader) = match response {
            Ok(r) => (
                r.status(),
                r.header("request-id").map(str::to_owned),
                r.into_reader(),
            ),
            Err(ureq::Error::Status(status, r)) => (
                status,
                r.header("request-id").map(str::to_owned),
                r.into_reader(),
            ),
            Err(e) => return Err(anyhow::anyhow!("transport failure: {e}")),
        };
        let mut body = Vec::new();
        let mut reader = reader;
        std::io::Read::read_to_end(&mut reader, &mut body)
            .context("reading the provider response body")?;
        Ok(RawResponse {
            status,
            body,
            request_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Small JSON helpers
// ---------------------------------------------------------------------------

fn json_obj(pairs: Vec<(&str, serde_json::Value)>) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for (k, v) in pairs {
        m.insert(k.to_owned(), v);
    }
    serde_json::Value::Object(m)
}

fn opt_u64(v: Option<u64>) -> serde_json::Value {
    match v {
        Some(n) => n.into(),
        None => serde_json::Value::Null,
    }
}

fn opt_str(v: Option<&str>) -> serde_json::Value {
    match v {
        Some(s) => s.into(),
        None => serde_json::Value::Null,
    }
}

fn as_u64(v: &serde_json::Value) -> Option<u64> {
    v.as_u64()
}
