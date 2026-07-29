//! Forced-query panel adapter — Slice B.
//!
//! The C1 experiment has three arms, and this module is the third one's whole
//! substance. RAW and squeeze-direct hand the model an artifact body and ask a
//! question. This arm hands it *metadata* and a set of typed operations, and
//! the only path to the data runs through deterministic execution.
//!
//! **The forcing is structural, not promised.** A [`PanelSession`] takes the
//! artifact text at construction and never gives it back: there is no accessor
//! that returns the payload, the decoded RAW, or the squeeze text. That is the
//! point. An arm that merely *asks* the model to prefer the tool measures the
//! model's willingness to comply, and then attaches a `QueryResultId` as a
//! decorative countersignature — an audit where the signature exists
//! independently of the act it certifies.
//!
//! Three boundaries do the work:
//!
//! * **No artifact body reaches the model.** [`PanelMetadata`] carries shapes
//!   and counts, never record bytes. Pinned by a test that asserts no record's
//!   bytes appear anywhere in the serialized metadata.
//! * **Materialization is scoped to a handle's own support.** The signature is
//!   `materialize(handle, ids)`, not `materialize(artifact, ids)`. A record id
//!   outside the support graph of *that result* is refused, so the store cannot
//!   be enumerated one plausible guess at a time. Without this the query
//!   interface degrades into an unusually inconvenient file browser.
//! * **Preview never decides anything.** The model may well answer from the
//!   preview — that is legitimate, because the preview *is* the official
//!   output of a deterministic query rather than a private reading of the
//!   artifact. But `candidate_count`, ambiguity, completeness and the verdict
//!   all come from the stored complete result. A preview showing one candidate
//!   over a result holding two verifies as [`VerifyOutcome::Ambiguous`].
//!
//! Failure is not a fallback. Inside a normative C1 cell, a query path that
//! ends in any non-`Valid` outcome yields [`CellOutcome::QueryPathFailed`] and
//! the cell is scored as such. Silently retrying the same cell against RAW
//! would let the third arm reach RAW-like correctness by the innovative method
//! of returning RAW.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Result};

use crate::canon::{
    ArtifactDigest, CanonicalQuery, FieldName, IndexName, KeyBytes, QueryResultId, SchemaId,
    SetName, StoreId,
};
use crate::query::{ExecutionCompletion, ExecutionLimits, HarnessResultRegistry, VerifyOutcome};
use crate::store::{CanonicalStore, KeyExtractor, RecordId, StorePlan};

/// What the model is told about an artifact it will never see.
///
/// Shapes and counts, so a question can be turned into an operation. No record
/// bytes: the point of the arm is that the payload does not enter attention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanelMetadata {
    pub artifact_digest: ArtifactDigest,
    pub store_id: StoreId,
    pub schema: SchemaId,
    pub decode_layers: u32,
    /// Section name to how many records it holds.
    pub sections: BTreeMap<String, u64>,
    pub record_count: u64,
    /// Index name to the shape of key it carries, as a short tag.
    pub indexes: BTreeMap<String, String>,
    pub max_candidates: u64,
    pub max_support_records: u64,
    pub max_preview_items: u64,
}

impl PanelMetadata {
    /// The canonical JSON form.
    pub fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "artifact_digest".into(),
            self.artifact_digest.to_canonical_text().into(),
        );
        obj.insert("store_id".into(), self.store_id.to_canonical_text().into());
        obj.insert("schema".into(), self.schema.as_str().into());
        obj.insert("decode_layers".into(), self.decode_layers.into());
        obj.insert("record_count".into(), self.record_count.into());
        obj.insert(
            "sections".into(),
            serde_json::Value::Object(
                self.sections
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::from(*v)))
                    .collect(),
            ),
        );
        obj.insert(
            "indexes".into(),
            serde_json::Value::Object(
                self.indexes
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::from(v.clone())))
                    .collect(),
            ),
        );
        obj.insert("max_candidates".into(), self.max_candidates.into());
        obj.insert(
            "max_support_records".into(),
            self.max_support_records.into(),
        );
        obj.insert("max_preview_items".into(), self.max_preview_items.into());
        serde_json::Value::Object(obj)
    }

    /// A stable, human-readable rendering for the prompt.
    ///
    /// Deliberately built from the typed fields rather than from anything that
    /// has touched a record, so "does the payload leak into the prompt" is a
    /// question about this function alone.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "artifact: {}\n",
            self.artifact_digest.to_canonical_text()
        ));
        out.push_str(&format!("store: {}\n", self.store_id.to_canonical_text()));
        out.push_str(&format!("schema: {}\n", self.schema.as_str()));
        out.push_str(&format!("decode_layers: {}\n", self.decode_layers));
        out.push_str(&format!("records: {}\n", self.record_count));
        out.push_str("sections:\n");
        for (name, count) in &self.sections {
            out.push_str(&format!("  {name}: {count}\n"));
        }
        out.push_str("indexes:\n");
        for (name, kind) in &self.indexes {
            out.push_str(&format!("  {name}: {kind}\n"));
        }
        out.push_str(&format!(
            "limits: max_candidates={} max_support_records={} max_preview_items={}\n",
            self.max_candidates, self.max_support_records, self.max_preview_items
        ));
        out
    }
}

/// What a query tool returns to the model.
///
/// The preview is bounded and advisory; `candidate_count` and `completion`
/// describe the *stored complete result*, so the two can disagree and the
/// disagreement is the honest signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    pub handle: QueryResultId,
    pub candidate_count: u64,
    pub completion: ExecutionCompletion,
    pub preview: Vec<KeyBytes>,
    /// Record ids backing this result — the only ids `materialize` will accept
    /// against this handle.
    pub support: Vec<RecordId>,
}

// ---------------------------------------------------------------------------
// The model-visible surface
// ---------------------------------------------------------------------------

/// A provider-neutral tool definition.
///
/// **`output_schema` is a contract, not necessarily a cost.** Not every provider
/// actually sends an output schema to the model, so the next increment must
/// count tokens against two separate objects: this provider-neutral contract,
/// used to check semantic equivalence, and the *actual* request envelope, whose
/// bytes are what the model was charged for. Declaring the whole
/// `PanelToolSchema` model-visible would replace an undercount with an
/// overcount, and the table would still be wrong — just from the other side.
///
/// One object serves five roles at once: what the adapter hands the model, what
/// the opening transcript event records, what token accounting charges for,
/// what a future provider mapper translates, and what the dry-run gate checks.
/// Generating the schema twice — once for the transcript and once for the API
/// request — would measure an internal schema while the provider received an
/// independently assembled *almost* identical one, and "almost" has a poor
/// record against evidential contracts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanelToolSchema {
    /// The runtime tool this describes. Typed rather than a loose string so a
    /// schema cannot name a tool that does not exist, nor drift from the one it
    /// claims to document.
    pub name: PanelTool,
    pub description: &'static str,
    pub input_schema: serde_json::Value,
    pub output_schema: serde_json::Value,
}

impl PanelToolSchema {
    /// The canonical JSON form, as recorded and as sent.
    pub fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert("name".into(), self.name.name().into());
        obj.insert("description".into(), self.description.into());
        obj.insert("input_schema".into(), self.input_schema.clone());
        obj.insert("output_schema".into(), self.output_schema.clone());
        serde_json::Value::Object(obj)
    }
}

/// The shape the final answer must take.
///
/// Separate from the tools on purpose: the answer is the model's terminal
/// output and its own `FinalAnswer` event, not an operation it may call. It
/// still needs a pinned schema, or the tools end up precisely measured while
/// the answer format stays "the model will work it out" — a perennial of
/// interface engineering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanelAnswerSchema {
    pub description: &'static str,
    pub schema: serde_json::Value,
}

impl PanelAnswerSchema {
    pub fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert("description".into(), self.description.into());
        obj.insert("schema".into(), self.schema.clone());
        serde_json::Value::Object(obj)
    }
}

fn obj(pairs: Vec<(&str, serde_json::Value)>) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for (k, v) in pairs {
        m.insert(k.to_owned(), v);
    }
    serde_json::Value::Object(m)
}

fn strings(items: &[&str]) -> serde_json::Value {
    serde_json::Value::Array(items.iter().map(|s| serde_json::Value::from(*s)).collect())
}

/// The one byte-value shape, defined once and referenced everywhere.
///
/// Written down a second time per tool is how two encodings quietly appear.
fn byte_envelope_defs() -> serde_json::Value {
    obj(vec![(
        "byteEnvelope",
        obj(vec![
            ("type", "object".into()),
            ("required", strings(&["encoding", "data"])),
            ("additionalProperties", false.into()),
            (
                "properties",
                obj(vec![
                    (
                        "encoding",
                        obj(vec![
                            ("type", "string".into()),
                            ("enum", strings(&["base64url-nopad"])),
                        ]),
                    ),
                    (
                        "data",
                        obj(vec![
                            ("type", "string".into()),
                            ("description", "base64url, no padding".into()),
                        ]),
                    ),
                    (
                        "display_utf8",
                        obj(vec![
                            ("type", "string".into()),
                            (
                                "description",
                                "advisory only; never authoritative for identity".into(),
                            ),
                        ]),
                    ),
                ]),
            ),
        ]),
    )])
}

fn byte_ref() -> serde_json::Value {
    obj(vec![("$ref", "#/$defs/byteEnvelope".into())])
}

/// A content-addressed identity: `sha256:` and 64 lowercase hex digits.
///
/// Given its own pattern rather than "any string" so the model is told the
/// shape it must echo back, and a truncated or re-cased handle is a schema
/// violation rather than a puzzle discovered at verification time.
fn digest_schema() -> serde_json::Value {
    obj(vec![
        ("type", "string".into()),
        ("pattern", "^sha256:[0-9a-f]{64}$".into()),
    ])
}

fn record_id_schema() -> serde_json::Value {
    obj(vec![
        ("type", "object".into()),
        ("required", strings(&["store", "section", "ordinal"])),
        ("additionalProperties", false.into()),
        (
            "properties",
            obj(vec![
                ("store", digest_schema()),
                ("section", obj(vec![("type", "string".into())])),
                (
                    "ordinal",
                    obj(vec![("type", "integer".into()), ("minimum", 0.into())]),
                ),
            ]),
        ),
    ])
}

fn array_of(item: serde_json::Value) -> serde_json::Value {
    obj(vec![("type", "array".into()), ("items", item)])
}

/// The result envelope both query tools return.
fn query_result_schema() -> serde_json::Value {
    obj(vec![
        ("type", "object".into()),
        (
            "required",
            strings(&[
                "handle",
                "candidate_count",
                "completion",
                "preview",
                "support",
            ]),
        ),
        ("additionalProperties", false.into()),
        (
            "properties",
            obj(vec![
                ("handle", digest_schema()),
                (
                    "candidate_count",
                    obj(vec![("type", "integer".into()), ("minimum", 0.into())]),
                ),
                (
                    "completion",
                    obj(vec![
                        ("type", "object".into()),
                        ("required", strings(&["state"])),
                        ("additionalProperties", false.into()),
                        (
                            "properties",
                            obj(vec![
                                (
                                    "state",
                                    obj(vec![
                                        ("type", "string".into()),
                                        ("enum", strings(&["exhausted", "limit-reached"])),
                                    ]),
                                ),
                                (
                                    "limit",
                                    obj(vec![("type", "integer".into()), ("minimum", 0.into())]),
                                ),
                            ]),
                        ),
                    ]),
                ),
                ("preview", array_of(byte_ref())),
                ("support", array_of(record_id_schema())),
            ]),
        ),
    ])
}

/// `qodec_lookup`: one index, one key.
pub fn lookup_schema() -> PanelToolSchema {
    PanelToolSchema {
        name: PanelTool::Lookup,
        description: "Find every record whose index key equals the given bytes. \
                      Returns a result handle, a bounded preview, the full \
                      candidate count, the completion state, and the record ids \
                      backing the result.",
        input_schema: obj(vec![
            ("type", "object".into()),
            ("required", strings(&["index", "key"])),
            ("additionalProperties", false.into()),
            (
                "properties",
                obj(vec![
                    ("index", obj(vec![("type", "string".into())])),
                    ("key", byte_ref()),
                ]),
            ),
            ("$defs", byte_envelope_defs()),
        ]),
        output_schema: query_result_schema(),
    }
}

/// `qodec_intersect`: candidates present in every named section.
pub fn intersect_schema() -> PanelToolSchema {
    PanelToolSchema {
        name: PanelTool::Intersect,
        description: "Find every index key present in all of the named sections. \
                      Returns the same result envelope as qodec_lookup.",
        input_schema: obj(vec![
            ("type", "object".into()),
            ("required", strings(&["index", "sections"])),
            ("additionalProperties", false.into()),
            (
                "properties",
                obj(vec![
                    ("index", obj(vec![("type", "string".into())])),
                    (
                        "sections",
                        obj(vec![
                            ("type", "array".into()),
                            ("minItems", 1.into()),
                            ("items", obj(vec![("type", "string".into())])),
                        ]),
                    ),
                ]),
            ),
        ]),
        output_schema: query_result_schema(),
    }
}

/// `qodec_materialize`: exact bytes for ids inside one result's support.
pub fn materialize_schema() -> PanelToolSchema {
    PanelToolSchema {
        name: PanelTool::Materialize,
        description: "Return the exact stored bytes for record ids. Only ids in \
                      the support of the given result handle are accepted; the \
                      store cannot be enumerated by guessing ids.",
        input_schema: obj(vec![
            ("type", "object".into()),
            ("required", strings(&["handle", "record_ids"])),
            ("additionalProperties", false.into()),
            (
                "properties",
                obj(vec![
                    ("handle", digest_schema()),
                    ("record_ids", array_of(record_id_schema())),
                ]),
            ),
        ]),
        output_schema: obj(vec![
            ("type", "object".into()),
            ("required", strings(&["records"])),
            ("additionalProperties", false.into()),
            ("properties", obj(vec![("records", array_of(byte_ref()))])),
            ("$defs", byte_envelope_defs()),
        ]),
    }
}

/// The three tools, in canonical order.
pub fn tool_schemas() -> Vec<PanelToolSchema> {
    vec![lookup_schema(), intersect_schema(), materialize_schema()]
}

/// The terminal answer format.
pub fn answer_schema() -> PanelAnswerSchema {
    PanelAnswerSchema {
        description: "The final answer. Cite the result handle it came from and \
                      the record ids that support it; both are checked against \
                      the stored complete result.",
        schema: obj(vec![
            ("type", "object".into()),
            ("required", strings(&["handle", "answer", "cited"])),
            ("additionalProperties", false.into()),
            (
                "properties",
                obj(vec![
                    ("handle", digest_schema()),
                    ("answer", byte_ref()),
                    ("cited", array_of(record_id_schema())),
                ]),
            ),
            ("$defs", byte_envelope_defs()),
        ]),
    }
}

/// Which typed tool was called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelTool {
    Lookup,
    Intersect,
    Materialize,
}

impl PanelTool {
    /// The name the model sees in the tool schema.
    pub fn name(self) -> &'static str {
        match self {
            PanelTool::Lookup => "qodec_lookup",
            PanelTool::Intersect => "qodec_intersect",
            PanelTool::Materialize => "qodec_materialize",
        }
    }
}

/// A call's arguments, typed rather than pre-rendered.
///
/// Held as values so the canonical serialization is the single place that
/// decides how bytes are written down. Formatting them into a `String` at the
/// call site would make the transcript a rendering of a rendering, and the
/// first lossy step would be invisible from the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolArguments {
    Lookup {
        index: IndexName,
        key: KeyBytes,
    },
    Intersect {
        index: IndexName,
        sections: Vec<SetName>,
    },
    Materialize {
        handle: QueryResultId,
        record_ids: Vec<RecordId>,
    },
}

/// What a call returned, in full.
///
/// `preview` and `support` carry the actual candidates and record ids, not
/// their counts. C1 charges the model for what crossed the boundary, and a
/// length cannot be tokenized: one support id and one long binary-safe
/// candidate differ by rather more than a philosophical margin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolCallOutcome {
    QueryResult {
        handle: QueryResultId,
        candidate_count: u64,
        completion: ExecutionCompletion,
        preview: Vec<KeyBytes>,
        support: Vec<RecordId>,
    },
    Materialized {
        records: Vec<Vec<u8>>,
    },
    Refused {
        reason: String,
    },
}

/// One entry in the normative transcript of a cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanelEvent {
    /// What the model was told about the artifact, and the tool schemas.
    Metadata {
        metadata: PanelMetadata,
        tool_schemas: Vec<PanelToolSchema>,
        answer_schema: PanelAnswerSchema,
    },
    ToolCall {
        sequence: u64,
        tool: PanelTool,
        arguments: ToolArguments,
        outcome: ToolCallOutcome,
    },
    FinalAnswer {
        sequence: u64,
        handle: QueryResultId,
        answer: KeyBytes,
        cited: Vec<RecordId>,
        verdict: VerifyOutcome,
    },
}

fn record_envelope(id: &RecordId) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("store".into(), id.store_id().to_canonical_text().into());
    obj.insert("section".into(), id.section().as_str().into());
    obj.insert("ordinal".into(), id.ordinal().into());
    serde_json::Value::Object(obj)
}

fn completion_envelope(c: ExecutionCompletion) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    match c {
        ExecutionCompletion::Exhausted => {
            obj.insert("state".into(), "exhausted".into());
        }
        ExecutionCompletion::LimitReached { limit } => {
            obj.insert("state".into(), "limit-reached".into());
            obj.insert("limit".into(), limit.into());
        }
    }
    serde_json::Value::Object(obj)
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

impl PanelEvent {
    /// The canonical JSON form — the machine source of truth.
    ///
    /// Every byte value goes through [`KeyBytes::to_envelope`], never through
    /// `Debug` and never through lossy UTF-8. `serde_json`'s default map is
    /// sorted, so the same events always serialize to the same bytes, which is
    /// what makes a byte-for-byte determinism check meaningful.
    pub fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        match self {
            PanelEvent::Metadata {
                metadata,
                tool_schemas,
                answer_schema,
            } => {
                obj.insert("event".into(), "metadata".into());
                obj.insert("metadata".into(), metadata.to_json());
                obj.insert(
                    "tool_schemas".into(),
                    tool_schemas
                        .iter()
                        .map(PanelToolSchema::to_json)
                        .collect::<Vec<_>>()
                        .into(),
                );
                obj.insert("answer_schema".into(), answer_schema.to_json());
            }
            PanelEvent::ToolCall {
                sequence,
                tool,
                arguments,
                outcome,
            } => {
                obj.insert("event".into(), "tool_call".into());
                obj.insert("sequence".into(), (*sequence).into());
                obj.insert("tool".into(), tool.name().into());
                obj.insert("arguments".into(), arguments.to_json());
                obj.insert("outcome".into(), outcome.to_json());
            }
            PanelEvent::FinalAnswer {
                sequence,
                handle,
                answer,
                cited,
                verdict,
            } => {
                obj.insert("event".into(), "final_answer".into());
                obj.insert("sequence".into(), (*sequence).into());
                obj.insert("handle".into(), handle.to_canonical_text().into());
                obj.insert("answer".into(), answer.to_envelope());
                obj.insert(
                    "cited".into(),
                    cited.iter().map(record_envelope).collect::<Vec<_>>().into(),
                );
                obj.insert("verdict".into(), verdict_name(*verdict).into());
            }
        }
        serde_json::Value::Object(obj)
    }
}

impl ToolArguments {
    fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        match self {
            ToolArguments::Lookup { index, key } => {
                obj.insert("index".into(), index.as_str().into());
                obj.insert("key".into(), key.to_envelope());
            }
            ToolArguments::Intersect { index, sections } => {
                obj.insert("index".into(), index.as_str().into());
                obj.insert(
                    "sections".into(),
                    sections
                        .iter()
                        .map(|s| serde_json::Value::from(s.as_str()))
                        .collect::<Vec<_>>()
                        .into(),
                );
            }
            ToolArguments::Materialize { handle, record_ids } => {
                obj.insert("handle".into(), handle.to_canonical_text().into());
                obj.insert(
                    "record_ids".into(),
                    record_ids
                        .iter()
                        .map(record_envelope)
                        .collect::<Vec<_>>()
                        .into(),
                );
            }
        }
        serde_json::Value::Object(obj)
    }
}

impl ToolCallOutcome {
    fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        match self {
            ToolCallOutcome::QueryResult {
                handle,
                candidate_count,
                completion,
                preview,
                support,
            } => {
                obj.insert("ok".into(), true.into());
                obj.insert("handle".into(), handle.to_canonical_text().into());
                obj.insert("candidate_count".into(), (*candidate_count).into());
                obj.insert("completion".into(), completion_envelope(*completion));
                obj.insert(
                    "preview".into(),
                    preview
                        .iter()
                        .map(KeyBytes::to_envelope)
                        .collect::<Vec<_>>()
                        .into(),
                );
                obj.insert(
                    "support".into(),
                    support
                        .iter()
                        .map(record_envelope)
                        .collect::<Vec<_>>()
                        .into(),
                );
            }
            ToolCallOutcome::Materialized { records } => {
                obj.insert("ok".into(), true.into());
                obj.insert(
                    "records".into(),
                    records
                        .iter()
                        .map(|r| KeyBytes::new(r.clone()).to_envelope())
                        .collect::<Vec<_>>()
                        .into(),
                );
            }
            ToolCallOutcome::Refused { reason } => {
                obj.insert("ok".into(), false.into());
                obj.insert("reason".into(), reason.clone().into());
            }
        }
        serde_json::Value::Object(obj)
    }
}

/// How a normative C1 cell ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellOutcome {
    /// The query path produced a verified answer.
    Accepted,
    /// The query path did not. Diagnostic fallback may follow *outside* the
    /// cell; it is never scored as a forced-query success.
    QueryPathFailed { verdict: VerifyOutcome },
}

impl CellOutcome {
    /// Whether a separate RAW fallback diagnostic is warranted after the cell.
    ///
    /// Reported rather than acted on: the decision to run one belongs to the
    /// harness, and its result belongs to a different column.
    pub fn fallback_required(&self) -> bool {
        matches!(self, CellOutcome::QueryPathFailed { .. })
    }
}

/// One artifact, opened once, exposed only through typed operations.
///
/// Holds the store and the registry together because the two must not drift:
/// verification resolves a handle through the registry and checks it against
/// *this* store, so a session is the unit in which "the same evidence" means
/// something.
#[derive(Debug)]
pub struct PanelSession {
    store: CanonicalStore,
    /// Kept so metadata can describe *how* the artifact was opened — depth and
    /// index shapes — without any of it being recovered from the records.
    plan: StorePlan,
    registry: HarnessResultRegistry,
    /// Built once at construction. The opening event records *these* values and
    /// the accessors hand back *these* values, so the surface the model is given
    /// and the surface the transcript claims cannot be two different objects
    /// that merely started out equal.
    tool_schemas: Vec<PanelToolSchema>,
    answer_schema: PanelAnswerSchema,
    schema: SchemaId,
    limits: ExecutionLimits,
    /// Per handle, the record ids that result is allowed to materialize.
    ///
    /// Kept beside the registry rather than derived on demand so that eviction
    /// and scope stay in step: a handle the registry has forgotten must not
    /// still authorize reads.
    scope: BTreeMap<QueryResultId, BTreeSet<RecordId>>,
    transcript: Vec<PanelEvent>,
    sequence: u64,
}

impl PanelSession {
    /// Open an artifact for the forced-query arm.
    ///
    /// `artifact_text` is consumed here and never exposed again. No accessor on
    /// this type returns the payload, the decoded RAW, or any record's bytes
    /// except through [`PanelSession::materialize`], which is scoped to an
    /// issued result's own support.
    pub fn open(
        artifact_text: &str,
        plan: &StorePlan,
        schema: SchemaId,
        limits: ExecutionLimits,
    ) -> Result<Self> {
        crate::query::check_limits(limits)?;
        let store = CanonicalStore::open(artifact_text, plan)?;
        Ok(PanelSession {
            store,
            plan: plan.clone(),
            registry: HarnessResultRegistry::new(),
            tool_schemas: tool_schemas(),
            answer_schema: answer_schema(),
            schema,
            limits,
            scope: BTreeMap::new(),
            transcript: Vec::new(),
            sequence: 0,
        })
    }

    /// The metadata the model is given in place of the artifact.
    ///
    /// Recorded as the transcript's opening event, because the prompt's
    /// model-visible cost starts here: the metadata and the tool schemas are
    /// what the model reads before it may call anything.
    pub fn metadata(&mut self) -> Result<PanelMetadata> {
        let metadata = self.build_metadata()?;
        if !self
            .transcript
            .iter()
            .any(|e| matches!(e, PanelEvent::Metadata { .. }))
        {
            self.transcript.push(PanelEvent::Metadata {
                metadata: metadata.clone(),
                tool_schemas: self.tool_schemas.clone(),
                answer_schema: self.answer_schema.clone(),
            });
        }
        Ok(metadata)
    }

    fn build_metadata(&self) -> Result<PanelMetadata> {
        let mut sections = BTreeMap::new();
        for name in self.store.sections() {
            sections.insert(name.as_str().to_owned(), 0u64);
        }
        for id in self.store.record_ids() {
            if let Some(slot) = sections.get_mut(id.section().as_str()) {
                *slot = slot.saturating_add(1);
            }
        }
        let mut indexes = BTreeMap::new();
        for spec in self.plan.indexes() {
            let kind = match &spec.extractor {
                KeyExtractor::WholeRecord => "whole-record".to_owned(),
                KeyExtractor::Field { separator, index } => {
                    format!("field(separator=0x{separator:02x}, index={index})")
                }
            };
            indexes.insert(spec.name.as_str().to_owned(), kind);
        }
        Ok(PanelMetadata {
            artifact_digest: *self.store.artifact_digest(),
            store_id: *self.store.store_id(),
            schema: self.schema.clone(),
            decode_layers: self.plan.decode_layers().get(),
            sections,
            record_count: u64::try_from(self.store.record_count()).unwrap_or(u64::MAX),
            indexes,
            max_candidates: self.limits.max_candidates,
            max_support_records: self.limits.max_support_records,
            max_preview_items: self.limits.max_preview_items,
        })
    }

    /// `qodec_lookup`: one index, one key.
    pub fn lookup(&mut self, index: &IndexName, key: &KeyBytes) -> Result<ToolResult> {
        let field = FieldName::parse(index.as_str())?;
        self.execute(
            PanelTool::Lookup,
            ToolArguments::Lookup {
                index: index.clone(),
                key: key.clone(),
            },
            CanonicalQuery::Lookup {
                field,
                value: key.clone(),
            },
        )
    }

    /// `qodec_intersect`: one index, every named section.
    pub fn intersect(&mut self, index: &IndexName, sections: &[SetName]) -> Result<ToolResult> {
        let key = FieldName::parse(index.as_str())?;
        self.execute(
            PanelTool::Intersect,
            ToolArguments::Intersect {
                index: index.clone(),
                sections: sections.to_vec(),
            },
            CanonicalQuery::Intersect {
                key,
                sets: sections.to_vec(),
            },
        )
    }

    fn execute(
        &mut self,
        tool: PanelTool,
        arguments: ToolArguments,
        query: CanonicalQuery,
    ) -> Result<ToolResult> {
        let sequence = self.next_sequence();
        let issued = match self.store.execute(&self.schema, query, self.limits) {
            Ok(issued) => issued,
            Err(e) => {
                self.transcript.push(PanelEvent::ToolCall {
                    sequence,
                    tool,
                    arguments,
                    outcome: ToolCallOutcome::Refused {
                        reason: format!("{e}"),
                    },
                });
                return Err(e);
            }
        };
        let candidate_count = u64::try_from(issued.candidate_count()).unwrap_or(u64::MAX);
        let completion = issued.completion();
        let preview = issued.preview().to_vec();
        let mut support: BTreeSet<RecordId> = BTreeSet::new();
        for candidate in issued.complete_result().candidates() {
            if let Some(ids) = issued.support_for(candidate) {
                support.extend(ids.iter().cloned());
            }
        }
        let handle = self.registry.issue(issued);
        self.scope.insert(handle, support.clone());
        let support_ids: Vec<RecordId> = support.iter().cloned().collect();
        self.transcript.push(PanelEvent::ToolCall {
            sequence,
            tool,
            arguments,
            outcome: ToolCallOutcome::QueryResult {
                handle,
                candidate_count,
                completion,
                preview: preview.clone(),
                support: support_ids,
            },
        });
        Ok(ToolResult {
            handle,
            candidate_count,
            completion,
            preview,
            support: support.into_iter().collect(),
        })
    }

    /// `qodec_materialize`: exact bytes for ids inside *this handle's* support.
    ///
    /// The handle is not decoration. Materializing by artifact id and arbitrary
    /// record ids would let a caller walk the store one guess at a time and
    /// reassemble the payload the arm exists to withhold; scoping to the
    /// support graph of a result the caller actually obtained keeps every read
    /// downstream of a deterministic query.
    pub fn materialize(
        &mut self,
        handle: &QueryResultId,
        ids: &[RecordId],
    ) -> Result<Vec<Vec<u8>>> {
        let sequence = self.next_sequence();
        let arguments = ToolArguments::Materialize {
            handle: *handle,
            record_ids: ids.to_vec(),
        };
        let result = self.materialize_inner(handle, ids);
        let outcome = match &result {
            Ok(records) => ToolCallOutcome::Materialized {
                records: records.clone(),
            },
            Err(e) => ToolCallOutcome::Refused {
                reason: format!("{e}"),
            },
        };
        self.transcript.push(PanelEvent::ToolCall {
            sequence,
            tool: PanelTool::Materialize,
            arguments,
            outcome,
        });
        result
    }

    fn materialize_inner(&self, handle: &QueryResultId, ids: &[RecordId]) -> Result<Vec<Vec<u8>>> {
        let Some(allowed) = self.scope.get(handle) else {
            bail!(
                "unknown or evicted result handle: {}",
                handle.to_canonical_text()
            );
        };
        for id in ids {
            if !allowed.contains(id) {
                bail!(
                    "record {}#{} is not in the support of result {}",
                    id.section().as_str(),
                    id.ordinal(),
                    handle.to_canonical_text()
                );
            }
        }
        Ok(self
            .store
            .materialize(ids)?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect())
    }

    /// The final answer, verified against the stored complete result.
    pub fn answer(
        &mut self,
        handle: &QueryResultId,
        proposed: &KeyBytes,
        cited: &[RecordId],
    ) -> CellOutcome {
        let sequence = self.next_sequence();
        let verdict = self.registry.verify(&self.store, handle, proposed, cited);
        self.transcript.push(PanelEvent::FinalAnswer {
            sequence,
            handle: *handle,
            answer: proposed.clone(),
            cited: cited.to_vec(),
            verdict,
        });
        match verdict {
            VerifyOutcome::Valid => CellOutcome::Accepted,
            verdict => CellOutcome::QueryPathFailed { verdict },
        }
    }

    fn next_sequence(&mut self) -> u64 {
        let n = self.sequence;
        self.sequence = self.sequence.saturating_add(1);
        n
    }

    /// The tool definitions handed to the model — the same values the opening
    /// transcript event recorded, not a second rendering of them.
    pub fn tool_schemas(&self) -> &[PanelToolSchema] {
        &self.tool_schemas
    }

    /// The answer format handed to the model, likewise.
    pub fn answer_schema(&self) -> &PanelAnswerSchema {
        &self.answer_schema
    }

    /// Every event this session recorded, in order.
    pub fn transcript(&self) -> &[PanelEvent] {
        &self.transcript
    }

    /// The canonical JSONL transcript — the machine source of truth.
    pub fn transcript_jsonl(&self) -> String {
        let mut out = String::new();
        for event in &self.transcript {
            out.push_str(&event.to_json().to_string());
            out.push('\n');
        }
        out
    }

    /// Forget a result, which is how a handle goes stale mid-session.
    pub fn evict(&mut self, handle: &QueryResultId) -> bool {
        self.scope.remove(handle);
        self.registry.evict(handle)
    }
}
