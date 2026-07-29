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
    pub operations: Vec<String>,
    pub max_candidates: u64,
    pub max_support_records: u64,
    pub max_preview_items: u64,
}

impl PanelMetadata {
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
        out.push_str("operations:\n");
        for op in &self.operations {
            out.push_str(&format!("  {op}\n"));
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

/// One recorded tool call: what was asked, and what came back.
///
/// The transcript exists because the experiment's model-visible cost is the sum
/// of what actually crossed the boundary — schemas, arguments, results, preview
/// — and reconstructing that afterwards from a summary would be an estimate
/// wearing a measurement's clothes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEnvelope {
    pub tool: String,
    pub arguments: String,
    pub result: String,
    /// `false` when the call was refused; refusals are part of the record, not
    /// a reason to omit it.
    pub ok: bool,
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
    schema: SchemaId,
    limits: ExecutionLimits,
    /// Per handle, the record ids that result is allowed to materialize.
    ///
    /// Kept beside the registry rather than derived on demand so that eviction
    /// and scope stay in step: a handle the registry has forgotten must not
    /// still authorize reads.
    scope: BTreeMap<QueryResultId, BTreeSet<RecordId>>,
    transcript: Vec<CallEnvelope>,
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
            schema,
            limits,
            scope: BTreeMap::new(),
            transcript: Vec::new(),
        })
    }

    /// The metadata the model is given in place of the artifact.
    pub fn metadata(&self) -> Result<PanelMetadata> {
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
            operations: vec![
                "qodec_lookup(index, key) -> handle, preview, candidate_count, completion, support"
                    .to_owned(),
                "qodec_intersect(index, sections) -> handle, preview, candidate_count, completion, support"
                    .to_owned(),
                "qodec_materialize(handle, record_ids) -> bytes for ids in that result's support"
                    .to_owned(),
                "answer(handle, answer, cited_evidence) -> verdict".to_owned(),
            ],
            max_candidates: self.limits.max_candidates,
            max_support_records: self.limits.max_support_records,
            max_preview_items: self.limits.max_preview_items,
        })
    }

    /// `qodec_lookup`: one index, one key.
    pub fn lookup(&mut self, index: &IndexName, key: &KeyBytes) -> Result<ToolResult> {
        let field = FieldName::parse(index.as_str())?;
        let args = format!("index={:?} key={:?}", index.as_str(), key.to_envelope());
        self.execute(
            "qodec_lookup",
            args,
            CanonicalQuery::Lookup {
                field,
                value: key.clone(),
            },
        )
    }

    /// `qodec_intersect`: one index, every named section.
    pub fn intersect(&mut self, index: &IndexName, sections: &[SetName]) -> Result<ToolResult> {
        let key = FieldName::parse(index.as_str())?;
        let args = format!(
            "index={:?} sections={:?}",
            index.as_str(),
            sections.iter().map(SetName::as_str).collect::<Vec<_>>()
        );
        self.execute(
            "qodec_intersect",
            args,
            CanonicalQuery::Intersect {
                key,
                sets: sections.to_vec(),
            },
        )
    }

    fn execute(
        &mut self,
        tool: &str,
        arguments: String,
        query: CanonicalQuery,
    ) -> Result<ToolResult> {
        let issued = match self.store.execute(&self.schema, query, self.limits) {
            Ok(issued) => issued,
            Err(e) => {
                self.transcript.push(CallEnvelope {
                    tool: tool.to_owned(),
                    arguments,
                    result: format!("error: {e}"),
                    ok: false,
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
        self.transcript.push(CallEnvelope {
            tool: tool.to_owned(),
            arguments,
            result: format!(
                "handle={} candidate_count={} completion={:?} preview={} support={}",
                handle.to_canonical_text(),
                candidate_count,
                completion,
                preview.len(),
                support.len()
            ),
            ok: true,
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
    pub fn materialize(&self, handle: &QueryResultId, ids: &[RecordId]) -> Result<Vec<Vec<u8>>> {
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
        &self,
        handle: &QueryResultId,
        proposed: &KeyBytes,
        cited: &[RecordId],
    ) -> CellOutcome {
        match self.registry.verify(&self.store, handle, proposed, cited) {
            VerifyOutcome::Valid => CellOutcome::Accepted,
            verdict => CellOutcome::QueryPathFailed { verdict },
        }
    }

    /// Every call this session recorded, in order.
    pub fn transcript(&self) -> &[CallEnvelope] {
        &self.transcript
    }

    /// Forget a result, which is how a handle goes stale mid-session.
    pub fn evict(&mut self, handle: &QueryResultId) -> bool {
        self.scope.remove(handle);
        self.registry.evict(handle)
    }
}
