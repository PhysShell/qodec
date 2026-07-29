//! Query execution and proof-carrying verification — Slice A, #15.
//!
//! The object this module issues is the point of the whole harness: a result
//! that only the execution path can produce. A caller cannot build one, a JSON
//! loader cannot conjure one, and the model never gets to restate what the
//! question was. Everything a verdict depends on is fixed at issue time and
//! covered by the identity.
//!
//! Three rules shape the design, each closing a way a verification layer can
//! look rigorous while being ceremonial:
//!
//! * **Truth comes from the stored full result, never from what the model
//!   cited.** Cited evidence is checked as a subset of the real supporting set
//!   and has no vote on the candidate set or its size. Otherwise a reply could
//!   cite evidence for the convenient candidate and quietly omit the other.
//! * **Nothing authoritative is stored twice.** `candidate_count` is computed,
//!   not carried, so there is no field to forge.
//! * **Completion is a state, not a boolean.** A result that stopped at a
//!   limit cannot present itself as exhaustive, because the difference is a
//!   variant rather than a flag someone might set.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Result};

use crate::canon::{
    canonical_query_digest, complete_result_digest, digest_result_support_bytes, encode_bytes,
    encode_count, encode_name, query_result_id, ArtifactDigest, CanonicalQuery,
    CanonicalQueryDigest, CanonicalResult, CompleteResultDigest, KeyBytes, QueryResultId,
    ResultSupportDigest, SchemaId, StoreId, StorePlanDigest,
};
use crate::store::{CanonicalStore, RecordId, ScanStop};

/// Bounds on one execution.
///
/// Two of these change the answer and one does not, which is the distinction
/// worth keeping straight: hitting a candidate or support bound means the
/// search did not finish, so the result is not exhaustive. A preview bound
/// only decides how much of a finished result is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionLimits {
    pub max_candidates: u64,
    pub max_support_records: u64,
    pub max_preview_items: u64,
}

impl ExecutionLimits {
    /// Bounds large enough for the Slice A fixtures, stated rather than absent.
    ///
    /// There is no "unlimited" constructor on purpose. An unbounded execution
    /// is how a query interface recreates the original problem — the whole
    /// store back in the context window — with a database underneath it for
    /// dignity.
    pub fn modest() -> Self {
        ExecutionLimits {
            max_candidates: 1_000,
            max_support_records: 100_000,
            max_preview_items: 50,
        }
    }
}

/// Whether the execution ran out of work or out of budget.
///
/// Deliberately not `bool complete`. A boolean invites someone to set it, and
/// the whole point of case 13 is that an incomplete result must not be able to
/// describe itself as complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionCompletion {
    /// The search finished: every candidate the store holds is present.
    Exhausted,
    /// A bound was reached first, so the result is a partial view.
    LimitReached { limit: u64 },
}

/// A query result that only [`CanonicalStore::execute`] can produce.
///
/// Every field is private. There is no public constructor, no setter, and no
/// deserializer, so the only way to hold one is to have executed a query
/// against a real store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessIssuedResult {
    schema: SchemaId,
    artifact_digest: ArtifactDigest,
    store_plan_digest: StorePlanDigest,
    store_id: StoreId,
    canonical_query: CanonicalQuery,
    canonical_query_digest: CanonicalQueryDigest,
    /// Candidates in canonical order, each with the records that support it.
    support: BTreeMap<KeyBytes, Vec<RecordId>>,
    completion: ExecutionCompletion,
    complete_result: CanonicalResult,
    complete_result_digest: CompleteResultDigest,
    support_bytes: Vec<u8>,
    result_support_digest: ResultSupportDigest,
    query_result_id: QueryResultId,
    /// A bounded view of the candidates, for showing. Never a basis for a
    /// verdict, and deliberately outside the identity: a preview is a
    /// representation of the result, not the result.
    preview: Vec<KeyBytes>,
}

impl HarnessIssuedResult {
    /// The immutable handle this result is addressed by.
    pub fn query_result_id(&self) -> &QueryResultId {
        &self.query_result_id
    }

    /// How many candidates the full result holds.
    ///
    /// Computed from the candidates, never stored. A count carried alongside
    /// the thing it counts is a count that can disagree with it, and case 6 of
    /// the negative matrix is exactly that disagreement being believed.
    pub fn candidate_count(&self) -> usize {
        self.complete_result.candidates().len()
    }

    /// Whether the execution finished or stopped at a bound.
    pub fn completion(&self) -> ExecutionCompletion {
        self.completion
    }

    /// The full candidate set, in canonical order.
    pub fn complete_result(&self) -> &CanonicalResult {
        &self.complete_result
    }

    /// A bounded view for display. Never the basis of a decision.
    pub fn preview(&self) -> &[KeyBytes] {
        &self.preview
    }

    /// The digest covering support and completion, as it enters the identity.
    pub fn result_support_digest(&self) -> &ResultSupportDigest {
        &self.result_support_digest
    }

    /// The records backing one candidate, or `None` if it is not a candidate.
    pub fn support_for(&self, candidate: &KeyBytes) -> Option<&[RecordId]> {
        self.support.get(candidate).map(Vec::as_slice)
    }
}

/// The outcome of verifying a proposed answer against an issued result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Exactly one candidate, and the answer is it.
    Valid,
    /// The answer is not the single candidate, or there is no candidate.
    Invalid,
    /// The full result holds more than one candidate. Never resolved by
    /// picking one, however tempting the model's citation makes it look.
    Ambiguous,
    /// The execution stopped at a limit, so absence proves nothing.
    Incomplete,
    /// Cited evidence is not a subset of what actually supports the answer.
    Unverifiable,
    /// The handle is unknown, or its stored result no longer matches it.
    StaleResultHandle,
    /// The result was computed over a different artifact.
    ArtifactMismatch,
    /// Same artifact, different plan: a different question.
    StorePlanMismatch,
    /// A recomputed digest disagrees with the stored one.
    QueryDigestMismatch,
}

/// Issued results, addressed by handle.
///
/// Verification goes through the registry rather than through a result the
/// caller hands over, so a handle can be *stale* — a state that a
/// caller-supplied object could never be in, and the one case 3 is about.
#[derive(Debug, Default)]
pub struct HarnessResultRegistry {
    issued: BTreeMap<QueryResultId, HarnessIssuedResult>,
}

impl HarnessResultRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        HarnessResultRegistry::default()
    }

    /// Record an issued result and return its handle.
    pub fn issue(&mut self, result: HarnessIssuedResult) -> QueryResultId {
        let id = result.query_result_id;
        self.issued.insert(id, result);
        id
    }

    /// Forget a result, which is how a handle becomes stale.
    pub fn evict(&mut self, handle: &QueryResultId) -> bool {
        self.issued.remove(handle).is_some()
    }

    /// Verify a proposed answer against the stored full result.
    ///
    /// Takes a **handle**, not a query. The model never gets to restate the
    /// question during its own verification — people are remarkably inventive
    /// when an interface leaves them a spare field.
    ///
    /// Never re-executes. A handle that no longer resolves is terminal, not a
    /// prompt to recompute: manufacturing fresh evidence at the moment the
    /// system detects its evidence is untrustworthy would turn a fail-closed
    /// state into a silent recovery. Re-execution belongs to acceptance
    /// replay, which runs offline and outside the answer path.
    pub fn verify(
        &self,
        store: &CanonicalStore,
        handle: &QueryResultId,
        proposed_answer: &KeyBytes,
        cited_evidence: &[RecordId],
    ) -> VerifyOutcome {
        let Some(result) = self.issued.get(handle) else {
            return VerifyOutcome::StaleResultHandle;
        };
        if &result.artifact_digest != store.artifact_digest() {
            return VerifyOutcome::ArtifactMismatch;
        }
        if &result.store_plan_digest != store.store_plan_digest() {
            return VerifyOutcome::StorePlanMismatch;
        }
        // Recompute rather than trust the stored fields, then check that the
        // handle is the identity of what is actually stored under it.
        let Ok(query_digest) = canonical_query_digest(&result.schema, &result.canonical_query)
        else {
            return VerifyOutcome::QueryDigestMismatch;
        };
        let Ok(result_digest) = complete_result_digest(&result.complete_result) else {
            return VerifyOutcome::QueryDigestMismatch;
        };
        let support_digest = digest_result_support_bytes(&result.support_bytes);
        if query_digest != result.canonical_query_digest
            || result_digest != result.complete_result_digest
            || support_digest != result.result_support_digest
        {
            return VerifyOutcome::QueryDigestMismatch;
        }
        let Ok(support_bytes) = canonical_support_bytes(&result.support, result.completion) else {
            return VerifyOutcome::QueryDigestMismatch;
        };
        if support_bytes != result.support_bytes {
            return VerifyOutcome::QueryDigestMismatch;
        }
        let recomputed = query_result_id(
            &result.schema,
            &result.store_id,
            &query_digest,
            &result_digest,
            &support_digest,
        );
        if &recomputed != handle {
            return VerifyOutcome::StaleResultHandle;
        }

        // Only now does the verdict depend on the result's content, and it
        // depends on the FULL result rather than on anything the model chose.
        if result.completion != ExecutionCompletion::Exhausted {
            return VerifyOutcome::Incomplete;
        }
        let candidates = result.complete_result.candidates();
        let [only] = candidates else {
            return if candidates.is_empty() {
                VerifyOutcome::Invalid
            } else {
                VerifyOutcome::Ambiguous
            };
        };
        if only != proposed_answer {
            return VerifyOutcome::Invalid;
        }
        // Cited evidence is audited, never authoritative: it may be empty, it
        // may be partial, but it may not point outside the real support.
        let real: BTreeSet<&RecordId> = result
            .support
            .get(only)
            .map(|ids| ids.iter().collect())
            .unwrap_or_default();
        if cited_evidence.iter().any(|id| !real.contains(id)) {
            return VerifyOutcome::Unverifiable;
        }
        VerifyOutcome::Valid
    }
}

/// Canonical bytes of what backs a result: support per candidate, plus the
/// completion state.
///
/// Record ids enter as their coordinates only. The store they belong to is
/// already bound by `store_id` in the identity, so repeating it per record
/// would restate a fact the preimage already carries.
fn canonical_support_bytes(
    support: &BTreeMap<KeyBytes, Vec<RecordId>>,
    completion: ExecutionCompletion,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match completion {
        ExecutionCompletion::Exhausted => out.push(1),
        ExecutionCompletion::LimitReached { limit } => {
            out.push(2);
            out.extend_from_slice(&limit.to_be_bytes());
        }
    }
    encode_count(&mut out, support.len())?;
    for (candidate, ids) in support {
        encode_bytes(&mut out, candidate.as_bytes());
        encode_count(&mut out, ids.len())?;
        for id in ids {
            encode_name(&mut out, id.section().as_str());
            out.extend_from_slice(&id.ordinal().to_be_bytes());
        }
    }
    Ok(out)
}

/// Execute a canonical query against an open store and issue a result.
///
/// The only constructor of [`HarnessIssuedResult`] anywhere, and `pub(crate)`
/// so the normative path really is the only path. Leaving it public would
/// close the door and thoughtfully leave a window beside it.
pub(crate) fn execute(
    store: &CanonicalStore,
    schema: &SchemaId,
    query: CanonicalQuery,
    limits: ExecutionLimits,
) -> Result<HarnessIssuedResult> {
    // Validated here rather than only in the wrapper: the check belongs to the
    // execution boundary, not to one convenient entry point.
    check_limits(limits)?;
    let mut support: BTreeMap<KeyBytes, Vec<RecordId>> = BTreeMap::new();
    let mut completion = ExecutionCompletion::Exhausted;

    match &query {
        CanonicalQuery::Lookup { field, value } => {
            let index = crate::canon::IndexName::parse(field.as_str())?;
            let scan = store.scan_lookup(&index, value, limits.max_support_records)?;
            if scan.stopped {
                completion = ExecutionCompletion::LimitReached {
                    limit: limits.max_support_records,
                };
            }
            if !scan.support.is_empty() {
                support.insert(value.clone(), scan.support);
            }
        }
        CanonicalQuery::Intersect { key, sets } => {
            let index = crate::canon::IndexName::parse(key.as_str())?;
            let scan = store.scan_intersect(
                &index,
                sets,
                limits.max_candidates,
                limits.max_support_records,
            )?;
            completion = match scan.stopped {
                None => ExecutionCompletion::Exhausted,
                Some(ScanStop::Candidates(limit)) => ExecutionCompletion::LimitReached { limit },
                Some(ScanStop::SupportRecords(limit)) => {
                    ExecutionCompletion::LimitReached { limit }
                }
            };
            support = scan.support;
        }
    }

    let complete_result = CanonicalResult::new(support.keys().cloned())?;
    let complete_result_digest = complete_result_digest(&complete_result)?;
    let support_bytes = canonical_support_bytes(&support, completion)?;
    let result_support_digest = digest_result_support_bytes(&support_bytes);
    let canonical_query_digest = canonical_query_digest(schema, &query)?;
    let query_result_id = query_result_id(
        schema,
        store.store_id(),
        &canonical_query_digest,
        &complete_result_digest,
        &result_support_digest,
    );
    let preview_len = usize::try_from(limits.max_preview_items).unwrap_or(usize::MAX);
    let preview: Vec<KeyBytes> = complete_result
        .candidates()
        .iter()
        .take(preview_len)
        .cloned()
        .collect();

    Ok(HarnessIssuedResult {
        schema: schema.clone(),
        artifact_digest: *store.artifact_digest(),
        store_plan_digest: *store.store_plan_digest(),
        store_id: *store.store_id(),
        canonical_query: query,
        canonical_query_digest,
        support,
        completion,
        complete_result,
        complete_result_digest,
        support_bytes,
        result_support_digest,
        query_result_id,
        preview,
    })
}

/// Refuse an execution whose bounds are meaningless.
pub(crate) fn check_limits(limits: ExecutionLimits) -> Result<()> {
    if limits.max_candidates == 0 || limits.max_support_records == 0 {
        bail!("execution limits must leave room for at least one candidate and one record");
    }
    Ok(())
}
