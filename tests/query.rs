//! RED contracts for the query execution layer — Slice A, #15.
//!
//! These close the six negative-matrix cases that needed an immutable
//! harness-issued result to be expressible at all: 3 (stale handle), 5
//! (evidence subset), 6 (forged candidate count), 7 (ambiguous), 11 (unbounded
//! result) and 13 (incomplete marked complete).
//!
//! What they have in common is that each is an answer that looks *formally*
//! verified while being wrong, which is exactly the failure a verification
//! layer exists to prevent and therefore the easiest one to accidentally
//! build.

use anyhow::Result;

use qodec::canon::{
    CanonicalQuery, FieldName, IndexName, KeyBytes, SchemaId, SetName, SCHEMA_QUERY_V1,
};
use qodec::query::{ExecutionCompletion, ExecutionLimits, HarnessResultRegistry, VerifyOutcome};
use qodec::store::{CanonicalStore, IndexSpec, KeyExtractor, RecordId, Segmentation, StorePlan};

// Support-digest goldens for the retry-store fixture, derived by
// tests/reference/canon_reference.py and verified by its `--check` mode in CI.
const GOLDEN_RETRY_SUPPORT_EXHAUSTED: &str =
    "sha256:808a47072a27e38455079dd89d1a5d6b1baeb5e206743c41a1ea466386535088";
const GOLDEN_RETRY_SUPPORT_LIMITED: &str =
    "sha256:07cdb7a863eebb11a7c7ea288e15c46f82e72869c7ceed6de2a8b217c7d084c4";

fn set(name: &str) -> Result<SetName> {
    SetName::parse(name)
}

fn key(bytes: &[u8]) -> KeyBytes {
    KeyBytes::new(bytes.to_vec())
}

fn schema() -> Result<SchemaId> {
    SchemaId::parse(SCHEMA_QUERY_V1)
}

fn raw_artifact(body: &str) -> String {
    format!("%q1 raw\n%q1 body\n{body}")
}

fn marked_seg() -> Result<Segmentation> {
    Ok(Segmentation::MarkedSections {
        prefix: "--- ".into(),
        suffix: " ---".into(),
        preamble: set("preamble")?,
    })
}

fn line_index() -> Result<Vec<IndexSpec>> {
    Ok(vec![IndexSpec {
        name: IndexName::parse("line")?,
        extractor: KeyExtractor::WholeRecord,
    }])
}

/// The default plan for these fixtures: one top-level layer.
fn plan(seg: Segmentation, specs: Vec<IndexSpec>) -> Result<StorePlan> {
    StorePlan::new(1, seg, specs)
}

/// Three retry blocks. `alpha` fails in all three; `beta` in two of them.
/// This is the shape the reader panels kept getting wrong.
fn retry_store() -> Result<CanonicalStore> {
    CanonicalStore::open(
        &raw_artifact(
            "--- attempt_1 ---\nalpha\nbeta\n\
             --- attempt_2 ---\nalpha\ngamma\n\
             --- attempt_3 ---\nalpha\nbeta\n",
        ),
        &plan(marked_seg()?, line_index()?)?,
    )
}

fn all_three() -> Result<Vec<SetName>> {
    Ok(vec![
        set("attempt_1")?,
        set("attempt_2")?,
        set("attempt_3")?,
    ])
}

fn intersect_all_three() -> Result<CanonicalQuery> {
    Ok(CanonicalQuery::Intersect {
        key: FieldName::parse("line")?,
        sets: all_three()?,
    })
}

// ---------------------------------------------------------------------------
// The happy path, so the negative cases mean something
// ---------------------------------------------------------------------------

/// One candidate, execution exhausted, answer matches: valid.
#[test]
fn the_single_candidate_verifies() -> Result<()> {
    let store = retry_store()?;
    let mut registry = HarnessResultRegistry::new();
    let result = store.execute(
        &schema()?,
        intersect_all_three()?,
        ExecutionLimits::modest(),
    )?;

    assert_eq!(result.candidate_count(), 1);
    assert_eq!(result.completion(), ExecutionCompletion::Exhausted);
    assert_eq!(result.complete_result().candidates(), [key(b"alpha")]);

    let evidence: Vec<RecordId> = result
        .support_for(&key(b"alpha"))
        .unwrap_or_default()
        .to_vec();
    assert_eq!(evidence.len(), 3, "one record per attempt block");

    let handle = registry.issue(result);
    assert_eq!(
        registry.verify(&store, &handle, &key(b"alpha"), &evidence),
        VerifyOutcome::Valid
    );
    // Citing nothing at all is still valid: evidence is audited, not required.
    assert_eq!(
        registry.verify(&store, &handle, &key(b"alpha"), &[]),
        VerifyOutcome::Valid
    );
    // A different answer is invalid, whatever evidence accompanies it.
    assert_eq!(
        registry.verify(&store, &handle, &key(b"beta"), &evidence),
        VerifyOutcome::Invalid
    );
    Ok(())
}

/// The result is issued by execution, and nothing else can produce one.
///
/// There is no public constructor, no setter and no deserializer for
/// `HarnessIssuedResult`, so this is enforced by the type rather than by
/// vigilance. What the test can show is that the identity is derived from the
/// store actually executed against.
#[test]
fn the_result_is_bound_to_the_store_that_issued_it() -> Result<()> {
    let store = retry_store()?;
    let result = store.execute(
        &schema()?,
        intersect_all_three()?,
        ExecutionLimits::modest(),
    )?;
    let handle = *result.query_result_id();

    let mut registry = HarnessResultRegistry::new();
    registry.issue(result);

    // Same artifact, different plan: a different question, reported as such.
    let other_plan = CanonicalStore::open(
        &raw_artifact(
            "--- attempt_1 ---\nalpha\nbeta\n\
             --- attempt_2 ---\nalpha\ngamma\n\
             --- attempt_3 ---\nalpha\nbeta\n",
        ),
        &plan(Segmentation::Lines { section: set("s")? }, line_index()?)?,
    )?;
    assert_eq!(store.artifact_digest(), other_plan.artifact_digest());
    assert_eq!(
        registry.verify(&other_plan, &handle, &key(b"alpha"), &[]),
        VerifyOutcome::StorePlanMismatch
    );

    // A different artifact entirely.
    let other_artifact = CanonicalStore::open(
        &raw_artifact("--- attempt_1 ---\nzzz\n"),
        &plan(marked_seg()?, line_index()?)?,
    )?;
    assert_eq!(
        registry.verify(&other_artifact, &handle, &key(b"alpha"), &[]),
        VerifyOutcome::ArtifactMismatch
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Case 3 — stale handle
// ---------------------------------------------------------------------------

/// A handle whose result is gone is terminal, not a prompt to re-execute.
///
/// Re-running the query here would replace missing evidence with freshly
/// manufactured evidence at exactly the moment the system detected its
/// evidence was untrustworthy — turning a fail-closed state into a silent
/// recovery. Re-execution belongs to acceptance replay, offline and outside
/// the answer path.
#[test]
fn a_stale_handle_is_terminal_and_is_not_repaired_by_re_execution() -> Result<()> {
    let store = retry_store()?;
    let mut registry = HarnessResultRegistry::new();
    let result = store.execute(
        &schema()?,
        intersect_all_three()?,
        ExecutionLimits::modest(),
    )?;
    let handle = registry.issue(result);

    assert_eq!(
        registry.verify(&store, &handle, &key(b"alpha"), &[]),
        VerifyOutcome::Valid
    );

    assert!(registry.evict(&handle), "the result was there to evict");
    assert_eq!(
        registry.verify(&store, &handle, &key(b"alpha"), &[]),
        VerifyOutcome::StaleResultHandle,
        "the query is still answerable, and that is beside the point"
    );

    // Re-executing produces the same identity — which is what makes replay
    // meaningful — but it does not resurrect the old handle by itself.
    let again = store.execute(
        &schema()?,
        intersect_all_three()?,
        ExecutionLimits::modest(),
    )?;
    assert_eq!(
        again.query_result_id(),
        &handle,
        "replay is checkable by construction"
    );
    assert_eq!(
        registry.verify(&store, &handle, &key(b"alpha"), &[]),
        VerifyOutcome::StaleResultHandle,
        "and verification still refuses until the result is deliberately issued again"
    );
    Ok(())
}

/// An unknown handle is stale rather than invalid: the system is saying it has
/// no record, not that the answer is wrong.
#[test]
fn an_unknown_handle_is_stale() -> Result<()> {
    let store = retry_store()?;
    let registry = HarnessResultRegistry::new();
    let result = store.execute(
        &schema()?,
        intersect_all_three()?,
        ExecutionLimits::modest(),
    )?;
    assert_eq!(
        registry.verify(&store, result.query_result_id(), &key(b"alpha"), &[]),
        VerifyOutcome::StaleResultHandle
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Case 5 — the evidence subset attack
// ---------------------------------------------------------------------------

/// Citing evidence for one candidate cannot make an ambiguous result single.
///
/// This is the bypass the contract was rewritten to close: truth is derived
/// from the stored full result, so a reply that cites only what supports its
/// preferred candidate changes nothing about how many candidates there are.
#[test]
fn citing_a_subset_cannot_collapse_an_ambiguous_result() -> Result<()> {
    // Both alpha and beta appear in attempts 1 and 3.
    let store = retry_store()?;
    let mut registry = HarnessResultRegistry::new();
    let two_blocks = CanonicalQuery::Intersect {
        key: FieldName::parse("line")?,
        sets: vec![set("attempt_1")?, set("attempt_3")?],
    };
    let result = store.execute(&schema()?, two_blocks, ExecutionLimits::modest())?;
    assert_eq!(result.candidate_count(), 2, "premise: genuinely ambiguous");

    let only_alpha: Vec<RecordId> = result
        .support_for(&key(b"alpha"))
        .unwrap_or_default()
        .to_vec();
    let handle = registry.issue(result);

    assert_eq!(
        registry.verify(&store, &handle, &key(b"alpha"), &only_alpha),
        VerifyOutcome::Ambiguous,
        "evidence for one candidate does not delete the other"
    );
    Ok(())
}

/// Evidence pointing outside the real supporting set is unverifiable.
#[test]
fn evidence_outside_the_real_support_is_unverifiable() -> Result<()> {
    let store = retry_store()?;
    let mut registry = HarnessResultRegistry::new();
    let result = store.execute(
        &schema()?,
        intersect_all_three()?,
        ExecutionLimits::modest(),
    )?;

    // A record that exists in the store but supports `beta`, not `alpha`.
    let beta_records = store.lookup(&IndexName::parse("line")?, &key(b"beta"))?;
    let handle = registry.issue(result);

    assert_eq!(
        registry.verify(&store, &handle, &key(b"alpha"), &beta_records),
        VerifyOutcome::Unverifiable,
        "a real record that backs a different candidate is still not evidence for this one"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Case 6 — a forged candidate count
// ---------------------------------------------------------------------------

/// The count is derived, so there is no field to forge.
///
/// A count stored beside the thing it counts is a count that can disagree with
/// it, and case 6 is that disagreement being believed. Here the only way to
/// change the count is to change the candidates, which changes the identity.
#[test]
fn the_candidate_count_is_derived_not_stored() -> Result<()> {
    let store = retry_store()?;
    let single = store.execute(
        &schema()?,
        intersect_all_three()?,
        ExecutionLimits::modest(),
    )?;
    assert_eq!(
        single.candidate_count(),
        single.complete_result().candidates().len()
    );
    assert_eq!(single.candidate_count(), 1);

    let two = store.execute(
        &schema()?,
        CanonicalQuery::Intersect {
            key: FieldName::parse("line")?,
            sets: vec![set("attempt_1")?, set("attempt_3")?],
        },
        ExecutionLimits::modest(),
    )?;
    assert_eq!(two.candidate_count(), 2);
    assert_ne!(
        single.query_result_id(),
        two.query_result_id(),
        "a different candidate set is a different identity"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Case 7 — ambiguity is never resolved by choosing
// ---------------------------------------------------------------------------

/// More than one candidate is ambiguous, for every proposed answer.
#[test]
fn ambiguity_is_not_resolved_by_picking_a_candidate() -> Result<()> {
    let store = retry_store()?;
    let mut registry = HarnessResultRegistry::new();
    let result = store.execute(
        &schema()?,
        CanonicalQuery::Intersect {
            key: FieldName::parse("line")?,
            sets: vec![set("attempt_1")?, set("attempt_3")?],
        },
        ExecutionLimits::modest(),
    )?;
    let handle = registry.issue(result);

    for answer in [b"alpha".as_slice(), b"beta".as_slice(), b"gamma".as_slice()] {
        assert_eq!(
            registry.verify(&store, &handle, &key(answer), &[]),
            VerifyOutcome::Ambiguous,
            "no candidate wins an ambiguous result, not even a correct-looking one"
        );
    }
    Ok(())
}

/// No candidates at all is invalid, not ambiguous and not valid-by-vacuum.
#[test]
fn an_empty_result_is_invalid() -> Result<()> {
    let store = retry_store()?;
    let mut registry = HarnessResultRegistry::new();
    let result = store.execute(
        &schema()?,
        CanonicalQuery::Lookup {
            field: FieldName::parse("line")?,
            value: key(b"nothing-like-this"),
        },
        ExecutionLimits::modest(),
    )?;
    assert_eq!(result.candidate_count(), 0);
    let handle = registry.issue(result);
    assert_eq!(
        registry.verify(&store, &handle, &key(b"nothing-like-this"), &[]),
        VerifyOutcome::Invalid
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Case 11 — bounded results
// ---------------------------------------------------------------------------

/// A candidate bound makes the result incomplete, and it says so.
#[test]
fn hitting_a_candidate_bound_marks_the_result_incomplete() -> Result<()> {
    let store = retry_store()?;
    let mut registry = HarnessResultRegistry::new();
    let result = store.execute(
        &schema()?,
        CanonicalQuery::Intersect {
            key: FieldName::parse("line")?,
            sets: vec![set("attempt_1")?, set("attempt_3")?],
        },
        ExecutionLimits {
            max_candidates: 1,
            ..ExecutionLimits::modest()
        },
    )?;
    assert_eq!(
        result.completion(),
        ExecutionCompletion::LimitReached { limit: 1 }
    );
    let handle = registry.issue(result);
    assert_eq!(
        registry.verify(&store, &handle, &key(b"alpha"), &[]),
        VerifyOutcome::Incomplete,
        "a truncated search proves nothing about what it did not reach"
    );
    Ok(())
}

/// A preview bound does **not** affect completeness. The two limits are
/// different things: how much is shown, and how much was searched.
#[test]
fn a_preview_bound_does_not_make_a_result_incomplete() -> Result<()> {
    let store = retry_store()?;
    let mut registry = HarnessResultRegistry::new();
    let result = store.execute(
        &schema()?,
        CanonicalQuery::Intersect {
            key: FieldName::parse("line")?,
            sets: vec![set("attempt_1")?, set("attempt_3")?],
        },
        ExecutionLimits {
            max_preview_items: 1,
            ..ExecutionLimits::modest()
        },
    )?;
    assert_eq!(result.completion(), ExecutionCompletion::Exhausted);
    assert_eq!(result.preview().len(), 1, "the preview is bounded");
    assert_eq!(result.candidate_count(), 2, "the result is not");

    let handle = registry.issue(result);
    assert_eq!(
        registry.verify(&store, &handle, &key(b"alpha"), &[]),
        VerifyOutcome::Ambiguous,
        "the verdict follows the full result, never the preview"
    );
    Ok(())
}

/// The support bound is an actual budget: the result never holds more records
/// than it was allowed to collect.
///
/// The first version of this layer checked the total *after* collecting
/// everything and merely relabelled the completion — which is a very
/// disciplined way to run out of memory, since the caller learns about the
/// budget only once the cost has been paid. The bound now stops the scan.
#[test]
fn the_support_bound_limits_what_is_stored_not_only_what_is_reported() -> Result<()> {
    let store = retry_store()?;
    // alpha and beta each carry two records across attempts 1 and 3.
    let two_blocks = CanonicalQuery::Intersect {
        key: FieldName::parse("line")?,
        sets: vec![set("attempt_1")?, set("attempt_3")?],
    };
    let unbounded = store.execute(&schema()?, two_blocks.clone(), ExecutionLimits::modest())?;
    let stored_records: usize = unbounded
        .complete_result()
        .candidates()
        .iter()
        .filter_map(|c| unbounded.support_for(c))
        .map(<[RecordId]>::len)
        .sum();
    assert_eq!(
        stored_records, 4,
        "premise: four supporting records in total"
    );

    let bounded = store.execute(
        &schema()?,
        two_blocks,
        ExecutionLimits {
            max_support_records: 3,
            ..ExecutionLimits::modest()
        },
    )?;
    let kept: usize = bounded
        .complete_result()
        .candidates()
        .iter()
        .filter_map(|c| bounded.support_for(c))
        .map(<[RecordId]>::len)
        .sum();
    assert!(
        u64::try_from(kept).unwrap_or(u64::MAX) <= 3,
        "the result must hold no more records than the budget allowed, kept {kept}"
    );
    assert!(
        kept < stored_records,
        "and strictly fewer than the unbounded run, or the bound did nothing"
    );
    assert_eq!(
        bounded.completion(),
        ExecutionCompletion::LimitReached { limit: 3 }
    );
    Ok(())
}

/// The candidate bound is an actual budget too.
#[test]
fn the_candidate_bound_limits_what_is_stored() -> Result<()> {
    let store = retry_store()?;
    let bounded = store.execute(
        &schema()?,
        CanonicalQuery::Intersect {
            key: FieldName::parse("line")?,
            sets: vec![set("attempt_1")?, set("attempt_3")?],
        },
        ExecutionLimits {
            max_candidates: 1,
            ..ExecutionLimits::modest()
        },
    )?;
    assert_eq!(
        bounded.candidate_count(),
        1,
        "the result must hold no more candidates than the budget allowed"
    );
    assert_eq!(
        bounded.completion(),
        ExecutionCompletion::LimitReached { limit: 1 }
    );
    Ok(())
}

/// A lookup is bounded by the same record budget.
#[test]
fn a_lookup_is_bounded_by_the_support_budget() -> Result<()> {
    let store = retry_store()?;
    let alpha = CanonicalQuery::Lookup {
        field: FieldName::parse("line")?,
        value: key(b"alpha"),
    };
    let full = store.execute(&schema()?, alpha.clone(), ExecutionLimits::modest())?;
    assert_eq!(
        full.support_for(&key(b"alpha")).unwrap_or_default().len(),
        3
    );
    assert_eq!(full.completion(), ExecutionCompletion::Exhausted);

    let bounded = store.execute(
        &schema()?,
        alpha,
        ExecutionLimits {
            max_support_records: 2,
            ..ExecutionLimits::modest()
        },
    )?;
    assert_eq!(
        bounded
            .support_for(&key(b"alpha"))
            .unwrap_or_default()
            .len(),
        2
    );
    assert_eq!(
        bounded.completion(),
        ExecutionCompletion::LimitReached { limit: 2 }
    );
    Ok(())
}

/// The preview bound changes neither the completion nor the identity: it is a
/// representation of the result, not the result.
#[test]
fn the_preview_bound_does_not_touch_completion_or_identity() -> Result<()> {
    let store = retry_store()?;
    let two_blocks = CanonicalQuery::Intersect {
        key: FieldName::parse("line")?,
        sets: vec![set("attempt_1")?, set("attempt_3")?],
    };
    let wide = store.execute(&schema()?, two_blocks.clone(), ExecutionLimits::modest())?;
    let narrow = store.execute(
        &schema()?,
        two_blocks,
        ExecutionLimits {
            max_preview_items: 1,
            ..ExecutionLimits::modest()
        },
    )?;
    assert_eq!(wide.preview().len(), 2);
    assert_eq!(narrow.preview().len(), 1);
    assert_eq!(wide.completion(), narrow.completion());
    assert_eq!(
        wide.query_result_id(),
        narrow.query_result_id(),
        "how much of a result is shown cannot change what the result is"
    );
    Ok(())
}

/// Limits that leave no room for a result are refused rather than silently
/// producing an empty answer.
#[test]
fn degenerate_limits_are_refused() -> Result<()> {
    let store = retry_store()?;
    assert!(store
        .execute(
            &schema()?,
            intersect_all_three()?,
            ExecutionLimits {
                max_candidates: 0,
                ..ExecutionLimits::modest()
            }
        )
        .is_err());
    // Both clauses, not just the first: a regression dropping the
    // support-records check would otherwise keep this test green.
    assert!(store
        .execute(
            &schema()?,
            intersect_all_three()?,
            ExecutionLimits {
                max_support_records: 0,
                ..ExecutionLimits::modest()
            }
        )
        .is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// Case 13 — completion is a state, not a flag
// ---------------------------------------------------------------------------

/// The same candidates from a finished and an unfinished search are different
/// results, with different identities.
///
/// This is what stops an incomplete result from presenting itself as complete:
/// the completion state is inside the digest, so relabelling it changes the
/// handle and the record no longer resolves.
#[test]
fn completion_state_is_part_of_the_identity() -> Result<()> {
    let store = retry_store()?;
    let two_blocks = CanonicalQuery::Intersect {
        key: FieldName::parse("line")?,
        sets: vec![set("attempt_1")?, set("attempt_3")?],
    };
    let exhausted = store.execute(&schema()?, two_blocks.clone(), ExecutionLimits::modest())?;
    let truncated = store.execute(
        &schema()?,
        two_blocks,
        ExecutionLimits {
            max_candidates: 1,
            ..ExecutionLimits::modest()
        },
    )?;

    assert_eq!(exhausted.completion(), ExecutionCompletion::Exhausted);
    assert_eq!(
        truncated.completion(),
        ExecutionCompletion::LimitReached { limit: 1 }
    );
    assert_ne!(
        exhausted.query_result_id(),
        truncated.query_result_id(),
        "an unfinished search must not be able to wear a finished result's identity"
    );
    Ok(())
}

/// The support encoding — including the completion state — matches an
/// independent reference, byte for byte.
///
/// An earlier test tried to pin this by comparing an exhausted result against
/// one truncated by a bound, asserting the candidate sets were identical. That
/// scenario is no longer constructible, and for a good reason: now that the
/// bounds actually stop the scan, a truncated result necessarily holds less
/// support, so completion can never be the *only* difference between two
/// executions. Pinning it therefore has to happen at the encoding, which is
/// where a golden vector belongs anyway.
///
/// Both constants are derived by `tests/reference/canon_reference.py` and
/// checked by its `--check` mode in CI, so neither is self-attested. The
/// version before this one also asserted two *literals* were unequal, which
/// compared the file to itself and could not fail — caught by CodeRabbit, and
/// exactly the failure mode the rest of this file keeps warning about.
#[test]
fn the_support_encoding_matches_the_independent_reference() -> Result<()> {
    let store = retry_store()?;
    let alpha = CanonicalQuery::Lookup {
        field: FieldName::parse("line")?,
        value: key(b"alpha"),
    };
    let full = store.execute(&schema()?, alpha.clone(), ExecutionLimits::modest())?;
    assert_eq!(
        full.result_support_digest().to_canonical_text(),
        GOLDEN_RETRY_SUPPORT_EXHAUSTED
    );

    let bounded = store.execute(
        &schema()?,
        alpha,
        ExecutionLimits {
            max_support_records: 2,
            ..ExecutionLimits::modest()
        },
    )?;
    assert_eq!(
        bounded.result_support_digest().to_canonical_text(),
        GOLDEN_RETRY_SUPPORT_LIMITED
    );

    // Two executions over the same candidate, differing in completion and in
    // how much support survived, must not share a support digest.
    assert_ne!(
        full.result_support_digest(),
        bounded.result_support_digest(),
        "the completion state and the surviving support must both reach the digest"
    );
    Ok(())
}

/// A handle is looked up by identity, not answered by whatever happens to be
/// in the registry.
///
/// A mutation resolving any stored result for an unknown handle also survived
/// the first version of these tests, because every stale-handle case here left
/// the registry empty. With a *different* result present, the lookup itself
/// has to do the work.
#[test]
fn a_handle_is_not_answered_by_a_different_stored_result() -> Result<()> {
    let store = retry_store()?;
    let mut registry = HarnessResultRegistry::new();

    let stored_one = store.execute(
        &schema()?,
        intersect_all_three()?,
        ExecutionLimits::modest(),
    )?;
    registry.issue(stored_one);

    // A perfectly valid result for a different question, never issued.
    let never_issued = store.execute(
        &schema()?,
        CanonicalQuery::Intersect {
            key: FieldName::parse("line")?,
            sets: vec![set("attempt_1")?, set("attempt_3")?],
        },
        ExecutionLimits::modest(),
    )?;
    assert_eq!(
        registry.verify(&store, never_issued.query_result_id(), &key(b"alpha"), &[]),
        VerifyOutcome::StaleResultHandle,
        "an unissued handle must not be answered by the result that happens to be stored"
    );
    Ok(())
}

/// Each handle resolves to *its own* result when several are stored.
///
/// The companion test above shows an unissued handle is refused. It does not,
/// on its own, pin the lookup: a verifier that grabbed an arbitrary stored
/// result would still be caught by the recomputed-identity check and answer
/// `StaleResultHandle`. That is safe but wrong — a legitimate handle would be
/// reported stale purely because another result was stored first. Verifying
/// both handles in a two-entry registry is what makes the lookup load-bearing,
/// since whichever one sorts second cannot be found by accident.
#[test]
fn every_stored_handle_resolves_to_its_own_result() -> Result<()> {
    let store = retry_store()?;
    let mut registry = HarnessResultRegistry::new();

    let join = store.execute(
        &schema()?,
        intersect_all_three()?,
        ExecutionLimits::modest(),
    )?;
    let lookup = store.execute(
        &schema()?,
        CanonicalQuery::Lookup {
            field: FieldName::parse("line")?,
            value: key(b"gamma"),
        },
        ExecutionLimits::modest(),
    )?;
    assert_ne!(join.query_result_id(), lookup.query_result_id());

    let join_handle = registry.issue(join);
    let lookup_handle = registry.issue(lookup);

    assert_eq!(
        registry.verify(&store, &join_handle, &key(b"alpha"), &[]),
        VerifyOutcome::Valid,
        "the join handle must resolve to the join result"
    );
    assert_eq!(
        registry.verify(&store, &lookup_handle, &key(b"gamma"), &[]),
        VerifyOutcome::Valid,
        "and the lookup handle to the lookup result"
    );
    Ok(())
}

/// Replay reproduces the identity exactly, which is the property the whole
/// scheme exists to provide.
#[test]
fn replaying_the_same_query_reproduces_the_identity() -> Result<()> {
    let store = retry_store()?;
    let first = store.execute(
        &schema()?,
        intersect_all_three()?,
        ExecutionLimits::modest(),
    )?;
    let second = store.execute(
        &schema()?,
        intersect_all_three()?,
        ExecutionLimits::modest(),
    )?;
    assert_eq!(first.query_result_id(), second.query_result_id());

    // A re-opened store is the same store, so it issues the same identity.
    let reopened = retry_store()?;
    let third = reopened.execute(
        &schema()?,
        intersect_all_three()?,
        ExecutionLimits::modest(),
    )?;
    assert_eq!(first.query_result_id(), third.query_result_id());
    Ok(())
}
