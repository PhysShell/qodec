//! RED contracts for the forced-query panel adapter — Slice B.
//!
//! The third C1 arm claims that the model reaches the data only through
//! deterministic execution. That claim is worth exactly as much as the
//! boundaries that enforce it, so each group below is a way the arm could look
//! forced while leaving a way around: the payload leaking into metadata, the
//! store being enumerated through materialize, the preview being mistaken for
//! the result, and a failed query path quietly scoring as a success.

use anyhow::Result;

use qodec::canon::{IndexName, KeyBytes, SchemaId, SetName, SCHEMA_QUERY_V1};
use qodec::panel::{CellOutcome, PanelSession};
use qodec::query::{ExecutionCompletion, ExecutionLimits, VerifyOutcome};
use qodec::store::{IndexSpec, KeyExtractor, RecordId, Segmentation, StorePlan};

fn schema() -> Result<SchemaId> {
    SchemaId::parse(SCHEMA_QUERY_V1)
}

fn key(bytes: &[u8]) -> KeyBytes {
    KeyBytes::new(bytes.to_vec())
}

fn raw_artifact(body: &str) -> String {
    format!("%q1 raw\n%q1 body\n{body}")
}

/// Three retry blocks: `alpha` fails in all three, `beta` in two.
fn retry_artifact() -> String {
    raw_artifact(
        "--- attempt_1 ---\nalpha\nbeta\n\
         --- attempt_2 ---\nalpha\nbeta\n\
         --- attempt_3 ---\nalpha\ngamma\n",
    )
}

fn marked_plan() -> Result<StorePlan> {
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

fn lines_plan() -> Result<StorePlan> {
    StorePlan::new(
        1,
        Segmentation::Lines {
            section: SetName::parse("s")?,
        },
        vec![IndexSpec {
            name: IndexName::parse("line")?,
            extractor: KeyExtractor::WholeRecord,
        }],
    )
}

fn session(artifact: &str, plan: &StorePlan) -> Result<PanelSession> {
    PanelSession::open(artifact, plan, schema()?, ExecutionLimits::modest())
}

fn attempts() -> Result<Vec<SetName>> {
    Ok(vec![
        SetName::parse("attempt_1")?,
        SetName::parse("attempt_2")?,
        SetName::parse("attempt_3")?,
    ])
}

// ---------------------------------------------------------------------------
// The payload does not reach the model
// ---------------------------------------------------------------------------

/// Metadata carries shapes and counts, never record bytes.
///
/// The strongest available statement: take every record the store holds and
/// assert none of them appears in the rendered metadata. A weaker test that
/// merely checked a couple of fields would pass a metadata struct that had
/// grown a `sample_records` field for debugging convenience.
#[test]
fn metadata_contains_no_record_bytes() -> Result<()> {
    let artifact = retry_artifact();
    let mut sess = session(&artifact, &marked_plan()?)?;
    let rendered = sess.metadata()?.render();

    for token in ["alpha", "beta", "gamma"] {
        assert!(
            !rendered.contains(token),
            "metadata leaked the record {token:?}:\n{rendered}"
        );
    }
    // And the shapes it *should* carry are present, so the test is not passing
    // because the metadata is empty.
    assert!(rendered.contains("attempt_1"), "section names are metadata");
    assert!(rendered.contains("records: 6"), "counts are metadata");

    // The tool surface is what the model gets instead of the body.
    let hits = sess.lookup(&IndexName::parse("line")?, &key(b"alpha"))?;
    assert_eq!(hits.candidate_count, 1);
    Ok(())
}

/// Section names are not record bytes, and the distinction has to survive a
/// section whose name happens to equal a record's text.
#[test]
fn a_section_named_like_a_record_still_reveals_nothing() -> Result<()> {
    // The marker line names the section "alpha"; a record also reads "alpha".
    let artifact = raw_artifact("--- alpha ---\nalpha\nbeta\n");
    let mut sess = session(&artifact, &marked_plan()?)?;
    let rendered = sess.metadata()?.render();
    assert!(
        rendered.contains("alpha"),
        "the section name is legitimately metadata"
    );
    assert!(
        !rendered.contains("beta"),
        "…but a record that is not a section name must not appear:\n{rendered}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Materialize is scoped to the handle that issued the ids
// ---------------------------------------------------------------------------

/// Ids inside the result's own support materialize.
#[test]
fn support_ids_materialize_through_their_own_handle() -> Result<()> {
    let artifact = retry_artifact();
    let mut sess = session(&artifact, &marked_plan()?)?;
    let hit = sess.lookup(&IndexName::parse("line")?, &key(b"alpha"))?;
    let bytes = sess.materialize(&hit.handle, &hit.support)?;
    assert_eq!(bytes.len(), 3, "alpha appears in all three attempts");
    for b in &bytes {
        assert_eq!(b.as_slice(), b"alpha");
    }
    Ok(())
}

/// A record id the result does not support is refused, even though the store
/// holds it and could resolve it perfectly well.
///
/// This is the boundary that stops the query interface from degrading into a
/// file browser: without it, a caller who obtained any handle could walk the
/// whole store one id at a time and reassemble the payload the arm exists to
/// withhold.
#[test]
fn an_id_outside_the_results_support_is_refused() -> Result<()> {
    let artifact = retry_artifact();
    let mut sess = session(&artifact, &marked_plan()?)?;

    let alpha = sess.lookup(&IndexName::parse("line")?, &key(b"alpha"))?;
    let gamma = sess.lookup(&IndexName::parse("line")?, &key(b"gamma"))?;

    // gamma's support is a real, resolvable id in this very store...
    assert_eq!(sess.materialize(&gamma.handle, &gamma.support)?.len(), 1);
    // ...and it is still refused against alpha's handle.
    let outcome = sess
        .materialize(&alpha.handle, &gamma.support)
        .map_err(|e| e.to_string());
    assert!(
        outcome
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("not in the support")),
        "a foreign-to-this-result id must be refused; got {outcome:?}"
    );
    Ok(())
}

/// Materialize refuses an unknown handle rather than falling back to the store.
#[test]
fn materialize_through_an_unknown_handle_is_refused() -> Result<()> {
    let artifact = retry_artifact();
    let mut sess = session(&artifact, &marked_plan()?)?;
    let hit = sess.lookup(&IndexName::parse("line")?, &key(b"alpha"))?;
    let ids = hit.support.clone();

    assert!(sess.evict(&hit.handle), "premise: the handle existed");
    let outcome = sess
        .materialize(&hit.handle, &ids)
        .map_err(|e| e.to_string());
    assert!(
        outcome
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("unknown or evicted")),
        "an evicted handle must stop authorizing reads; got {outcome:?}"
    );
    Ok(())
}

/// Eviction clears the scope as well as the registry.
///
/// Kept separate from the test above because the two could be satisfied by
/// different bugs: a scope that outlives its registry entry would still refuse
/// *this* call while leaving the ids authorized for a later handle collision.
#[test]
fn eviction_removes_the_scope_not_only_the_result() -> Result<()> {
    let artifact = retry_artifact();
    let mut sess = session(&artifact, &marked_plan()?)?;
    let hit = sess.lookup(&IndexName::parse("line")?, &key(b"alpha"))?;
    sess.evict(&hit.handle);

    // Re-running the identical query reissues the same handle — the identity is
    // content-addressed — and it must authorize again only because the scope was
    // rebuilt, not because a stale entry survived.
    let again = sess.lookup(&IndexName::parse("line")?, &key(b"alpha"))?;
    assert_eq!(
        again.handle, hit.handle,
        "premise: identity is deterministic"
    );
    assert_eq!(sess.materialize(&again.handle, &again.support)?.len(), 3);
    Ok(())
}

// ---------------------------------------------------------------------------
// The preview is not the result
// ---------------------------------------------------------------------------

/// A preview showing one candidate over an ambiguous result does not rescue it.
///
/// The model is free to answer from the preview — that is a deterministic
/// query's official output, not a private reading of the artifact. What it must
/// not gain is anything from the truncation.
#[test]
fn answering_from_a_truncated_preview_is_still_ambiguous() -> Result<()> {
    let artifact = raw_artifact("alpha\nbeta\n");
    let plan = lines_plan()?;
    let mut sess = PanelSession::open(
        &artifact,
        &plan,
        schema()?,
        ExecutionLimits {
            max_preview_items: 1,
            ..ExecutionLimits::modest()
        },
    )?;

    let hit = sess.intersect(&IndexName::parse("line")?, &[SetName::parse("s")?])?;
    assert_eq!(hit.preview.len(), 1, "premise: the preview is truncated");
    assert_eq!(hit.candidate_count, 2, "…over a two-candidate result");

    let shown = hit.preview.first().cloned().unwrap_or_else(|| key(b""));
    let outcome = sess.answer(&hit.handle, &shown, &hit.support);
    assert_eq!(
        outcome,
        CellOutcome::QueryPathFailed {
            verdict: VerifyOutcome::Ambiguous
        },
        "the stored complete result decides, not the preview"
    );
    Ok(())
}

/// The preview bound changes neither the identity nor the reported count.
#[test]
fn the_preview_bound_does_not_move_the_handle_or_the_count() -> Result<()> {
    let artifact = raw_artifact("alpha\nbeta\n");
    let plan = lines_plan()?;
    let mut wide_sess = PanelSession::open(&artifact, &plan, schema()?, ExecutionLimits::modest())?;
    let wide = wide_sess.intersect(&IndexName::parse("line")?, &[SetName::parse("s")?])?;

    let mut narrow_sess = PanelSession::open(
        &artifact,
        &plan,
        schema()?,
        ExecutionLimits {
            max_preview_items: 1,
            ..ExecutionLimits::modest()
        },
    )?;
    let narrow = narrow_sess.intersect(&IndexName::parse("line")?, &[SetName::parse("s")?])?;

    assert_ne!(wide.preview.len(), narrow.preview.len(), "premise");
    assert_eq!(
        wide.handle, narrow.handle,
        "the preview is outside identity"
    );
    assert_eq!(wide.candidate_count, narrow.candidate_count);
    Ok(())
}

// ---------------------------------------------------------------------------
// A failed query path is a failed cell
// ---------------------------------------------------------------------------

/// The single-candidate happy path.
#[test]
fn a_single_candidate_answer_is_accepted() -> Result<()> {
    let artifact = retry_artifact();
    let mut sess = session(&artifact, &marked_plan()?)?;
    let hit = sess.intersect(&IndexName::parse("line")?, &attempts()?)?;
    assert_eq!(hit.candidate_count, 1, "only alpha is in every attempt");
    let answer = hit.preview.first().cloned().unwrap_or_else(|| key(b""));
    assert_eq!(
        sess.answer(&hit.handle, &answer, &hit.support),
        CellOutcome::Accepted
    );
    Ok(())
}

/// Every non-`Valid` verdict is a failed cell that asks for a separate
/// diagnostic, never a silent retry inside the same cell.
#[test]
fn every_non_valid_verdict_fails_the_cell_and_flags_fallback() -> Result<()> {
    let artifact = retry_artifact();
    let mut sess = session(&artifact, &marked_plan()?)?;
    let hit = sess.intersect(&IndexName::parse("line")?, &attempts()?)?;

    // Wrong answer.
    let wrong = sess.answer(&hit.handle, &key(b"not-a-candidate"), &hit.support);
    assert_eq!(
        wrong,
        CellOutcome::QueryPathFailed {
            verdict: VerifyOutcome::Invalid
        }
    );
    assert!(wrong.fallback_required());

    // Cited evidence outside the real support.
    let answer = hit.preview.first().cloned().unwrap_or_else(|| key(b""));
    let beta = sess.lookup(&IndexName::parse("line")?, &key(b"beta"))?;
    let intruder: Vec<RecordId> = beta.support.clone();
    let unverifiable = sess.answer(&hit.handle, &answer, &intruder);
    assert!(
        matches!(
            unverifiable,
            CellOutcome::QueryPathFailed {
                verdict: VerifyOutcome::Unverifiable
            }
        ),
        "evidence outside the support must not verify; got {unverifiable:?}"
    );
    assert!(unverifiable.fallback_required());

    // A stale handle is terminal, not a prompt to recompute.
    let stale = sess.intersect(&IndexName::parse("line")?, &attempts()?)?;
    sess.evict(&stale.handle);
    let gone = sess.answer(&stale.handle, &answer, &stale.support);
    assert_eq!(
        gone,
        CellOutcome::QueryPathFailed {
            verdict: VerifyOutcome::StaleResultHandle
        }
    );
    assert!(gone.fallback_required());

    // And the accepted path does *not* ask for a fallback, so the flag carries
    // information rather than being universally true.
    assert!(!CellOutcome::Accepted.fallback_required());
    Ok(())
}

/// Hitting an execution bound makes the cell fail rather than answer.
#[test]
fn an_incomplete_execution_fails_the_cell() -> Result<()> {
    let artifact = raw_artifact("alpha\nbeta\ngamma\n");
    let plan = lines_plan()?;
    let mut sess = PanelSession::open(
        &artifact,
        &plan,
        schema()?,
        ExecutionLimits {
            max_candidates: 1,
            ..ExecutionLimits::modest()
        },
    )?;
    let hit = sess.intersect(&IndexName::parse("line")?, &[SetName::parse("s")?])?;
    assert!(
        matches!(hit.completion, ExecutionCompletion::LimitReached { .. }),
        "premise: the scan stopped at a bound"
    );
    let answer = hit.preview.first().cloned().unwrap_or_else(|| key(b""));
    assert_eq!(
        sess.answer(&hit.handle, &answer, &hit.support),
        CellOutcome::QueryPathFailed {
            verdict: VerifyOutcome::Incomplete
        },
        "absence proves nothing once the search stopped early"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The transcript is the measurement
// ---------------------------------------------------------------------------

/// The transcript is the measurement, so it records what actually crossed the
/// boundary — values, not counts.
///
/// The earlier version of this contract asserted three query calls and called
/// that the tool path. It was green while `materialize` and `answer` recorded
/// nothing at all, and while a query event stored `preview.len()` in place of
/// the candidates. Neither omission is a correctness hole; both are accounting
/// holes, and a length cannot be tokenized.
#[test]
fn the_transcript_records_the_whole_tool_path_with_real_values() -> Result<()> {
    let artifact = retry_artifact();
    let mut sess = session(&artifact, &marked_plan()?)?;

    sess.metadata()?;
    let hit = sess.intersect(&IndexName::parse("line")?, &attempts()?)?;
    // A refused materialize, then a valid one.
    let beta = sess.lookup(&IndexName::parse("line")?, &key(b"beta"))?;
    assert!(sess.materialize(&hit.handle, &beta.support).is_err());
    sess.materialize(&hit.handle, &hit.support)?;
    let answer = hit.preview.first().cloned().unwrap_or_else(|| key(b""));
    sess.answer(&hit.handle, &answer, &hit.support);

    let jsonl = sess.transcript_jsonl();
    let lines: Vec<&str> = jsonl.lines().collect();
    assert_eq!(lines.len(), 6, "metadata + 4 tool calls + final answer");

    let events: Vec<serde_json::Value> = lines
        .iter()
        .map(|l| serde_json::from_str(l))
        .collect::<std::result::Result<_, _>>()?;
    let kinds: Vec<&str> = events
        .iter()
        .filter_map(|e| e.get("event").and_then(|v| v.as_str()))
        .collect();
    assert_eq!(
        kinds,
        [
            "metadata",
            "tool_call",
            "tool_call",
            "tool_call",
            "tool_call",
            "final_answer"
        ],
        "materialize and answer must appear, not only the queries"
    );

    // The refused materialize is in the record, with ok:false.
    let refused = events
        .iter()
        .find(|e| e.pointer("/outcome/ok") == Some(&serde_json::Value::Bool(false)));
    assert!(refused.is_some(), "a refusal must be recorded, not dropped");

    // The query event carries the actual candidates and support ids.
    let query = events
        .iter()
        .find(|e| e.get("tool").and_then(|v| v.as_str()) == Some("qodec_intersect"))
        .ok_or_else(|| anyhow::anyhow!("no intersect event"))?;
    let preview = query
        .pointer("/outcome/preview")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("preview must be an array of envelopes"))?;
    assert_eq!(
        preview.first().and_then(|v| v.get("display_utf8")),
        Some(&serde_json::Value::from("alpha")),
        "the candidate itself, not its length"
    );
    let support = query
        .pointer("/outcome/support")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("support must be an array of record envelopes"))?;
    assert_eq!(support.len(), 3);
    assert!(
        support.first().and_then(|v| v.get("ordinal")).is_some(),
        "record ids are structured, not counted"
    );

    // Materialized bytes go through the byte envelope.
    let mat = events
        .iter()
        .find(|e| {
            e.get("tool").and_then(|v| v.as_str()) == Some("qodec_materialize")
                && e.pointer("/outcome/ok") == Some(&serde_json::Value::Bool(true))
        })
        .ok_or_else(|| anyhow::anyhow!("no successful materialize event"))?;
    let records = mat
        .pointer("/outcome/records")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("records must be an array"))?;
    assert_eq!(records.len(), 3);
    assert_eq!(
        records.first().and_then(|v| v.get("encoding")),
        Some(&serde_json::Value::from("base64url-nopad")),
        "materialized bytes use the byte envelope, never Debug or lossy UTF-8"
    );

    // The final answer carries the verdict.
    let final_event = events
        .last()
        .ok_or_else(|| anyhow::anyhow!("no final event"))?;
    assert_eq!(
        final_event.get("verdict").and_then(|v| v.as_str()),
        Some("valid")
    );
    Ok(())
}

/// A non-UTF-8 key survives the transcript as bytes.
#[test]
fn transcript_arguments_are_byte_safe() -> Result<()> {
    let mut sess = PanelSession::open(
        &raw_artifact("x\n"),
        &lines_plan()?,
        schema()?,
        ExecutionLimits::modest(),
    )?;
    sess.lookup(&IndexName::parse("line")?, &key(&[0xFF, 0x00]))?;
    let jsonl = sess.transcript_jsonl();
    assert!(
        !jsonl.contains('\u{FFFD}'),
        "a non-UTF-8 key must not become replacement characters: {jsonl}"
    );
    let event: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap_or("{}"))?;
    let data = event
        .pointer("/arguments/key/data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("key must be a byte envelope"))?;
    assert_eq!(data, "_wA", "0xFF 0x00 in base64url-nopad");
    assert!(
        event.pointer("/arguments/key/display_utf8").is_none(),
        "invalid UTF-8 gets no courtesy field"
    );
    Ok(())
}

/// Serializing the same session twice yields identical bytes.
#[test]
fn the_canonical_transcript_is_deterministic() -> Result<()> {
    let artifact = retry_artifact();
    let mut a = session(&artifact, &marked_plan()?)?;
    let mut b = session(&artifact, &marked_plan()?)?;
    for sess in [&mut a, &mut b] {
        sess.metadata()?;
        let hit = sess.intersect(&IndexName::parse("line")?, &attempts()?)?;
        sess.materialize(&hit.handle, &hit.support)?;
        let answer = hit.preview.first().cloned().unwrap_or_else(|| key(b""));
        sess.answer(&hit.handle, &answer, &hit.support);
    }
    assert_eq!(
        a.transcript_jsonl(),
        b.transcript_jsonl(),
        "two identical sessions must serialize byte-for-byte alike"
    );
    Ok(())
}
