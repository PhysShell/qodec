//! RED contracts for the canonical store and index — Slice A, #14.
//!
//! Written against the invariants before the query surface grows on top of
//! them. Each group corresponds to a way the store could look correct while
//! being wrong: a key silently decoded, two records merged into one, an index
//! whose order depends on the run, a materialization that reconstructs rather
//! than returns, and a loader that believes a file because the file said so.

use anyhow::Result;

use qodec::canon::{
    canonical_query_digest, complete_result_digest, digest_store_plan_bytes, query_result_id,
    store_id, ArtifactDigest, CanonicalQuery, CanonicalResult, CompleteResultDigest, FieldName,
    IndexName, KeyBytes, SchemaId, SetName, StorePlanDigest, StoredQueryResult, SCHEMA_QUERY_V1,
};
use qodec::store::{CanonicalStore, IndexSpec, KeyExtractor, RecordId, Segmentation};

fn set(name: &str) -> Result<SetName> {
    SetName::parse(name)
}

fn index(name: &str) -> Result<IndexName> {
    IndexName::parse(name)
}

fn key(bytes: &[u8]) -> KeyBytes {
    KeyBytes::new(bytes.to_vec())
}

/// A well-formed `%q1 raw` container: the body passes through decode
/// unchanged, which keeps these contracts about the store rather than about a
/// codec. The `%q1 body` line is required — an artifact without it is not a
/// container at all.
fn raw_artifact(body: &str) -> String {
    format!("%q1 raw\n%q1 body\n{body}")
}

fn lines_seg() -> Result<Segmentation> {
    Ok(Segmentation::Lines { section: set("s")? })
}

fn whole_record_index() -> Result<Vec<IndexSpec>> {
    Ok(vec![IndexSpec {
        name: index("line")?,
        extractor: KeyExtractor::WholeRecord,
    }])
}

// ---------------------------------------------------------------------------
// Record identity
// ---------------------------------------------------------------------------

/// Identical RAW records at different positions stay two records.
///
/// This is why `RecordId` is not a hash of the record bytes: content-only
/// identity would merge them with no cryptographic collision involved and no
/// error to notice, and the store would confidently report one occurrence of
/// something that happened twice.
#[test]
fn identical_records_at_different_positions_stay_distinct() -> Result<()> {
    let store = CanonicalStore::open(
        &raw_artifact("dup\ndup\ndup\n"),
        &lines_seg()?,
        &whole_record_index()?,
    )?;
    assert_eq!(store.record_count(), 3, "three lines are three records");

    let hits = store.lookup(&index("line")?, &key(b"dup"))?;
    assert_eq!(hits.len(), 3, "all three positions must be indexed");
    let ordinals: Vec<u64> = hits.iter().map(RecordId::ordinal).collect();
    assert_eq!(ordinals, [0, 1, 2], "positions are distinct and ordered");

    // And they materialize to the same bytes without being the same record.
    let bytes = store.materialize(&hits)?;
    assert_eq!(bytes, [b"dup".as_slice(); 3]);
    Ok(())
}

/// Record ids are stable across independent opens of the same artifact.
#[test]
fn record_ids_are_stable_across_replays() -> Result<()> {
    let artifact = raw_artifact("a\nb\nc\n");
    let first = CanonicalStore::open(&artifact, &lines_seg()?, &whole_record_index()?)?;
    let second = CanonicalStore::open(&artifact, &lines_seg()?, &whole_record_index()?)?;

    let ids_a: Vec<RecordId> = first.record_ids().collect();
    let ids_b: Vec<RecordId> = second.record_ids().collect();
    assert_eq!(ids_a, ids_b, "ids and their order must reproduce exactly");
    assert_eq!(first.artifact_digest(), second.artifact_digest());
    Ok(())
}

/// A different artifact is a different artifact digest, so ids from one store
/// mean nothing in another even when they look identical.
#[test]
fn artifact_digest_binds_the_store() -> Result<()> {
    let a = CanonicalStore::open(&raw_artifact("x\n"), &lines_seg()?, &whole_record_index()?)?;
    let b = CanonicalStore::open(&raw_artifact("y\n"), &lines_seg()?, &whole_record_index()?)?;
    assert_ne!(a.artifact_digest(), b.artifact_digest());
    Ok(())
}

// ---------------------------------------------------------------------------
// Byte keys through the index
// ---------------------------------------------------------------------------

/// A key that is not valid UTF-8 survives extraction, indexing and lookup.
///
/// Reachable in practice: splitting on a UTF-8 continuation byte cuts a
/// multi-byte character, so the field before it ends mid-sequence. Nothing in
/// the path may decode, replace or truncate it.
#[test]
fn non_utf8_key_round_trips_through_the_index() -> Result<()> {
    // "é" is C3 A9; splitting on A9 leaves a field ending in a lone C3.
    let store = CanonicalStore::open(
        &raw_artifact("é1\n"),
        &lines_seg()?,
        &[IndexSpec {
            name: index("split")?,
            extractor: KeyExtractor::Field {
                separator: 0xA9,
                index: 0,
            },
        }],
    )?;
    let broken = key(&[0xC3]);
    assert!(
        String::from_utf8(broken.as_bytes().to_vec()).is_err(),
        "premise: the extracted key is not valid UTF-8"
    );
    assert_eq!(
        store.lookup(&index("split")?, &broken)?.len(),
        1,
        "an invalid-UTF-8 key must be indexed and findable as itself"
    );
    Ok(())
}

/// Two different invalid sequences must not collapse into one key.
#[test]
fn distinct_invalid_sequences_do_not_collapse_in_the_index() -> Result<()> {
    let store = CanonicalStore::open(
        &raw_artifact("é1\nê1\n"),
        &lines_seg()?,
        &[IndexSpec {
            name: index("split")?,
            extractor: KeyExtractor::Field {
                separator: 0xA9,
                index: 0,
            },
        }],
    )?;
    // "é" = C3 A9 → field "C3"; "ê" = C3 AA, which contains no A9, so the
    // whole line is the field. Two different keys, neither of them UTF-8.
    let a = store.lookup(&index("split")?, &key(&[0xC3]))?;
    assert_eq!(
        a.iter().map(RecordId::ordinal).collect::<Vec<_>>(),
        [0],
        "the truncated key matches exactly the record it came from, not its neighbour"
    );
    Ok(())
}

/// An interior NUL is an ordinary key byte, not a terminator.
#[test]
fn interior_nul_does_not_truncate_an_index_key() -> Result<()> {
    let store = CanonicalStore::open(
        &raw_artifact("ab\0cd\nab\n"),
        &lines_seg()?,
        &whole_record_index()?,
    )?;
    assert_eq!(store.lookup(&index("line")?, &key(b"ab\0cd"))?.len(), 1);
    assert_eq!(store.lookup(&index("line")?, &key(b"ab"))?.len(), 1);
    assert!(
        store.lookup(&index("line")?, &key(b"ab\0"))?.is_empty(),
        "a prefix is not a key"
    );
    Ok(())
}

/// Normalization forms index as the distinct byte strings they are.
#[test]
fn normalization_forms_index_distinctly() -> Result<()> {
    let store = CanonicalStore::open(
        &raw_artifact("é\ne\u{301}\n"),
        &lines_seg()?,
        &whole_record_index()?,
    )?;
    assert_eq!(store.record_count(), 2);
    assert_eq!(
        store.lookup(&index("line")?, &key("é".as_bytes()))?.len(),
        1
    );
    assert_eq!(
        store
            .lookup(&index("line")?, &key("e\u{301}".as_bytes()))?
            .len(),
        1
    );
    Ok(())
}

/// A record without the requested field is absent from that index rather than
/// indexed under an empty key.
#[test]
fn a_missing_field_is_missing_not_empty() -> Result<()> {
    let store = CanonicalStore::open(
        &raw_artifact("a:b\nnoseparator\n"),
        &lines_seg()?,
        &[IndexSpec {
            name: index("second")?,
            extractor: KeyExtractor::Field {
                separator: b':',
                index: 1,
            },
        }],
    )?;
    assert_eq!(store.lookup(&index("second")?, &key(b"b"))?.len(), 1);
    assert!(
        store.lookup(&index("second")?, &key(b""))?.is_empty(),
        "the record with no second field must not appear under the empty key"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Index shape and ordering
// ---------------------------------------------------------------------------

/// Record id lists are sorted and deduplicated, and the order reproduces.
#[test]
fn index_lists_are_sorted_unique_and_reproducible() -> Result<()> {
    let artifact = raw_artifact("k\nk\nother\nk\n");
    let first = CanonicalStore::open(&artifact, &lines_seg()?, &whole_record_index()?)?;
    let second = CanonicalStore::open(&artifact, &lines_seg()?, &whole_record_index()?)?;

    let a = first.lookup(&index("line")?, &key(b"k"))?;
    let b = second.lookup(&index("line")?, &key(b"k"))?;
    assert_eq!(a, b, "identical input must give an identical list");
    assert_eq!(
        a.iter().map(RecordId::ordinal).collect::<Vec<_>>(),
        [0, 1, 3]
    );

    let mut sorted = a.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(a, sorted, "the list must already be sorted and unique");
    Ok(())
}

/// Asking about an index that does not exist is an error; asking about a key
/// that is not present is an empty answer. Collapsing the two would let a typo
/// read as evidence of absence.
#[test]
fn unknown_index_errors_but_absent_key_is_empty() -> Result<()> {
    let store = CanonicalStore::open(&raw_artifact("a\n"), &lines_seg()?, &whole_record_index()?)?;
    assert!(store.lookup(&index("nope")?, &key(b"a")).is_err());
    assert!(store.lookup(&index("line")?, &key(b"zzz"))?.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// Intersection across sections
// ---------------------------------------------------------------------------

/// The join the reader panels kept failing: a key counts only when it appears
/// in every requested section.
#[test]
fn intersect_requires_presence_in_every_section() -> Result<()> {
    let artifact = raw_artifact(
        "--- attempt_1 ---\nalpha\nbeta\n\
         --- attempt_2 ---\nalpha\ngamma\n\
         --- attempt_3 ---\nalpha\nbeta\n",
    );
    let seg = Segmentation::MarkedSections {
        prefix: "--- ".into(),
        suffix: " ---".into(),
        preamble: set("preamble")?,
    };
    let store = CanonicalStore::open(&artifact, &seg, &whole_record_index()?)?;

    let all_three = store.intersect(
        &index("line")?,
        &[set("attempt_1")?, set("attempt_2")?, set("attempt_3")?],
    )?;
    assert_eq!(
        all_three.candidates(),
        [key(b"alpha")],
        "only alpha appears in all three sections"
    );

    let two = store.intersect(&index("line")?, &[set("attempt_1")?, set("attempt_3")?])?;
    assert_eq!(two.candidates(), [key(b"alpha"), key(b"beta")]);
    Ok(())
}

/// A section that does not exist is an error, not an empty intersection —
/// otherwise a misspelled section name would read as "nothing qualifies".
#[test]
fn unknown_section_is_an_error() -> Result<()> {
    let store = CanonicalStore::open(&raw_artifact("a\n"), &lines_seg()?, &whole_record_index()?)?;
    assert!(store.intersect(&index("line")?, &[set("absent")?]).is_err());
    assert!(store.intersect(&index("line")?, &[]).is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// Materialization
// ---------------------------------------------------------------------------

/// Materialized bytes are the stored bytes, exactly.
#[test]
fn materialized_bytes_equal_the_source_lines() -> Result<()> {
    let body = "first line\nsecond\u{feff} line\nthird\0line\n";
    let store = CanonicalStore::open(&raw_artifact(body), &lines_seg()?, &whole_record_index()?)?;
    let ids: Vec<RecordId> = store.record_ids().collect();
    let got = store.materialize(&ids)?;
    let want: Vec<&[u8]> = body.lines().map(str::as_bytes).collect();
    assert_eq!(got, want, "materialization must return the source bytes");
    Ok(())
}

/// An unknown id fails the whole call rather than returning a short list that
/// would look like evidence while quietly omitting what did not resolve.
#[test]
fn materialize_refuses_partial_results() -> Result<()> {
    let store = CanonicalStore::open(&raw_artifact("a\n"), &lines_seg()?, &whole_record_index()?)?;
    let mut ids: Vec<RecordId> = store.record_ids().collect();
    let other = CanonicalStore::open(
        &raw_artifact("a\nb\n"),
        &lines_seg()?,
        &whole_record_index()?,
    )?;
    ids.extend(other.record_ids());
    assert!(
        store.materialize(&ids).is_err(),
        "an id this store never issued must fail the call"
    );
    Ok(())
}

/// A foreign id whose coordinates exist locally must be rejected on the
/// binding alone — case 10 of the negative matrix.
///
/// This test exists because the previous revision failed the property while
/// its test passed. `s#0` exists in almost every store, so a foreign id
/// resolved against local records and returned another artifact's bytes with
/// no error anywhere; the old test only went red later, on a second id that
/// happened not to exist. A test that is green because of a different bug is
/// worse than no test, so this one passes a single id whose coordinates are
/// certainly present.
#[test]
fn a_foreign_id_with_local_coordinates_is_rejected() -> Result<()> {
    let a = CanonicalStore::open(
        &raw_artifact("alpha\n"),
        &lines_seg()?,
        &whole_record_index()?,
    )?;
    let b = CanonicalStore::open(
        &raw_artifact("beta\n"),
        &lines_seg()?,
        &whole_record_index()?,
    )?;

    let from_b: Vec<RecordId> = b.record_ids().collect();
    let local: Vec<RecordId> = a.record_ids().collect();
    let (Some(foreign), Some(mine)) = (from_b.first(), local.first()) else {
        anyhow::bail!("both stores must yield exactly one record");
    };

    // The coordinates unquestionably exist in A; only the binding differs.
    assert_eq!(foreign.section(), mine.section());
    assert_eq!(foreign.ordinal(), mine.ordinal());
    assert_ne!(foreign.store_id(), mine.store_id());

    let outcome = a.materialize(&from_b).map_err(|e| e.to_string());
    assert!(
        outcome
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("store-mismatch")),
        "a foreign id must be refused on its binding, however familiar its \
         coordinates look; got {outcome:?}"
    );
    Ok(())
}

/// The same artifact opened under two plans issues two incompatible ids for
/// the same coordinates — case 10 in its second form.
///
/// Fixing the cross-artifact case did not fix this one, and the difference is
/// instructive: both stores here have the *identical* artifact digest, so any
/// binding weaker than the store id waves the foreign id straight through.
/// `Lines` sees `--- s ---` at `s#0`; `MarkedSections` sees `alpha` there.
/// Measured on the previous revision before the fix: store A returned
/// `"--- s ---"` for an id that meant `"alpha"`.
#[test]
fn record_id_from_another_plan_over_same_artifact_is_rejected() -> Result<()> {
    let artifact = raw_artifact("--- s ---\nalpha\n");
    let by_lines = CanonicalStore::open(&artifact, &lines_seg()?, &whole_record_index()?)?;
    let by_marks = CanonicalStore::open(
        &artifact,
        &Segmentation::MarkedSections {
            prefix: "--- ".into(),
            suffix: " ---".into(),
            preamble: set("preamble")?,
        },
        &whole_record_index()?,
    )?;

    assert_eq!(
        by_lines.artifact_digest(),
        by_marks.artifact_digest(),
        "premise: one artifact, so the artifact digest cannot distinguish them"
    );
    assert_ne!(
        by_lines.store_id(),
        by_marks.store_id(),
        "two plans over one artifact are two stores"
    );

    // `s#0` exists in both, and means different bytes in each.
    let from_marks: Vec<RecordId> = by_marks
        .record_ids()
        .filter(|id| id.section().as_str() == "s")
        .collect();
    let (Some(foreign),) = (from_marks.first(),) else {
        anyhow::bail!("the marked plan must place a record at s#0");
    };
    assert_eq!(foreign.ordinal(), 0);
    assert_eq!(
        by_marks.materialize(&from_marks)?,
        [b"alpha".as_slice()],
        "in its own store the id means `alpha`"
    );

    let outcome = by_lines.materialize(&from_marks).map_err(|e| e.to_string());
    assert!(
        outcome
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("store-mismatch")),
        "an id from another plan must be refused on its store binding, not \
         silently resolved to this plan's line; got {outcome:?}"
    );
    Ok(())
}

/// A different plan over the same artifact changes the store id even when the
/// segmentation is identical and only the indexes differ.
#[test]
fn index_specs_are_part_of_the_plan() -> Result<()> {
    let artifact = raw_artifact("a:b\n");
    let whole = CanonicalStore::open(&artifact, &lines_seg()?, &whole_record_index()?)?;
    let field = CanonicalStore::open(
        &artifact,
        &lines_seg()?,
        &[IndexSpec {
            name: index("line")?,
            extractor: KeyExtractor::Field {
                separator: b':',
                index: 0,
            },
        }],
    )?;
    assert_eq!(whole.artifact_digest(), field.artifact_digest());
    assert_ne!(
        whole.store_id(),
        field.store_id(),
        "the indexes are part of how the artifact was opened"
    );
    Ok(())
}

/// Spec order is not part of the plan: the same set of indexes listed in
/// either order opens the same store.
#[test]
fn spec_order_does_not_change_the_store_id() -> Result<()> {
    let artifact = raw_artifact("a:b\n");
    let one = IndexSpec {
        name: index("whole")?,
        extractor: KeyExtractor::WholeRecord,
    };
    let two = IndexSpec {
        name: index("first")?,
        extractor: KeyExtractor::Field {
            separator: b':',
            index: 0,
        },
    };
    let forward = CanonicalStore::open(&artifact, &lines_seg()?, &[one.clone(), two.clone()])?;
    let reverse = CanonicalStore::open(&artifact, &lines_seg()?, &[two, one])?;
    assert_eq!(
        forward.store_id(),
        reverse.store_id(),
        "specs are canonicalized by name, so caller order cannot rename the store"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Declared sections
// ---------------------------------------------------------------------------

/// A section that is declared but holds no records intersects to an empty
/// result, not to an error.
///
/// The two answers mean opposite things. "No such section" says the question
/// was malformed; an empty result says the question was fine and nothing
/// qualified. Deriving the known sections from the records that happen to
/// exist collapses them, so a correctly spelled empty section would be
/// reported as a typo.
#[test]
fn a_declared_but_empty_section_intersects_to_nothing() -> Result<()> {
    let artifact = raw_artifact("--- attempt_1 ---\n--- attempt_2 ---\nalpha\n");
    let seg = Segmentation::MarkedSections {
        prefix: "--- ".into(),
        suffix: " ---".into(),
        preamble: set("preamble")?,
    };
    let store = CanonicalStore::open(&artifact, &seg, &whole_record_index()?)?;

    let known: Vec<&SetName> = store.sections().collect();
    assert!(
        known.contains(&&set("attempt_1")?),
        "an empty section is still a section: {known:?}"
    );

    let empty = store.intersect(&index("line")?, &[set("attempt_1")?])?;
    assert!(
        empty.candidates().is_empty(),
        "intersecting an empty section yields nothing, and is not an error"
    );
    assert_eq!(
        store
            .intersect(&index("line")?, &[set("attempt_2")?])?
            .candidates(),
        [key(b"alpha")]
    );
    Ok(())
}

/// An artifact with no records still declares its single section.
#[test]
fn an_empty_artifact_still_declares_its_section() -> Result<()> {
    let store = CanonicalStore::open(&raw_artifact(""), &lines_seg()?, &whole_record_index()?)?;
    assert_eq!(store.record_count(), 0);
    assert_eq!(store.sections().collect::<Vec<_>>(), [&set("s")?]);
    assert!(store
        .intersect(&index("line")?, &[set("s")?])?
        .candidates()
        .is_empty());
    assert!(store.intersect(&index("line")?, &[set("other")?]).is_err());
    Ok(())
}

/// Re-opening a section is refused explicitly rather than left to collide.
///
/// Resuming would need an ordinal continuation rule, and inventing one
/// silently is how two records quietly become one. Refusing is a defensible
/// limitation; discovering it later as a duplicate-id error would not be.
#[test]
fn reopening_a_section_is_refused() -> Result<()> {
    let artifact = raw_artifact("--- a ---\nx\n--- b ---\ny\n--- a ---\nz\n");
    let seg = Segmentation::MarkedSections {
        prefix: "--- ".into(),
        suffix: " ---".into(),
        preamble: set("preamble")?,
    };
    let outcome = CanonicalStore::open(&artifact, &seg, &whole_record_index()?)
        .map(|s| s.record_count())
        .map_err(|e| e.to_string());
    assert!(
        outcome
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("opened more than once")),
        "a re-opened section must fail the build and say what is unsupported; got {outcome:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Atomic construction
// ---------------------------------------------------------------------------

/// A failed open yields an error and no store — there is no partially built
/// value to observe, and a later successful open is unaffected.
#[test]
fn failed_open_leaves_no_partial_store() -> Result<()> {
    let artifact = raw_artifact("a\nb\n");
    let duplicate_specs = vec![
        IndexSpec {
            name: index("line")?,
            extractor: KeyExtractor::WholeRecord,
        },
        IndexSpec {
            name: index("line")?,
            extractor: KeyExtractor::Field {
                separator: b':',
                index: 0,
            },
        },
    ];
    assert!(
        CanonicalStore::open(&artifact, &lines_seg()?, &duplicate_specs).is_err(),
        "a duplicate index name must fail the build"
    );

    // The only way to hold a store is to have been handed a complete one.
    let good = CanonicalStore::open(&artifact, &lines_seg()?, &whole_record_index()?)?;
    assert_eq!(good.record_count(), 2);
    Ok(())
}

/// A malformed artifact fails the open rather than producing an empty store
/// that would answer every query with "nothing found".
#[test]
fn malformed_artifact_fails_the_open() -> Result<()> {
    // An unknown codec: the container parses, the decode refuses.
    assert!(
        CanonicalStore::open(
            "%q1 nosuchcodec\n%q1 body\nbody\n",
            &lines_seg()?,
            &whole_record_index()?
        )
        .is_err(),
        "an unknown codec must fail rather than yield an empty store"
    );

    // Not a container at all. This is the one `crate::decode` would have
    // waved through, returning the text unchanged as `Ok` — so the store
    // would have indexed the artifact's own header as if it were payload.
    assert!(
        CanonicalStore::open("just some text\n", &lines_seg()?, &whole_record_index()?).is_err(),
        "a non-container must fail to open rather than be adopted as raw payload"
    );

    // A truncated container: header present, `%q1 body` line missing.
    assert!(
        CanonicalStore::open("%q1 raw\ndup\n", &lines_seg()?, &whole_record_index()?).is_err(),
        "an unterminated container must fail to open"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The loader
// ---------------------------------------------------------------------------

/// A plan digest standing in for one produced by `CanonicalStore::open`.
fn a_plan() -> StorePlanDigest {
    digest_store_plan_bytes(b"plan-a")
}

fn another_plan() -> StorePlanDigest {
    digest_store_plan_bytes(b"plan-b")
}

fn stored() -> Result<StoredQueryResult> {
    let schema = SchemaId::parse(SCHEMA_QUERY_V1)?;
    let artifact_digest = ArtifactDigest::of_artifact_bytes(b"%q1 raw\nalpha\n");
    let store_plan_digest = a_plan();
    let sid = store_id(&artifact_digest, &store_plan_digest);
    let canonical_query = CanonicalQuery::Lookup {
        field: FieldName::parse("line")?,
        value: key(b"alpha"),
    };
    let complete_result = CanonicalResult::new([key(b"alpha")])?;
    let qd = canonical_query_digest(&schema, &canonical_query)?;
    let rd = complete_result_digest(&complete_result)?;
    Ok(StoredQueryResult {
        query_result_id: query_result_id(&schema, &sid, &qd, &rd),
        schema,
        artifact_digest,
        store_plan_digest,
        store_id: sid,
        canonical_query,
        canonical_query_digest: qd,
        complete_result,
        complete_result_digest: rd,
    })
}

/// A consistent record verifies.
#[test]
fn a_consistent_stored_result_verifies() -> Result<()> {
    stored()?.verify_internal_consistency()
}

/// Every field the loader could have been lied to about is recomputed, and
/// each mismatch is rejected separately.
///
/// Parsing asserts a role at the boundary; only recomputation converts a claim
/// into evidence. A loader that merely parses believes whatever it is handed,
/// which is a poor property for the component standing between the system and
/// its files.
#[test]
fn the_loader_recomputes_rather_than_believes() -> Result<()> {
    // The query was tampered with, but the stored digest still describes the
    // original — the record is self-inconsistent.
    let mut tampered_query = stored()?;
    tampered_query.canonical_query = CanonicalQuery::Lookup {
        field: FieldName::parse("line")?,
        value: key(b"beta"),
    };
    assert!(
        tampered_query.verify_internal_consistency().is_err(),
        "query digest must be recomputed"
    );

    // The result was swapped for a different one.
    let mut tampered_result = stored()?;
    tampered_result.complete_result = CanonicalResult::new([key(b"beta")])?;
    assert!(
        tampered_result.verify_internal_consistency().is_err(),
        "result digest must be recomputed"
    );

    // Both digests are consistent, but the identity was forged.
    let mut forged_id = stored()?;
    forged_id.query_result_id = query_result_id(
        &SchemaId::parse(SCHEMA_QUERY_V1)?,
        &store_id(
            &ArtifactDigest::of_artifact_bytes(b"a different artifact"),
            &a_plan(),
        ),
        &forged_id.canonical_query_digest,
        &forged_id.complete_result_digest,
    );
    assert!(
        forged_id.verify_internal_consistency().is_err(),
        "identity must be recomputed"
    );

    // A digest that parses as the right role but describes other bytes.
    let mut wrong_role_value = stored()?;
    wrong_role_value.complete_result_digest = CompleteResultDigest::parse_canonical_text(
        &wrong_role_value.canonical_query_digest.to_canonical_text(),
    )?;
    assert!(
        wrong_role_value.verify_internal_consistency().is_err(),
        "a well-typed digest of the wrong content must still be rejected"
    );
    Ok(())
}

/// Relabelling the artifact without recomputing the identity is caught as an
/// internal inconsistency.
#[test]
fn a_relabelled_artifact_breaks_internal_consistency() -> Result<()> {
    let mut moved = stored()?;
    moved.artifact_digest = ArtifactDigest::of_artifact_bytes(b"%q1 raw\n%q1 body\nbeta\n");
    assert!(
        moved.verify_internal_consistency().is_err(),
        "the stored identity no longer matches the stored components"
    );
    Ok(())
}

/// Internal consistency is not provenance, and this is the case that shows it.
///
/// A record describing a *different* artifact, whose identity was then
/// correctly recomputed over that artifact, is flawless by its own lights. It
/// is simply an answer about evidence nobody opened. Only a check against the
/// store actually in hand can say so, and it must report that as
/// `artifact-mismatch` rather than as corruption — otherwise whoever reads the
/// error goes looking for a bug in the wrong place.
#[test]
fn a_self_consistent_result_for_another_artifact_is_an_artifact_mismatch() -> Result<()> {
    let other = ArtifactDigest::of_artifact_bytes(b"%q1 raw\n%q1 body\nbeta\n");
    let mut moved = stored()?;
    moved.artifact_digest = other;
    moved.store_id = store_id(&other, &moved.store_plan_digest);
    moved.query_result_id = query_result_id(
        &moved.schema,
        &moved.store_id,
        &moved.canonical_query_digest,
        &moved.complete_result_digest,
    );
    moved.verify_internal_consistency()?;

    let opened = ArtifactDigest::of_artifact_bytes(b"%q1 raw\n%q1 body\nalpha\n");
    let outcome = moved
        .verify_for_store(&opened, &a_plan())
        .map_err(|e| e.to_string());
    assert!(
        outcome
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("artifact-mismatch")),
        "a result computed over another artifact must fail for this one, and be \
         reported as artifact-mismatch rather than corruption; got {outcome:?}"
    );

    // And it does verify for the store it actually describes.
    moved.verify_for_store(&other, &moved.store_plan_digest.clone())?;
    Ok(())
}

/// The same artifact opened a different way is a different question, reported
/// as `store-plan-mismatch` rather than folded into the artifact case.
///
/// The two say different things — "this is about a different document" and
/// "this is about the same document read a different way" — and they call for
/// different responses. A record self-consistent under plan B is not corrupt;
/// it simply answers about a store nobody opened.
#[test]
fn a_self_consistent_result_under_another_plan_is_a_plan_mismatch() -> Result<()> {
    let mut moved = stored()?;
    moved.store_plan_digest = another_plan();
    moved.store_id = store_id(&moved.artifact_digest, &moved.store_plan_digest);
    moved.query_result_id = query_result_id(
        &moved.schema,
        &moved.store_id,
        &moved.canonical_query_digest,
        &moved.complete_result_digest,
    );
    moved.verify_internal_consistency()?;

    let outcome = moved
        .verify_for_store(&moved.artifact_digest, &a_plan())
        .map_err(|e| e.to_string());
    assert!(
        outcome
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("store-plan-mismatch")),
        "same artifact, different plan must be reported as store-plan-mismatch; got {outcome:?}"
    );
    Ok(())
}

/// The happy path binds both halves.
#[test]
fn verify_for_store_accepts_the_matching_store() -> Result<()> {
    let record = stored()?;
    record.verify_for_store(&record.artifact_digest, &record.store_plan_digest)
}
