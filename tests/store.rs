//! RED contracts for the canonical store and index — Slice A, #14.
//!
//! Written against the invariants before the query surface grows on top of
//! them. Each group corresponds to a way the store could look correct while
//! being wrong: a key silently decoded, two records merged into one, an index
//! whose order depends on the run, a materialization that reconstructs rather
//! than returns, and a loader that believes a file because the file said so.

use anyhow::Result;

use qodec::canon::{
    canonical_query_digest, complete_result_digest, query_result_id, ArtifactDigest,
    CanonicalQuery, CanonicalResult, CompleteResultDigest, FieldName, IndexName, KeyBytes,
    SchemaId, SetName, StoredQueryResult, SCHEMA_QUERY_V1,
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

    let ids_a: Vec<&RecordId> = first.record_ids().collect();
    let ids_b: Vec<&RecordId> = second.record_ids().collect();
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
    let ids: Vec<RecordId> = store.record_ids().cloned().collect();
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
    let mut ids: Vec<RecordId> = store.record_ids().cloned().collect();
    let other = CanonicalStore::open(
        &raw_artifact("a\nb\n"),
        &lines_seg()?,
        &whole_record_index()?,
    )?;
    ids.extend(other.record_ids().cloned());
    assert!(
        store.materialize(&ids).is_err(),
        "an id this store never issued must fail the call"
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

fn stored() -> Result<StoredQueryResult> {
    let schema = SchemaId::parse(SCHEMA_QUERY_V1)?;
    let artifact_digest = ArtifactDigest::of_artifact_bytes(b"%q1 raw\nalpha\n");
    let canonical_query = CanonicalQuery::Lookup {
        field: FieldName::parse("line")?,
        value: key(b"alpha"),
    };
    let complete_result = CanonicalResult::new([key(b"alpha")])?;
    let qd = canonical_query_digest(&schema, &canonical_query)?;
    let rd = complete_result_digest(&complete_result)?;
    Ok(StoredQueryResult {
        query_result_id: query_result_id(&schema, &artifact_digest, &qd, &rd),
        schema,
        artifact_digest,
        canonical_query,
        canonical_query_digest: qd,
        complete_result,
        complete_result_digest: rd,
    })
}

/// A consistent record verifies.
#[test]
fn a_consistent_stored_result_verifies() -> Result<()> {
    stored()?.verify()
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
        tampered_query.verify().is_err(),
        "query digest must be recomputed"
    );

    // The result was swapped for a different one.
    let mut tampered_result = stored()?;
    tampered_result.complete_result = CanonicalResult::new([key(b"beta")])?;
    assert!(
        tampered_result.verify().is_err(),
        "result digest must be recomputed"
    );

    // Both digests are consistent, but the identity was forged.
    let mut forged_id = stored()?;
    forged_id.query_result_id = query_result_id(
        &SchemaId::parse(SCHEMA_QUERY_V1)?,
        &ArtifactDigest::of_artifact_bytes(b"a different artifact"),
        &forged_id.canonical_query_digest,
        &forged_id.complete_result_digest,
    );
    assert!(forged_id.verify().is_err(), "identity must be recomputed");

    // A digest that parses as the right role but describes other bytes.
    let mut wrong_role_value = stored()?;
    wrong_role_value.complete_result_digest = CompleteResultDigest::parse_canonical_text(
        &wrong_role_value.canonical_query_digest.to_canonical_text(),
    )?;
    assert!(
        wrong_role_value.verify().is_err(),
        "a well-typed digest of the wrong content must still be rejected"
    );
    Ok(())
}

/// The artifact binding is part of the identity: the same query and result
/// against a different artifact is a different result.
#[test]
fn identity_binds_the_artifact() -> Result<()> {
    let mut moved = stored()?;
    moved.artifact_digest = ArtifactDigest::of_artifact_bytes(b"%q1 raw\nbeta\n");
    assert!(
        moved.verify().is_err(),
        "a result cannot be relabelled onto another artifact"
    );
    Ok(())
}
