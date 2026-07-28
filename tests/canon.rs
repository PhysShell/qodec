//! Contract tests for canonical serialization and framed content identity.
//!
//! These are the first RED contracts of Slice A. They exist before any query
//! engine because the engine's whole evidential model rests on identities
//! being reproducible across runtimes, and an identity scheme is easiest to
//! get subtly wrong while every test still passes.
//!
//! The four groups below correspond to four distinct ways the scheme can be
//! broken without anything looking broken: colliding field boundaries, digests
//! of one type accepted as another, one digest wearing several spellings, and
//! an implementation that agrees only with itself.

use anyhow::Result;

use qodec::canon::{
    canonical_query_bytes, canonical_query_digest, canonical_result_bytes, complete_result_digest,
    digest_canonical_query_bytes, digest_complete_result_bytes, query_result_id, ArtifactDigest,
    CanonicalQuery, CanonicalQueryDigest, CanonicalResult, CompleteResultDigest, FieldName,
    KeyBytes, QueryResultId, SchemaId, SetName, SCHEMA_QUERY_V1,
};

// Golden values, computed by an independent reference implementation written
// from the normative spec (Python + hashlib, different language, different
// author path) and pasted here as literals. Recomputing them with this crate's
// own helpers would prove only that the function agrees with itself.
const GOLDEN_ARTIFACT: &str =
    "sha256:3b1f8a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8";
const GOLDEN_QUERY_BYTES_1: &str =
    "0100000000000000057375697465000000000000000e636c693a3a7265616465725f3137";
const GOLDEN_QUERY_DIGEST_1: &str =
    "sha256:3e79e10d0c254fad81eaf8bb8b4f691b9b364b36e6fc159f6381d17f60b605fd";
const GOLDEN_QUERY_BYTES_2: &str = "020000000000000007746573745f6964000000030000000000000009617474656d70745f310000000000000009617474656d70745f320000000000000009617474656d70745f33";
const GOLDEN_QUERY_DIGEST_2: &str =
    "sha256:c2d8481019f90be4c51417a4d1c96ff2eea74360da7b334e154b0a9c1bdc3959";
const GOLDEN_RESULT_BYTES: &str = "00000001000000000000000e636c693a3a7265616465725f3137";
const GOLDEN_RESULT_DIGEST: &str =
    "sha256:2aa08310fcc7f109f454ec56e59065e4859632f1f39d602dcfe6a70c4e57b769";
const GOLDEN_QRID_1: &str =
    "sha256:57e1309bab6e734c820b0f796f9836fbbf96acc9bc8dda8d7119e57e752f4d46";
const GOLDEN_QRID_2: &str =
    "sha256:1675faf7aaa65b4009c2a46728a3ebd2a9dfe9e079fccfe7bf3cb89f0f5297cd";
const GOLDEN_QRID_V2SCHEMA: &str =
    "sha256:f5b6763d71130e7429fc6b1ee9fb75089df64df82ae8017ac66293bb443f2c0a";
const SUBST_AS_QUERY: &str =
    "sha256:c83a3f0b7f95b6042477e7607923ed1a6a832a09636d4f00bfe17074a3a07639";
const SUBST_AS_RESULT: &str =
    "sha256:d4b00ce4eea1715a518dffd2dfce519ebff818600ae63e9725b3205f0e51ae19";
// A key that is not valid UTF-8 and carries an interior NUL: 0xFF 0x00 0xFE 0x80.
const GOLDEN_RAW_KEY_QUERY_BYTES: &str = "01000000000000000573756974650000000000000004ff00fe80";
const GOLDEN_RAW_KEY_QUERY_DIGEST: &str =
    "sha256:d90ce55379b8e24944071ed13187242f91b1aedbb01ec8bdec315b7b832a1bce";
const GOLDEN_RAW_KEY_RESULT_BYTES: &str =
    "000000020000000000000004ff00fe800000000000000004ff00fe81";
const GOLDEN_RAW_KEY_RESULT_DIGEST: &str =
    "sha256:fea17a889d54e8d2f57191a5e2f022a37f50cb49ce8b5a23b10e77c4ed68ebb9";

const RAW_KEY: [u8; 4] = [0xFF, 0x00, 0xFE, 0x80];
const RAW_KEY_SIBLING: [u8; 4] = [0xFF, 0x00, 0xFE, 0x81];

fn field(name: &str) -> Result<FieldName> {
    FieldName::parse(name)
}

fn key(bytes: &[u8]) -> KeyBytes {
    KeyBytes::new(bytes.to_vec())
}

fn v1() -> Result<SchemaId> {
    SchemaId::parse(SCHEMA_QUERY_V1)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn golden_query_1() -> Result<CanonicalQuery> {
    Ok(CanonicalQuery::Lookup {
        field: field("suite")?,
        value: key(b"cli::reader_17"),
    })
}

fn golden_query_2() -> Result<CanonicalQuery> {
    Ok(CanonicalQuery::Intersect {
        key: field("test_id")?,
        // Deliberately out of order: canonicalization must fix this.
        sets: vec![
            SetName::parse("attempt_3")?,
            SetName::parse("attempt_1")?,
            SetName::parse("attempt_2")?,
        ],
    })
}

fn golden_result() -> Result<CanonicalResult> {
    CanonicalResult::new([key(b"cli::reader_17")])
}

// ---------------------------------------------------------------------------
// Group 1 — boundary ambiguity
// ---------------------------------------------------------------------------

/// Two distinct field sets that a naive concatenation would fuse into one
/// byte string must produce different canonical bytes and different digests.
#[test]
fn framing_separates_field_sets_that_naive_concat_would_collide() -> Result<()> {
    let a = CanonicalQuery::Lookup {
        field: field("ab")?,
        value: key(b"c"),
    };
    let b = CanonicalQuery::Lookup {
        field: field("a")?,
        value: key(b"bc"),
    };

    // The premise of the test: unframed, these are indistinguishable.
    assert_eq!(
        format!("{}{}", "ab", "c"),
        format!("{}{}", "a", "bc"),
        "premise broken: the naive concatenation of these field sets should collide"
    );

    assert_ne!(
        canonical_query_bytes(&v1()?, &a)?,
        canonical_query_bytes(&v1()?, &b)?,
        "framed encodings must differ"
    );
    assert_ne!(
        canonical_query_digest(&v1()?, &a)?,
        canonical_query_digest(&v1()?, &b)?,
        "framed digests must differ"
    );
    Ok(())
}

/// Component roles are not interchangeable inside the identity preimage.
///
/// Note what this does **not** prove. Boundary ambiguity at the
/// `query_result_id` level is currently *latent*, not present: every
/// component except `schema` is a fixed-width 32-byte digest, so an unframed
/// concatenation would still be parseable and no collision can be constructed
/// today. That accidental safety is exactly the debt worth refusing — it
/// evaporates the first time a second variable-length component, a digest
/// algorithm tag, or a new field is added. The framing is therefore pinned
/// now, and what actually holds it in place is the golden-vector test below:
/// removing the framing makes this crate disagree with the reference
/// implementation immediately.
#[test]
fn identity_components_are_not_interchangeable() -> Result<()> {
    let art = ArtifactDigest::parse_canonical_text(GOLDEN_ARTIFACT)?;
    let qd = canonical_query_digest(&v1()?, &golden_query_1()?)?;
    let rd = complete_result_digest(&golden_result()?)?;

    // Passing `rd` where `qd` belongs no longer compiles: the roles are
    // distinct types. The confusion can only be *expressed* by re-asserting
    // roles across the text boundary — the one documented escape hatch — and
    // even then the identity differs.
    let qd_as_result = CompleteResultDigest::parse_canonical_text(&qd.to_canonical_text())?;
    let rd_as_query = CanonicalQueryDigest::parse_canonical_text(&rd.to_canonical_text())?;

    assert_ne!(
        query_result_id(&v1()?, &art, &qd, &rd),
        query_result_id(&v1()?, &art, &rd_as_query, &qd_as_result),
        "query and result digests must not be interchangeable within the preimage"
    );
    Ok(())
}

/// Set members are canonicalized, so a logically identical intersection
/// written in a different order is the *same* query — this is the property
/// that makes replay meaningful rather than accidental.
#[test]
fn set_order_and_duplicates_do_not_change_identity() -> Result<()> {
    let a = CanonicalQuery::Intersect {
        key: field("test_id")?,
        sets: vec![SetName::parse("attempt_1")?, SetName::parse("attempt_2")?],
    };
    let b = CanonicalQuery::Intersect {
        key: field("test_id")?,
        sets: vec![
            SetName::parse("attempt_2")?,
            SetName::parse("attempt_1")?,
            SetName::parse("attempt_2")?,
        ],
    };
    assert_eq!(
        canonical_query_digest(&v1()?, &a)?,
        canonical_query_digest(&v1()?, &b)?
    );
    Ok(())
}

/// The same for results: a total order is imposed on construction.
#[test]
fn result_order_and_duplicates_are_canonicalized() -> Result<()> {
    let a = CanonicalResult::new([key(b"b"), key(b"a")])?;
    let b = CanonicalResult::new([key(b"a"), key(b"b"), key(b"a")])?;
    assert_eq!(a.candidates(), [key(b"a"), key(b"b")]);
    assert_eq!(complete_result_digest(&a)?, complete_result_digest(&b)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// Group 2 — type substitution
// ---------------------------------------------------------------------------

/// Identical payload bytes digested under the query domain and the result
/// domain must yield different digests. This is the direct proof of domain
/// separation: a query digest is not a valid result digest by provenance,
/// even when someone supplies the very same bytes.
#[test]
fn identical_bytes_digest_differently_per_domain() {
    let x = b"identical-payload-bytes";
    let as_query = digest_canonical_query_bytes(x);
    let as_result = digest_complete_result_bytes(x);

    // Note what the compiler already says here: `assert_ne!(as_query,
    // as_result)` does not compile, because the two are different types. That
    // is a stronger guarantee than unequal values — the roles cannot be
    // compared, let alone substituted. The value-level check therefore runs
    // over the canonical text.
    assert_ne!(
        as_query.to_canonical_text(),
        as_result.to_canonical_text(),
        "domain separation must make a query digest unusable as a result digest"
    );
    assert_eq!(as_query.to_canonical_text(), SUBST_AS_QUERY);
    assert_eq!(as_result.to_canonical_text(), SUBST_AS_RESULT);
}

// ---------------------------------------------------------------------------
// Group 3 — representation independence
// ---------------------------------------------------------------------------

/// One canonical text form is accepted. Every other spelling is rejected
/// rather than normalized, so two systems cannot come to disagree about
/// whether they hold the same digest while both believe they do.
#[test]
fn digest_text_forms_are_strictly_parsed_or_rejected() -> Result<()> {
    let lower = "3b1f8a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8";
    let upper = lower.to_uppercase();

    // The one accepted form.
    let d = ArtifactDigest::parse_canonical_text(&format!("sha256:{lower}"))?;
    assert_eq!(d.to_canonical_text(), format!("sha256:{lower}"));

    // Everything else is an error, not a silent normalization.
    for bad in [
        lower.to_string(),             // bare lowercase hex, no prefix
        upper.clone(),                 // bare uppercase hex
        format!("sha256:{upper}"),     // prefixed uppercase
        format!("SHA256:{lower}"),     // uppercased scheme
        "sha256:3b1f8a2c".to_string(), // short body
        format!("sha256:{lower}ab"),   // long body
        format!("sha-256:{lower}"),    // wrong scheme spelling
        String::new(),
    ] {
        assert!(
            ArtifactDigest::parse_canonical_text(&bad).is_err(),
            "must reject non-canonical digest text {bad:?}"
        );
    }
    Ok(())
}

/// Raw bytes and text are different things, and only the raw bytes reach a
/// preimage. Round-tripping through the canonical text must be lossless.
#[test]
fn digest_round_trips_through_canonical_text() -> Result<()> {
    let art = ArtifactDigest::parse_canonical_text(GOLDEN_ARTIFACT)?;
    let again = ArtifactDigest::parse_canonical_text(&art.to_canonical_text())?;
    assert_eq!(art, again);
    assert_eq!(art.as_bytes().len(), 32);
    Ok(())
}

// ---------------------------------------------------------------------------
// Group 4 — cross-runtime golden vectors
// ---------------------------------------------------------------------------

/// Canonical bytes must match the independent reference byte for byte. If
/// this fails, this crate and the reference disagree about the wire format,
/// which no amount of internal self-consistency would have revealed.
#[test]
fn canonical_bytes_match_independent_reference() -> Result<()> {
    assert_eq!(
        hex(&canonical_query_bytes(&v1()?, &golden_query_1()?)?),
        GOLDEN_QUERY_BYTES_1
    );
    assert_eq!(
        hex(&canonical_query_bytes(&v1()?, &golden_query_2()?)?),
        GOLDEN_QUERY_BYTES_2
    );
    assert_eq!(
        hex(&canonical_result_bytes(&golden_result()?)?),
        GOLDEN_RESULT_BYTES
    );
    Ok(())
}

/// Digests and the composite identity must match the independent reference.
#[test]
fn digests_and_identity_match_independent_reference() -> Result<()> {
    let art = ArtifactDigest::parse_canonical_text(GOLDEN_ARTIFACT)?;
    let qd1 = canonical_query_digest(&v1()?, &golden_query_1()?)?;
    let qd2 = canonical_query_digest(&v1()?, &golden_query_2()?)?;
    let rd = complete_result_digest(&golden_result()?)?;

    assert_eq!(qd1.to_canonical_text(), GOLDEN_QUERY_DIGEST_1);
    assert_eq!(qd2.to_canonical_text(), GOLDEN_QUERY_DIGEST_2);
    assert_eq!(rd.to_canonical_text(), GOLDEN_RESULT_DIGEST);
    assert_eq!(
        query_result_id(&v1()?, &art, &qd1, &rd).to_canonical_text(),
        GOLDEN_QRID_1
    );
    assert_eq!(
        query_result_id(&v1()?, &art, &qd2, &rd).to_canonical_text(),
        GOLDEN_QRID_2
    );
    Ok(())
}

/// Replay is checkable by construction: recomputing from the same inputs
/// reproduces the same ID, with no stored state consulted.
#[test]
fn identity_is_reproducible_from_inputs_alone() -> Result<()> {
    let art = ArtifactDigest::parse_canonical_text(GOLDEN_ARTIFACT)?;
    let compute = || -> Result<QueryResultId> {
        let qd = canonical_query_digest(&v1()?, &golden_query_2()?)?;
        let rd = complete_result_digest(&golden_result()?)?;
        Ok(query_result_id(&v1()?, &art, &qd, &rd))
    };
    assert_eq!(compute()?, compute()?);
    assert_eq!(compute()?.to_canonical_text(), GOLDEN_QRID_2);
    Ok(())
}

// ---------------------------------------------------------------------------
// Schema is load-bearing, not decorative
// ---------------------------------------------------------------------------

/// The same logical query under a different schema must get a different ID
/// even when the canonical bytes happen to be identical. Otherwise the
/// version is declared but means nothing cryptographically.
#[test]
fn schema_version_changes_identity_even_with_identical_bytes() -> Result<()> {
    let art = ArtifactDigest::parse_canonical_text(GOLDEN_ARTIFACT)?;
    let qd = canonical_query_digest(&v1()?, &golden_query_1()?)?;
    let rd = complete_result_digest(&golden_result()?)?;

    let v2 = SchemaId::identity_only("qodec.query.v2")?;
    let id_v1 = query_result_id(&v1()?, &art, &qd, &rd);
    let id_v2 = query_result_id(&v2, &art, &qd, &rd);

    assert_ne!(id_v1, id_v2, "schema must be load-bearing in the identity");
    assert_eq!(id_v1.to_canonical_text(), GOLDEN_QRID_1);
    assert_eq!(id_v2.to_canonical_text(), GOLDEN_QRID_V2SCHEMA);
    Ok(())
}

/// An unknown schema has no encoder in this build, and asking for one is an
/// error rather than a silent fallback to v1's rules.
#[test]
fn unknown_schema_has_no_encoder() -> Result<()> {
    assert!(SchemaId::parse("qodec.query.v2").is_err());
    let v2 = SchemaId::identity_only("qodec.query.v2")?;
    assert!(canonical_query_bytes(&v2, &golden_query_1()?).is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// Content policy
// ---------------------------------------------------------------------------

/// Protocol names are text and keep the strict policy: a BOM is invisible and
/// would make two apparently identical *names* differ, and an empty name is a
/// protocol error rather than data.
#[test]
fn protocol_names_reject_empty_and_bom() -> Result<()> {
    assert!(FieldName::parse("").is_err());
    assert!(SetName::parse("").is_err());
    assert!(FieldName::parse("\u{feff}suite").is_err());
    assert!(SetName::parse("attempt\u{feff}1").is_err());
    assert!(FieldName::parse("suite").is_ok());
    Ok(())
}

/// A key is whatever bytes the decoder found. Invalid UTF-8, interior NUL and
/// a high byte are all ordinary key content, and none of them may be decoded,
/// replaced or truncated on the way through.
#[test]
fn arbitrary_bytes_survive_as_keys() -> Result<()> {
    let q = CanonicalQuery::Lookup {
        field: field("suite")?,
        value: key(&RAW_KEY),
    };
    // The compiler proves this statically for the literal; assert it on an
    // owned copy so the premise is stated in the test rather than only in a
    // lint message.
    assert!(
        String::from_utf8(RAW_KEY.to_vec()).is_err(),
        "premise: this key is not valid UTF-8"
    );
    assert_eq!(
        hex(&canonical_query_bytes(&v1()?, &q)?),
        GOLDEN_RAW_KEY_QUERY_BYTES
    );
    assert_eq!(
        canonical_query_digest(&v1()?, &q)?.to_canonical_text(),
        GOLDEN_RAW_KEY_QUERY_DIGEST
    );

    let r = CanonicalResult::new([key(&RAW_KEY), key(&RAW_KEY_SIBLING)])?;
    assert_eq!(
        hex(&canonical_result_bytes(&r)?),
        GOLDEN_RAW_KEY_RESULT_BYTES
    );
    assert_eq!(
        complete_result_digest(&r)?.to_canonical_text(),
        GOLDEN_RAW_KEY_RESULT_DIGEST
    );
    Ok(())
}

/// Two *different* invalid UTF-8 sequences must not collapse into one key.
///
/// This is the concrete disaster a lossy decode would cause: both would become
/// `U+FFFD`, one lookup would answer for the other's records, and the replay
/// would be perfectly deterministic and perfectly wrong.
#[test]
fn distinct_invalid_utf8_sequences_do_not_collapse() -> Result<()> {
    let a = key(&[0xFF]);
    let b = key(&[0xFE]);
    assert_ne!(a, b);
    let r = CanonicalResult::new([a.clone(), b.clone()])?;
    assert_eq!(r.candidates().len(), 2, "the two keys must stay distinct");

    let qa = CanonicalQuery::Lookup {
        field: field("k")?,
        value: a,
    };
    let qb = CanonicalQuery::Lookup {
        field: field("k")?,
        value: b,
    };
    assert_ne!(
        canonical_query_digest(&v1()?, &qa)?,
        canonical_query_digest(&v1()?, &qb)?
    );
    Ok(())
}

/// An interior NUL is an ordinary byte, and truncating at it would silently
/// merge every key sharing a prefix.
#[test]
fn interior_nul_does_not_truncate_a_key() -> Result<()> {
    let full = key(b"ab\0cd");
    let prefix = key(b"ab");
    assert_ne!(full, prefix);
    let r = CanonicalResult::new([full, prefix])?;
    assert_eq!(r.candidates().len(), 2);
    Ok(())
}

/// Normalization forms stay distinct — now for a stronger reason than before:
/// nothing decodes the bytes at all, so there is no stage at which they could
/// be folded together.
#[test]
fn unicode_normalization_forms_are_distinct_keys() -> Result<()> {
    let nfc = "é".as_bytes(); // U+00E9
    let nfd = "e\u{301}".as_bytes(); // U+0065 U+0301
    assert_ne!(nfc, nfd, "premise: these differ at the byte level");

    let a = CanonicalQuery::Lookup {
        field: field("k")?,
        value: key(nfc),
    };
    let b = CanonicalQuery::Lookup {
        field: field("k")?,
        value: key(nfd),
    };
    assert_ne!(
        canonical_query_digest(&v1()?, &a)?,
        canonical_query_digest(&v1()?, &b)?,
        "normalization forms must remain distinct, consistently with byte-exact decode"
    );
    Ok(())
}

/// An empty key is legal data; an empty name is not. Length prefixes carry
/// the empty case rather than the encoder eliding it.
#[test]
fn empty_key_is_legal_and_empty_name_is_not() -> Result<()> {
    let empty_value = CanonicalQuery::Lookup {
        field: field("k")?,
        value: key(b""),
    };
    assert!(canonical_query_bytes(&v1()?, &empty_value).is_ok());
    assert!(CanonicalResult::new([key(b"")]).is_ok());
    assert!(FieldName::parse("").is_err());

    let empty_set = CanonicalQuery::Intersect {
        key: field("k")?,
        sets: vec![],
    };
    assert!(canonical_query_bytes(&v1()?, &empty_set).is_ok());
    assert!(CanonicalResult::new([]).is_ok());
    Ok(())
}

// ---------------------------------------------------------------------------
// The JSON envelope for byte values
// ---------------------------------------------------------------------------

/// Bytes round-trip through the one permitted envelope form.
#[test]
fn key_bytes_round_trip_through_the_envelope() -> Result<()> {
    for bytes in [
        RAW_KEY.to_vec(),
        b"cli::reader_17".to_vec(),
        vec![],
        vec![0x00],
        (0u8..=255).collect(),
    ] {
        let k = KeyBytes::new(bytes.clone());
        let round = KeyBytes::from_envelope(&k.to_envelope())?;
        assert_eq!(round, k, "envelope must round-trip {bytes:?}");
    }
    Ok(())
}

/// `display_utf8` appears only when the bytes really are UTF-8, and is never
/// the authoritative value.
#[test]
fn display_utf8_is_advisory_and_checked() -> Result<()> {
    let text = KeyBytes::new(b"cli::reader_17".to_vec()).to_envelope();
    assert_eq!(
        text.get("display_utf8").and_then(|v| v.as_str()),
        Some("cli::reader_17")
    );
    let raw = KeyBytes::new(RAW_KEY.to_vec()).to_envelope();
    assert!(
        raw.get("display_utf8").is_none(),
        "invalid UTF-8 must not be given a display form"
    );

    // A display that disagrees with the data is a contradiction, not a hint.
    let lying = serde_json::json!({
        "encoding": "base64url-nopad",
        "data": "Y2xpOjpyZWFkZXJfMTc",
        "display_utf8": "something::else",
    });
    assert!(KeyBytes::from_envelope(&lying).is_err());
    Ok(())
}

/// The envelope is parsed strictly: one encoding name, one alphabet, no
/// padding, no second spelling of the same bytes.
#[test]
fn envelope_parsing_is_strict() -> Result<()> {
    let ok = serde_json::json!({"encoding": "base64url-nopad", "data": "Y2xp"});
    assert_eq!(
        KeyBytes::from_envelope(&ok)?.as_bytes(),
        b"cli",
        "premise: the accepted form decodes"
    );

    for bad in [
        serde_json::json!({"encoding": "base64", "data": "Y2xp"}),
        serde_json::json!({"encoding": "base64url-nopad", "data": "Y2xpOjpyZWFkZXJfMTc="}),
        serde_json::json!({"encoding": "base64url-nopad", "data": "++//"}),
        serde_json::json!({"encoding": "base64url-nopad", "data": "Y2xp "}),
        serde_json::json!({"encoding": "base64url-nopad", "data": "A"}),
        // Non-zero trailing bits: a second spelling of the same one byte.
        serde_json::json!({"encoding": "base64url-nopad", "data": "_B"}),
        serde_json::json!({"encoding": "base64url-nopad"}),
        serde_json::json!({"encoding": "base64url-nopad", "data": 17}),
        serde_json::json!({"encoding": "base64url-nopad", "data": "Y2xp", "extra": 1}),
        serde_json::json!("Y2xp"),
    ] {
        assert!(
            KeyBytes::from_envelope(&bad).is_err(),
            "must reject envelope {bad}"
        );
    }
    Ok(())
}

/// The two variants must never share an encoding, whatever their payloads.
#[test]
fn discriminants_separate_the_operations() -> Result<()> {
    let lookup = CanonicalQuery::Lookup {
        field: field("k")?,
        value: key(b"v"),
    };
    let intersect = CanonicalQuery::Intersect {
        key: field("k")?,
        sets: vec![SetName::parse("v")?],
    };
    let lb = canonical_query_bytes(&v1()?, &lookup)?;
    let ib = canonical_query_bytes(&v1()?, &intersect)?;
    assert_ne!(lb.first(), ib.first(), "discriminants must differ");
    assert_ne!(lb, ib);
    Ok(())
}
