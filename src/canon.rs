//! Canonical serialization and framed content identity for the query harness.
//!
//! Slice A of `docs/proposals/qodec-query-harness.md` rests on one claim: a
//! query result's identity **is** its content, so replaying the same canonical
//! query over the same artifact reproduces the same `query_result_id` by
//! construction rather than by bookkeeping. That claim is only worth as much
//! as the bytes it hashes, which is why this module exists before any query
//! code does.
//!
//! Two rules hold everywhere below, and the tests enforce both:
//!
//! * **No identity-producing hash accepts an unframed concatenation.** Every
//!   component is length-delimited, so no two distinct field sets can produce
//!   the same preimage. Today's components happen to be fixed-width digests,
//!   which would make boundaries recoverable by accident; relying on that
//!   would be a debt taken on at birth, since the first added algorithm,
//!   version, or component silently breaks it.
//! * **No digest domain accepts a plain byte slice without a type tag.** A
//!   query digest is not a valid result digest even when the payload bytes are
//!   identical, because the domain string is part of the preimage. This is
//!   type confusion protection, not cryptographic decoration.
//!
//! Human-readable JSON stays an envelope representation. Identity is computed
//! over the normative binary encoding here, so changing a pretty-printer, a
//! JSON library, or a map iteration order cannot move an ID.

use anyhow::{bail, Result};
use sha2::{Digest as _, Sha256};

/// The only query schema Slice A serializes.
pub const SCHEMA_QUERY_V1: &str = "qodec.query.v1";

// Domain tags. Each is versioned independently of the others: a change to how
// queries are encoded must not silently redefine result identity.
const DOMAIN_CANONICAL_QUERY: &str = "qodec.canonical-query.v1";
const DOMAIN_COMPLETE_RESULT: &str = "qodec.complete-result.v1";
const DOMAIN_QUERY_RESULT_ID: &str = "qodec.query-result-id.v1";

/// One lowercase hex digit as a nibble; uppercase is an error, not a variant.
fn lowercase_nibble(b: u8, text: &str) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => bail!("digest body must be lowercase hex, got byte {b:#04x} in {text:?}"),
    }
}

/// A SHA-256 digest as raw bytes.
///
/// Deliberately not a `String`. Hex is a display concern; the moment a digest
/// is allowed to travel as text, `"9f..."`, `"9F..."` and `"sha256:9f..."`
/// become three inputs that look interchangeable to a reader and are not
/// interchangeable to a hash function. The preimage always carries the raw 32
/// bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    /// The raw 32 bytes, which is what any preimage embeds.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wrap 32 bytes already known to be a digest of the right domain.
    ///
    /// Reserved for callers that computed the digest through this module or
    /// read it from a pinned artifact header; it performs no domain check
    /// because raw bytes carry no domain.
    pub fn from_raw(bytes: [u8; 32]) -> Self {
        Digest(bytes)
    }

    /// Parse the one canonical text form, `sha256:` + 64 lowercase hex digits.
    ///
    /// Strict on purpose. Uppercase hex, bare hex without the prefix, and any
    /// other spelling are **rejected** rather than normalized: silently
    /// accepting several spellings is how two systems come to disagree about
    /// whether they hold the same digest while both believe they do.
    pub fn parse_canonical_text(text: &str) -> Result<Self> {
        let Some(hex) = text.strip_prefix("sha256:") else {
            bail!("digest must be written `sha256:<64 lowercase hex>`, got {text:?}");
        };
        if hex.len() != 64 {
            bail!(
                "digest body must be 64 hex digits, got {} in {text:?}",
                hex.len()
            );
        }
        let mut out = [0u8; 32];
        for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            let [hi, lo] = pair else {
                bail!("digest body must split into byte pairs, got {text:?}");
            };
            *byte = (lowercase_nibble(*hi, text)? << 4) | lowercase_nibble(*lo, text)?;
        }
        Ok(Digest(out))
    }

    /// The canonical text form, for JSON envelopes, logs, and human eyes.
    pub fn to_canonical_text(&self) -> String {
        let mut s = String::with_capacity(7 + 64);
        s.push_str("sha256:");
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

/// Which schema's serialization rules apply.
///
/// The schema is not a label attached after the fact: it selects the encoder
/// **and** enters the `query_result_id` preimage. So the same logical query
/// under `qodec.query.v1` and a future `qodec.query.v2` gets different IDs
/// even if v2 happens to emit identical canonical bytes — otherwise the
/// version is declared but means nothing cryptographically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaId(String);

impl SchemaId {
    /// Accept only schemas this build knows how to serialize.
    pub fn parse(s: &str) -> Result<Self> {
        if s != SCHEMA_QUERY_V1 {
            bail!("unknown query schema {s:?}; this build serializes only {SCHEMA_QUERY_V1:?}");
        }
        Ok(SchemaId(s.to_string()))
    }

    /// Construct a schema id without an encoder for it.
    ///
    /// Only identity derivation accepts this: `query_result_id` must be able
    /// to bind an ID to a schema whose encoder lives elsewhere, and refusing
    /// would make cross-version identity untestable.
    pub fn identity_only(s: &str) -> Result<Self> {
        if s.is_empty() {
            bail!("schema id must not be empty");
        }
        reject_bom(s, "schema id")?;
        Ok(SchemaId(s.to_string()))
    }

    /// The schema string as it enters the preimage.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A query in the only form that identity is computed over.
///
/// A narrow typed enum rather than free-form JSON. Slice A needs exactly two
/// operations, and pinning them as variants means the encoding cannot drift
/// with a serializer option, a library upgrade, or a map iteration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalQuery {
    /// Exact match of one field against one value.
    Lookup { field: String, value: String },
    /// Intersection of named sets on a join key.
    Intersect { key: String, sets: Vec<String> },
}

impl CanonicalQuery {
    /// Discriminants are explicit and frozen; never derived from variant order.
    fn discriminant(&self) -> u8 {
        match self {
            CanonicalQuery::Lookup { .. } => 1,
            CanonicalQuery::Intersect { .. } => 2,
        }
    }
}

/// The complete result set, before any preview truncation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalResult {
    candidates: Vec<String>,
}

impl CanonicalResult {
    /// Build a result in canonical form: total order, no duplicates.
    ///
    /// Ordering is by UTF-8 byte value, which is the only order available
    /// without dragging in a locale. Without a total order the result digest
    /// is unstable across replays and the whole identity scheme collapses —
    /// case 12 of the Slice A negative matrix.
    pub fn new(candidates: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut v: Vec<String> = candidates.into_iter().collect();
        for c in &v {
            reject_bom(c, "result candidate")?;
        }
        v.sort_unstable();
        v.dedup();
        Ok(CanonicalResult { candidates: v })
    }

    /// The canonical candidates, sorted and deduplicated.
    pub fn candidates(&self) -> &[String] {
        &self.candidates
    }
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// A length-delimited domain header: `u16be(len) || utf8`.
fn domain_header(domain: &str) -> Vec<u8> {
    let bytes = domain.as_bytes();
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// A tagged, length-delimited field: `u16be(tag) || tag || u64be(val) || val`.
///
/// Both the tag and the value are delimited, so neither a tag that looks like
/// the start of a value nor a value that looks like the next tag can shift a
/// boundary.
fn framed_field(tag: &str, value: &[u8]) -> Vec<u8> {
    let tag_bytes = tag.as_bytes();
    let mut out = Vec::with_capacity(2 + tag_bytes.len() + 8 + value.len());
    out.extend_from_slice(&(tag_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(tag_bytes);
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
    out
}

/// `u64be(len) || bytes`.
fn length_prefixed(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Private on purpose: every exported hash entry point is domain-tagged.
fn sha256_raw(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(input);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

/// Reject a byte-order mark anywhere in a canonical string.
///
/// A leading U+FEFF is invisible and would make two apparently identical keys
/// hash differently; allowing it buys nothing and costs a debugging afternoon.
fn reject_bom(s: &str, what: &str) -> Result<()> {
    if s.contains('\u{feff}') {
        bail!("{what} must not contain U+FEFF (byte order mark)");
    }
    Ok(())
}

/// `u64be(len) || utf8`, with no escaping — the encoding is binary, so there
/// is nothing to escape and therefore no escaping dialect to disagree about.
///
/// **No Unicode normalization is performed, and this is deliberate.** Canonical
/// keys are produced by `decode_once` from the artifact's exact RAW bytes, so
/// normalizing them here would divorce an index key from the bytes it indexes
/// and break `qodec_materialize`'s byte-equality check. Two strings differing
/// only in normalization form are therefore different keys, consistently with
/// qodec's byte-exact contract everywhere else. Callers that need NFC must
/// normalize before the bytes reach the artifact, not after.
fn encode_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u64).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// `u32be(count) || encode_str(e)…`, in the order given.
///
/// Infallible by construction: content validation happens where the value
/// enters the type — [`CanonicalResult::new`] for results, and
/// [`canonical_query_bytes`] for queries — so the encoder itself has no
/// failure mode to swallow, and no unreachable panic to explain away.
fn encode_seq(out: &mut Vec<u8>, items: &[String]) {
    out.extend_from_slice(&(items.len() as u32).to_be_bytes());
    for item in items {
        encode_str(out, item);
    }
}

/// Serialize a query to its canonical bytes under the given schema.
///
/// Set members are sorted and deduplicated, so two logically identical
/// intersections written in different orders produce the same bytes — which is
/// the property that makes replay meaningful rather than incidental.
pub fn canonical_query_bytes(schema: &SchemaId, query: &CanonicalQuery) -> Result<Vec<u8>> {
    if schema.as_str() != SCHEMA_QUERY_V1 {
        bail!(
            "no canonical encoder for schema {:?}; this build encodes only {SCHEMA_QUERY_V1:?}",
            schema.as_str()
        );
    }
    let mut out = vec![query.discriminant()];
    match query {
        CanonicalQuery::Lookup { field, value } => {
            reject_bom(field, "lookup field")?;
            reject_bom(value, "lookup value")?;
            encode_str(&mut out, field);
            encode_str(&mut out, value);
        }
        CanonicalQuery::Intersect { key, sets } => {
            reject_bom(key, "intersect key")?;
            for s in sets {
                reject_bom(s, "intersect set name")?;
            }
            encode_str(&mut out, key);
            let mut sets = sets.clone();
            sets.sort_unstable();
            sets.dedup();
            encode_seq(&mut out, &sets);
        }
    }
    Ok(out)
}

/// Serialize a complete result to its canonical bytes.
///
/// Infallible: [`CanonicalResult`] cannot be constructed without passing
/// validation and being put into total order, so there is no state left here
/// that could fail.
pub fn canonical_result_bytes(result: &CanonicalResult) -> Vec<u8> {
    let mut out = Vec::new();
    encode_seq(&mut out, &result.candidates);
    out
}

// ---------------------------------------------------------------------------
// Domain-separated digests
// ---------------------------------------------------------------------------

/// Digest canonical query bytes under the query domain.
pub fn digest_canonical_query_bytes(bytes: &[u8]) -> Digest {
    let mut preimage = domain_header(DOMAIN_CANONICAL_QUERY);
    preimage.extend_from_slice(&length_prefixed(bytes));
    Digest(sha256_raw(&preimage))
}

/// Digest complete result bytes under the result domain.
///
/// Distinct from [`digest_canonical_query_bytes`] even for identical input
/// bytes: the domain string is part of the preimage, so a query digest can
/// never be presented as a result digest by protocol provenance.
pub fn digest_complete_result_bytes(bytes: &[u8]) -> Digest {
    let mut preimage = domain_header(DOMAIN_COMPLETE_RESULT);
    preimage.extend_from_slice(&length_prefixed(bytes));
    Digest(sha256_raw(&preimage))
}

/// Digest of a query, end to end.
pub fn canonical_query_digest(schema: &SchemaId, query: &CanonicalQuery) -> Result<Digest> {
    Ok(digest_canonical_query_bytes(&canonical_query_bytes(
        schema, query,
    )?))
}

/// Digest of a complete result, end to end.
pub fn complete_result_digest(result: &CanonicalResult) -> Digest {
    digest_complete_result_bytes(&canonical_result_bytes(result))
}

/// The content-addressed identity of a query result.
///
/// ```text
/// query_result_id = sha256(
///       domain("qodec.query-result-id.v1")
///    || field("schema",   utf8(schema_id))
///    || field("artifact", artifact_digest_raw_32)
///    || field("query",    canonical_query_digest_raw_32)
///    || field("result",   complete_result_digest_raw_32)
/// )
/// ```
///
/// Every component is framed and every digest enters as raw bytes. Replaying
/// the same canonical query over the same artifact under the same schema
/// reproduces this value; any change to the artifact, the question, the
/// result, or the schema changes it.
pub fn query_result_id(
    schema: &SchemaId,
    artifact_digest: &Digest,
    query_digest: &Digest,
    result_digest: &Digest,
) -> Digest {
    let mut preimage = domain_header(DOMAIN_QUERY_RESULT_ID);
    preimage.extend_from_slice(&framed_field("schema", schema.as_str().as_bytes()));
    preimage.extend_from_slice(&framed_field("artifact", artifact_digest.as_bytes()));
    preimage.extend_from_slice(&framed_field("query", query_digest.as_bytes()));
    preimage.extend_from_slice(&framed_field("result", result_digest.as_bytes()));
    Digest(sha256_raw(&preimage))
}
