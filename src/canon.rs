//! Canonical serialization and framed content identity for the query harness.
//!
//! Slice A of `docs/proposals/qodec-query-harness.md` rests on one claim: a
//! query result's identity **is** its content, so replaying the same canonical
//! query over the same **store** — one artifact together with the plan that
//! opened it — reproduces the same `query_result_id` by construction rather
//! than by bookkeeping. The artifact alone is not enough: two segmentations
//! of one artifact answer the same question differently. That claim is only worth as much
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
const DOMAIN_ARTIFACT: &str = "qodec.artifact.v1";
const DOMAIN_STORE_PLAN: &str = "qodec.store-plan.v1";
const DOMAIN_STORE_ID: &str = "qodec.store-id.v1";
const DOMAIN_RESULT_SUPPORT: &str = "qodec.result-support.v1";
const DOMAIN_PROVIDER_REQUEST: &str = "qodec.provider-request.v1";

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

// ---------------------------------------------------------------------------
// Digest roles
// ---------------------------------------------------------------------------
//
// Domain separation already makes a query digest and a result digest different
// *values*. It does not stop anyone from assembling a role-confused record,
// because at the type level both were merely `Digest` and the compiler had no
// opinion about which slot they belonged in. These newtypes move that check
// from "a negative test will catch it later" to "it does not compile".
//
// Each carries a `parse_canonical_text` because these values genuinely arrive
// as text across a boundary — a pinned artifact header, a stored result
// record, a handle presented by a caller. Parsing **asserts** a role that the
// raw bytes do not carry, which is exactly why it is spelled out per role
// rather than offered as one generic conversion.

/// Identifies the artifact a query ran against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactDigest(Digest);

/// Digest of the canonical bytes of a query, under the query domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalQueryDigest(Digest);

/// Digest of the canonical bytes of a complete result, under the result domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompleteResultDigest(Digest);

/// Identifies *how* an artifact was opened: segmentation plus index specs.
///
/// Coordinates only mean something inside a plan. The same artifact opened
/// with two segmentations yields two different records at `s#0`, so an id that
/// names only the artifact is ambiguous exactly where it looks precise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorePlanDigest(Digest);

/// Identifies one opened store: an artifact together with the plan that opened
/// it. This is the space in which a record's coordinates are unambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreId(Digest);

/// Covers what backs a result: which records support which candidate, and
/// whether the execution actually ran to exhaustion.
///
/// Separate from [`CompleteResultDigest`] because they answer different
/// questions — "what was found" versus "on what evidence, and was the search
/// finished". Folding them together would also make the frozen description of
/// `complete_result_digest` untrue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResultSupportDigest(Digest);

/// The content-addressed identity of a query result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueryResultId(Digest);

/// Identifies the exact request body that went to a provider.
///
/// Digests the **serialized wire bytes**, not the struct that produced them.
/// A digest over the struct would certify what the code meant to send; this one
/// certifies what was actually sent, which is the only version the model saw.
/// It is also what makes a transport retry provable: two attempts carrying the
/// same value are the same request tried twice, and a semantic retry — a
/// different prompt after a failure — cannot wear that identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderRequestDigest(Digest);

macro_rules! impl_digest_role {
    ($name:ident, $role:literal) => {
        impl $name {
            #[doc = concat!("The raw 32 bytes of this ", $role, ", as they enter a preimage.")]
            pub fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }

            #[doc = concat!("The canonical text form of this ", $role, ".")]
            pub fn to_canonical_text(&self) -> String {
                self.0.to_canonical_text()
            }

            #[doc = concat!("Parse a ", $role, " from `sha256:<64 lowercase hex>`.")]
            ///
            /// Asserts the role: raw bytes carry no evidence of which slot
            /// they belong in. Use only where the value genuinely crosses a
            /// boundary as text, never to move a digest between roles.
            pub fn parse_canonical_text(text: &str) -> Result<Self> {
                Ok($name(Digest::parse_canonical_text(text)?))
            }
        }
    };
}

impl_digest_role!(ArtifactDigest, "artifact digest");

impl ArtifactDigest {
    /// Digest the artifact's own bytes under the artifact domain.
    ///
    /// Domain-tagged like everything else: an artifact digest must not be
    /// presentable as a query or result digest merely because someone hashed
    /// the same bytes.
    pub fn of_artifact_bytes(bytes: &[u8]) -> Self {
        let mut preimage = domain_header(DOMAIN_ARTIFACT);
        preimage.extend_from_slice(&length_prefixed(bytes));
        ArtifactDigest(Digest(sha256_raw(&preimage)))
    }
}
impl_digest_role!(CanonicalQueryDigest, "canonical query digest");
impl_digest_role!(CompleteResultDigest, "complete result digest");
impl_digest_role!(StorePlanDigest, "store plan digest");
impl_digest_role!(StoreId, "store id");
impl_digest_role!(ResultSupportDigest, "result support digest");
impl_digest_role!(QueryResultId, "query result id");
impl_digest_role!(ProviderRequestDigest, "provider request digest");

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

// ---------------------------------------------------------------------------
// Protocol names versus artifact data
// ---------------------------------------------------------------------------
//
// These are two different kinds of string and conflating them is how a
// byte-exact system quietly becomes a text system.
//
// **Protocol names** — schema, index, field and set identifiers — are chosen
// by the schema, not extracted from a payload. They are text, and the strict
// UTF-8 / BOM-rejecting / non-normalizing policy applies to them.
//
// **Artifact-derived values** are whatever bytes `decode_once` actually found.
// The artifact is byte-exact by contract, so a key lifted out of it is a byte
// string, full stop. Interpreting it as text would make `0x00` remarkable, let
// two distinct byte sequences collapse into one via `U+FFFD`, and — worst —
// divorce the index key from the record bytes it indexes, so `materialize`
// would stop proving byte equality and start proving resemblance.

macro_rules! protocol_name {
    ($name:ident, $what:literal) => {
        #[doc = concat!("A ", $what, " chosen by the schema, not lifted from a payload.")]
        ///
        /// Text by nature, so the strict policy applies: valid UTF-8, no BOM,
        /// no normalization, non-empty. An empty name is a protocol error
        /// rather than data — unlike an empty [`KeyBytes`], which is simply a
        /// key that happens to be zero bytes long.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Parse a ", $what, ", rejecting empty and BOM-bearing input.")]
            pub fn parse(s: &str) -> Result<Self> {
                if s.is_empty() {
                    bail!(concat!($what, " must not be empty"));
                }
                reject_bom(s, $what)?;
                Ok($name(s.to_string()))
            }

            #[doc = concat!("The ", $what, " as it enters the canonical encoding.")]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

protocol_name!(FieldName, "field name");
protocol_name!(SetName, "set name");
protocol_name!(IndexName, "index name");

/// A value extracted from the artifact: an arbitrary byte string.
///
/// No UTF-8 requirement, no BOM policy, no normalization, no escaping. `0x00`
/// is an ordinary byte of a key rather than an occasion for human alarm, and
/// two distinct invalid UTF-8 sequences remain two distinct keys because
/// nothing ever tries to decode them.
///
/// Ordering is unsigned lexicographic over the bytes, which is what
/// `Box<[u8]>` already gives and what the index must use for a reproducible
/// total order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyBytes(Box<[u8]>);

impl KeyBytes {
    /// Wrap bytes as a key. Every byte string is a legal key, including empty.
    pub fn new(bytes: impl Into<Box<[u8]>>) -> Self {
        KeyBytes(bytes.into())
    }

    /// The exact bytes, as they enter the canonical encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The one envelope form a byte value may take in JSON.
    ///
    /// `{"encoding": "base64url-nopad", "data": "..."}`, plus a
    /// `display_utf8` field when the bytes happen to be valid UTF-8. That
    /// field is a courtesy for human readers and is **never** authoritative:
    /// identity and lookup use the decoded raw bytes only.
    pub fn to_envelope(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert("encoding".into(), "base64url-nopad".into());
        obj.insert("data".into(), base64url_nopad_encode(&self.0).into());
        if let Ok(text) = std::str::from_utf8(&self.0) {
            obj.insert("display_utf8".into(), text.into());
        }
        serde_json::Value::Object(obj)
    }

    /// Parse the envelope form, strictly.
    ///
    /// A `display_utf8` that disagrees with the decoded bytes is an error
    /// rather than a field to ignore: a value that describes itself two ways
    /// has already lost the argument about which one is authoritative.
    pub fn from_envelope(value: &serde_json::Value) -> Result<Self> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("byte value envelope must be an object"))?;
        for key in obj.keys() {
            if !matches!(key.as_str(), "encoding" | "data" | "display_utf8") {
                bail!("unknown field {key:?} in byte value envelope");
            }
        }
        match obj.get("encoding").and_then(|v| v.as_str()) {
            Some("base64url-nopad") => {}
            other => bail!("byte value encoding must be \"base64url-nopad\", got {other:?}"),
        }
        let data = obj
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("byte value envelope needs a string `data`"))?;
        let bytes = base64url_nopad_decode(data)?;
        if let Some(shown) = obj.get("display_utf8") {
            let shown = shown
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("`display_utf8` must be a string"))?;
            if std::str::from_utf8(&bytes) != Ok(shown) {
                bail!("`display_utf8` disagrees with the decoded bytes");
            }
        }
        Ok(KeyBytes(bytes.into_boxed_slice()))
    }
}

/// A query in the only form that identity is computed over.
///
/// A narrow typed enum rather than free-form JSON. Slice A needs exactly two
/// operations, and pinning them as variants means the encoding cannot drift
/// with a serializer option, a library upgrade, or a map iteration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalQuery {
    /// Exact match of one field against one artifact-derived value.
    Lookup { field: FieldName, value: KeyBytes },
    /// Intersection of named sets on a join key.
    Intersect { key: FieldName, sets: Vec<SetName> },
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
///
/// Candidates are artifact-derived values, so they are [`KeyBytes`] for the
/// same reason `Lookup.value` is: an index able to hold a key that a result
/// cannot express would be a curious system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalResult {
    candidates: Vec<KeyBytes>,
}

impl CanonicalResult {
    /// Build a result in canonical form: total order, no duplicates.
    ///
    /// Ordering is unsigned lexicographic over the raw bytes — no locale, no
    /// collation, nothing that could differ between runtimes. Without a total
    /// order the result digest is unstable across replays and the whole
    /// identity scheme collapses; case 12 of the Slice A negative matrix.
    pub fn new(candidates: impl IntoIterator<Item = KeyBytes>) -> Result<Self> {
        let mut v: Vec<KeyBytes> = candidates.into_iter().collect();
        v.sort_unstable();
        v.dedup();
        Ok(CanonicalResult { candidates: v })
    }

    /// The canonical candidates, sorted and deduplicated.
    pub fn candidates(&self) -> &[KeyBytes] {
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

/// One 6-bit group as a base64url digit.
///
/// Arithmetic rather than a lookup table: no indexing, so no panicking path to
/// reason about. Callers mask to 6 bits, so the final arm only ever sees 63.
fn b64url_digit(value: u32) -> char {
    match value {
        0..=25 => (b'A' + value as u8) as char,
        26..=51 => (b'a' + (value - 26) as u8) as char,
        52..=61 => (b'0' + (value - 52) as u8) as char,
        62 => '-',
        _ => '_',
    }
}

/// The inverse: a base64url digit as its 6-bit value, or `None` if the byte is
/// not in the alphabet. Padding and the standard alphabet's `+/` land here.
fn b64url_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a') as u32 + 26),
        b'0'..=b'9' => Some((c - b'0') as u32 + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// base64url without padding — the one text form a byte value may take.
fn base64url_nopad_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for shift in [18u32, 12, 6, 0].into_iter().take(chunk.len() + 1) {
            out.push(b64url_digit((n >> shift) & 63));
        }
    }
    out
}

/// Decode strictly: no padding, no standard-alphabet characters, no
/// whitespace, and no non-zero trailing bits.
///
/// The last point matters more than it looks. Two different encodings that
/// decode to the same bytes would give one byte string two spellings, and a
/// value with two spellings has no business being part of a content address.
fn base64url_nopad_decode(text: &str) -> Result<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for ch in text.bytes() {
        let Some(v) = b64url_value(ch) else {
            bail!("base64url-nopad rejects byte {ch:#04x}; padding and `+/` are not accepted");
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits >= 6 {
        bail!("base64url-nopad input has a dangling character");
    }
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        bail!("base64url-nopad input has non-zero trailing bits; encoding is not canonical");
    }
    Ok(out)
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
pub(crate) fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A protocol name enters as its UTF-8 bytes.
///
/// Wire-identical to [`encode_bytes`] on purpose: the difference between a
/// name and a key is what is *validated on the way in*, not how it is framed.
///
/// Stated precisely, because the loose version of this claim was wrong: the
/// wire encoding and all previously frozen non-empty-name vectors remain
/// unchanged. The final v1 input domain additionally admits arbitrary byte
/// values and **deliberately rejects empty protocol names**, which an
/// intermediate commit on this branch had accepted. That is a narrowing, not
/// a pure extension, so "fully additive" was the wrong word. It needs no
/// `qodec.query.v2` because v1 is being defined here rather than kept
/// compatible with a work-in-progress commit — git history is not a published
/// standard, however much it resembles one from the inside.
pub(crate) fn encode_name(out: &mut Vec<u8>, s: &str) {
    encode_bytes(out, s.as_bytes());
}

/// `u32be(count) || encode_str(e)…`, in the order given.
///
/// Infallible by construction: content validation happens where the value
/// enters the type — [`CanonicalResult::new`] for results, and
/// [`canonical_query_bytes`] for queries — so the encoder itself has no
/// failure mode to swallow, and no unreachable panic to explain away.
pub(crate) fn encode_count(out: &mut Vec<u8>, len: usize) -> Result<()> {
    // `as u32` would wrap silently, and a wrapped count is the worst possible
    // failure here: the sequence would still encode, still hash, and still
    // produce a confident identity for the wrong content.
    let count =
        u32::try_from(len).map_err(|_| anyhow::anyhow!("sequence of {len} items exceeds u32"))?;
    out.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

/// `u32be(count) || encode_name(e)…`, in the order given.
fn encode_name_seq(out: &mut Vec<u8>, items: &[SetName]) -> Result<()> {
    encode_count(out, items.len())?;
    for item in items {
        encode_name(out, item.as_str());
    }
    Ok(())
}

/// `u32be(count) || encode_bytes(e)…`, in the order given.
fn encode_key_seq(out: &mut Vec<u8>, items: &[KeyBytes]) -> Result<()> {
    encode_count(out, items.len())?;
    for item in items {
        encode_bytes(out, item.as_bytes());
    }
    Ok(())
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
            // The name was validated when it was parsed; the value is data and
            // is encoded exactly as found.
            encode_name(&mut out, field.as_str());
            encode_bytes(&mut out, value.as_bytes());
        }
        CanonicalQuery::Intersect { key, sets } => {
            encode_name(&mut out, key.as_str());
            let mut sets = sets.clone();
            sets.sort_unstable();
            sets.dedup();
            encode_name_seq(&mut out, &sets)?;
        }
    }
    Ok(out)
}

/// Serialize a complete result to its canonical bytes.
///
/// Fallible only in the one way that matters: a result too large to carry a
/// `u32` count is refused rather than encoded with a truncated length.
pub fn canonical_result_bytes(result: &CanonicalResult) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_key_seq(&mut out, &result.candidates)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Domain-separated digests
// ---------------------------------------------------------------------------

/// Digest canonical query bytes under the query domain.
pub fn digest_canonical_query_bytes(bytes: &[u8]) -> CanonicalQueryDigest {
    let mut preimage = domain_header(DOMAIN_CANONICAL_QUERY);
    preimage.extend_from_slice(&length_prefixed(bytes));
    CanonicalQueryDigest(Digest(sha256_raw(&preimage)))
}

/// Digest complete result bytes under the result domain.
///
/// Distinct from [`digest_canonical_query_bytes`] even for identical input
/// bytes: the domain string is part of the preimage, so a query digest can
/// never be presented as a result digest by protocol provenance.
pub fn digest_complete_result_bytes(bytes: &[u8]) -> CompleteResultDigest {
    let mut preimage = domain_header(DOMAIN_COMPLETE_RESULT);
    preimage.extend_from_slice(&length_prefixed(bytes));
    CompleteResultDigest(Digest(sha256_raw(&preimage)))
}

/// Digest canonical store-plan bytes under the store-plan domain.
///
/// The plan is how an artifact was opened. It is digested rather than carried
/// whole because it enters an identity, and identities want fixed-width
/// components with a domain of their own.
pub fn digest_store_plan_bytes(bytes: &[u8]) -> StorePlanDigest {
    let mut preimage = domain_header(DOMAIN_STORE_PLAN);
    preimage.extend_from_slice(&length_prefixed(bytes));
    StorePlanDigest(Digest(sha256_raw(&preimage)))
}

/// The identity of an opened store: which artifact, opened which way.
///
/// ```text
/// store_id = sha256(
///       domain("qodec.store-id.v1")
///    || field("artifact", artifact_digest_raw_32)
///    || field("plan",     store_plan_digest_raw_32))
/// ```
pub fn store_id(artifact: &ArtifactDigest, plan: &StorePlanDigest) -> StoreId {
    let mut preimage = domain_header(DOMAIN_STORE_ID);
    preimage.extend_from_slice(&framed_field("artifact", artifact.as_bytes()));
    preimage.extend_from_slice(&framed_field("plan", plan.as_bytes()));
    StoreId(Digest(sha256_raw(&preimage)))
}

/// Digest the exact serialized request body under the provider-request domain.
///
/// Takes bytes rather than a request type on purpose. The identity must cover
/// what left the process, so the only honest input is the buffer that was
/// handed to the transport — anything earlier certifies an intention.
pub fn digest_provider_request_bytes(bytes: &[u8]) -> ProviderRequestDigest {
    let mut preimage = domain_header(DOMAIN_PROVIDER_REQUEST);
    preimage.extend_from_slice(&length_prefixed(bytes));
    ProviderRequestDigest(Digest(sha256_raw(&preimage)))
}

/// Digest canonical support bytes under the result-support domain.
pub fn digest_result_support_bytes(bytes: &[u8]) -> ResultSupportDigest {
    let mut preimage = domain_header(DOMAIN_RESULT_SUPPORT);
    preimage.extend_from_slice(&length_prefixed(bytes));
    ResultSupportDigest(Digest(sha256_raw(&preimage)))
}

/// Digest of a query, end to end.
pub fn canonical_query_digest(
    schema: &SchemaId,
    query: &CanonicalQuery,
) -> Result<CanonicalQueryDigest> {
    Ok(digest_canonical_query_bytes(&canonical_query_bytes(
        schema, query,
    )?))
}

/// Digest of a complete result, end to end.
pub fn complete_result_digest(result: &CanonicalResult) -> Result<CompleteResultDigest> {
    Ok(digest_complete_result_bytes(&canonical_result_bytes(
        result,
    )?))
}

/// The content-addressed identity of a query result.
///
/// ```text
/// query_result_id = sha256(
///       domain("qodec.query-result-id.v1")
///    || field("schema", utf8(schema_id))
///    || field("store",  store_id_raw_32)
///    || field("query",  canonical_query_digest_raw_32)
///    || field("result",  complete_result_digest_raw_32)
///    || field("support", result_support_digest_raw_32)
/// )
/// ```
///
/// The **support** component is what stops evidence from being swapped
/// underneath an unchanged handle. Without it a result could keep its identity
/// while the records said to back it were replaced, and "proof-carrying" would
/// survive only as a pleasant name in a README.
///
/// The **store**, not merely the artifact. A result depends on how the
/// artifact was segmented and which indexes existed, so an identity naming
/// only the artifact would be immutable with respect to the evidence and
/// amnesiac with respect to how the answer was reached — a very technological
/// form of forgetfulness. `store_id` already binds the artifact transitively.
///
/// Every component is framed and every digest enters as raw bytes. Replaying
/// the same canonical query over the same **store** under the same schema
/// reproduces this value; any change to the artifact, the plan that opened it,
/// the question, the result, the supporting records, or the schema changes it.
/// The roles are distinct types, so a result digest cannot be passed where a
/// query digest belongs. That mistake is now a compile error rather than a
/// silently well-formed record with a confidently wrong identity.
pub fn query_result_id(
    schema: &SchemaId,
    store: &StoreId,
    query_digest: &CanonicalQueryDigest,
    result_digest: &CompleteResultDigest,
    support_digest: &ResultSupportDigest,
) -> QueryResultId {
    let mut preimage = domain_header(DOMAIN_QUERY_RESULT_ID);
    preimage.extend_from_slice(&framed_field("schema", schema.as_str().as_bytes()));
    preimage.extend_from_slice(&framed_field("store", store.as_bytes()));
    preimage.extend_from_slice(&framed_field("query", query_digest.as_bytes()));
    preimage.extend_from_slice(&framed_field("result", result_digest.as_bytes()));
    preimage.extend_from_slice(&framed_field("support", support_digest.as_bytes()));
    QueryResultId(Digest(sha256_raw(&preimage)))
}

// ---------------------------------------------------------------------------
// Loading a stored result
// ---------------------------------------------------------------------------

/// A query result as persisted, before anything about it has been believed.
///
/// Every field here arrived from outside — a file, a caller, a previous run —
/// so the typed roles say what each value *claims* to be and nothing yet says
/// the claim is true. `parse_canonical_text` asserts a role at the boundary;
/// it cannot prove provenance, because raw bytes carry none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredQueryResult {
    pub schema: SchemaId,
    pub artifact_digest: ArtifactDigest,
    pub store_plan_digest: StorePlanDigest,
    pub store_id: StoreId,
    pub canonical_query: CanonicalQuery,
    /// Canonical bytes of what backs the result: supporting records per
    /// candidate, and the completion state of the execution.
    pub support_bytes: Vec<u8>,
    pub result_support_digest: ResultSupportDigest,
    pub canonical_query_digest: CanonicalQueryDigest,
    pub complete_result: CanonicalResult,
    pub complete_result_digest: CompleteResultDigest,
    pub query_result_id: QueryResultId,
}

impl StoredQueryResult {
    /// Check that the record agrees with itself.
    ///
    /// The compiler protects code inside this crate from role confusion. It
    /// cannot protect the crate from files, callers, and the other classical
    /// sources of entropy — so a loader that merely parses is a loader that
    /// believes whatever it is handed. Recomputation is the only step that
    /// converts a claim into evidence.
    ///
    /// **This proves consistency, not provenance**, and the distinction is not
    /// pedantic. A record naming a different artifact, whose identity was then
    /// correctly recomputed over that artifact, is perfectly self-consistent
    /// and still answers a question about evidence nobody opened. Binding a
    /// result to the artifact actually in hand is
    /// [`verify_for_store`](Self::verify_for_store), and only that method can
    /// report `artifact-mismatch` or `store-plan-mismatch`.
    pub fn verify_internal_consistency(&self) -> Result<()> {
        let store = store_id(&self.artifact_digest, &self.store_plan_digest);
        if store != self.store_id {
            bail!(
                "stored store_id {} does not match the stored artifact and plan, which derive {}",
                self.store_id.to_canonical_text(),
                store.to_canonical_text()
            );
        }
        let query = canonical_query_digest(&self.schema, &self.canonical_query)?;
        if query != self.canonical_query_digest {
            bail!(
                "stored canonical_query_digest {} does not match the stored query, which digests to {}",
                self.canonical_query_digest.to_canonical_text(),
                query.to_canonical_text()
            );
        }
        let result = complete_result_digest(&self.complete_result)?;
        if result != self.complete_result_digest {
            bail!(
                "stored complete_result_digest {} does not match the stored result, which digests to {}",
                self.complete_result_digest.to_canonical_text(),
                result.to_canonical_text()
            );
        }
        let support = digest_result_support_bytes(&self.support_bytes);
        if support != self.result_support_digest {
            bail!(
                "stored result_support_digest {} does not match the stored support bytes, which \
                 digest to {}",
                self.result_support_digest.to_canonical_text(),
                support.to_canonical_text()
            );
        }
        let id = query_result_id(&self.schema, &store, &query, &result, &support);
        if id != self.query_result_id {
            bail!(
                "stored query_result_id {} does not match the recomputed {}",
                self.query_result_id.to_canonical_text(),
                id.to_canonical_text()
            );
        }
        Ok(())
    }

    /// Check the record against the store actually opened, then against itself.
    ///
    /// The binding comparisons come **first**, and they are reported
    /// separately. A record describing another artifact, or the same artifact
    /// opened a different way, is not a corrupt record — it may be flawless —
    /// it is simply an answer about something else, and reporting that as an
    /// internal inconsistency would send whoever reads the error looking for a
    /// bug in the wrong place.
    ///
    /// Artifact and plan are distinguished rather than folded into a single
    /// store comparison, because the two say different things: "this is about
    /// a different document" and "this is about the same document read a
    /// different way" call for different responses.
    pub fn verify_for_store(
        &self,
        expected_artifact: &ArtifactDigest,
        expected_plan: &StorePlanDigest,
    ) -> Result<()> {
        if &self.artifact_digest != expected_artifact {
            bail!(
                "artifact-mismatch: result was computed over {}, the opened artifact is {}",
                self.artifact_digest.to_canonical_text(),
                expected_artifact.to_canonical_text()
            );
        }
        if &self.store_plan_digest != expected_plan {
            bail!(
                "store-plan-mismatch: result was computed under plan {}, this store was opened \
                 with plan {}",
                self.store_plan_digest.to_canonical_text(),
                expected_plan.to_canonical_text()
            );
        }
        self.verify_internal_consistency()
    }
}
