//! Canonical store and index over a byte-exact artifact — Slice A.
//!
//! The proposal calls this step `decode_once`: one full decode of an artifact,
//! from which a record store and a key index are built, after which every
//! query is a set operation over record IDs and nothing ever looks at the
//! compressed representation again.
//!
//! **The name `decode_once` is deliberately not reused here**, because
//! [`crate::decode_once`] already exists and means something else — decode
//! exactly *one container layer*. Wiring the harness to that would leave a
//! pipeline half-decoded while every type still lined up, so this module calls
//! [`crate::decode`], which unwraps to RAW, and names its own entry point
//! [`CanonicalStore::open`]. A collision between "one layer" and "one full
//! decode" is precisely the kind that stays quiet until the results are wrong.
//!
//! Four properties hold, and the tests enforce each:
//!
//! * **Keys are bytes.** The artifact is byte-exact, so a key lifted out of it
//!   is a byte string. Nothing decodes, normalizes, or truncates it.
//! * **Record identity includes position.** Two identical records at two
//!   positions are two records, not one record encountered twice.
//! * **Construction is atomic, and fails closed.** `open` returns a complete
//!   store or an error; there is no partially-built state to observe. Note
//!   that this needed explicit work rather than falling out of `decode`:
//!   [`crate::decode`] is *lenient*, returning input it cannot parse unchanged
//!   as `Ok`, which is correct for a pipeline unwrapper and would have let a
//!   malformed artifact be adopted as a raw payload here — a fully populated,
//!   entirely confident store over garbage.
//! * **Materialization returns stored bytes.** Not a re-encoding, not a
//!   reconstruction — the same bytes the store holds.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Result};

use crate::canon::{ArtifactDigest, CanonicalResult, IndexName, KeyBytes, SetName};

/// Where a record sits in the artifact.
///
/// Deliberately **not** a hash of the record bytes. Two identical RAW records
/// in different positions are two distinct records; identifying them by
/// content alone would silently merge them, with no cryptographic collision
/// involved and no error to notice. The artifact binding lives on the store,
/// so a `RecordId` is only ever meaningful together with the store that
/// issued it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordId {
    section: SetName,
    ordinal: u64,
}

impl RecordId {
    /// The section this record belongs to.
    pub fn section(&self) -> &SetName {
        &self.section
    }

    /// The zero-based position of this record within its section.
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }
}

/// How the decoded RAW text is divided into sections and records.
///
/// A narrow typed enum for the same reason the query model is one: the
/// division decides record identity, so it must not depend on a caller's
/// closure, a regex dialect, or a locale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segmentation {
    /// One section; every line is a record, in file order.
    Lines { section: SetName },
    /// Sections start at a marker line `<prefix><name><suffix>`; every other
    /// line is a record of the section currently open. Lines before the first
    /// marker belong to `preamble`.
    MarkedSections {
        prefix: String,
        suffix: String,
        preamble: SetName,
    },
}

/// How an index key is extracted from a record's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyExtractor {
    /// The whole record, verbatim.
    WholeRecord,
    /// The `index`-th field (zero-based) after splitting on `separator`.
    ///
    /// A record with too few fields is simply absent from this index rather
    /// than indexed under a truncated or empty key — a missing key is missing,
    /// not empty, and conflating the two is how a lookup starts answering for
    /// records it never matched.
    Field { separator: u8, index: u32 },
}

impl KeyExtractor {
    /// Extract this record's key, or `None` when the record has none.
    fn extract(&self, record: &[u8]) -> Option<KeyBytes> {
        match self {
            KeyExtractor::WholeRecord => Some(KeyBytes::new(record.to_vec())),
            KeyExtractor::Field { separator, index } => {
                let wanted = usize::try_from(*index).ok()?;
                record
                    .split(|b| b == separator)
                    .nth(wanted)
                    .map(|f| KeyBytes::new(f.to_vec()))
            }
        }
    }
}

/// Which index to build, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexSpec {
    pub name: IndexName,
    pub extractor: KeyExtractor,
}

/// A decoded artifact as a deterministic data store.
///
/// `BTreeMap` throughout, not for love of trees but because the serialized and
/// replayed order must be reproducible. A hash map may become an internal
/// optimisation later; it must never decide an order that a digest depends on.
#[derive(Debug, Clone)]
pub struct CanonicalStore {
    artifact_digest: ArtifactDigest,
    records: BTreeMap<RecordId, Box<[u8]>>,
    indexes: BTreeMap<IndexName, BTreeMap<KeyBytes, Vec<RecordId>>>,
}

impl CanonicalStore {
    /// Decode an artifact once and build the store and every index.
    ///
    /// Returns a complete store or an error. There is no partially-built
    /// value to observe, because nothing is published until every index is
    /// finished — atomicity here is structural rather than promised.
    pub fn open(artifact_text: &str, seg: &Segmentation, specs: &[IndexSpec]) -> Result<Self> {
        let artifact_digest = ArtifactDigest::of_artifact_bytes(artifact_text.as_bytes());
        // Require a well-formed container *before* decoding.
        //
        // `crate::decode` is lenient by design: input it cannot parse is
        // returned unchanged, as `Ok`. That is right for a pipeline unwrapper
        // and wrong here — it would let a malformed artifact be adopted as a
        // raw payload and produce a confident, fully-populated store over
        // garbage, which is case 1 of the Slice A negative matrix passing
        // silently. So the container is parsed first and a failure to parse is
        // a failure to open.
        crate::container::parse(artifact_text)
            .map_err(|e| anyhow::anyhow!("artifact is not a well-formed %q1 container: {e}"))?;
        // ONE full decode. `crate::decode` unwraps pipelines to RAW;
        // `crate::decode_once` would stop after a single container layer.
        let raw = crate::decode(artifact_text)?;
        let records = segment(&raw, seg)?;

        let mut indexes: BTreeMap<IndexName, BTreeMap<KeyBytes, Vec<RecordId>>> = BTreeMap::new();
        for spec in specs {
            if indexes.contains_key(&spec.name) {
                bail!("duplicate index name {:?}", spec.name.as_str());
            }
            let mut index: BTreeMap<KeyBytes, Vec<RecordId>> = BTreeMap::new();
            for (id, bytes) in &records {
                if let Some(key) = spec.extractor.extract(bytes) {
                    index.entry(key).or_default().push(id.clone());
                }
            }
            for ids in index.values_mut() {
                ids.sort();
                ids.dedup();
            }
            indexes.insert(spec.name.clone(), index);
        }
        Ok(CanonicalStore {
            artifact_digest,
            records,
            indexes,
        })
    }

    /// The artifact this store was built from.
    pub fn artifact_digest(&self) -> &ArtifactDigest {
        &self.artifact_digest
    }

    /// How many records the artifact yielded.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Every record id, in canonical order.
    pub fn record_ids(&self) -> impl Iterator<Item = &RecordId> {
        self.records.keys()
    }

    /// Records carrying `key` in `index`, in canonical order.
    ///
    /// An unknown index is an error; an absent key is an empty result. The
    /// distinction matters: "you asked about something that does not exist"
    /// and "nothing matched" are different answers, and collapsing them lets a
    /// typo read as evidence of absence.
    pub fn lookup(&self, index: &IndexName, key: &KeyBytes) -> Result<Vec<RecordId>> {
        let idx = self
            .indexes
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("no index named {:?}", index.as_str()))?;
        Ok(idx.get(key).cloned().unwrap_or_default())
    }

    /// Keys present in **every** named section, under `index`.
    ///
    /// This is the join the reader panels kept getting wrong: a key qualifies
    /// only if some record carrying it lives in each requested section. The
    /// answer is a [`CanonicalResult`], so it arrives already in total order
    /// and deduplicated.
    pub fn intersect(&self, index: &IndexName, sections: &[SetName]) -> Result<CanonicalResult> {
        let idx = self
            .indexes
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("no index named {:?}", index.as_str()))?;
        if sections.is_empty() {
            bail!("intersect needs at least one section");
        }
        let known: BTreeSet<&SetName> = self.records.keys().map(|id| &id.section).collect();
        for s in sections {
            if !known.contains(s) {
                bail!("no section named {:?} in this artifact", s.as_str());
            }
        }
        let wanted: BTreeSet<&SetName> = sections.iter().collect();
        let mut hits = Vec::new();
        for (key, ids) in idx {
            let present: BTreeSet<&SetName> = ids.iter().map(|id| &id.section).collect();
            if wanted.iter().all(|s| present.contains(*s)) {
                hits.push(key.clone());
            }
        }
        CanonicalResult::new(hits)
    }

    /// The exact stored bytes of each requested record.
    ///
    /// Returns what the store holds, never a re-encoding or a reconstruction,
    /// which is what lets byte equality against the original payload be
    /// checked rather than asserted. An unknown id fails the whole call: a
    /// partial materialization would look like evidence while quietly omitting
    /// the part that did not resolve.
    pub fn materialize(&self, ids: &[RecordId]) -> Result<Vec<&[u8]>> {
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let bytes = self.records.get(id).ok_or_else(|| {
                anyhow::anyhow!(
                    "record {:?}#{} is not in this store",
                    id.section.as_str(),
                    id.ordinal
                )
            })?;
            out.push(&**bytes);
        }
        Ok(out)
    }
}

/// Divide decoded RAW text into identified records.
fn segment(raw: &str, seg: &Segmentation) -> Result<BTreeMap<RecordId, Box<[u8]>>> {
    let mut out: BTreeMap<RecordId, Box<[u8]>> = BTreeMap::new();
    match seg {
        Segmentation::Lines { section } => {
            for (i, line) in raw.lines().enumerate() {
                insert_record(&mut out, section.clone(), i, line.as_bytes())?;
            }
        }
        Segmentation::MarkedSections {
            prefix,
            suffix,
            preamble,
        } => {
            if prefix.is_empty() && suffix.is_empty() {
                bail!("marked sections need a non-empty prefix or suffix");
            }
            let mut current = preamble.clone();
            let mut ordinal = 0usize;
            for line in raw.lines() {
                if let Some(name) = line
                    .strip_prefix(prefix.as_str())
                    .and_then(|r| r.strip_suffix(suffix.as_str()))
                {
                    current = SetName::parse(name)?;
                    ordinal = 0;
                    continue;
                }
                insert_record(&mut out, current.clone(), ordinal, line.as_bytes())?;
                ordinal += 1;
            }
        }
    }
    Ok(out)
}

/// Insert one record, refusing to overwrite an already-issued id.
fn insert_record(
    out: &mut BTreeMap<RecordId, Box<[u8]>>,
    section: SetName,
    ordinal: usize,
    bytes: &[u8],
) -> Result<()> {
    let ordinal = u64::try_from(ordinal)
        .map_err(|_| anyhow::anyhow!("record ordinal {ordinal} exceeds u64"))?;
    let id = RecordId { section, ordinal };
    if out.contains_key(&id) {
        bail!(
            "duplicate record id {:?}#{ordinal} — segmentation is not injective",
            id.section.as_str()
        );
    }
    out.insert(id, bytes.to_vec().into_boxed_slice());
    Ok(())
}
