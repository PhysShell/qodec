//! Canonical store and index over a byte-exact artifact — Slice A.
//!
//! The proposal calls this step `decode_once`: one full decode of an artifact,
//! from which a record store and a key index are built, after which every
//! query is a set operation over record IDs and nothing ever looks at the
//! compressed representation again.
//!
//! **The name `decode_once` is deliberately not reused for the entry point**,
//! because [`crate::decode_once`] already exists and means one *container
//! layer*, not one full open. This module's entry point is therefore
//! [`CanonicalStore::open`], and it calls `crate::decode_once` exactly
//! [`StorePlan::decode_layers`] times. A collision between "one layer" and
//! "one full decode" is precisely the kind that stays quiet until the results
//! are wrong.
//!
//! Five properties hold, and the tests enforce each:
//!
//! * **Depth is declared, never inferred.** See [`StorePlan`]. The earlier
//!   revision called [`crate::decode`], which unwraps until the text stops
//!   parsing as a container. That is a guess, and it is wrong in both
//!   directions at once: it walks past the artifact's pipeline boundary when a
//!   RAW payload is itself container-shaped, and it accepts a corrupt
//!   intermediate layer as though it were the payload.
//! * **Keys are bytes.** The artifact is byte-exact, so a key lifted out of it
//!   is a byte string. Nothing decodes, normalizes, or truncates it.
//! * **Record identity includes position.** Two identical records at two
//!   positions are two records, not one record encountered twice.
//! * **Construction is atomic, and fails closed.** `open` returns a complete
//!   store or an error; there is no partially-built state to observe. Every
//!   one of the `decode_layers` layers must parse *and* decode, so a malformed
//!   artifact cannot be adopted as a raw payload — a fully populated, entirely
//!   confident store over garbage.
//! * **Materialization returns stored bytes.** Not a re-encoding, not a
//!   reconstruction — the same bytes the store holds.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use anyhow::{bail, Context, Result};

use crate::canon::{
    digest_store_plan_bytes, encode_bytes, encode_count, encode_name, store_id, ArtifactDigest,
    CanonicalResult, IndexName, KeyBytes, SetName, StoreId, StorePlanDigest,
};

/// One index: key bytes to the records carrying them, in canonical order.
type KeyIndex = BTreeMap<KeyBytes, Vec<LocalRecordId>>;
/// Every index the store was built with, by name.
type IndexSet = BTreeMap<IndexName, KeyIndex>;
/// The record table: coordinates to the exact decoded bytes at them.
type RecordTable = BTreeMap<LocalRecordId, Box<[u8]>>;
/// What segmentation yields: the records, and every section it declared.
type Segmented = (RecordTable, BTreeSet<SetName>);

/// Coordinates inside one artifact. Never leaves this module.
///
/// Compact on purpose: repeating the artifact digest in every stored key would
/// cost 32 bytes per record to restate something the store already knows.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct LocalRecordId {
    section: SetName,
    ordinal: u64,
}

/// A record identity, bound to the artifact that issued it.
///
/// Two things are deliberate here.
///
/// It is **not** a hash of the record bytes. Two identical RAW records in
/// different positions are two distinct records; identifying them by content
/// alone would silently merge them, with no cryptographic collision involved
/// and no error to notice.
///
/// It carries the **store id**, not merely the artifact digest. Coordinates
/// are only unambiguous inside the space where they were issued, and that
/// space is an artifact *together with the plan that opened it*. Both halves
/// were established by running the collision rather than reasoning about it:
///
/// * across artifacts, `s#0` exists in almost every store, so a foreign id
///   resolved locally and returned another artifact's bytes;
/// * across plans over the *same* artifact — identical artifact digest —
///   `Lines` and `MarkedSections` both issue `s#0`, pointing at
///   `"--- s ---"` and `"alpha"` respectively, and the first revision to fix
///   the artifact case still returned the wrong line here.
///
/// That is case 10 of the Slice A negative matrix in both of its forms.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordId {
    store_id: StoreId,
    local: LocalRecordId,
}

impl RecordId {
    /// The store this id is valid against: one artifact, opened one way.
    pub fn store_id(&self) -> &StoreId {
        &self.store_id
    }

    /// The section this record belongs to.
    pub fn section(&self) -> &SetName {
        &self.local.section
    }

    /// The zero-based position of this record within its section.
    pub fn ordinal(&self) -> u64 {
        self.local.ordinal
    }

    /// Rebuild an id from the wire envelope a caller was handed.
    ///
    /// Needed because the model names records in JSON and something must turn
    /// that back into a typed id. Deliberately *not* a privilege: parsing
    /// asserts a claim, it does not grant one. An id built here is still
    /// checked against the support of the result it is presented with, so a
    /// fabricated coordinate — a section that does not exist, an ordinal past
    /// the end, another store's id — parses fine and is then refused. The
    /// alternative, letting the panel accept loose JSON and resolve
    /// coordinates itself, would put the same construction in a place where
    /// the scope check is easier to forget.
    pub fn from_envelope(value: &serde_json::Value) -> Result<Self> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("record id must be an object"))?;
        for key in obj.keys() {
            if !matches!(key.as_str(), "store" | "section" | "ordinal") {
                bail!("unknown field {key:?} in record id");
            }
        }
        let store = obj
            .get("store")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("record id needs a string `store`"))?;
        let section = obj
            .get("section")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("record id needs a string `section`"))?;
        let ordinal = obj
            .get("ordinal")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("record id needs an unsigned integer `ordinal`"))?;
        Ok(RecordId {
            store_id: StoreId::parse_canonical_text(store)?,
            local: LocalRecordId {
                section: SetName::parse(section)?,
                ordinal,
            },
        })
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

/// How an artifact is opened: how deep to decode, how to segment, what to index.
///
/// The plan exists because the artifact's bytes do not determine their own
/// reading. `container::raw(x)` is `"%q1 raw\n%q1 body\n" + x`, so a one-layer
/// artifact whose RAW payload legitimately begins `%q1 raw` is *byte-identical*
/// to a two-layer pipeline whose inner separator was truncated. Those two want
/// opposite answers — return the payload, or refuse as corrupt — and no
/// examination of the text can tell them apart, because what distinguishes them
/// is not in the text. An open-ended "unwrap until it stops parsing" loop is
/// therefore not a conservative default; it is a silent guess.
///
/// So depth is declared. It comes from the trusted fixture or store manifest
/// written alongside the artifact, and never from the model or the query
/// caller: resolving an ambiguity and then inviting the untrusted party to pick
/// its resolution would leave exactly the hole it closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorePlan {
    decode_layers: NonZeroU32,
    segmentation: Segmentation,
    /// Sorted by index name at construction, so the order a caller happened to
    /// list its specs in cannot change the store's identity.
    indexes: Vec<IndexSpec>,
}

impl StorePlan {
    /// Build a plan, rejecting a depth of zero and duplicate index names.
    ///
    /// Zero layers would mean adopting the container *itself* as RAW data —
    /// indexing `%q1 raw` and the separator line as records and calling the
    /// result an artifact's contents. The crate has enough ways to be
    /// confidently wrong already, so the type does not offer that one.
    pub fn new(
        decode_layers: u32,
        segmentation: Segmentation,
        specs: Vec<IndexSpec>,
    ) -> Result<Self> {
        let decode_layers = NonZeroU32::new(decode_layers)
            .ok_or_else(|| anyhow::anyhow!("decode_layers must be at least 1, got 0"))?;
        let mut indexes = specs;
        indexes.sort_by(|a, b| a.name.as_str().cmp(b.name.as_str()));
        for pair in indexes.windows(2) {
            if let [a, b] = pair {
                if a.name == b.name {
                    bail!("duplicate index name {:?}", a.name.as_str());
                }
            }
        }
        Ok(StorePlan {
            decode_layers,
            segmentation,
            indexes,
        })
    }

    /// How many top-level container layers `open` will decode.
    pub fn decode_layers(&self) -> NonZeroU32 {
        self.decode_layers
    }

    /// How the decoded RAW text is divided into sections and records.
    pub fn segmentation(&self) -> &Segmentation {
        &self.segmentation
    }

    /// The index specs, in canonical (name-sorted) order.
    pub fn indexes(&self) -> &[IndexSpec] {
        &self.indexes
    }

    /// This plan's digest — one of the two halves of a [`StoreId`].
    pub fn digest(&self) -> Result<StorePlanDigest> {
        Ok(digest_store_plan_bytes(&self.canonical_bytes()?))
    }
}

/// A decoded artifact as a deterministic data store.
///
/// `BTreeMap` throughout, not for love of trees but because the serialized and
/// replayed order must be reproducible. A hash map may become an internal
/// optimisation later; it must never decide an order that a digest depends on.
#[derive(Debug, Clone)]
pub struct CanonicalStore {
    artifact_digest: ArtifactDigest,
    store_plan_digest: StorePlanDigest,
    store_id: StoreId,
    /// Every section the artifact declares, including ones holding no records.
    ///
    /// Kept separately from `records` on purpose: deriving the known sections
    /// from the records that exist would make a declared-but-empty section
    /// indistinguishable from a misspelled one, so intersecting over it would
    /// report "no such section" when the correct answer is an empty result.
    sections: BTreeSet<SetName>,
    records: RecordTable,
    indexes: IndexSet,
}

impl CanonicalStore {
    /// Decode an artifact to the plan's depth and build the store and indexes.
    ///
    /// Returns a complete store or an error. There is no partially-built
    /// value to observe, because nothing is published until every index is
    /// finished — atomicity here is structural rather than promised.
    ///
    /// The depth comes from `plan`, never from the artifact and never from a
    /// caller downstream of the model. See [`StorePlan`] for why it cannot be
    /// inferred from the bytes.
    pub fn open(artifact_text: &str, plan: &StorePlan) -> Result<Self> {
        let artifact_digest = ArtifactDigest::of_artifact_bytes(artifact_text.as_bytes());
        // Exactly `decode_layers` top-level layers, each of which must parse
        // and decode. `crate::decode` is *not* used: it loops until the text
        // stops parsing as a container, which both unwraps past the artifact's
        // pipeline boundary when a payload is container-shaped and accepts a
        // corrupt intermediate layer as if it were the payload. Both are the
        // same guess, made in opposite directions.
        //
        // Note what is *not* counted here: a codec's internal containers — a
        // mosaic's segments, say — are decoded inside `decode_container` as
        // part of their own layer, so they never inflate the top-level depth.
        let mut current = artifact_text.to_owned();
        for layer in 0..plan.decode_layers.get() {
            current = crate::decode_once(&current).with_context(|| {
                format!(
                    "artifact layer {}/{} is not a valid decodable %q1 container",
                    layer + 1,
                    plan.decode_layers
                )
            })?;
        }
        // Whatever layer `decode_layers` lands on *is* the RAW payload. Its
        // shape is deliberately not inspected: a payload has every right to
        // look like a container, and checking would reject valid artifacts
        // while still not detecting the corrupt ones.
        let raw = current;
        let store_plan_digest = plan.digest()?;
        let store_id = store_id(&artifact_digest, &store_plan_digest);
        let (records, sections) = segment(&raw, &plan.segmentation)?;

        let mut indexes: IndexSet = BTreeMap::new();
        for spec in &plan.indexes {
            let mut index: KeyIndex = BTreeMap::new();
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
            store_plan_digest,
            store_id,
            sections,
            records,
            indexes,
        })
    }

    /// The artifact this store was built from.
    pub fn artifact_digest(&self) -> &ArtifactDigest {
        &self.artifact_digest
    }

    /// How this artifact was opened: segmentation plus index specs.
    pub fn store_plan_digest(&self) -> &StorePlanDigest {
        &self.store_plan_digest
    }

    /// This store's identity — the space in which its record ids are valid.
    pub fn store_id(&self) -> &StoreId {
        &self.store_id
    }

    /// Scan an index for keys present in every named section, collecting
    /// support, and **stop** as soon as a budget would be exceeded.
    ///
    /// The bound is operational, not a label applied afterwards. Collecting
    /// everything and then reporting "that was over the limit" is a very
    /// disciplined way to run out of memory: the caller learns about the
    /// budget only once the cost has already been paid. Nothing beyond the
    /// budget is ever placed in the returned map.
    ///
    /// A candidate whose own support would not fit is not stored partially —
    /// half the evidence for a candidate is worse than none, because it looks
    /// like evidence.
    pub fn scan_intersect(
        &self,
        index: &IndexName,
        sections: &[SetName],
        max_candidates: u64,
        max_support_records: u64,
    ) -> Result<IntersectScan> {
        let idx = self
            .indexes
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("no index named {:?}", index.as_str()))?;
        if sections.is_empty() {
            bail!("intersect needs at least one section");
        }
        for s in sections {
            if !self.sections.contains(s) {
                bail!("no section named {:?} in this artifact", s.as_str());
            }
        }
        let wanted: BTreeSet<&SetName> = sections.iter().collect();
        let mut support: BTreeMap<KeyBytes, Vec<RecordId>> = BTreeMap::new();
        let mut total: u64 = 0;
        let mut stopped = None;

        for (key, ids) in idx {
            let present: BTreeSet<&SetName> = ids.iter().map(|id| &id.section).collect();
            if !wanted.iter().all(|s| present.contains(*s)) {
                continue;
            }
            // A qualifying candidate exists beyond the budget: that is the
            // signal, and it is detected before anything more is stored.
            if u64::try_from(support.len()).unwrap_or(u64::MAX) >= max_candidates {
                stopped = Some(ScanStop::Candidates(max_candidates));
                break;
            }
            let kept: Vec<RecordId> = ids
                .iter()
                .filter(|id| wanted.contains(&id.section))
                .map(|id| self.bind(id))
                .collect();
            let cost = u64::try_from(kept.len()).unwrap_or(u64::MAX);
            if total.saturating_add(cost) > max_support_records {
                stopped = Some(ScanStop::SupportRecords(max_support_records));
                break;
            }
            total = total.saturating_add(cost);
            support.insert(key.clone(), kept);
        }
        Ok(IntersectScan { support, stopped })
    }

    /// Records carrying `key`, up to a budget, reporting whether more exist.
    pub fn scan_lookup(
        &self,
        index: &IndexName,
        key: &KeyBytes,
        max_support_records: u64,
    ) -> Result<LookupScan> {
        let idx = self
            .indexes
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("no index named {:?}", index.as_str()))?;
        let all = idx.get(key);
        let budget = usize::try_from(max_support_records).unwrap_or(usize::MAX);
        let stopped = all.is_some_and(|ids| ids.len() > budget);
        let support = all
            .map(|ids| ids.iter().take(budget).map(|id| self.bind(id)).collect())
            .unwrap_or_default();
        Ok(LookupScan { support, stopped })
    }

    /// Execute a canonical query and issue an immutable result.
    ///
    /// Delegates to [`crate::query::execute`], which is the only place a
    /// [`crate::query::HarnessIssuedResult`] can be constructed.
    pub fn execute(
        &self,
        schema: &crate::canon::SchemaId,
        query: crate::canon::CanonicalQuery,
        limits: crate::query::ExecutionLimits,
    ) -> Result<crate::query::HarnessIssuedResult> {
        crate::query::execute(self, schema, query, limits)
    }

    /// How many records the artifact yielded.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Every section the artifact declares, including empty ones.
    pub fn sections(&self) -> impl Iterator<Item = &SetName> {
        self.sections.iter()
    }

    /// Every record id, in canonical order, bound to this artifact.
    pub fn record_ids(&self) -> impl Iterator<Item = RecordId> + '_ {
        self.records.keys().map(|local| self.bind(local))
    }

    /// Attach this store's artifact binding to local coordinates.
    fn bind(&self, local: &LocalRecordId) -> RecordId {
        RecordId {
            store_id: self.store_id,
            local: local.clone(),
        }
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
        Ok(idx
            .get(key)
            .map(|ids| ids.iter().map(|l| self.bind(l)).collect())
            .unwrap_or_default())
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
        // Declared sections, not merely populated ones: a section that exists
        // and holds nothing must intersect to an empty result, while a section
        // that does not exist must be an error. Deriving this from the records
        // would collapse the two and let a typo read as "nothing qualifies".
        for s in sections {
            if !self.sections.contains(s) {
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
        // Artifact binding first, for every id, before any coordinate is
        // resolved. Checking it per-id while resolving would let a foreign id
        // whose coordinates happen to exist return this artifact's bytes, and
        // the call would only fail later — if some *other* id happened not to
        // resolve. That is exactly how the previous revision passed its own
        // test for the wrong reason.
        for id in ids {
            if id.store_id != self.store_id {
                bail!(
                    "store-mismatch: record id belongs to store {}, this store is {}",
                    id.store_id.to_canonical_text(),
                    self.store_id.to_canonical_text()
                );
            }
        }
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let bytes = self.records.get(&id.local).ok_or_else(|| {
                anyhow::anyhow!(
                    "record {:?}#{} is not in this store",
                    id.local.section.as_str(),
                    id.local.ordinal
                )
            })?;
            out.push(&**bytes);
        }
        Ok(out)
    }
}

/// Divide decoded RAW text into identified records and declared sections.
///
/// Returns both, because a section that exists and holds no records is a
/// different thing from a section that does not exist, and only the caller
/// keeping the declared set can tell them apart afterwards.
fn segment(raw: &str, seg: &Segmentation) -> Result<Segmented> {
    let mut out: RecordTable = BTreeMap::new();
    let mut sections: BTreeSet<SetName> = BTreeSet::new();
    match seg {
        Segmentation::Lines { section } => {
            // Declared unconditionally: an artifact with an empty payload
            // still has this section, and intersecting over it is an empty
            // result rather than an unknown-section error.
            sections.insert(section.clone());
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
            sections.insert(preamble.clone());
            let mut current = preamble.clone();
            let mut ordinal = 0usize;
            for line in raw.lines() {
                if let Some(name) = line
                    .strip_prefix(prefix.as_str())
                    .and_then(|r| r.strip_suffix(suffix.as_str()))
                {
                    let name = SetName::parse(name)?;
                    // Re-opening a section is refused explicitly rather than
                    // left to collide as a duplicate id downstream. Resuming
                    // would need an ordinal continuation rule, and inventing
                    // one silently is how two records quietly become one.
                    if !sections.insert(name.clone()) {
                        bail!(
                            "section {:?} is opened more than once; resuming a section is not \
                             supported, so its records would collide",
                            name.as_str()
                        );
                    }
                    current = name;
                    ordinal = 0;
                    continue;
                }
                insert_record(&mut out, current.clone(), ordinal, line.as_bytes())?;
                ordinal += 1;
            }
        }
    }
    Ok((out, sections))
}

/// Insert one record, refusing to overwrite an already-issued id.
fn insert_record(
    out: &mut RecordTable,
    section: SetName,
    ordinal: usize,
    bytes: &[u8],
) -> Result<()> {
    let ordinal = u64::try_from(ordinal)
        .map_err(|_| anyhow::anyhow!("record ordinal {ordinal} exceeds u64"))?;
    let id = LocalRecordId { section, ordinal };
    if out.contains_key(&id) {
        bail!(
            "duplicate record id {:?}#{ordinal} — segmentation is not injective",
            id.section.as_str()
        );
    }
    out.insert(id, bytes.to_vec().into_boxed_slice());
    Ok(())
}

impl StorePlan {
    /// Canonical bytes of an open plan: depth, segmentation, every index spec.
    ///
    /// ```text
    /// plan := u32be(decode_layers)
    ///      || segmentation_discriminant || segmentation_parameters…
    ///      || u32be(index_count) || index_spec…
    /// ```
    ///
    /// `decode_layers` leads, and it belongs to the identity rather than being
    /// a hint alongside it: two stores over the same bytes at different depths
    /// hold genuinely different records, so they must be different stores.
    /// Every variant carries an explicit frozen discriminant and every
    /// variable-width parameter is length-delimited, for the same reasons the
    /// query encoding does. The specs were sorted by name at construction, so
    /// the encoder does not need to re-sort to be canonical.
    ///
    /// Public because it is the normative serialization, and an independent
    /// implementation has to be able to compare against it directly. Pinning
    /// only [`StorePlan::digest`] would leave the encoder free to drift from
    /// the published format as long as it drifted consistently with itself.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.decode_layers.get().to_be_bytes());
        match &self.segmentation {
            Segmentation::Lines { section } => {
                out.push(1);
                encode_name(&mut out, section.as_str());
            }
            Segmentation::MarkedSections {
                prefix,
                suffix,
                preamble,
            } => {
                out.push(2);
                // Markers are data, not protocol names: either may legitimately
                // be empty, and neither is a schema identifier.
                encode_bytes(&mut out, prefix.as_bytes());
                encode_bytes(&mut out, suffix.as_bytes());
                encode_name(&mut out, preamble.as_str());
            }
        }
        encode_count(&mut out, self.indexes.len())?;
        for spec in &self.indexes {
            encode_name(&mut out, spec.name.as_str());
            match &spec.extractor {
                KeyExtractor::WholeRecord => out.push(1),
                KeyExtractor::Field { separator, index } => {
                    out.push(2);
                    out.push(*separator);
                    out.extend_from_slice(&index.to_be_bytes());
                }
            }
        }
        Ok(out)
    }
}

/// Why a bounded scan stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStop {
    /// Another qualifying candidate exists beyond the candidate budget.
    Candidates(u64),
    /// The next candidate's support would not fit in the record budget.
    SupportRecords(u64),
}

/// What a bounded intersect scan collected, and whether it finished.
#[derive(Debug, Clone)]
pub struct IntersectScan {
    pub support: BTreeMap<KeyBytes, Vec<RecordId>>,
    pub stopped: Option<ScanStop>,
}

/// What a bounded lookup collected, and whether more records exist.
#[derive(Debug, Clone)]
pub struct LookupScan {
    pub support: Vec<RecordId>,
    pub stopped: bool,
}
