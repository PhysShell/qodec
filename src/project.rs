//! `qodec project` — a generic, relation-aware projection primitive (v0).
//!
//! Qodec owns a projection capability here, but it owns it *generically*: the
//! request/result protocol carries no domain meaning. Eligibility, staleness,
//! authority classes, topics — anything caller-domain-specific — is decided by
//! the caller and arrives as a bare `eligible: bool` plus opaque `caller_evidence`.
//! Qodec enforces the supplied admission decision; it never redefines it. There is
//! deliberately no caller-domain, observation-namespace, question-namespace or
//! B1-namespace string literal in this file (a source-scan test enforces that).
//!
//! v0 is relation-aware *closure*, not an optimizer: it starts from the caller's
//! base selection, adds exactly the records and edges that the declared relation
//! requirements demand, keeps ineligible/stale requirement targets relation-only,
//! and fails closed if the mandatory closure overflows either budget. It never
//! evicts a baseline record and never invents an edge.
//!
//! Identity is recomputed, never trusted: the request canonical digest, every
//! payload's canonical bytes, the exact relation target sets, the selected count
//! and the semantic byte usage are all computed here from the request bytes.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};

pub const REQUEST_SCHEMA: &str = "qodec-project-request-v0";
pub const RESULT_SCHEMA: &str = "qodec-project-result-v0";
pub const PRODUCER_VERSION: &str = "qodec.project/v0";
/// Self-identity: sha256 of this module's own source, embedded at compile time.
pub fn implementation_sha256() -> String {
    hex(&Sha256::digest(include_str!("project.rs").as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Canonical JSON: serde_json's default `Map` is a `BTreeMap`, so object keys are
/// emitted in sorted order and `to_string` is compact (`,`/`:` separators). This
/// matches the caller's `sort_keys=True, separators=(',',':')` canonical form, so
/// digests computed on both sides agree.
fn canonical(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

fn sha256_str(s: &str) -> String {
    hex(&Sha256::digest(s.as_bytes()))
}

// ---- typed views over the request Value (no serde-derive dependency) --------

fn obj<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>> {
    v.as_object()
        .with_context(|| format!("{what} must be a JSON object"))
}
fn field<'a>(m: &'a Map<String, Value>, k: &str, what: &str) -> Result<&'a Value> {
    m.get(k)
        .with_context(|| format!("{what} missing required field {k:?}"))
}
fn field_str<'a>(m: &'a Map<String, Value>, k: &str, what: &str) -> Result<&'a str> {
    field(m, k, what)?
        .as_str()
        .with_context(|| format!("{what}.{k} must be a string"))
}
fn field_u64(m: &Map<String, Value>, k: &str, what: &str) -> Result<u64> {
    field(m, k, what)?
        .as_u64()
        .with_context(|| format!("{what}.{k} must be a non-negative integer"))
}
fn field_bool(m: &Map<String, Value>, k: &str, what: &str) -> Result<bool> {
    field(m, k, what)?
        .as_bool()
        .with_context(|| format!("{what}.{k} must be a boolean"))
}
fn field_arr<'a>(m: &'a Map<String, Value>, k: &str, what: &str) -> Result<&'a Vec<Value>> {
    field(m, k, what)?
        .as_array()
        .with_context(|| format!("{what}.{k} must be an array"))
}

struct Record {
    payload: Value,
    eligible: bool,
    base_selected: bool,
    canonical_bytes: u64,
}

struct Requirement {
    requirement_id: String,
    from: String,
    kind: String,
    endpoint_policy: String, // "edge_witness" | "all_current_targets_materialized"
    expected_targets: Vec<String>,
}

// ---- the projection ---------------------------------------------------------

/// Canonical request form: set-valued arrays are order-independent, so they are
/// sorted before the request digest is taken, and the caller-supplied `input_digest`
/// (a claim, not authority) is excluded. Reordering inputs therefore cannot move the
/// request identity — the whole result is deterministic under input reordering.
fn normalize_request(req: &Value) -> Value {
    let mut m = req.as_object().cloned().unwrap_or_default();
    m.remove("input_digest");
    if let Some(Value::Array(a)) = m.get_mut("records") {
        a.sort_by(|x, y| x["id"].as_str().cmp(&y["id"].as_str()));
    }
    if let Some(Value::Array(a)) = m.get_mut("relations") {
        a.sort_by(|x, y| {
            let kx = (x["from"].as_str(), x["kind"].as_str(), x["to"].as_str());
            let ky = (y["from"].as_str(), y["kind"].as_str(), y["to"].as_str());
            kx.cmp(&ky)
        });
    }
    if let Some(Value::Array(a)) = m.get_mut("relation_requirements") {
        for r in a.iter_mut() {
            if let Some(Value::Array(t)) = r.get_mut("expected_targets") {
                t.sort_by(|x, y| x.as_str().cmp(&y.as_str()));
            }
        }
        a.sort_by(|x, y| {
            x["requirement_id"]
                .as_str()
                .cmp(&y["requirement_id"].as_str())
        });
    }
    if let Some(Value::Array(a)) = m.get_mut("required_record_ids") {
        a.sort_by(|x, y| x.as_str().cmp(&y.as_str()));
    }
    Value::Object(m)
}

// All map indexing below uses keys drawn from the same maps (record_order,
// selected, reasons all key into `records`), so it cannot panic; clippy cannot
// prove that, so the restriction lint is suppressed here as the repo does elsewhere.
#[allow(clippy::indexing_slicing)]
pub fn project_json(request_text: &str) -> Result<String> {
    let req: Value = serde_json::from_str(request_text).context("request is not valid JSON")?;
    let rm = obj(&req, "request")?;
    if field_str(rm, "schema", "request")? != REQUEST_SCHEMA {
        bail!("request.schema must be {REQUEST_SCHEMA:?}");
    }
    let request_id = field_str(rm, "request_id", "request")?.to_string();
    let request_canonical_sha256 = sha256_str(&canonical(&normalize_request(&req)));

    // budget
    let bm = obj(field(rm, "budget", "request")?, "request.budget")?;
    let semantic_byte_limit = field_u64(bm, "semantic_byte_limit", "budget")?;
    let record_limit = field_u64(bm, "record_limit", "budget")?;

    // records (reject duplicate ids)
    let mut records: BTreeMap<String, Record> = BTreeMap::new();
    let mut record_order: Vec<String> = Vec::new();
    for (i, rv) in field_arr(rm, "records", "request")?.iter().enumerate() {
        let m = obj(rv, &format!("records[{i}]"))?;
        let id = field_str(m, "id", "record")?.to_string();
        let payload = field(m, "payload", "record")?.clone();
        let cb = canonical(&payload).len() as u64 + 1; // +1 record separator (LF)
                                                       // caller_evidence is opaque: qodec enforces `eligible`, never redefines it,
                                                       // so the evidence is validated-present but not interpreted here.
        let _caller_evidence = field(m, "caller_evidence", "record")?;
        let rec = Record {
            payload,
            eligible: field_bool(m, "eligible", "record")?,
            base_selected: field_bool(m, "base_selected", "record")?,
            canonical_bytes: cb,
        };
        if records.insert(id.clone(), rec).is_some() {
            bail!("duplicate record id {id:?}");
        }
        record_order.push(id);
    }

    // relations (reject duplicate exact triples + unknown endpoints)
    let mut edges: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut by_from_kind: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for (i, ev) in field_arr(rm, "relations", "request")?.iter().enumerate() {
        let m = obj(ev, &format!("relations[{i}]"))?;
        let f = field_str(m, "from", "relation")?.to_string();
        let k = field_str(m, "kind", "relation")?.to_string();
        let t = field_str(m, "to", "relation")?.to_string();
        if !records.contains_key(&f) {
            bail!("relation from unknown endpoint {f:?}");
        }
        if !records.contains_key(&t) {
            bail!("relation to unknown endpoint {t:?}");
        }
        if !edges.insert((f.clone(), k.clone(), t.clone())) {
            bail!("duplicate relation triple {f:?}/{k:?}/{t:?}");
        }
        by_from_kind.entry((f, k)).or_default().insert(t);
    }

    // requirements
    let mut reqs: Vec<Requirement> = Vec::new();
    for (i, qv) in field_arr(rm, "relation_requirements", "request")?
        .iter()
        .enumerate()
    {
        let m = obj(qv, &format!("relation_requirements[{i}]"))?;
        if field_str(m, "direction", "requirement")? != "outgoing"
            || field(m, "depth", "requirement")?.as_u64() != Some(1)
            || field_str(m, "match", "requirement")? != "all"
        {
            bail!("requirement v0 supports only direction=outgoing depth=1 match=all");
        }
        let policy = field_str(m, "endpoint_policy", "requirement")?.to_string();
        if policy != "edge_witness" && policy != "all_current_targets_materialized" {
            bail!("unknown endpoint_policy {policy:?}");
        }
        let expected: Vec<String> = field_arr(m, "expected_targets", "requirement")?
            .iter()
            .map(|t| {
                t.as_str()
                    .map(str::to_string)
                    .context("expected_targets item must be a string")
            })
            .collect::<Result<_>>()?;
        reqs.push(Requirement {
            requirement_id: field_str(m, "requirement_id", "requirement")?.to_string(),
            from: field_str(m, "from", "requirement")?.to_string(),
            kind: field_str(m, "kind", "requirement")?.to_string(),
            endpoint_policy: policy,
            expected_targets: expected,
        });
    }

    reqs.sort_by(|a, b| a.requirement_id.cmp(&b.requirement_id));

    let required_ids: Vec<String> = field_arr(rm, "required_record_ids", "request")?
        .iter()
        .map(|t| {
            t.as_str()
                .map(str::to_string)
                .context("required_record_ids item must be a string")
        })
        .collect::<Result<_>>()?;

    // ---- selection ----
    // reason codes are closed enums; a record may carry several.
    let mut reasons: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut selected: BTreeSet<String> = BTreeSet::new();
    let add_reason = |sel: &mut BTreeSet<String>,
                      reasons: &mut BTreeMap<String, BTreeSet<String>>,
                      id: &str,
                      code: &str| {
        sel.insert(id.to_string());
        reasons
            .entry(id.to_string())
            .or_default()
            .insert(code.to_string());
    };

    // rule 7: base
    for id in &record_order {
        if records[id].base_selected {
            add_reason(&mut selected, &mut reasons, id, "base_selected");
        }
    }
    // rule 8: required record ids
    for id in &required_ids {
        let r = records
            .get(id)
            .with_context(|| format!("required_record_id {id:?} not in records"))?;
        if !r.eligible {
            bail!("required_record_id {id:?} is ineligible (rule 12)");
        }
        add_reason(&mut selected, &mut reasons, id, "required_record");
    }

    // rules 9/10: requirement closure. First: recompute + verify target sets (rules 5/6),
    // reject fabricated/mismatched, reject unknown endpoints already done.
    let mut req_out: Vec<Value> = Vec::new();
    for rq in &reqs {
        if !records.contains_key(&rq.from) {
            bail!(
                "requirement {:?} from unknown record {:?}",
                rq.requirement_id,
                rq.from
            );
        }
        let recomputed: BTreeSet<String> = by_from_kind
            .get(&(rq.from.clone(), rq.kind.clone()))
            .cloned()
            .unwrap_or_default();
        let expected: BTreeSet<String> = rq.expected_targets.iter().cloned().collect();
        // rule 6: equality with expected_targets (catches fabricated + missing)
        if recomputed != expected {
            bail!(
                "requirement {:?}: recomputed targets {:?} != expected_targets {:?}",
                rq.requirement_id,
                recomputed,
                expected
            );
        }
        // rule 12: source must be eligible to materialize
        let src = &records[&rq.from];
        if !src.eligible {
            bail!(
                "requirement {:?}: source {:?} is ineligible (rule 12)",
                rq.requirement_id,
                rq.from
            );
        }
        add_reason(
            &mut selected,
            &mut reasons,
            &rq.from,
            if rq.endpoint_policy == "edge_witness" {
                "edge_witness_source"
            } else {
                "all_current_source"
            },
        );

        let mut materialized: Vec<String> = Vec::new();
        let mut relation_only: Vec<String> = Vec::new();
        for t in &rq.expected_targets {
            let tr = &records[t];
            if rq.endpoint_policy == "all_current_targets_materialized" {
                // rule 10: fail closed if a required target is ineligible/absent
                if !tr.eligible {
                    bail!(
                        "requirement {:?}: all_current target {:?} is ineligible (fail closed)",
                        rq.requirement_id,
                        t
                    );
                }
                add_reason(&mut selected, &mut reasons, t, "all_current_target");
                materialized.push(t.clone());
            } else {
                // edge_witness: eligible target may be materialized; ineligible stays relation-only
                if tr.eligible {
                    add_reason(&mut selected, &mut reasons, t, "edge_witness_target");
                    materialized.push(t.clone());
                } else {
                    relation_only.push(t.clone());
                }
            }
        }
        materialized.sort();
        relation_only.sort();
        let present: Vec<String> = rq.expected_targets.to_vec();
        req_out.push(json!({
            "requirement_id": rq.requirement_id,
            "expected_targets": rq.expected_targets,
            "present_targets": present,          // every exact edge is present in the graph (verified above)
            "materialized_targets": materialized,
            "relation_only_targets": relation_only,
            "satisfied": true,
        }));
    }

    // rule 15: fail closed if mandatory closure overflows either budget.
    let selected_records = selected.len() as u64;
    let semantic_bytes_used: u64 = selected.iter().map(|id| records[id].canonical_bytes).sum();
    let within_budget =
        semantic_bytes_used <= semantic_byte_limit && selected_records <= record_limit;
    if !within_budget {
        bail!(
            "mandatory closure overflows budget: {semantic_bytes_used} bytes / {selected_records} records \
             vs limits {semantic_byte_limit} / {record_limit} (fail closed, rule 15)"
        );
    }

    // ---- result assembly (deterministic ordering) ----
    let mut selected_out: Vec<Value> = Vec::new();
    for id in &selected {
        // ^ BTreeSet iterates in sorted order
        let r = &records[id];
        let codes: Vec<String> = reasons[id].iter().cloned().collect();
        selected_out.push(json!({
            "id": id,
            "payload": r.payload,
            "canonical_bytes": r.canonical_bytes,
            "selection_reason_codes": codes,
        }));
    }
    // relations: every request-graph edge whose `from` is selected — the outgoing
    // relation neighbourhood of the projection (a generic rule: a selected record
    // carries its outgoing edges, including witness edges to relation-only targets).
    // Requirement edges are a subset of these, since every requirement source is
    // materialized. `edges` is a BTreeSet, so emission is sorted/deterministic.
    let relations_out: Vec<Value> = edges
        .iter()
        .filter(|(f, _, _)| selected.contains(f))
        .map(|(f, k, t)| json!({"from": f, "kind": k, "to": t}))
        .collect();
    // omitted: every non-selected record, with a closed reason code
    let mut omitted_out: Vec<Value> = Vec::new();
    for id in &record_order {
        if selected.contains(id) {
            continue;
        }
        let r = &records[id];
        let is_relation_only = req_out.iter().any(|q| {
            q["relation_only_targets"]
                .as_array()
                .map(|a| a.iter().any(|x| x == id))
                .unwrap_or(false)
        });
        let code = if is_relation_only {
            "relation_only_target"
        } else if !r.eligible {
            "ineligible"
        } else {
            "not_selected"
        };
        omitted_out.push(json!({"id": id, "reason_code": code, "detail": Value::Null}));
    }
    omitted_out.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));

    let mut result = Map::new();
    result.insert("schema".into(), json!(RESULT_SCHEMA));
    result.insert("request_id".into(), json!(request_id));
    result.insert(
        "request_canonical_sha256".into(),
        json!(format!("sha256:{request_canonical_sha256}")),
    );
    result.insert("producer".into(), json!({
        "version": PRODUCER_VERSION,
        "implementation_sha256": format!("sha256:{}", implementation_sha256()),
        "execution_commit": std::env::var("QODEC_EXECUTION_COMMIT").unwrap_or_else(|_| "unknown".into()),
        "execution_tree": std::env::var("QODEC_EXECUTION_TREE").unwrap_or_else(|_| "unknown".into()),
    }));
    result.insert("selected".into(), Value::Array(selected_out));
    result.insert("relations".into(), Value::Array(relations_out));
    result.insert("omitted".into(), Value::Array(omitted_out));
    result.insert(
        "budget".into(),
        json!({
            "semantic_bytes_used": semantic_bytes_used,
            "selected_records": selected_records,
            "semantic_byte_limit": semantic_byte_limit,
            "record_limit": record_limit,
            "within_budget": within_budget,
        }),
    );
    result.insert("requirements".into(), Value::Array(req_out));

    // result_canonical_sha256 over the result WITHOUT the self-referential field
    let result_val = Value::Object(result.clone());
    let result_sha = sha256_str(&canonical(&result_val));
    result.insert(
        "result_canonical_sha256".into(),
        json!(format!("sha256:{result_sha}")),
    );

    Ok(canonical(&Value::Object(result)) + "\n")
}
