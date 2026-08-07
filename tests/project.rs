//! Qualification suite for `qodec project` (v0): the generic relation-aware
//! projection primitive. Fixtures use unrelated synthetic ids — no domain
//! semantics. Each load-bearing rule has a pinning test that fails if the rule
//! is removed (mutation-sensitivity), plus a source-scan test that forbids any
//! case-/B1-specific literal in the production module.
//!
//! Written in the repo's lint style: no `unwrap`/`expect`/`panic`/index — errors
//! are threaded as `Result<(), String>` and values read through safe accessors.

use serde_json::{json, Value};
use std::process::Command;

const NULL: Value = Value::Null;

fn get<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k).unwrap_or(&NULL)
}

/// Run the projector and parse its result JSON, surfacing any error as a String.
fn run(req: &Value) -> Result<Value, String> {
    let text = qodec::project::project_json(&req.to_string()).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn err_contains(res: Result<Value, String>, needle: &str) -> bool {
    matches!(res, Err(e) if e.contains(needle))
}

/// A base request: base=r-keep; edge_witness r-src1/supersedes -> r-stale
/// (ineligible target, stays relation-only); all_current r-src2/depends_on -> r-cur.
fn base() -> Value {
    json!({
        "schema": "qodec-project-request-v0", "request_id": "q", "input_digest": "sha256:00",
        "budget": {"semantic_byte_limit": 100000, "record_limit": 32},
        "records": [
            {"id": "r-keep", "payload": {"v": 1}, "eligible": true, "base_selected": true, "relevance_score": 1.0, "caller_evidence": {}},
            {"id": "r-src1", "payload": {"v": 2}, "eligible": true, "base_selected": false, "relevance_score": 0.5, "caller_evidence": {}},
            {"id": "r-stale", "payload": {"v": 3}, "eligible": false, "base_selected": false, "relevance_score": 0.0, "caller_evidence": {}},
            {"id": "r-src2", "payload": {"v": 4}, "eligible": true, "base_selected": false, "relevance_score": 0.5, "caller_evidence": {}},
            {"id": "r-cur", "payload": {"v": 5}, "eligible": true, "base_selected": false, "relevance_score": 0.5, "caller_evidence": {}}
        ],
        "relations": [
            {"from": "r-src1", "kind": "supersedes", "to": "r-stale"},
            {"from": "r-src2", "kind": "depends_on", "to": "r-cur"}
        ],
        "relation_requirements": [
            {"requirement_id": "req1", "from": "r-src1", "kind": "supersedes", "direction": "outgoing", "depth": 1, "match": "all", "endpoint_policy": "edge_witness", "expected_targets": ["r-stale"]},
            {"requirement_id": "req2", "from": "r-src2", "kind": "depends_on", "direction": "outgoing", "depth": 1, "match": "all", "endpoint_policy": "all_current_targets_materialized", "expected_targets": ["r-cur"]}
        ],
        "required_record_ids": []
    })
}

fn arr_mut<'a>(v: &'a mut Value, k: &str) -> Option<&'a mut Vec<Value>> {
    v.get_mut(k).and_then(|x| x.as_array_mut())
}

fn set(v: &mut Value, k: &str, val: Value) {
    if let Some(o) = v.as_object_mut() {
        o.insert(k.to_string(), val);
    }
}

fn set2(v: &mut Value, k1: &str, k2: &str, val: Value) {
    if let Some(o) = v.get_mut(k1).and_then(|x| x.as_object_mut()) {
        o.insert(k2.to_string(), val);
    }
}

fn arr(v: &Value, k: &str) -> Vec<Value> {
    get(v, k).as_array().cloned().unwrap_or_default()
}

fn selected_ids(r: &Value) -> Vec<String> {
    let mut v: Vec<String> = arr(r, "selected")
        .iter()
        .filter_map(|s| get(s, "id").as_str().map(String::from))
        .collect();
    v.sort();
    v
}

fn requirement<'a>(r: &'a Value, id: &str) -> Option<&'a Value> {
    // returns the requirement object by requirement_id, without indexing
    get(r, "requirements")
        .as_array()
        .into_iter()
        .flatten()
        .find(|q| get(q, "requirement_id").as_str() == Some(id))
}

// ---- valid closures -------------------------------------------------------

#[test]
fn valid_edge_witness_and_all_current_closure() -> Result<(), String> {
    let r = run(&base())?;
    assert_eq!(
        selected_ids(&r),
        vec!["r-cur", "r-keep", "r-src1", "r-src2"]
    );
    assert!(!selected_ids(&r).contains(&"r-stale".to_string()));
    let stale_omitted = arr(&r, "omitted")
        .into_iter()
        .find(|o| get(o, "id").as_str() == Some("r-stale"));
    assert_eq!(
        stale_omitted
            .as_ref()
            .map(|o| get(o, "reason_code").clone()),
        Some(json!("relation_only_target"))
    );
    for q in arr(&r, "requirements") {
        assert_eq!(get(&q, "satisfied"), &json!(true));
    }
    assert_eq!(get(get(&r, "budget"), "within_budget"), &json!(true));
    Ok(())
}

#[test]
fn stale_target_retained_relation_only() -> Result<(), String> {
    let r = run(&base())?;
    let req1 = requirement(&r, "req1").cloned().unwrap_or(NULL);
    assert_eq!(get(&req1, "relation_only_targets"), &json!(["r-stale"]));
    assert_eq!(get(&req1, "materialized_targets"), &json!([]));
    Ok(())
}

#[test]
fn all_current_target_materialized() -> Result<(), String> {
    let r = run(&base())?;
    assert!(selected_ids(&r).contains(&"r-cur".to_string()));
    let req2 = requirement(&r, "req2").cloned().unwrap_or(NULL);
    assert_eq!(get(&req2, "materialized_targets"), &json!(["r-cur"]));
    Ok(())
}

#[test]
fn required_record_id_is_included() -> Result<(), String> {
    let mut b = base();
    set(&mut b, "required_record_ids", json!(["r-src2"]));
    let r = run(&b)?;
    assert!(selected_ids(&r).contains(&"r-src2".to_string()));
    Ok(())
}

// ---- fail-closed rejections (each pins a load-bearing rule) ----------------

fn without_record(id: &str) -> Value {
    let mut b = base();
    if let Some(a) = arr_mut(&mut b, "records") {
        a.retain(|r| get(r, "id").as_str() != Some(id));
    }
    b
}

#[test]
fn missing_source_rejected() {
    assert!(run(&without_record("r-src1")).is_err());
}

#[test]
fn ineligible_mandatory_source_rejected() {
    let mut b = base();
    if let Some(a) = arr_mut(&mut b, "records") {
        for r in a {
            if get(r, "id").as_str() == Some("r-src2") {
                set(r, "eligible", json!(false));
            }
        }
    }
    assert!(err_contains(run(&b), "ineligible") || err_contains(run(&b), "fail closed"));
}

#[test]
fn missing_expected_target_rejected() {
    let mut b = base();
    if let Some(a) = arr_mut(&mut b, "relation_requirements") {
        for q in a {
            if get(q, "requirement_id").as_str() == Some("req2") {
                set(q, "expected_targets", json!(["r-cur", "r-keep"]));
            }
        }
    }
    assert!(err_contains(run(&b), "expected_targets"));
}

#[test]
fn fabricated_expected_target_rejected() {
    let mut b = base();
    if let Some(a) = arr_mut(&mut b, "relations") {
        a.push(json!({"from": "r-src2", "kind": "depends_on", "to": "r-keep"}));
    }
    assert!(err_contains(run(&b), "expected_targets"));
}

#[test]
fn duplicate_record_id_rejected() {
    let mut b = base();
    if let Some(a) = arr_mut(&mut b, "records") {
        a.push(json!({"id": "r-keep", "payload": {"v": 9}, "eligible": true, "base_selected": false, "relevance_score": 0.0, "caller_evidence": {}}));
    }
    assert!(err_contains(run(&b), "duplicate record id"));
}

#[test]
fn duplicate_relation_triple_rejected() {
    let mut b = base();
    if let Some(a) = arr_mut(&mut b, "relations") {
        a.push(json!({"from": "r-src1", "kind": "supersedes", "to": "r-stale"}));
    }
    assert!(err_contains(run(&b), "duplicate relation triple"));
}

#[test]
fn unknown_relation_endpoint_rejected() {
    let mut b = base();
    if let Some(a) = arr_mut(&mut b, "relations") {
        a.push(json!({"from": "r-src1", "kind": "x", "to": "r-nope"}));
    }
    assert!(err_contains(run(&b), "unknown endpoint"));
}

#[test]
fn mismatched_target_set_rejected() {
    let mut b = base();
    if let Some(a) = arr_mut(&mut b, "relations") {
        a.retain(|e| {
            !(get(e, "from").as_str() == Some("r-src2") && get(e, "to").as_str() == Some("r-cur"))
        });
    }
    assert!(err_contains(run(&b), "expected_targets"));
}

// ---- budgets --------------------------------------------------------------

fn used_bytes(r: &Value) -> u64 {
    get(get(r, "budget"), "semantic_bytes_used")
        .as_u64()
        .unwrap_or_default()
}

#[test]
fn byte_budget_exact_boundary_passes() -> Result<(), String> {
    let used = used_bytes(&run(&base())?);
    let mut b = base();
    set2(&mut b, "budget", "semantic_byte_limit", json!(used));
    let r = run(&b)?;
    assert_eq!(get(get(&r, "budget"), "within_budget"), &json!(true));
    Ok(())
}

#[test]
fn byte_budget_overflow_fails_closed() -> Result<(), String> {
    let used = used_bytes(&run(&base())?);
    let mut b = base();
    set2(
        &mut b,
        "budget",
        "semantic_byte_limit",
        json!(used.saturating_sub(1)),
    );
    assert!(err_contains(run(&b), "overflows budget"));
    Ok(())
}

#[test]
fn record_budget_exact_boundary_passes() -> Result<(), String> {
    let mut b = base();
    set2(&mut b, "budget", "record_limit", json!(4));
    let r = run(&b)?;
    assert_eq!(get(get(&r, "budget"), "within_budget"), &json!(true));
    Ok(())
}

#[test]
fn record_budget_overflow_fails_closed() {
    let mut b = base();
    set2(&mut b, "budget", "record_limit", json!(3));
    assert!(err_contains(run(&b), "overflows budget"));
}

// ---- determinism ----------------------------------------------------------

#[test]
fn deterministic_under_reversed_input_ordering() -> Result<(), String> {
    let a = qodec::project::project_json(&base().to_string()).map_err(|e| e.to_string())?;
    let mut b = base();
    if let Some(x) = arr_mut(&mut b, "records") {
        x.reverse();
    }
    if let Some(x) = arr_mut(&mut b, "relations") {
        x.reverse();
    }
    if let Some(x) = arr_mut(&mut b, "relation_requirements") {
        x.reverse();
    }
    let c = qodec::project::project_json(&b.to_string()).map_err(|e| e.to_string())?;
    assert_eq!(a, c, "result must be byte-identical under input reordering");
    Ok(())
}

// ---- parser surface -------------------------------------------------------

#[test]
fn malformed_json_rejected() {
    assert!(qodec::project::project_json("{ not json").is_err());
}

#[test]
fn duplicate_json_key_is_last_wins_defined() -> Result<(), String> {
    // serde_json cannot reject duplicate keys; it is defined (last value wins).
    let text = r#"{"schema":"qodec-project-request-v0","request_id":"a","request_id":"b",
        "input_digest":"x","budget":{"semantic_byte_limit":100,"record_limit":10},
        "records":[],"relations":[],"relation_requirements":[],"required_record_ids":[]}"#;
    let out = qodec::project::project_json(text).map_err(|e| e.to_string())?;
    let r: Value = serde_json::from_str(&out).map_err(|e| e.to_string())?;
    assert_eq!(get(&r, "request_id"), &json!("b"));
    Ok(())
}

// ---- atomic output (CLI) --------------------------------------------------

#[test]
fn atomic_output_refusal_no_partial_file() -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!("qodec-proj-atomic-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let out = dir.join("result.json");
    let bad = dir.join("bad-request.json");
    std::fs::write(&bad, "{ not a valid request").map_err(|e| e.to_string())?;
    let status = Command::new(env!("CARGO_BIN_EXE_qodec"))
        .args([
            "project",
            "--request",
            &bad.to_string_lossy(),
            "--out",
            &out.to_string_lossy(),
        ])
        .status()
        .map_err(|e| e.to_string())?;
    assert!(!status.success(), "bad request must fail");
    assert!(!out.exists(), "no partial output file on refusal");
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn atomic_output_success_writes_result() -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!("qodec-proj-ok-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let out = dir.join("result.json");
    let req = dir.join("request.json");
    std::fs::write(&req, base().to_string()).map_err(|e| e.to_string())?;
    let status = Command::new(env!("CARGO_BIN_EXE_qodec"))
        .args([
            "project",
            "--request",
            &req.to_string_lossy(),
            "--out",
            &out.to_string_lossy(),
        ])
        .status()
        .map_err(|e| e.to_string())?;
    assert!(status.success());
    let text = std::fs::read_to_string(&out).map_err(|e| e.to_string())?;
    let r: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    assert_eq!(get(&r, "schema"), &json!("qodec-project-result-v0"));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ---- no case oracle -------------------------------------------------------

#[test]
fn production_module_has_no_case_or_b1_literal() {
    let src = include_str!("../src/project.rs");
    let forbidden = [
        concat!("case", "-0002"),
        concat!("obs", "-round0-closed"),
        concat!("obs", "-reviewer-durability-resolved"),
        concat!("qa3", "-superseded"),
        concat!("o7", ".b1"),
    ];
    for tok in forbidden {
        assert!(
            !src.contains(tok),
            "src/project.rs must not contain {tok:?}"
        );
    }
}
