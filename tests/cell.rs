//! Contracts for one C1 cell.
//!
//! The load-bearing ones are about containment and about scoring. Containment
//! is checked in both the plaintext and the base64url form, because byte
//! values legitimately travel base64-encoded and a plaintext-only search is
//! blind in exactly the direction the transcript is correct — the same hole
//! that had to be closed in the panel dry-run gate.
//!
//! Every negative containment claim is paired with a positive control on the
//! direct arm. A test asserting "the payload is absent" passes just as happily
//! when the needle is wrong, and it keeps passing forever.

use anyhow::{anyhow, Result};

use qodec::canon::{IndexName, KeyBytes, SchemaId, SetName, SCHEMA_QUERY_V1};
use qodec::cell::{
    run_direct_cell, run_forced_query_cell, ArmOutcome, CellRecord, CellSpec, ProtocolViolation,
    TurnRecord,
};
use qodec::panel::{PanelEvent, PanelSession};
use qodec::provider::{
    Arm, ContentBlock, FixtureIdentity, ModelIdentity, ModelStatus, ProgrammedTransport,
    ProviderKind, RawResponse, SamplingParams, SealedRequest,
};
use qodec::query::{ExecutionLimits, VerifyOutcome};
use qodec::store::{IndexSpec, KeyExtractor, Segmentation, StorePlan};

const PROVIDER: ProviderKind = ProviderKind::AnthropicMessages;

/// One artifact layer over three attempt sections. `alpha` is in all three;
/// `beta` in the first two only.
const FIXTURE: &str = "%q1 raw\n%q1 body\n\
--- attempt_1 ---\nalpha\nbeta\n\
--- attempt_2 ---\nalpha\nbeta\n\
--- attempt_3 ---\nalpha\ngamma\n";

/// The decoded RAW body — what the forced-query arm exists to withhold.
const RAW_BODY: &str = "--- attempt_1 ---\nalpha\nbeta\n\
--- attempt_2 ---\nalpha\nbeta\n\
--- attempt_3 ---\nalpha\ngamma\n";

const TASK: &str = "Which line appears in every attempt?";
const MODEL: &str = "test-model-1";

// ---------------------------------------------------------------------------
// Fixture plumbing
// ---------------------------------------------------------------------------

fn plan() -> Result<StorePlan> {
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

fn session() -> Result<PanelSession> {
    PanelSession::open(
        FIXTURE,
        &plan()?,
        SchemaId::parse(SCHEMA_QUERY_V1)?,
        ExecutionLimits::modest(),
    )
}

fn spec(arm: Arm) -> Result<CellSpec> {
    Ok(CellSpec {
        arm,
        provider: PROVIDER,
        model: ModelIdentity::parse(MODEL)?,
        sampling: SamplingParams::deterministic(512)?,
        // One identity for all three arms: they differ in presentation, not
        // in what they are about.
        fixture: FixtureIdentity::of_source("attempts", FIXTURE)?,
        task: TASK.to_owned(),
        expected: KeyBytes::new(b"alpha".to_vec()),
        max_turns: 4,
        max_transport_attempts: 1,
    })
}

// ---------------------------------------------------------------------------
// A deterministic stand-in model
// ---------------------------------------------------------------------------

fn reply(model: &str, blocks: Vec<serde_json::Value>) -> Result<RawResponse> {
    Ok(RawResponse {
        status: 200,
        body: serde_json::to_vec(&serde_json::json!({
            "id": "msg_test",
            "model": model,
            "stop_reason": "tool_use",
            "content": blocks,
            "usage": {"input_tokens": 12, "output_tokens": 6, "cache_read_input_tokens": 0},
        }))?,
        request_id: Some("req_test".to_owned()),
    })
}

fn tool_use(id: &str, name: &str, input: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"type": "tool_use", "id": id, "name": name, "input": input})
}

fn intersect_call(sections: &[&str]) -> serde_json::Value {
    tool_use(
        "call_0",
        "qodec_intersect",
        serde_json::json!({"index": "line", "sections": sections}),
    )
}

/// The most recent tool result the harness put into the conversation.
fn last_tool_result(sealed: &SealedRequest) -> Result<serde_json::Value> {
    for message in sealed.envelope().messages.iter().rev() {
        for block in message.content.iter().rev() {
            if let ContentBlock::ToolResult { content, .. } = block {
                return Ok(content.clone());
            }
        }
    }
    Err(anyhow!("no tool result in the conversation yet"))
}

/// Build the answer call from whatever the previous query returned.
fn answer_from(result: &serde_json::Value, id: &str) -> Result<serde_json::Value> {
    let handle = result
        .get("handle")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("tool result carried no handle"))?;
    let answer = result
        .pointer("/preview/0")
        .ok_or_else(|| anyhow!("tool result carried no preview"))?
        .clone();
    let cited = result
        .get("support")
        .cloned()
        .unwrap_or(serde_json::Value::Array(Vec::new()));
    Ok(tool_use(
        id,
        "qodec_answer",
        serde_json::json!({"handle": handle, "answer": answer, "cited": cited}),
    ))
}

// ---------------------------------------------------------------------------
// Containment
// ---------------------------------------------------------------------------

fn b64url_nopad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let packed = (b0 << 16) | (b1 << 8) | b2;
        let digits = [
            (packed >> 18) & 63,
            (packed >> 12) & 63,
            (packed >> 6) & 63,
            packed & 63,
        ];
        for digit in digits.iter().take(chunk.len().saturating_add(1)) {
            if let Some(c) = ALPHABET.get(*digit as usize) {
                out.push(char::from(*c));
            }
        }
    }
    out
}

/// The needle as it appears inside a JSON string field.
///
/// Not an optional refinement. A payload with a line break never appears
/// literally in a JSON body — the wire holds `\n`, two characters — so a
/// plaintext-only search returns "absent" for every multi-line document and
/// keeps returning it after the document starts leaking. The positive control
/// below is what surfaced this; reading the helper had not.
fn json_escaped(needle: &str) -> String {
    let quoted = serde_json::to_string(needle).unwrap_or_default();
    let mut chars = quoted.chars();
    chars.next();
    chars.next_back();
    chars.as_str().to_owned()
}

/// Whether a needle appears in a wire body, in any form it could take there:
/// plain, JSON-escaped, or base64url inside a byte envelope.
fn wire_contains(turn: &TurnRecord, needle: &str) -> bool {
    let body = String::from_utf8_lossy(turn.request.wire_bytes()).into_owned();
    body.contains(needle)
        || body.contains(&json_escaped(needle))
        || body.contains(&b64url_nopad(needle.as_bytes()))
}

/// Structural markers: container framing and section headers.
fn markers() -> Vec<&'static str> {
    FIXTURE
        .lines()
        .filter(|l| l.starts_with("%q1 ") || l.starts_with("--- "))
        .collect()
}

// ---------------------------------------------------------------------------
// The forced-query arm
// ---------------------------------------------------------------------------

fn run_happy_forced_query() -> Result<CellRecord> {
    let spec = spec(Arm::ForcedQuery)?;
    let mut session = session()?;
    let mut transport =
        ProgrammedTransport::new(|sealed: &SealedRequest, turn: usize| match turn {
            0 => reply(
                MODEL,
                vec![intersect_call(&["attempt_1", "attempt_2", "attempt_3"])],
            ),
            _ => {
                let result = last_tool_result(sealed)?;
                reply(MODEL, vec![answer_from(&result, "call_answer")?])
            }
        });
    run_forced_query_cell(&spec, &mut session, &mut transport)
}

/// The arm's whole claim: the document never crosses the boundary.
///
/// Checked over every request actually sent, in plaintext and base64url, for
/// the full RAW body and for every structural marker. Records the model asked
/// for legitimately do cross — that is what a query is for — so the needle is
/// the payload and its framing, not the word `alpha`.
#[test]
fn the_forced_query_arm_never_puts_the_artifact_on_the_wire() -> Result<()> {
    let record = run_happy_forced_query()?;
    assert!(
        !record.turns.is_empty(),
        "the cell must have sent something"
    );

    for turn in &record.turns {
        assert!(
            !wire_contains(turn, RAW_BODY),
            "turn {} carried the whole RAW body",
            turn.ordinal
        );
        for marker in markers() {
            assert!(
                !wire_contains(turn, marker),
                "turn {} carried artifact structure {marker:?}",
                turn.ordinal
            );
        }
    }
    assert!(matches!(
        record.outcome,
        ArmOutcome::Answered { correct: true }
    ));
    Ok(())
}

/// The positive control for the test above.
///
/// Without it, containment would pass just as well with a misspelled needle,
/// and would keep passing after the payload started leaking.
#[test]
fn the_direct_arm_does_put_the_payload_on_the_wire() -> Result<()> {
    let spec = spec(Arm::Raw)?;
    let mut transport = ProgrammedTransport::new(|_: &SealedRequest, _| {
        reply(
            MODEL,
            vec![tool_use(
                "call_answer",
                "qodec_answer",
                serde_json::json!({"answer": KeyBytes::new(b"alpha".to_vec()).to_envelope()}),
            )],
        )
    });
    let record = run_direct_cell(&spec, RAW_BODY, &mut transport)?;

    let turn = record
        .turns
        .first()
        .ok_or_else(|| anyhow!("the direct arm must send a request"))?;
    assert!(
        wire_contains(turn, RAW_BODY),
        "the RAW arm is supposed to send the document — if this fails, \
         the containment needle is wrong, not the containment"
    );
    for marker in markers() {
        if marker.starts_with("--- ") {
            assert!(
                wire_contains(turn, marker),
                "marker {marker:?} should be present"
            );
        }
    }
    assert!(record.outcome.correct());
    Ok(())
}

/// An answer whose bytes are right but whose verdict is not `Valid` is not a
/// success, and is not retried against RAW.
///
/// Ambiguity is produced honestly: intersecting two of the three sections
/// leaves `alpha` and `beta` as candidates, so the stored complete result has
/// two and the verdict must be `Ambiguous` even though the model answered
/// `alpha`.
#[test]
fn a_correct_answer_on_a_failed_verdict_is_not_scored_correct() -> Result<()> {
    let spec = spec(Arm::ForcedQuery)?;
    let mut session = session()?;
    let mut transport =
        ProgrammedTransport::new(|sealed: &SealedRequest, turn: usize| match turn {
            0 => reply(MODEL, vec![intersect_call(&["attempt_1", "attempt_2"])]),
            _ => {
                let result = last_tool_result(sealed)?;
                reply(MODEL, vec![answer_from(&result, "call_answer")?])
            }
        });
    let record = run_forced_query_cell(&spec, &mut session, &mut transport)?;

    let ArmOutcome::QueryPathFailed { verdict, correct } = &record.outcome else {
        return Err(anyhow!(
            "expected a failed query path, got {:?}",
            record.outcome
        ));
    };
    assert_eq!(*verdict, VerifyOutcome::Ambiguous);
    assert!(
        *correct,
        "the answer bytes did match — that is precisely why this case matters"
    );
    assert!(
        !record.outcome.correct(),
        "an unverified right answer must not be scored as a right answer"
    );

    // And no rescue happened: nothing after the failure, and still no payload.
    assert_eq!(
        record.turns.len(),
        2,
        "a failed cell does not get a third turn"
    );
    for turn in &record.turns {
        assert!(!wire_contains(turn, RAW_BODY), "no RAW fallback may occur");
    }
    Ok(())
}

/// A refused operation is a recorded event, not an aborted cell. Dropping the
/// cell on refusal would delete the measurement the refusal produces.
#[test]
fn a_refused_operation_does_not_abort_the_cell() -> Result<()> {
    let spec = spec(Arm::ForcedQuery)?;
    let mut session = session()?;
    let mut transport =
        ProgrammedTransport::new(|sealed: &SealedRequest, turn: usize| match turn {
            0 => reply(
                MODEL,
                vec![intersect_call(&["attempt_1", "attempt_2", "attempt_3"])],
            ),
            1 => {
                // A real store id and a real section, but an ordinal outside this
                // result's support.
                let result = last_tool_result(sealed)?;
                let handle = result
                    .get("handle")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("no handle"))?;
                let store = result
                    .pointer("/support/0/store")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("no support"))?;
                reply(
                    MODEL,
                    vec![tool_use(
                        "call_bad",
                        "qodec_materialize",
                        serde_json::json!({
                            "handle": handle,
                            "record_ids": [{"store": store, "section": "attempt_3", "ordinal": 1}],
                        }),
                    )],
                )
            }
            _ => {
                // The refusal is the last tool result; the query result is earlier.
                for message in sealed.envelope().messages.iter() {
                    for block in message.content.iter() {
                        if let ContentBlock::ToolResult { content, .. } = block {
                            if content.get("handle").is_some() {
                                return reply(MODEL, vec![answer_from(content, "call_answer")?]);
                            }
                        }
                    }
                }
                Err(anyhow!("no query result to answer from"))
            }
        });
    let record = run_forced_query_cell(&spec, &mut session, &mut transport)?;

    assert!(
        record.outcome.correct(),
        "the cell still reached a valid answer"
    );
    let refusals = record
        .panel_transcript
        .iter()
        .filter(|e| {
            matches!(
                e,
                PanelEvent::ToolCall {
                    outcome: qodec::panel::ToolCallOutcome::Refused { .. },
                    ..
                }
            )
        })
        .count();
    assert_eq!(refusals, 1, "the refusal must survive in the transcript");

    // And the model was told. Asserting only that the session recorded a
    // refusal leaves the cell free to hand the model an empty success, which
    // is a different experiment conducted on an uninformed subject.
    let told = record
        .turns
        .iter()
        .flat_map(|t| t.request.envelope().messages.iter())
        .flat_map(|m| m.content.iter())
        .find_map(|b| match b {
            ContentBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
            } if tool_use_id == "call_bad" => Some((content.clone(), *is_error)),
            _ => None,
        })
        .ok_or_else(|| anyhow!("the refused call produced no tool result"))?;
    assert!(told.1, "a refusal must reach the model flagged as an error");
    let reason = told
        .0
        .get("error")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("a refusal must carry its reason"))?;
    assert!(
        reason.contains("not in the support"),
        "the reason must say what was refused, got {reason:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Accounting
// ---------------------------------------------------------------------------

/// Two planes, side by side, never summed into one number.
#[test]
fn the_two_accounting_planes_stay_apart() -> Result<()> {
    let record = run_happy_forced_query()?;
    let json = record.to_json();

    let provider = json
        .pointer("/accounting/provider_reported")
        .ok_or_else(|| anyhow!("provider-reported plane missing"))?;
    let local = json
        .pointer("/accounting/deterministic_local")
        .ok_or_else(|| anyhow!("local plane missing"))?;
    assert!(provider.get("input_tokens").is_some());
    assert!(local.get("request_bytes").is_some());

    // No field anywhere claims to be a total across the two.
    let text = json.to_string();
    for forbidden in ["\"total\"", "\"total_tokens\"", "\"total_bytes\""] {
        assert!(
            !text.contains(forbidden),
            "the record must not offer {forbidden} — the planes have different units"
        );
    }
    Ok(())
}

/// The local plane is exactly reproducible from the record it describes.
#[test]
fn the_local_plane_is_recomputable_from_the_record() -> Result<()> {
    let record = run_happy_forced_query()?;
    let expected_request: u64 = record
        .turns
        .iter()
        .map(|t| t.request.wire_bytes().len() as u64)
        .sum();
    let expected_response: u64 = record
        .turns
        .iter()
        .filter_map(|t| t.exchange.raw().map(|r| r.body.len() as u64))
        .sum();
    assert_eq!(
        record.accounting.deterministic_local.request_bytes,
        expected_request
    );
    assert_eq!(
        record.accounting.deterministic_local.response_bytes,
        expected_response
    );
    assert!(expected_request > 0 && expected_response > 0);
    Ok(())
}

/// Provider counters accumulate across turns.
///
/// Written because the first implementation seeded the accumulator with an
/// all-`None` [`qodec::provider::ProviderUsage`]; since `None` is contagious by
/// design, the first addition annihilated the total and every cell reported
/// that the provider had said nothing. Nothing failed — the field was simply
/// `null` everywhere, which is indistinguishable from a provider that omits
/// usage. Found by reading a rendered table, not by a test, so here is the
/// test.
#[test]
fn provider_counters_are_summed_across_turns_not_annihilated() -> Result<()> {
    let record = run_three_turn_forced_query()?;
    assert_eq!(record.turns.len(), 3);
    assert_eq!(
        record.accounting.provider_reported.input_tokens,
        Some(36),
        "three turns at 12 input tokens each"
    );
    assert_eq!(record.accounting.provider_reported.output_tokens, Some(18));
    Ok(())
}

/// And the contagion rule still holds where it should: one turn that reports
/// no input tokens makes the total unreported rather than quietly smaller.
#[test]
fn one_unreported_turn_makes_the_total_unreported() -> Result<()> {
    let spec = spec(Arm::ForcedQuery)?;
    let mut session = session()?;
    let mut transport =
        ProgrammedTransport::new(|sealed: &SealedRequest, turn: usize| match turn {
            0 => {
                // A turn whose usage block omits `input_tokens`.
                Ok(RawResponse {
                    status: 200,
                    body: serde_json::to_vec(&serde_json::json!({
                        "id": "msg_test",
                        "model": MODEL,
                        "stop_reason": "tool_use",
                        "content": [intersect_call(&["attempt_1", "attempt_2", "attempt_3"])],
                        "usage": {"output_tokens": 6},
                    }))?,
                    request_id: None,
                })
            }
            _ => {
                let result = last_tool_result(sealed)?;
                reply(MODEL, vec![answer_from(&result, "call_answer")?])
            }
        });
    let record = run_forced_query_cell(&spec, &mut session, &mut transport)?;
    assert_eq!(
        record.accounting.provider_reported.input_tokens, None,
        "a total containing an unreported turn is itself unreported"
    );
    assert_eq!(record.accounting.provider_reported.output_tokens, Some(12));
    Ok(())
}

/// Materialized bytes are the forced-query arm's analogue of a payload in the
/// prompt, and are counted only where they happen.
#[test]
fn materialized_bytes_are_counted_only_where_records_were_materialized() -> Result<()> {
    let record = run_three_turn_forced_query()?;

    // Three sections, one `alpha` each, five bytes apiece.
    assert_eq!(
        record.accounting.deterministic_local.materialized_raw_bytes,
        15
    );
    assert_eq!(
        record.accounting.deterministic_local.operation_call_count,
        2
    );
    assert!(
        record.accounting.deterministic_local.tool_call_count
            > record.accounting.deterministic_local.operation_call_count,
        "the answer call is a wire tool call but not a panel operation"
    );

    let direct = run_direct_arm_answering("alpha")?;
    assert_eq!(
        direct.accounting.deterministic_local.materialized_raw_bytes, 0,
        "a direct arm materializes nothing; its payload is in the prompt"
    );
    Ok(())
}

/// intersect, then materialize the whole support, then answer from it.
fn run_three_turn_forced_query() -> Result<CellRecord> {
    let spec = spec(Arm::ForcedQuery)?;
    let mut session = session()?;
    let mut transport =
        ProgrammedTransport::new(|sealed: &SealedRequest, turn: usize| match turn {
            0 => reply(
                MODEL,
                vec![intersect_call(&["attempt_1", "attempt_2", "attempt_3"])],
            ),
            1 => {
                let result = last_tool_result(sealed)?;
                let handle = result
                    .get("handle")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("no handle"))?;
                let support = result
                    .get("support")
                    .cloned()
                    .ok_or_else(|| anyhow!("no support"))?;
                reply(
                    MODEL,
                    vec![tool_use(
                        "call_mat",
                        "qodec_materialize",
                        serde_json::json!({"handle": handle, "record_ids": support}),
                    )],
                )
            }
            _ => {
                for message in sealed.envelope().messages.iter() {
                    for block in message.content.iter() {
                        if let ContentBlock::ToolResult { content, .. } = block {
                            if content.get("handle").is_some() {
                                return reply(MODEL, vec![answer_from(content, "call_answer")?]);
                            }
                        }
                    }
                }
                Err(anyhow!("no query result to answer from"))
            }
        });
    run_forced_query_cell(&spec, &mut session, &mut transport)
}

fn run_direct_arm_answering(answer: &str) -> Result<CellRecord> {
    let spec = spec(Arm::Raw)?;
    let bytes = answer.as_bytes().to_vec();
    let mut transport = ProgrammedTransport::new(move |_: &SealedRequest, _| {
        reply(
            MODEL,
            vec![tool_use(
                "call_answer",
                "qodec_answer",
                serde_json::json!({"answer": KeyBytes::new(bytes.clone()).to_envelope()}),
            )],
        )
    });
    run_direct_cell(&spec, RAW_BODY, &mut transport)
}

// ---------------------------------------------------------------------------
// Comparability
// ---------------------------------------------------------------------------

/// A model that is not the one requested breaks the comparison while every row
/// still names one model. Detected rather than assumed away.
#[test]
fn a_substituted_model_is_detected() -> Result<()> {
    let spec = spec(Arm::Raw)?;
    let mut transport = ProgrammedTransport::new(|_: &SealedRequest, _| {
        reply(
            "some-other-snapshot",
            vec![tool_use(
                "call_answer",
                "qodec_answer",
                serde_json::json!({"answer": KeyBytes::new(b"alpha".to_vec()).to_envelope()}),
            )],
        )
    });
    let record = run_direct_cell(&spec, RAW_BODY, &mut transport)?;
    assert_eq!(record.model_status(), ModelStatus::Drifted);
    assert!(
        !record.comparable(),
        "a drifted cell cannot stand in a table"
    );

    let faithful = run_direct_arm_answering("alpha")?;
    assert_eq!(faithful.model_status(), ModelStatus::Verified);
    assert!(faithful.comparable());
    Ok(())
}

/// A provider that reported no model leaves the cell incomparable.
///
/// Not "probably fine". The run did not establish which model produced the
/// answer, and a row built on that asserts something nobody checked.
#[test]
fn a_cell_whose_model_was_never_reported_is_not_comparable() -> Result<()> {
    let spec = spec(Arm::Raw)?;
    let mut transport = ProgrammedTransport::new(|_: &SealedRequest, _| {
        Ok(RawResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "id": "msg_test",
                "stop_reason": "tool_use",
                "content": [tool_use(
                    "call_answer",
                    "qodec_answer",
                    serde_json::json!({"answer": KeyBytes::new(b"alpha".to_vec()).to_envelope()}),
                )],
                "usage": {"input_tokens": 1, "output_tokens": 1},
            }))?,
            request_id: None,
        })
    });
    let record = run_direct_cell(&spec, RAW_BODY, &mut transport)?;

    assert!(record.outcome.correct(), "the answer itself was right");
    assert_eq!(
        record.model_status(),
        ModelStatus::Missing,
        "silence is not agreement"
    );
    assert!(
        !record.comparable(),
        "a correct answer from an unidentified model is still not comparable"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The terminal-answer protocol
// ---------------------------------------------------------------------------

/// Two answers in one response are a violation, not a choice.
///
/// Taking the first would be a coin toss with a tidy implementation, and the
/// record afterwards would look exactly like a run where the model was
/// unambiguous. The two answers here disagree, so whichever was picked, the
/// harness would confidently report a result the model never settled on.
#[test]
fn two_terminal_answers_are_a_protocol_violation() -> Result<()> {
    let spec = spec(Arm::ForcedQuery)?;
    let mut session = session()?;
    let mut transport =
        ProgrammedTransport::new(|sealed: &SealedRequest, turn: usize| match turn {
            0 => reply(
                MODEL,
                vec![intersect_call(&["attempt_1", "attempt_2", "attempt_3"])],
            ),
            _ => {
                let result = last_tool_result(sealed)?;
                let handle = result
                    .get("handle")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("no handle"))?;
                let mk = |id: &str, text: &[u8]| {
                    tool_use(
                        id,
                        "qodec_answer",
                        serde_json::json!({
                            "handle": handle,
                            "answer": KeyBytes::new(text.to_vec()).to_envelope(),
                            "cited": [],
                        }),
                    )
                };
                reply(MODEL, vec![mk("a1", b"alpha"), mk("a2", b"gamma")])
            }
        });
    let record = run_forced_query_cell(&spec, &mut session, &mut transport)?;

    let ArmOutcome::ProtocolViolation { violation } = &record.outcome else {
        return Err(anyhow!(
            "expected a protocol violation, got {:?}",
            record.outcome
        ));
    };
    assert_eq!(*violation, ProtocolViolation::MultipleAnswers { count: 2 });
    assert!(
        !record.outcome.correct(),
        "an unreadable response is not a right one"
    );
    Ok(())
}

/// An answer arriving beside operations is a violation: the answer would rest
/// on results the model had not yet seen.
#[test]
fn an_answer_mixed_with_operations_is_a_protocol_violation() -> Result<()> {
    let spec = spec(Arm::ForcedQuery)?;
    let mut session = session()?;
    let mut transport = ProgrammedTransport::new(|_: &SealedRequest, _| {
        reply(
            MODEL,
            vec![
                intersect_call(&["attempt_1", "attempt_2", "attempt_3"]),
                tool_use(
                    "a1",
                    "qodec_answer",
                    serde_json::json!({
                        "handle": "sha256:".to_owned() + &"0".repeat(64),
                        "answer": KeyBytes::new(b"alpha".to_vec()).to_envelope(),
                        "cited": [],
                    }),
                ),
            ],
        )
    });
    let record = run_forced_query_cell(&spec, &mut session, &mut transport)?;

    let ArmOutcome::ProtocolViolation { violation } = &record.outcome else {
        return Err(anyhow!(
            "expected a protocol violation, got {:?}",
            record.outcome
        ));
    };
    assert_eq!(
        *violation,
        ProtocolViolation::AnswerMixedWithOperations { operations: 1 }
    );
    Ok(())
}

/// A direct arm gets exactly one call, and it must be the answer channel.
#[test]
fn a_direct_arm_sending_more_than_one_call_is_a_protocol_violation() -> Result<()> {
    let spec = spec(Arm::Raw)?;
    let answer = || {
        tool_use(
            "a",
            "qodec_answer",
            serde_json::json!({"answer": KeyBytes::new(b"alpha".to_vec()).to_envelope()}),
        )
    };
    let mut transport = ProgrammedTransport::new(move |_: &SealedRequest, _| {
        reply(MODEL, vec![answer(), answer()])
    });
    let record = run_direct_cell(&spec, RAW_BODY, &mut transport)?;
    assert!(matches!(
        record.outcome,
        ArmOutcome::ProtocolViolation {
            violation: ProtocolViolation::ExtraCallsInDirectArm { count: 2 }
        }
    ));

    let mut wrong_tool = ProgrammedTransport::new(|_: &SealedRequest, _| {
        reply(
            MODEL,
            vec![tool_use("a", "qodec_lookup", serde_json::json!({}))],
        )
    });
    let record = run_direct_cell(&spec, RAW_BODY, &mut wrong_tool)?;
    assert!(matches!(
        record.outcome,
        ArmOutcome::ProtocolViolation {
            violation: ProtocolViolation::UnexpectedToolInDirectArm { .. }
        }
    ));
    Ok(())
}

/// One answer and no operations is the well-formed terminal response, and it
/// still works. Without this, every test above would pass on an implementation
/// that rejected everything.
#[test]
fn one_answer_and_no_operations_is_accepted() -> Result<()> {
    let record = run_happy_forced_query()?;
    assert!(matches!(
        record.outcome,
        ArmOutcome::Answered { correct: true }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// A failed crossing still leaves a record
// ---------------------------------------------------------------------------

/// A transport that never gets through still produces a CellRecord.
///
/// Otherwise the most interesting live defect leaves behind a line on stderr
/// and somebody's recollection of roughly how it fell over.
#[test]
fn a_cell_whose_transport_never_succeeded_still_produces_a_record() -> Result<()> {
    let mut spec = spec(Arm::Raw)?;
    spec.max_transport_attempts = 3;
    let mut transport =
        ProgrammedTransport::new(|_: &SealedRequest, _| Err(anyhow!("connection reset")));
    let record = run_direct_cell(&spec, RAW_BODY, &mut transport)?;

    let ArmOutcome::CrossingFailed { kind, reason } = &record.outcome else {
        return Err(anyhow!(
            "expected a failed crossing, got {:?}",
            record.outcome
        ));
    };
    assert_eq!(kind, "transport-failed");
    assert!(!reason.is_empty());

    let turn = record
        .turns
        .first()
        .ok_or_else(|| anyhow!("a failed crossing must still record its turn"))?;
    assert_eq!(turn.exchange.attempts().len(), 3, "every attempt is kept");
    assert!(turn.exchange.raw().is_none());

    // The request that failed is still fully recorded, bytes and all.
    assert!(!turn.request.wire_bytes().is_empty());
    assert!(record.accounting.deterministic_local.request_bytes > 0);

    // And it serializes, which is where a record has to survive.
    let json = record.to_json();
    assert_eq!(
        json.pointer("/turns/0/exchange/kind")
            .and_then(|v| v.as_str()),
        Some("transport-failed")
    );
    Ok(())
}

/// A provider rejection likewise: the cell ends, and the bytes are in the file.
#[test]
fn a_rejected_cell_keeps_the_rejection_body() -> Result<()> {
    let spec = spec(Arm::Raw)?;
    let mut transport = ProgrammedTransport::new(|_: &SealedRequest, _| {
        Ok(RawResponse {
            status: 429,
            body: serde_json::to_vec(&serde_json::json!({
                "type": "error",
                "error": {"type": "rate_limit_error", "message": "slow down"},
            }))?,
            request_id: Some("req_429".to_owned()),
        })
    });
    let record = run_direct_cell(&spec, RAW_BODY, &mut transport)?;

    let ArmOutcome::CrossingFailed { kind, reason } = &record.outcome else {
        return Err(anyhow!(
            "expected a failed crossing, got {:?}",
            record.outcome
        ));
    };
    assert_eq!(kind, "provider-rejected");
    assert!(
        reason.contains("429"),
        "the status belongs in the reason: {reason}"
    );

    let json = record.to_json();
    let body = json
        .pointer("/turns/0/exchange/raw/body")
        .ok_or_else(|| anyhow!("the rejection body must be kept"))?;
    let bytes = KeyBytes::from_envelope(body)?;
    assert!(
        String::from_utf8_lossy(bytes.as_bytes()).contains("slow down"),
        "the provider's own words survive into the record"
    );
    // Charged, not free: a failed crossing that looks cheap makes the cost
    // table wrong in the flattering direction.
    assert!(record.accounting.deterministic_local.response_bytes > 0);
    Ok(())
}

/// All three arms of one cell describe the same bytes.
#[test]
fn the_three_arms_share_one_fixture_identity() -> Result<()> {
    let digests: Vec<_> = Arm::all()
        .into_iter()
        .map(|arm| spec(arm).map(|s| s.fixture.source_digest))
        .collect::<Result<Vec<_>>>()?;
    let first = digests.first().ok_or_else(|| anyhow!("no arms"))?;
    assert!(
        digests.iter().all(|d| d == first),
        "arms that do not share a fixture identity are not one row"
    );
    Ok(())
}

/// The direct path refuses the forced-query arm. It holds a payload, so
/// accepting that arm here would reintroduce the exact bypass the third arm
/// exists to rule out.
#[test]
fn the_direct_path_refuses_the_forced_query_arm() -> Result<()> {
    let spec = spec(Arm::ForcedQuery)?;
    let mut transport = ProgrammedTransport::new(|_: &SealedRequest, _| reply(MODEL, vec![]));
    assert!(run_direct_cell(&spec, RAW_BODY, &mut transport).is_err());
    Ok(())
}

/// And the panel path refuses the direct arms, for symmetry of the same rule.
#[test]
fn the_panel_path_refuses_the_direct_arms() -> Result<()> {
    let spec = spec(Arm::SqueezeDirect)?;
    let mut session = session()?;
    let mut transport = ProgrammedTransport::new(|_: &SealedRequest, _| reply(MODEL, vec![]));
    assert!(run_forced_query_cell(&spec, &mut session, &mut transport).is_err());
    Ok(())
}

// ---------------------------------------------------------------------------
// A malformed terminal answer is a record, not an abort
// ---------------------------------------------------------------------------
//
// Found in review by Codex and, independently, by CodeRabbit. Every other failure
// in this module routes through `finish` and leaves a `CellRecord`; the terminal
// answer's argument parsing was the one path that escaped as `Err`, aborting the
// whole run before any JSONL was written. The provider does not guarantee that
// generated tool arguments satisfy the supplied schema, so this is an ordinary
// live event, not a corner case.

/// A direct arm whose answer envelope will not decode still produces a record.
#[test]
fn a_malformed_direct_answer_is_recorded_not_raised() -> Result<()> {
    let spec = spec(Arm::Raw)?;
    let mut transport = ProgrammedTransport::new(|_: &SealedRequest, _| {
        reply(
            MODEL,
            vec![tool_use(
                "call_answer",
                "qodec_answer",
                // Right shape, undecodable content: the envelope's `data` is not
                // valid base64url.
                serde_json::json!({"answer": {"encoding": "base64url-nopad", "data": "!!!!"}}),
            )],
        )
    });
    let record = run_direct_cell(&spec, RAW_BODY, &mut transport)?;
    match &record.outcome {
        ArmOutcome::ProtocolViolation {
            violation: ProtocolViolation::MalformedAnswerArguments { reason },
        } => assert!(!reason.is_empty(), "the violation must say what failed"),
        other => {
            return Err(anyhow!(
                "a malformed answer must be a protocol violation, got {other:?}"
            ))
        }
    }
    assert!(
        !record.outcome.correct(),
        "there is no answer here to be correct"
    );
    // The turn survives, which is the whole point.
    let [only_turn] = record.turns.as_slice() else {
        return Err(anyhow!(
            "expected exactly one turn, got {}",
            record.turns.len()
        ));
    };
    assert!(
        only_turn.exchange.normalized().is_some(),
        "the crossing completed; it was the answer's arguments that did not parse"
    );
    Ok(())
}

/// A forced arm's malformed answer keeps the turns AND the panel transcript.
#[test]
fn a_malformed_forced_answer_keeps_the_turns_and_transcript() -> Result<()> {
    let spec = spec(Arm::ForcedQuery)?;
    let mut session = session()?;
    let mut transport = ProgrammedTransport::new(|sealed: &SealedRequest, n| {
        if n == 0 {
            reply(
                MODEL,
                vec![intersect_call(&["attempt_1", "attempt_2", "attempt_3"])],
            )
        } else {
            // A real handle from the previous turn, but a citation that is not a
            // record id — so parsing fails after the session did real work.
            let result = last_tool_result(sealed)?;
            let handle = result
                .get("handle")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("no handle"))?;
            reply(
                MODEL,
                vec![tool_use(
                    "call_answer",
                    "qodec_answer",
                    serde_json::json!({
                        "handle": handle,
                        "answer": KeyBytes::new(b"alpha".to_vec()).to_envelope(),
                        "cited_records": ["not-a-record-id"],
                    }),
                )],
            )
        }
    });
    let record = run_forced_query_cell(&spec, &mut session, &mut transport)?;
    assert!(
        matches!(
            record.outcome,
            ArmOutcome::ProtocolViolation {
                violation: ProtocolViolation::MalformedAnswerArguments { .. }
            }
        ),
        "got {:?}",
        record.outcome
    );
    assert_eq!(record.turns.len(), 2, "both turns must survive");
    assert!(
        !record.panel_transcript.is_empty(),
        "the transcript of the work the session really did must survive"
    );
    assert_eq!(
        record.accounting.deterministic_local.operation_call_count, 1,
        "the intersect the model really ran is still charged"
    );
    Ok(())
}
