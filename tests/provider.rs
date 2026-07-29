//! Contracts for the provider crossing.
//!
//! Everything here is about the difference between what we believe was sent
//! and what was sent. Each test is written so that a plausible-looking
//! implementation which reconstructs, re-serializes, or quietly drops
//! something fails it.

use std::num::NonZeroU32;

use anyhow::{anyhow, Result};

use qodec::canon::KeyBytes;
use qodec::panel::{answer_schema, lookup_schema, tool_schemas};
use qodec::provider::{
    deliver, exchange, map_answer, map_tool, normalize, Arm, AttemptOutcome, ExchangeOutcome,
    FixtureIdentity, Message, ModelIdentity, ModelStatus, ModelTransport, ProviderKind,
    ProviderResponseFormat, RawResponse, RequestEnvelope, RequestMapping, SamplingParams,
    ScriptedTransport, SealedRequest, SendFailure, ANSWER_TOOL_NAME,
};

const PROVIDER: ProviderKind = ProviderKind::AnthropicMessages;

fn once() -> NonZeroU32 {
    NonZeroU32::MIN
}

fn tries(n: u32) -> Result<NonZeroU32> {
    NonZeroU32::new(n).ok_or_else(|| anyhow!("attempt budget must not be zero"))
}

fn sampling(seed: Option<u64>) -> Result<SamplingParams> {
    SamplingParams {
        max_output_tokens: 256,
        temperature: Some(0.0),
        top_p: None,
        thinking_budget_tokens: None,
        seed,
    }
    .validated()
}

fn envelope(mapping: RequestMapping, sampling: SamplingParams) -> Result<RequestEnvelope> {
    Ok(RequestEnvelope {
        provider: PROVIDER,
        model: ModelIdentity::parse("test-model-1")?,
        arm: Arm::ForcedQuery,
        fixture: FixtureIdentity::of_source("f", "hello")?,
        instructions: "instructions".to_owned(),
        messages: vec![Message::user_text("question")],
        mapping,
        sampling,
    })
}

fn panel_mapping(sampling: &SamplingParams) -> RequestMapping {
    RequestMapping::for_panel(PROVIDER, &tool_schemas(), &answer_schema(), sampling)
}

fn ok_response(body: serde_json::Value) -> Result<RawResponse> {
    Ok(RawResponse {
        status: 200,
        body: serde_json::to_vec(&body)?,
        request_id: Some("req_test".to_owned()),
    })
}

fn plain_reply(text: &str) -> Result<RawResponse> {
    ok_response(serde_json::json!({
        "id": "msg_test",
        "model": "test-model-1",
        "stop_reason": "end_turn",
        "content": [{"type": "text", "text": text}],
        "usage": {"input_tokens": 11, "output_tokens": 7, "cache_read_input_tokens": 3},
    }))
}

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

/// `output_schema` has no wire slot, so it must leave a record of not being
/// sent. A mapping that dropped it silently would be indistinguishable from
/// one that never had it, and the token table would be quietly wrong.
#[test]
fn the_wire_drops_output_schema_and_records_the_drop() -> Result<()> {
    let neutral = lookup_schema();
    assert!(
        neutral.output_schema.is_object(),
        "the neutral schema must actually carry an output_schema, \
         or this test proves nothing"
    );

    let mapped = map_tool(&neutral, PROVIDER);
    assert!(
        mapped.dropped.contains(&"output_schema"),
        "the drop must be recorded, got {:?}",
        mapped.dropped
    );

    let sampling = sampling(None)?;
    let sealed = SealedRequest::seal(envelope(panel_mapping(&sampling), sampling)?)?;
    let wire = String::from_utf8(sealed.wire_bytes().to_vec())?;
    assert!(
        !wire.contains("output_schema"),
        "no output_schema may reach the wire"
    );
    Ok(())
}

/// The input schema is the part the model is actually charged for, so it must
/// cross unchanged rather than be re-derived on the way.
#[test]
fn the_neutral_input_schema_crosses_unchanged() -> Result<()> {
    let neutral = lookup_schema();
    let mapped = map_tool(&neutral, PROVIDER);
    assert_eq!(mapped.definition.input_schema, neutral.input_schema);
    assert_eq!(mapped.definition.name, neutral.name.name());
    assert_eq!(mapped.definition.description, neutral.description);
    Ok(())
}

/// A sampling knob the provider has no slot for must be named, not forgotten.
/// A run claiming determinism from a `seed` the API never received is claiming
/// a property it does not have.
#[test]
fn an_unsupported_seed_is_recorded_rather_than_silently_ignored() -> Result<()> {
    let with_seed = sampling(Some(7))?;
    let mapping = panel_mapping(&with_seed);
    assert!(
        mapping.unsupported_parameters.contains(&"seed"),
        "requesting a seed this provider lacks must be recorded, got {:?}",
        mapping.unsupported_parameters
    );

    let sealed = SealedRequest::seal(envelope(mapping, with_seed)?)?;
    let wire: serde_json::Value = serde_json::from_slice(sealed.wire_bytes())?;
    assert!(
        wire.get("seed").is_none(),
        "a parameter the provider does not accept must not be invented on the wire"
    );

    let without = sampling(None)?;
    assert!(
        panel_mapping(&without).unsupported_parameters.is_empty(),
        "nothing is unsupported when nothing unsupported was asked for"
    );
    Ok(())
}

/// Three panel operations, four wire tools. The terminal answer needs a
/// schema-constrained channel and on this API that channel is a tool; the
/// count is stated here so that collapsing the answer into the operation set
/// becomes a visible change rather than a quiet one.
#[test]
fn the_wire_carries_four_tools_for_three_operations() -> Result<()> {
    let sampling = sampling(None)?;
    let mapping = panel_mapping(&sampling);
    assert_eq!(tool_schemas().len(), 3, "the panel has three operations");

    let wire_tools = mapping.wire_tools();
    assert_eq!(
        wire_tools.len(),
        4,
        "three operations plus the answer channel"
    );
    let last = wire_tools
        .last()
        .ok_or_else(|| anyhow!("wire tools must not be empty"))?;
    assert_eq!(last.name, ANSWER_TOOL_NAME);

    let format = mapping
        .response_format
        .as_ref()
        .ok_or_else(|| anyhow!("the panel mapping must constrain the answer"))?;
    let ProviderResponseFormat::TerminalTool(def) = format;
    assert_eq!(def.input_schema, answer_schema().schema);
    Ok(())
}

/// The answer channel is derived from the neutral answer schema, not written
/// out a second time beside it.
#[test]
fn the_answer_channel_is_the_neutral_answer_schema() -> Result<()> {
    let neutral = answer_schema();
    let ProviderResponseFormat::TerminalTool(def) = map_answer(&neutral, PROVIDER);
    assert_eq!(def.name, ANSWER_TOOL_NAME);
    assert_eq!(def.description, neutral.description);
    assert_eq!(def.input_schema, neutral.schema);
    Ok(())
}

/// Every arm must act through a tool, and every arm says so with the identical
/// wire value.
///
/// Left to the provider default, a direct arm would usually reply in prose and
/// grading would become a measurement of the matcher we wrote to read it. Since
/// the answer channel is a tool in all three arms, the forcing value must be
/// the same in all three too — otherwise the arms differ in how the answer is
/// obtained as well as in how the data is reached, and only one of those is
/// supposed to be the variable.
#[test]
fn every_arm_must_act_through_a_tool_and_says_so_identically() -> Result<()> {
    let s = sampling(None)?;
    let panel = panel_mapping(&s);
    let direct = RequestMapping::direct(PROVIDER, &qodec::cell::direct_answer_schema(), &s);
    assert_eq!(
        panel.tool_choice, direct.tool_choice,
        "the arms must not differ in whether the model may decline to act"
    );

    for mapping in [panel, direct] {
        let sealed = SealedRequest::seal(envelope(mapping, s.clone())?)?;
        let wire: serde_json::Value = serde_json::from_slice(sealed.wire_bytes())?;
        assert_eq!(
            wire.pointer("/tool_choice/type").and_then(|v| v.as_str()),
            Some("any"),
            "the forcing must reach the wire, not merely the record"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------

/// The central claim of the module: the bytes recorded are the bytes sent.
///
/// Checked against what the transport actually received, not against a second
/// serialization of the same envelope — the latter would agree with itself
/// even if both disagreed with the wire.
#[test]
fn the_transport_receives_exactly_the_sealed_bytes() -> Result<()> {
    let sampling = sampling(None)?;
    let sealed = SealedRequest::seal(envelope(panel_mapping(&sampling), sampling)?)?;
    let mut transport = ScriptedTransport::new(vec![plain_reply("hi").map_err(|e| e.to_string())]);
    let _ = exchange(&mut transport, &sealed, once());

    let seen = transport
        .seen_bodies()
        .first()
        .ok_or_else(|| anyhow!("the transport saw nothing"))?;
    assert_eq!(
        seen.as_slice(),
        sealed.wire_bytes(),
        "the transport must receive the sealed buffer itself"
    );

    // And the record describes those same bytes.
    let recorded = sealed.to_json();
    let body = recorded
        .pointer("/wire_body")
        .ok_or_else(|| anyhow!("the record must carry the wire body"))?;
    assert_eq!(
        KeyBytes::from_envelope(body)?.as_bytes(),
        sealed.wire_bytes()
    );
    assert_eq!(
        recorded.pointer("/wire_bytes_len").and_then(|v| v.as_u64()),
        Some(sealed.wire_bytes().len() as u64)
    );
    Ok(())
}

/// Two equal envelopes seal to one identity; one changed field does not.
#[test]
fn sealing_is_deterministic_and_sensitive() -> Result<()> {
    let s = sampling(None)?;
    let a = SealedRequest::seal(envelope(panel_mapping(&s), s.clone())?)?;
    let b = SealedRequest::seal(envelope(panel_mapping(&s), s.clone())?)?;
    assert_eq!(a.digest(), b.digest());
    assert_eq!(a.wire_bytes(), b.wire_bytes());

    let mut changed = envelope(panel_mapping(&s), s)?;
    changed.messages = vec![Message::user_text("a different question")];
    let c = SealedRequest::seal(changed)?;
    assert_ne!(
        a.digest(),
        c.digest(),
        "a different question must be a different request"
    );
    Ok(())
}

/// Arm and fixture identify the experiment, not the request. Inventing wire
/// fields for them would change what the model is charged for so that our
/// bookkeeping could be more convenient.
#[test]
fn experiment_identity_is_recorded_but_never_sent() -> Result<()> {
    let s = sampling(None)?;
    let sealed = SealedRequest::seal(envelope(panel_mapping(&s), s)?)?;
    let wire: serde_json::Value = serde_json::from_slice(sealed.wire_bytes())?;
    for field in ["arm", "fixture", "provider", "mapping"] {
        assert!(
            wire.get(field).is_none(),
            "{field:?} must not appear in the wire body"
        );
    }
    let recorded = sealed.to_json();
    assert_eq!(
        recorded.pointer("/envelope/arm").and_then(|v| v.as_str()),
        Some("forced-query")
    );
    assert_eq!(
        recorded
            .pointer("/envelope/fixture/name")
            .and_then(|v| v.as_str()),
        Some("f")
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// A transport retry is the same request tried again. Every attempt must carry
/// one request identity, which is what makes it distinguishable from a
/// semantic retry — a different prompt sent after a failure and reported as if
/// it were the same one.
#[test]
fn a_transport_retry_repeats_exactly_one_request_identity() -> Result<()> {
    let s = sampling(None)?;
    let sealed = SealedRequest::seal(envelope(panel_mapping(&s), s)?)?;
    let mut transport = ScriptedTransport::new(vec![
        Err("connection reset".to_owned()),
        Err("connection reset".to_owned()),
        plain_reply("hi").map_err(|e| e.to_string()),
    ]);
    let (_, attempts) = deliver(&mut transport, &sealed, tries(3)?);
    assert_eq!(attempts.len(), 3);
    for attempt in &attempts {
        assert_eq!(
            attempt.request_digest,
            sealed.digest(),
            "every attempt must carry the one request's identity"
        );
    }
    // And the bytes really were repeated, not merely claimed to be.
    for body in transport.seen_bodies() {
        assert_eq!(body.as_slice(), sealed.wire_bytes());
    }
    Ok(())
}

/// A crossing that never got through still leaves the record of what was tried.
///
/// The earlier version returned a bare `Err` and the attempt list died with it,
/// which loses precisely the failure that has nothing else to leave behind.
#[test]
fn a_transport_that_never_succeeds_still_records_its_attempts() -> Result<()> {
    let s = sampling(None)?;
    let sealed = SealedRequest::seal(envelope(panel_mapping(&s), s)?)?;
    let mut transport =
        ScriptedTransport::new(vec![Err("reset".to_owned()), Err("reset".to_owned())]);
    let outcome = exchange(&mut transport, &sealed, tries(2)?);

    let ExchangeOutcome::TransportFailed { attempts } = &outcome else {
        return Err(anyhow!(
            "expected a transport failure, got {}",
            outcome.kind()
        ));
    };
    assert_eq!(attempts.len(), 2, "both attempts belong in the record");
    assert!(outcome.raw().is_none());
    assert!(outcome.normalized().is_none());
    for attempt in attempts {
        assert_eq!(attempt.request_digest, sealed.digest());
        assert!(matches!(
            attempt.outcome,
            qodec::provider::AttemptOutcome::TransportError { .. }
        ));
    }
    // And the record survives serialization, which is where it has to survive.
    let json = outcome.to_json();
    assert_eq!(
        json.get("kind").and_then(|v| v.as_str()),
        Some("transport-failed")
    );
    assert_eq!(
        json.pointer("/attempts")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    Ok(())
}

/// A provider rejection keeps the bytes it was rejected with.
///
/// Distinguished from a body that would not parse: folded together, a provider
/// outage and a schema change we caused arrive under one label and get
/// investigated as one thing.
#[test]
fn a_provider_rejection_is_recorded_with_its_body() -> Result<()> {
    let s = sampling(None)?;
    let sealed = SealedRequest::seal(envelope(panel_mapping(&s), s)?)?;
    let body = serde_json::to_vec(&serde_json::json!({
        "type": "error",
        "error": {"type": "invalid_request_error", "message": "bad tool schema"},
    }))?;
    let mut transport = ScriptedTransport::new(vec![Ok(RawResponse {
        status: 400,
        body: body.clone(),
        request_id: Some("req_bad".to_owned()),
    })]);
    let outcome = exchange(&mut transport, &sealed, once());

    let ExchangeOutcome::ProviderRejected { raw, reason, .. } = &outcome else {
        return Err(anyhow!("expected a rejection, got {}", outcome.kind()));
    };
    assert_eq!(raw.body, body, "the rejected body is kept, not summarized");
    assert!(
        reason.contains("400"),
        "the status belongs in the reason: {reason}"
    );
    assert!(
        reason.contains("bad tool schema"),
        "and the provider's words: {reason}"
    );
    Ok(())
}

/// A body that will not parse is its own outcome, and its bytes are kept.
#[test]
fn an_unparseable_body_is_its_own_outcome() -> Result<()> {
    let s = sampling(None)?;
    let sealed = SealedRequest::seal(envelope(panel_mapping(&s), s)?)?;
    let mut transport = ScriptedTransport::new(vec![Ok(RawResponse {
        status: 200,
        body: b"this is not JSON".to_vec(),
        request_id: None,
    })]);
    let outcome = exchange(&mut transport, &sealed, once());

    let ExchangeOutcome::NormalizationFailed { raw, .. } = &outcome else {
        return Err(anyhow!(
            "expected a normalization failure, got {}",
            outcome.kind()
        ));
    };
    assert_eq!(raw.body, b"this is not JSON");
    Ok(())
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// A non-2xx status is a rejection, decided before parsing.
///
/// Kept out of [`normalize`] on purpose. Folded together, a provider outage and
/// a body we could not parse arrive under one label and get investigated as one
/// thing, which is one investigation too few.
#[test]
fn a_non_success_status_is_a_rejection_not_a_parse_problem() -> Result<()> {
    let raw = RawResponse {
        status: 400,
        body: serde_json::to_vec(&serde_json::json!({
            "type": "error",
            "error": {"type": "invalid_request_error", "message": "bad tool schema"},
        }))?,
        request_id: Some("req_bad".to_owned()),
    };
    let reason = qodec::provider::rejection_reason(PROVIDER, &raw)
        .ok_or_else(|| anyhow!("HTTP 400 must be recognised as a rejection"))?;
    assert!(
        reason.contains("400"),
        "the status belongs in the reason: {reason}"
    );
    assert!(
        reason.contains("bad tool schema"),
        "the provider's own message belongs in the reason: {reason}"
    );

    // A rejection with an unparseable body is still a rejection: the status
    // decides, so a broken error payload cannot promote a 500 into a success.
    let opaque = RawResponse {
        status: 502,
        body: b"<html>bad gateway</html>".to_vec(),
        request_id: None,
    };
    assert!(qodec::provider::rejection_reason(PROVIDER, &opaque).is_some());

    let ok = ok_response(serde_json::json!({
        "id": "m", "model": "test-model-1", "stop_reason": "end_turn",
        "content": [], "usage": {},
    }))?;
    assert!(
        qodec::provider::rejection_reason(PROVIDER, &ok).is_none(),
        "a success must not be reported as a rejection"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Transport target
// ---------------------------------------------------------------------------

/// A retry is the same body sent to the same place.
///
/// The body digest alone proves only that identical JSON went *somewhere*.
/// Endpoint, API version, content type and timeout decide what the provider
/// actually received, so they belong to the claim.
#[test]
fn every_attempt_records_where_it_went() -> Result<()> {
    let s = sampling(None)?;
    let sealed = SealedRequest::seal(envelope(panel_mapping(&s), s)?)?;
    let mut transport = ScriptedTransport::new(vec![
        Err("reset".to_owned()),
        plain_reply("hi").map_err(|e| e.to_string()),
    ]);
    let expected = transport.target();
    let (_, attempts) = deliver(&mut transport, &sealed, tries(2)?);

    assert_eq!(attempts.len(), 2);
    for attempt in &attempts {
        assert_eq!(attempt.request_digest, sealed.digest());
        assert_eq!(
            attempt.target, expected,
            "a retry that changed target is not the same request tried again"
        );
        let json = attempt.to_json();
        assert!(
            json.pointer("/target/endpoint").is_some(),
            "the target must survive into the record"
        );
    }
    Ok(())
}

/// The target has no room for a credential, and no path by which one arrives.
///
/// This value is written into a committed transcript. A struct that *could*
/// hold a key eventually holds one, so the check is both structural — there is
/// no field — and behavioural: a base URL carrying userinfo is refused rather
/// than trimmed, since trimming would accept the mistake and hide it.
#[test]
fn a_transport_target_can_carry_no_credential() -> Result<()> {
    let live = qodec::provider::HttpTransport::new(
        "https://api.example.invalid",
        "sk-secret-value",
        "2023-06-01",
        30,
    )?;
    let target = live.target();
    let rendered = target.to_json().to_string();
    assert!(
        !rendered.contains("sk-secret-value"),
        "the key must not reach the target record"
    );
    assert_eq!(target.endpoint, "https://api.example.invalid");
    assert_eq!(target.api_version, "2023-06-01");
    assert_eq!(target.timeout_secs, 30);

    assert!(
        qodec::provider::HttpTransport::new(
            "https://user:pass@api.example.invalid",
            "k",
            "2023-06-01",
            30,
        )
        .is_err(),
        "a base URL with userinfo must be refused, not silently accepted"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Model identity
// ---------------------------------------------------------------------------

/// A provider that named no model has not agreed with us.
///
/// The two-valued version had to decide what `drifted = false` meant when the
/// provider said nothing, and the convenient answer converts "we do not know"
/// into "it matched" — which is the substitution a great many comparison tables
/// are built on.
#[test]
fn a_missing_reported_model_is_not_agreement() -> Result<()> {
    let requested = ModelIdentity::parse("test-model-1")?;
    assert_eq!(
        ModelStatus::of(&requested, Some("test-model-1")),
        ModelStatus::Verified
    );
    assert_eq!(ModelStatus::of(&requested, None), ModelStatus::Missing);
    assert_eq!(
        ModelStatus::of(&requested, Some("other-snapshot")),
        ModelStatus::Drifted
    );

    assert!(ModelStatus::Verified.comparable());
    assert!(
        !ModelStatus::Missing.comparable(),
        "an unknown model makes a cell incomparable, not merely unremarkable"
    );
    assert!(!ModelStatus::Drifted.comparable());

    // The worst turn decides the cell.
    assert_eq!(
        ModelStatus::Verified.worst(ModelStatus::Missing),
        ModelStatus::Missing
    );
    assert_eq!(
        ModelStatus::Missing.worst(ModelStatus::Drifted),
        ModelStatus::Drifted
    );
    assert_eq!(
        ModelStatus::Drifted.worst(ModelStatus::Verified),
        ModelStatus::Drifted
    );
    Ok(())
}

/// Raw and normalized are both kept, and the raw half is the exact bytes.
/// Keeping only the parse would discard the evidence for the parse.
#[test]
fn the_response_record_keeps_the_bytes_and_the_parse() -> Result<()> {
    let s = sampling(None)?;
    let sealed = SealedRequest::seal(envelope(panel_mapping(&s), s)?)?;
    let reply = plain_reply("the answer is alpha")?;
    let expected_body = reply.body.clone();
    let mut transport = ScriptedTransport::new(vec![Ok(reply)]);
    let outcome = exchange(&mut transport, &sealed, once());

    let raw = outcome
        .raw()
        .ok_or_else(|| anyhow!("a completed crossing keeps its bytes"))?;
    let normalized = outcome
        .normalized()
        .ok_or_else(|| anyhow!("a completed crossing keeps its parse"))?;
    assert_eq!(raw.body, expected_body);
    assert_eq!(normalized.text, "the answer is alpha");
    assert_eq!(normalized.reported_model.as_deref(), Some("test-model-1"));
    assert_eq!(normalized.usage.input_tokens, Some(11));
    assert_eq!(normalized.usage.output_tokens, Some(7));
    assert_eq!(normalized.usage.cached_input_tokens, Some(3));
    assert_eq!(normalized.usage.reasoning_tokens, None);

    let json = outcome.to_json();
    let recorded = json
        .pointer("/raw/body")
        .ok_or_else(|| anyhow!("the record must keep the raw body"))?;
    assert_eq!(
        KeyBytes::from_envelope(recorded)?.as_bytes(),
        &expected_body
    );
    assert!(
        json.pointer("/normalized/text").is_some(),
        "the record must keep the parse as well as the bytes"
    );
    Ok(())
}

/// A counter the provider did not send stays `None`, and a total that includes
/// it stays `None` too. Treating a missing counter as zero understates the
/// figure without ever saying so.
#[test]
fn a_missing_provider_counter_is_not_quietly_zero() -> Result<()> {
    let raw = ok_response(serde_json::json!({
        "id": "msg_test",
        "model": "test-model-1",
        "stop_reason": "end_turn",
        "content": [{"type": "text", "text": "hi"}],
        "usage": {"output_tokens": 4},
    }))?;
    let normalized = normalize(PROVIDER, &raw)?;
    assert_eq!(normalized.usage.input_tokens, None);
    assert_eq!(normalized.usage.output_tokens, Some(4));

    let complete = qodec::provider::ProviderUsage {
        input_tokens: Some(10),
        cached_input_tokens: Some(0),
        output_tokens: Some(1),
        reasoning_tokens: None,
    };
    let summed = complete.plus(normalized.usage);
    assert_eq!(
        summed.input_tokens, None,
        "a sum involving an unreported counter is itself unreported"
    );
    assert_eq!(summed.output_tokens, Some(5));
    Ok(())
}

/// Blocks that carry neither an operation nor an answer are skipped by the
/// parse and kept in the bytes.
#[test]
fn unknown_block_kinds_are_skipped_by_the_parse_and_kept_in_the_raw() -> Result<()> {
    let raw = ok_response(serde_json::json!({
        "id": "msg_test",
        "model": "test-model-1",
        "stop_reason": "tool_use",
        "content": [
            {"type": "thinking", "thinking": "internal deliberation"},
            {"type": "text", "text": "visible"},
        ],
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }))?;
    let normalized = normalize(PROVIDER, &raw)?;
    assert_eq!(normalized.text, "visible");
    assert!(normalized.tool_calls.is_empty());
    assert!(
        String::from_utf8(raw.body.clone())?.contains("internal deliberation"),
        "the raw bytes keep what the parse discards"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// A billed turn is never free (Codex P1)
// ---------------------------------------------------------------------------

/// A malformed content block does not make the counters unreadable.
///
/// This is the shape a provider change would actually produce: a 200 whose
/// `usage` is perfectly good and whose `content` has a `tool_use` missing its
/// `id`. Normalization fails — correctly — but the generation was very likely
/// billed, and dropping the counters would make the broken cell look free. A cost
/// table wrong in the flattering direction is the one nobody investigates.
#[test]
fn usage_survives_a_normalization_failure() -> Result<()> {
    let s = sampling(None)?;
    let sealed = SealedRequest::seal(envelope(panel_mapping(&s), s)?)?;
    let body = serde_json::to_vec(&serde_json::json!({
        "id": "msg_x",
        "model": "test-model-1",
        "stop_reason": "tool_use",
        // A tool_use with no `id`: normalize_anthropic refuses it.
        "content": [{"type": "tool_use", "name": "qodec_answer", "input": {}}],
        "usage": {"input_tokens": 41, "output_tokens": 7, "cache_read_input_tokens": 3},
    }))?;
    let mut transport = ScriptedTransport::new(vec![Ok(RawResponse {
        status: 200,
        body,
        request_id: None,
    })]);
    let outcome = exchange(&mut transport, &sealed, once());
    let ExchangeOutcome::NormalizationFailed { usage, .. } = &outcome else {
        return Err(anyhow!(
            "a malformed content block must be a normalization failure, got {}",
            outcome.kind()
        ));
    };
    assert_eq!(
        usage.input_tokens,
        Some(41),
        "the input counter was readable"
    );
    assert_eq!(usage.output_tokens, Some(7));
    assert_eq!(usage.cached_input_tokens, Some(3));
    assert_eq!(
        outcome.reported_usage().and_then(|u| u.input_tokens),
        Some(41),
        "and it must be reachable through the uniform accessor the fold uses"
    );

    // It must also be IN THE RECORD, or the cell total rests on a number no
    // reader of the JSONL can check.
    let rendered = outcome.to_json();
    assert_eq!(
        rendered
            .pointer("/reported_usage/input_tokens")
            .and_then(|v| v.as_u64()),
        Some(41)
    );
    Ok(())
}

/// A body that is not JSON at all yields unknown counters, not zero ones.
#[test]
fn unreadable_bytes_yield_unknown_usage_never_zero() -> Result<()> {
    let s = sampling(None)?;
    let sealed = SealedRequest::seal(envelope(panel_mapping(&s), s)?)?;
    let mut transport = ScriptedTransport::new(vec![Ok(RawResponse {
        status: 200,
        body: b"<html>not json</html>".to_vec(),
        request_id: None,
    })]);
    let outcome = exchange(&mut transport, &sealed, once());
    let usage = outcome
        .reported_usage()
        .ok_or_else(|| anyhow!("a normalization failure still reports a usage struct"))?;
    assert_eq!(
        usage.input_tokens, None,
        "unknown must stay unknown; a zero would claim the provider said something"
    );
    Ok(())
}

/// A rejection or a request that never arrived has no counters to report.
#[test]
fn a_rejected_or_undelivered_turn_reports_no_usage() -> Result<()> {
    let s = sampling(None)?;
    let sealed = SealedRequest::seal(envelope(panel_mapping(&s), s)?)?;
    let mut rejected = ScriptedTransport::new(vec![Ok(RawResponse {
        status: 429,
        body: br#"{"error":{"message":"slow down"}}"#.to_vec(),
        request_id: None,
    })]);
    assert!(exchange(&mut rejected, &sealed, once())
        .reported_usage()
        .is_none());

    let mut dead = ScriptedTransport::new(vec![Err("reset".to_owned())]);
    assert!(exchange(&mut dead, &sealed, once())
        .reported_usage()
        .is_none());
    Ok(())
}

// ---------------------------------------------------------------------------
// The live transport refuses to send a key unsafely (CodeRabbit)
// ---------------------------------------------------------------------------

/// `x-api-key` travels in a header, so a plain-http endpoint puts it in cleartext.
#[test]
fn the_live_transport_requires_https_and_a_real_timeout() -> Result<()> {
    let key = "sk-would-be-leaked";
    assert!(
        qodec::provider::HttpTransport::new("http://api.example.invalid", key, "2023-06-01", 30)
            .is_err(),
        "a plain-http endpoint must be refused: the API key rides in a header"
    );
    assert!(
        qodec::provider::HttpTransport::new("ftp://api.example.invalid", key, "2023-06-01", 30)
            .is_err(),
        "any non-https scheme must be refused"
    );
    // Zero is neither "no timeout" nor "immediately" on ureq 2.x — it is a
    // pathological third thing, on the one path that carries a real credential.
    assert!(
        qodec::provider::HttpTransport::new("https://api.example.invalid", key, "2023-06-01", 0)
            .is_err(),
        "a zero timeout must be refused"
    );
    // Control: the valid combination still builds.
    assert!(
        qodec::provider::HttpTransport::new("https://api.example.invalid", key, "2023-06-01", 30)
            .is_ok(),
        "https with a real timeout must still be accepted"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Which side of the response headers the attempt died on
// ---------------------------------------------------------------------------
//
// `TransportFailed` asserts that no response bytes existed. Once HTTP response
// headers have arrived that assertion is false, and acting on it is expensive
// rather than merely untidy: the provider has produced a generation it may bill
// for, so a retry buys a second one we can read no better than the first, and
// the cell then records `transport-failed` with no usage for work that was paid
// for. These contracts pin the boundary from both sides.

/// A reader that yields some bytes and then fails, like a connection dropped
/// after the status line.
struct BreaksAfter {
    remaining: usize,
}

impl std::io::Read for BreaksAfter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "peer went away mid-body",
            ));
        }
        let n = buf.len().min(self.remaining);
        for b in buf.iter_mut().take(n) {
            *b = b'x';
        }
        self.remaining -= n;
        Ok(n)
    }
}

/// A failure before any response is retried, and the budget is spent.
///
/// The pre-header half of the boundary. Nothing was produced, so asking again is
/// asking the same question a second time.
#[test]
fn a_pre_header_failure_is_retried_to_the_budget() -> Result<()> {
    let s = sampling(None)?;
    let sealed = SealedRequest::seal(envelope(panel_mapping(&s), s)?)?;
    let mut transport = ScriptedTransport::with_failures(vec![
        Err(SendFailure::before("connection reset")),
        Err(SendFailure::before("connection reset")),
        Err(SendFailure::before("connection reset")),
    ]);
    let outcome = exchange(&mut transport, &sealed, tries(3)?);

    let ExchangeOutcome::TransportFailed { attempts } = &outcome else {
        return Err(anyhow!("expected transport-failed, got {}", outcome.kind()));
    };
    assert_eq!(
        attempts.len(),
        3,
        "all three attempts were made and recorded"
    );
    assert_eq!(
        transport.seen_bodies().len(),
        3,
        "and really sent three times"
    );
    for attempt in attempts {
        assert!(matches!(
            attempt.outcome,
            AttemptOutcome::TransportError { .. }
        ));
    }
    Ok(())
}

/// A failure after headers is terminal: one call, one attempt, nothing else
/// consumed.
///
/// The queued successes are the point. If the implementation retried, it would
/// find a working reply waiting and report a cheerful `completed` — hiding both
/// the extra generation and the fact that a retry happened at all.
#[test]
fn a_post_header_failure_is_not_retried() -> Result<()> {
    let s = sampling(None)?;
    let sealed = SealedRequest::seal(envelope(panel_mapping(&s), s)?)?;
    let mut transport = ScriptedTransport::with_failures(vec![
        Err(SendFailure::AfterHeaders {
            status: 200,
            request_id: Some("req_capture".to_owned()),
            body_bytes_observed: 4096,
            reason: "body exceeded the cap".to_owned(),
        }),
        plain_reply("hi").map_err(|e| SendFailure::before(e.to_string())),
        plain_reply("hi").map_err(|e| SendFailure::before(e.to_string())),
    ]);
    let outcome = exchange(&mut transport, &sealed, tries(3)?);

    let ExchangeOutcome::ResponseCaptureFailed {
        status,
        request_id,
        body_bytes_observed,
        attempts,
        ..
    } = &outcome
    else {
        return Err(anyhow!(
            "expected response-capture-failed, got {}",
            outcome.kind()
        ));
    };
    assert_eq!(*status, 200);
    assert_eq!(request_id.as_deref(), Some("req_capture"));
    assert_eq!(*body_bytes_observed, 4096);

    assert_eq!(attempts.len(), 1, "exactly one attempt was recorded");
    assert_eq!(
        transport.seen_bodies().len(),
        1,
        "and exactly one request left the process — this is the billing claim"
    );
    assert_eq!(
        transport.replies_remaining(),
        2,
        "the queued successes must be untouched; consuming one means a retry happened"
    );
    let [only] = attempts.as_slice() else {
        return Err(anyhow!(
            "expected exactly one attempt, got {}",
            attempts.len()
        ));
    };
    assert!(matches!(
        only.outcome,
        AttemptOutcome::ResponseCaptureFailed { .. }
    ));

    // Not a non-delivery, and it must not be able to masquerade as one.
    assert!(outcome.raw().is_none(), "no complete body was captured");
    assert!(outcome.normalized().is_none());
    assert!(
        outcome.reported_usage().is_none(),
        "counters are unknown, and unknown is not zero"
    );
    Ok(())
}

/// The serialized form keeps the evidence that a response existed.
///
/// `raw` is null here, so without status and request id the record would read
/// exactly like a request that never arrived — which is the confusion the whole
/// variant exists to remove.
#[test]
fn a_capture_failure_serializes_as_its_own_kind() -> Result<()> {
    let s = sampling(None)?;
    let sealed = SealedRequest::seal(envelope(panel_mapping(&s), s)?)?;
    let mut transport = ScriptedTransport::with_failures(vec![Err(SendFailure::AfterHeaders {
        status: 200,
        request_id: Some("req_xyz".to_owned()),
        body_bytes_observed: 67_108_865,
        reason: "provider response body exceeded 67108864 bytes".to_owned(),
    })]);
    let outcome = exchange(&mut transport, &sealed, once());
    let json = outcome.to_json();

    assert_eq!(
        json.pointer("/kind").and_then(|v| v.as_str()),
        Some("response-capture-failed"),
        "and specifically NOT transport-failed"
    );
    assert!(json.pointer("/raw").is_some_and(serde_json::Value::is_null));
    assert!(json
        .pointer("/normalized")
        .is_some_and(serde_json::Value::is_null));
    assert!(
        json.pointer("/reported_usage")
            .is_some_and(serde_json::Value::is_null),
        "a turn whose counters are unknown must serialize null, never a zero"
    );
    assert_eq!(
        json.pointer("/response_status").and_then(|v| v.as_u64()),
        Some(200),
        "the response did arrive, and the record has to say so"
    );
    assert_eq!(
        json.pointer("/response_request_id")
            .and_then(|v| v.as_str()),
        Some("req_xyz")
    );
    assert_eq!(
        json.pointer("/body_bytes_observed")
            .and_then(|v| v.as_u64()),
        Some(67_108_865),
        "a lower bound, named as one — not body_len"
    );
    assert_eq!(
        json.pointer("/attempts/0/outcome").and_then(|v| v.as_str()),
        Some("response-capture-failed")
    );
    Ok(())
}

/// The body cap, from both sides, and an I/O error partway through.
///
/// Driven through `capture_body` with a small limit: the contract is about the
/// boundary, and allocating 64 MiB to confirm arithmetic would be a ceremony
/// rather than a test. Exactly-at-limit is a complete body and must be kept —
/// an off-by-one here silently discards a legitimate response.
#[test]
fn the_body_cap_is_exact_and_both_failures_are_post_header() -> Result<()> {
    use qodec::provider::capture_body;

    // Exactly at the limit: kept.
    let at_limit = vec![b'a'; 64];
    let mut r = at_limit.as_slice();
    let body = capture_body(200, Some("req_a".to_owned()), &mut r, 64)
        .map_err(|f| anyhow!("a body exactly at the cap must be accepted, got: {f}"))?;
    assert_eq!(body.len(), 64);

    // One byte over: refused, and refused as a post-header failure.
    let over = vec![b'a'; 65];
    let mut r = over.as_slice();
    let Err(failure) = capture_body(200, Some("req_b".to_owned()), &mut r, 64) else {
        return Err(anyhow!(
            "a body past the cap must be refused, not silently truncated"
        ));
    };
    let SendFailure::AfterHeaders {
        status,
        request_id,
        body_bytes_observed,
        reason,
    } = &failure
    else {
        return Err(anyhow!(
            "the cap is only ever hit after headers, so this must never be retryable: {failure}"
        ));
    };
    assert_eq!(*status, 200);
    assert_eq!(request_id.as_deref(), Some("req_b"));
    assert_eq!(*body_bytes_observed, 65);
    assert!(
        reason.contains("exceeded"),
        "the reason must name what happened, got {reason:?}"
    );

    // A reader that dies mid-body: also post-header, and the observed count is
    // what was actually read rather than anything claimed by a header.
    let mut broken = BreaksAfter { remaining: 10 };
    let Err(failure) = capture_body(200, None, &mut broken, 64) else {
        return Err(anyhow!(
            "an I/O error mid-body does not yield a complete response"
        ));
    };
    let SendFailure::AfterHeaders {
        body_bytes_observed,
        reason,
        ..
    } = &failure
    else {
        return Err(anyhow!(
            "a body that broke after the status line must not be retried: {failure}"
        ));
    };
    assert_eq!(*body_bytes_observed, 10, "a lower bound, honestly counted");
    assert!(reason.contains("reading the provider response body"));
    Ok(())
}

/// The live agent does not follow redirects, so the key cannot ride one.
///
/// Checking the scheme of the constructor's URL does not establish an https-only
/// key path: with redirects on, an https endpoint answering 302 to an http
/// location moves the request — and `x-api-key` with it — onto cleartext, chosen
/// by the server rather than by us. The sink's connection count is the real
/// assertion; the returned status only shows the 3xx was recorded as the response
/// it is.
#[test]
fn the_live_agent_refuses_to_follow_a_redirect() -> Result<()> {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let sink = TcpListener::bind("127.0.0.1:0")?;
    let sink_addr = sink.local_addr()?;
    let sink_hits = Arc::new(AtomicUsize::new(0));
    let hits = Arc::clone(&sink_hits);
    std::thread::spawn(move || {
        for stream in sink.incoming() {
            hits.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut stream) = stream {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi");
            }
        }
    });

    let redirector = TcpListener::bind("127.0.0.1:0")?;
    let redirector_addr = redirector.local_addr()?;
    std::thread::spawn(move || {
        for mut stream in redirector.incoming().flatten() {
            {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 302 Found\r\nlocation: http://{sink_addr}/v1/messages\r\n\
                     content-length: 0\r\n\r\n"
                );
                let _ = stream.write_all(response.as_bytes());
            }
        }
    });

    // Bounded. `live_agent` sets no agent-level timeout — the live transport
    // always supplies a per-request one, and refuses a zero — so without this the
    // stand-ins above are the only thing keeping the call finite. A stand-in that
    // dies before writing a status line would then hang this test rather than fail
    // it, and a hung job is strictly worse than a red one: it burns a runner and
    // tells you nothing. This repository has already spent one commit on a CI step
    // wrongly believed to have hung, which is reason enough not to build a test
    // that genuinely can.
    let response = qodec::provider::live_agent()
        .post(&format!("http://{redirector_addr}/v1/messages"))
        .timeout(std::time::Duration::from_secs(10))
        .set("x-api-key", "SECRET-KEY-MUST-NOT-TRAVEL")
        .send_bytes(b"{}");

    let status = match response {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(s, _)) => s,
        Err(e) => return Err(anyhow!("the redirector should have answered: {e}")),
    };
    assert_eq!(
        status, 302,
        "the 3xx is the response; it must be recorded, not acted on"
    );

    // Give a hypothetical follow-up time to land before concluding it did not.
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(
        sink_hits.load(Ordering::SeqCst),
        0,
        "the redirect target received a request — the API key just travelled in cleartext"
    );
    Ok(())
}
