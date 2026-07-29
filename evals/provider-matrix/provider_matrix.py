#!/usr/bin/env python3
"""Qodec provider/model discovery and qualification primitives.

ModelHubby is an untrusted discovery source. This tool turns an exported JSON
catalog into a canonical, reviewable snapshot; plans explicit provider×model
runs with fail-closed policy filters; and probes OpenAI-compatible endpoints
without fallback or model substitution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SCHEMA = "qodec-provider-catalog-v1"
PLAN_SCHEMA = "qodec-provider-plan-v1"
PROBE_SCHEMA = "qodec-provider-probe-v1"
POLICY_VALUES = {"yes", "no", "unknown"}


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


def required_text(row: dict[str, Any], field: str) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def policy(row: dict[str, Any], field: str) -> str:
    value = row.get(field, "unknown")
    if isinstance(value, bool):
        value = "yes" if value else "no"
    if not isinstance(value, str):
        raise ValueError(f"{field} must be yes/no/unknown")
    value = value.lower().strip()
    if value not in POLICY_VALUES:
        raise ValueError(f"{field} must be yes/no/unknown, got {value!r}")
    return value


def source_rows(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        rows = raw
    elif isinstance(raw, dict) and isinstance(raw.get("targets"), list):
        rows = raw["targets"]
    elif isinstance(raw, dict) and isinstance(raw.get("models"), list):
        rows = raw["models"]
    else:
        raise ValueError("source must be a JSON list or an object with targets/models")
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError("every source row must be an object")
    return rows


def normalize_target(row: dict[str, Any]) -> dict[str, Any]:
    provider = required_text(row, "provider").lower()
    model = required_text(row, "model")
    api_style = str(row.get("api_style", "openai-chat")).strip().lower()
    if api_style != "openai-chat":
        raise ValueError(f"unsupported api_style {api_style!r}; only openai-chat is qualified")
    api_base = required_text(row, "api_base").rstrip("/")
    key_env = required_text(row, "key_env")
    target = {
        "target_id": f"{provider}--{model}",
        "provider": provider,
        "model": model,
        "api_style": api_style,
        "api_base": api_base,
        "key_env": key_env,
        "free_tier": policy(row, "free_tier"),
        "card_required": policy(row, "card_required"),
        "training_use": policy(row, "training_use"),
    }
    if isinstance(row.get("source_url"), str) and row["source_url"].strip():
        target["source_url"] = row["source_url"].strip()
    return target


def import_catalog(source: Path, observed_at: str) -> dict[str, Any]:
    raw_bytes = source.read_bytes()
    rows = source_rows(json.loads(raw_bytes))
    targets = [normalize_target(row) for row in rows]
    targets.sort(key=lambda row: (row["provider"], row["model"], row["api_base"]))
    ids = [row["target_id"] for row in targets]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate provider/model target_id")
    return {
        "schema": SCHEMA,
        "source": {
            "kind": "modelhubby-export",
            "observed_at": observed_at,
            "raw_sha256": sha256_bytes(raw_bytes),
        },
        "targets": targets,
    }


def target_allowed(target: dict[str, Any], args: argparse.Namespace) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if args.free_only and target["free_tier"] != "yes":
        reasons.append(f"free_tier={target['free_tier']}")
    if args.no_card and target["card_required"] != "no":
        reasons.append(f"card_required={target['card_required']}")
    if args.no_training and target["training_use"] != "no":
        reasons.append(f"training_use={target['training_use']}")
    return not reasons, reasons


def build_plan(catalog: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    if catalog.get("schema") != SCHEMA:
        raise ValueError(f"expected {SCHEMA}")
    selected, rejected = [], []
    for target in catalog["targets"]:
        allowed, reasons = target_allowed(target, args)
        (selected if allowed else rejected).append(
            target if allowed else {"target_id": target["target_id"], "reasons": reasons}
        )
    identity = {
        "catalog_sha256": sha256_bytes(canonical_bytes(catalog)),
        "filters": {
            "free_only": args.free_only,
            "no_card": args.no_card,
            "no_training": args.no_training,
        },
        "selected_target_ids": [row["target_id"] for row in selected],
    }
    return {
        "schema": PLAN_SCHEMA,
        "identity": identity,
        "plan_sha256": sha256_bytes(canonical_bytes(identity)),
        "selected": selected,
        "rejected": rejected,
    }


def receipt_filename(target_id: str) -> str:
    """A file name derived from a target id, kept a file name.

    Model ids routinely carry a slash — `openai/gpt-oss-120b` — and writing
    `out_dir / f"{target_id}.json"` turns that into a directory. The receipt
    then no longer lives where its id says, and two targets differing only in
    where the slash falls can land on the same path. Escaped rather than
    stripped, so the mapping stays reversible by eye.
    """
    return target_id.replace("%", "%25").replace("/", "%2F").replace("\\", "%5C") + ".json"


def classify_http(status: int) -> str:
    if status in (401, 403):
        return "AUTH_FAILURE"
    if status == 404:
        return "MODEL_NOT_FOUND"
    if status == 429:
        return "RATE_LIMITED"
    if 500 <= status <= 599:
        return "PROVIDER_5XX"
    return "HTTP_FAILURE"


def probe_target(target: dict[str, Any], timeout: float) -> dict[str, Any]:
    started = time.time()
    request_body = canonical_bytes({
        "model": target["model"],
        "messages": [{"role": "user", "content": "Return exactly: QODEC_PROBE_OK"}],
        "temperature": 0,
        "max_tokens": 16,
    })
    base = target["api_base"]
    url = base if base.endswith("/chat/completions") else base + "/chat/completions"
    result: dict[str, Any] = {
        "schema": PROBE_SCHEMA,
        "target_id": target["target_id"],
        "provider": target["provider"],
        "requested_model": target["model"],
        "request_sha256": sha256_bytes(request_body),
        "endpoint": url,
    }
    key = os.environ.get(target["key_env"])
    if not key:
        result.update(classification="AUTH_FAILURE", detail=f"missing env {target['key_env']}")
        return result
    request = urllib.request.Request(
        url,
        data=request_body,
        method="POST",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
        result.update(
            classification=classify_http(status),
            http_status=status,
            response_sha256=sha256_bytes(raw),
            latency_ms=round((time.time() - started) * 1000),
        )
        return result
    except TimeoutError:
        result.update(classification="TIMEOUT", latency_ms=round((time.time() - started) * 1000))
        return result
    except urllib.error.URLError as exc:
        reason = exc.reason
        result.update(
            classification="TIMEOUT" if isinstance(reason, TimeoutError) else "TRANSPORT_FAILURE",
            detail=str(reason),
            latency_ms=round((time.time() - started) * 1000),
        )
        return result

    result.update(
        http_status=status,
        response_sha256=sha256_bytes(raw),
        latency_ms=round((time.time() - started) * 1000),
    )
    try:
        payload = json.loads(raw)
        reported_model = payload.get("model")
        choices = payload.get("choices", [])
        content = choices[0]["message"]["content"] if choices else None
    except (json.JSONDecodeError, KeyError, TypeError, IndexError):
        result["classification"] = "INVALID_OUTPUT"
        return result
    result["reported_model"] = reported_model
    if reported_model and reported_model != target["model"]:
        result["classification"] = "PROVIDER_SUBSTITUTED"
    elif content != "QODEC_PROBE_OK":
        result["classification"] = "INVALID_OUTPUT"
    else:
        result["classification"] = "PASS"
    if isinstance(payload.get("usage"), dict):
        result["provider_usage"] = payload["usage"]
    return result


# ---------------------------------------------------------------------------
# Tool-calling qualification
# ---------------------------------------------------------------------------
#
# An availability probe answers "is this endpoint alive and is it the model we
# asked for". That is necessary and nowhere near sufficient: it sends no tools,
# so a target can PASS it and still be unable to run C1's forced-query arm at
# all. The arm needs four tool declarations accepted, forcing honoured, a
# multi-turn loop with results fed back under their call ids, and a terminal
# answer whose arguments parse. Nothing in a bare completion predicts any of it.
#
# The canary is therefore the structural contract of the arm, not a friendly
# `get_weather` that a model with the attention span of a goldfish would also
# pass. Same four tools, same schemas, same forcing, same loop shape.

QUALIFY_SCHEMA = "qodec-provider-qualification-v1"
ANSWER_TOOL = "qodec_answer"
SURFACE_SCHEMA = "qodec-c1-panel-surface-v1"

# The model id the frozen request golden is written against. Substituted for the
# real target at send time; see `canonical_request`.
GOLDEN_MODEL = "MODEL-UNDER-QUALIFICATION"

# Distinct causes, because they call for distinct actions. Collapsing a dialect
# rejection into "unavailable" is how a fixable request shape gets recorded as a
# dead target and quietly dropped from the matrix.
CLASSIFICATIONS = (
    "UNAVAILABLE",
    "AUTH_FAILED",
    "RATE_LIMITED",
    "PROVIDER_REJECTED",
    "MODEL_MISSING",
    "PROVIDER_SUBSTITUTED",
    "TOOL_CHOICE_UNSUPPORTED",
    "TOOL_RESULT_REJECTED",
    "MALFORMED_TOOL_ARGUMENTS",
    "PROTOCOL_VIOLATION",
    "NO_TERMINAL_ANSWER",
    "PASS",
)

QUALIFY_INSTRUCTIONS = (
    "You are answering one question about a document you cannot see. The document is not in "
    "this conversation and will not be shown to you. You have tools that run deterministic "
    "queries against it and return results, and a tool that returns the exact bytes of records "
    "backing a result you already obtained. Use them to establish the answer, then call "
    "qodec_answer exactly once, citing the result handle it came from and the record ids that "
    "support it."
)

QUALIFY_TASK = (
    "Exactly one line appears in every attempt section. Which line is it?\n\n"
    "--- artifact metadata ---\n"
    "schema: qodec.query.v1\n"
    "decode_layers: 1\n"
    "records: 6\n"
    "sections:\n  attempt_1: 2\n  attempt_2: 2\n  attempt_3: 2\n"
    "indexes:\n  line: whole-record\n"
)

# The canary answers a question about the wire protocol, not about qodec, so the
# operation results are canned rather than served from a real store. A store
# would add a second thing that can fail and tell us nothing extra about whether
# the provider speaks this dialect.
CANNED_HANDLE = "sha256:" + "0" * 64
CANNED_RESULT = {
    "handle": CANNED_HANDLE,
    "candidate_count": 1,
    "completion": {"state": "exhausted"},
    "preview": [{"encoding": "base64url-nopad", "data": "YWxwaGE", "display_utf8": "alpha"}],
    "support": [
        {"store": CANNED_HANDLE, "section": f"attempt_{n}", "ordinal": 0} for n in (1, 2, 3)
    ],
}
CANNED_RECORDS = {"records": [{"encoding": "base64url-nopad", "data": "YWxwaGE", "display_utf8": "alpha"}]}


MODEL_STATUS_SEVERITY = {"verified": 0, "missing": 1, "drifted": 2}


def model_status_of(requested: str, reported: Any) -> str:
    """Three values, not two.

    A boolean "drifted" has to decide what to say when the provider named no
    model, and the convenient answer — "not drifted" — turns *we do not know*
    into *it matched*.
    """
    if not isinstance(reported, str) or not reported:
        return "missing"
    return "verified" if reported == requested else "drifted"


def fold_model_status(turns: list[dict[str, Any]]) -> str:
    """The worst turn decides; no turns at all is `missing`, not `verified`."""
    worst = "missing"
    seen = False
    for turn in turns:
        status = turn.get("model_status")
        if status not in MODEL_STATUS_SEVERITY:
            continue
        if not seen:
            worst, seen = status, True
        elif MODEL_STATUS_SEVERITY[status] > MODEL_STATUS_SEVERITY[worst]:
            worst = status
    return worst


def load_surface(path: Path) -> dict[str, Any]:
    """Read the frozen C1 panel surface, refusing anything else."""
    surface = read_json(path)
    if surface.get("schema") != SURFACE_SCHEMA:
        raise ValueError(f"expected {SURFACE_SCHEMA}, got {surface.get('schema')!r}")
    if len(surface.get("operations", [])) != 3:
        raise ValueError("the C1 surface has exactly three operations")
    return surface


def openai_tools(surface: dict[str, Any]) -> list[dict[str, Any]]:
    """Wrap the neutral surface in OpenAI-chat function declarations.

    The wrap is mechanical and lives in exactly one place. The schemas
    themselves are not restated here: they arrive from the frozen surface, which
    is generated from the crate that defines them. A canary that paraphrased the
    schemas would qualify a request the adapter will never send.
    """
    tools = [
        {
            "type": "function",
            "function": {
                "name": op["name"],
                "description": op["description"],
                "parameters": op["input_schema"],
            },
        }
        for op in surface["operations"]
    ]
    terminal = surface["terminal_answer"]
    tools.append({
        "type": "function",
        "function": {
            "name": ANSWER_TOOL,
            "description": terminal["description"],
            "parameters": terminal["schema"],
        },
    })
    return tools


def canonical_request(surface: dict[str, Any], model: str, messages: list[dict[str, Any]]) -> dict[str, Any]:
    """The request body, in the one shape qualification is about."""
    return {
        "model": model,
        "messages": messages,
        "tools": openai_tools(surface),
        # Forced, exactly as the arm forces it. Left to the provider default a
        # model may answer in prose, and the arm would be measuring the parser
        # written to grade prose rather than the model.
        "tool_choice": "required",
        "temperature": 0,
        "max_tokens": 1024,
    }


def opening_messages() -> list[dict[str, Any]]:
    return [
        {"role": "system", "content": QUALIFY_INSTRUCTIONS},
        {"role": "user", "content": QUALIFY_TASK},
    ]


def classify_qualify_http(status: int, body: bytes, turn: int) -> tuple[str, str]:
    """Map a non-success status to a cause, with the provider's own words kept.

    `turn` matters: a rejection of the very first request is about the tools or
    the forcing, while a rejection of a later one — the first that carries
    `role: tool` messages — is about the result shape. Same status, different
    thing to fix.
    """
    detail = ""
    param = ""
    try:
        payload = json.loads(body)
        error = payload.get("error") if isinstance(payload, dict) else None
        if isinstance(error, dict):
            detail = str(error.get("message", ""))
            param = str(error.get("param", "") or "")
        elif isinstance(payload, dict):
            detail = str(payload.get("message", ""))
    except (json.JSONDecodeError, TypeError):
        detail = body[:400].decode("utf-8", "replace")

    if status in (401, 403):
        return "AUTH_FAILED", detail
    if status == 404:
        return "MODEL_MISSING", detail
    if status == 429:
        return "RATE_LIMITED", detail
    if 500 <= status <= 599:
        return "UNAVAILABLE", detail
    if status == 400:
        haystack = f"{param} {detail}".lower()
        if "tool_choice" in haystack or "tool choice" in haystack or "tools" in haystack:
            # Named by the provider, not guessed from the shape of the failure.
            return "TOOL_CHOICE_UNSUPPORTED", detail
        if turn > 0:
            return "TOOL_RESULT_REJECTED", detail
        return "PROVIDER_REJECTED", detail
    return "PROVIDER_REJECTED", detail


def parse_tool_calls(message: dict[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
    """Normalize `assistant.tool_calls`, or say why it could not be read."""
    raw = message.get("tool_calls")
    if not isinstance(raw, list) or not raw:
        return [], "assistant message carried no tool_calls"
    calls = []
    for entry in raw:
        if not isinstance(entry, dict):
            return [], "a tool call was not an object"
        function = entry.get("function")
        call_id = entry.get("id")
        if not isinstance(function, dict) or not isinstance(call_id, str) or not call_id:
            return [], "a tool call lacked an id or a function"
        name = function.get("name")
        if not isinstance(name, str) or not name:
            return [], "a tool call lacked a function name"
        calls.append({"id": call_id, "name": name, "raw_arguments": function.get("arguments")})
    return calls, None


def decode_arguments(call: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """OpenAI-chat sends arguments as a JSON *string*; Anthropic sends an object.

    Handling both is not politeness toward sloppy providers — it is the one
    place where the two dialects genuinely differ in kind rather than in naming,
    and a qualification that only accepted one would misreport the other as
    malformed.
    """
    raw = call["raw_arguments"]
    if isinstance(raw, dict):
        return raw, None
    if not isinstance(raw, str):
        return None, f"arguments for {call['name']} were neither an object nor a string"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"arguments for {call['name']} are not valid JSON: {exc}"
    if not isinstance(parsed, dict):
        return None, f"arguments for {call['name']} decoded to {type(parsed).__name__}, not an object"
    return parsed, None


def required_keys(surface: dict[str, Any], name: str) -> list[str]:
    if name == ANSWER_TOOL:
        return list(surface["terminal_answer"]["schema"].get("required", []))
    for op in surface["operations"]:
        if op["name"] == name:
            return list(op["input_schema"].get("required", []))
    return []


def canned_result_for(name: str) -> dict[str, Any]:
    return CANNED_RECORDS if name == "qodec_materialize" else CANNED_RESULT


def qualify_target(
    target: dict[str, Any],
    surface: dict[str, Any],
    timeout: float,
    max_turns: int,
    send: Any,
) -> dict[str, Any]:
    """Run the C1 protocol shape against one provider × model target.

    `send` is injected so every classification is reachable without a network.
    A qualification whose failure paths can only be exercised against a real
    provider is a qualification whose failure paths are never exercised.
    """
    base = target["api_base"]
    url = base if base.endswith("/chat/completions") else base + "/chat/completions"
    receipt: dict[str, Any] = {
        "schema": QUALIFY_SCHEMA,
        "target_id": target["target_id"],
        "provider": target["provider"],
        "requested_model": target["model"],
        "reported_model": None,
        "model_status": "missing",
        "transport_target": {
            "api_style": target["api_style"],
            "endpoint": base,
            "path": "/chat/completions",
            "content_type": "application/json",
            "timeout_secs": timeout,
        },
        "turns": [],
        "turn_count": 0,
        "classification": "UNAVAILABLE",
        "detail": "",
    }

    messages = opening_messages()
    for turn in range(max_turns):
        body = canonical_bytes(canonical_request(surface, target["model"], messages))
        record: dict[str, Any] = {
            "ordinal": turn,
            "request_sha256": sha256_bytes(body),
            "request_bytes": len(body),
        }
        status, raw, detail = send(url, body, timeout)
        record["response_sha256"] = sha256_bytes(raw) if raw is not None else None
        if status is None:
            record["outcome"] = "transport-failure"
            record["detail"] = detail
            receipt["turns"].append(record)
            receipt.update(classification="UNAVAILABLE", detail=detail, turn_count=turn + 1)
            return receipt
        record["http_status"] = status
        if not 200 <= status < 300:
            kind, message = classify_qualify_http(status, raw, turn)
            record["outcome"] = "provider-rejected"
            record["detail"] = message
            receipt["turns"].append(record)
            receipt.update(classification=kind, detail=message, turn_count=turn + 1)
            return receipt

        try:
            payload = json.loads(raw)
            message = payload["choices"][0]["message"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            record["outcome"] = "unreadable-response"
            record["detail"] = str(exc)
            receipt["turns"].append(record)
            receipt.update(classification="PROVIDER_REJECTED", detail=str(exc), turn_count=turn + 1)
            return receipt

        reported = payload.get("model")
        receipt["reported_model"] = reported
        record["model_status"] = model_status_of(target["model"], reported)
        # Worst turn decides, exactly as the Rust side does: a cell is only as
        # identified as its least identified turn. Folded from the per-turn
        # values at the end rather than accumulated here, so a run with no turns
        # is `missing` — unknown — instead of inheriting a seed nobody set.
        receipt["model_status"] = fold_model_status(receipt["turns"] + [record])
        if isinstance(payload.get("usage"), dict):
            record["reported_usage"] = payload["usage"]

        calls, why = parse_tool_calls(message)
        if why:
            record["outcome"] = "no-tool-call"
            record["detail"] = why
            receipt["turns"].append(record)
            receipt.update(classification="NO_TERMINAL_ANSWER", detail=why, turn_count=turn + 1)
            return receipt
        record["tool_names"] = [c["name"] for c in calls]
        record["tool_call_ids"] = [c["id"] for c in calls]

        known = {op["name"] for op in surface["operations"]} | {ANSWER_TOOL}
        unknown = [c["name"] for c in calls if c["name"] not in known]
        if unknown:
            why = f"called tools that were never declared: {unknown}"
            record["outcome"] = "protocol-violation"
            record["detail"] = why
            receipt["turns"].append(record)
            receipt.update(classification="PROTOCOL_VIOLATION", detail=why, turn_count=turn + 1)
            return receipt

        decoded = []
        for call in calls:
            args, why = decode_arguments(call)
            if why:
                record["outcome"] = "malformed-arguments"
                record["detail"] = why
                receipt["turns"].append(record)
                receipt.update(
                    classification="MALFORMED_TOOL_ARGUMENTS", detail=why, turn_count=turn + 1
                )
                return receipt
            missing = [k for k in required_keys(surface, call["name"]) if k not in args]
            if missing:
                why = f"{call['name']} arguments missing required {missing}"
                record["outcome"] = "malformed-arguments"
                record["detail"] = why
                receipt["turns"].append(record)
                receipt.update(
                    classification="MALFORMED_TOOL_ARGUMENTS", detail=why, turn_count=turn + 1
                )
                return receipt
            decoded.append((call, args))
        record["arguments_valid"] = True

        answers = [c for c, _ in decoded if c["name"] == ANSWER_TOOL]
        operations = [(c, a) for c, a in decoded if c["name"] != ANSWER_TOOL]
        if len(answers) > 1:
            why = f"{len(answers)} terminal answers in one response"
            record["outcome"] = "protocol-violation"
            record["detail"] = why
            receipt["turns"].append(record)
            receipt.update(classification="PROTOCOL_VIOLATION", detail=why, turn_count=turn + 1)
            return receipt
        if answers and operations:
            why = f"a terminal answer alongside {len(operations)} operation(s)"
            record["outcome"] = "protocol-violation"
            record["detail"] = why
            receipt["turns"].append(record)
            receipt.update(classification="PROTOCOL_VIOLATION", detail=why, turn_count=turn + 1)
            return receipt

        if answers:
            record["outcome"] = "terminal-answer"
            record["terminal_answer_valid"] = True
            receipt["turns"].append(record)
            receipt.update(classification="PASS", turn_count=turn + 1)
            if receipt["model_status"] == "drifted":
                receipt["classification"] = "PROVIDER_SUBSTITUTED"
                receipt["detail"] = (
                    f"requested {target['model']}, provider reported {receipt['reported_model']}"
                )
            return receipt

        record["outcome"] = "operations"
        receipt["turns"].append(record)
        # Replayed unchanged, with every result keyed to the call that asked for
        # it. A tool result whose id does not match is the provider's most
        # common reason to reject the next request, so the linkage is part of
        # what is being qualified.
        messages.append({
            "role": "assistant",
            "content": message.get("content"),
            "tool_calls": [
                {
                    "id": c["id"],
                    "type": "function",
                    "function": {"name": c["name"], "arguments": c["raw_arguments"]
                                 if isinstance(c["raw_arguments"], str)
                                 else json.dumps(c["raw_arguments"], sort_keys=True)},
                }
                for c, _ in decoded
            ],
        })
        for call, _args in decoded:
            messages.append({
                "role": "tool",
                "tool_call_id": call["id"],
                "content": json.dumps(canned_result_for(call["name"]), sort_keys=True),
            })

    receipt.update(
        classification="NO_TERMINAL_ANSWER",
        detail=f"no terminal answer within {max_turns} turns",
        turn_count=max_turns,
    )
    return receipt


def http_send(url: str, body: bytes, timeout: float) -> tuple[int | None, bytes | None, str]:
    """The one place qualification touches a network."""
    key_env = http_send.key_env  # type: ignore[attr-defined]
    key = os.environ.get(key_env)
    if not key:
        return None, None, f"missing env {key_env}"
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(), ""
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), ""
    except TimeoutError:
        return None, None, "timeout"
    except urllib.error.URLError as exc:
        return None, None, str(exc.reason)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import")
    imp.add_argument("--source", type=Path, required=True)
    imp.add_argument("--observed-at", required=True, help="UTC ISO-8601 timestamp, supplied explicitly")
    imp.add_argument("--out", type=Path, required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--catalog", type=Path, required=True)
    plan.add_argument("--out", type=Path, required=True)
    plan.add_argument("--free-only", action="store_true")
    plan.add_argument("--no-card", action="store_true")
    plan.add_argument("--no-training", action="store_true")
    probe = sub.add_parser("probe")
    probe.add_argument("--plan", type=Path, required=True)
    probe.add_argument("--out-dir", type=Path, required=True)
    probe.add_argument("--timeout", type=float, default=30.0)
    qualify = sub.add_parser("qualify")
    qualify.add_argument("--plan", type=Path, required=True)
    qualify.add_argument("--surface", type=Path, required=True)
    qualify.add_argument("--out-dir", type=Path, required=True)
    qualify.add_argument("--timeout", type=float, default=60.0)
    qualify.add_argument("--max-turns", type=int, default=6)
    return p


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "import":
            write_json(args.out, import_catalog(args.source, args.observed_at))
        elif args.command == "plan":
            write_json(args.out, build_plan(read_json(args.catalog), args))
        elif args.command == "probe":
            plan = read_json(args.plan)
            if plan.get("schema") != PLAN_SCHEMA:
                raise ValueError(f"expected {PLAN_SCHEMA}")
            args.out_dir.mkdir(parents=True, exist_ok=True)
            for target in plan["selected"]:
                write_json(
                    args.out_dir / receipt_filename(target["target_id"]),
                    probe_target(target, args.timeout),
                )
        else:
            plan = read_json(args.plan)
            if plan.get("schema") != PLAN_SCHEMA:
                raise ValueError(f"expected {PLAN_SCHEMA}")
            surface = load_surface(args.surface)
            args.out_dir.mkdir(parents=True, exist_ok=True)
            for target in plan["selected"]:
                http_send.key_env = target["key_env"]  # type: ignore[attr-defined]
                receipt = qualify_target(target, surface, args.timeout, args.max_turns, http_send)
                write_json(args.out_dir / receipt_filename(target["target_id"]), receipt)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"provider-matrix: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
