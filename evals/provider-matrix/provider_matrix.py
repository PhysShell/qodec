#!/usr/bin/env python3
"""Qodec provider/model discovery and qualification primitives.

ModelHubby is an untrusted discovery source. This tool turns an exported JSON
catalog into a canonical, reviewable snapshot; plans explicit provider×model
runs with fail-closed policy filters; and probes OpenAI-compatible endpoints
without fallback or model substitution.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, NamedTuple

# The frozen, dependency-free validator already used by the N0 corpus tools and
# the N2 registries. Reused rather than re-implemented: a second hand-rolled
# validator would be a second set of keywords to get subtly wrong, and the
# schemas being checked here are the crate's own, not ones written to suit it.
CORPUS_TOOLS = Path(__file__).resolve().parents[1] / "interop" / "v2" / "corpus" / "tools"
sys.path.insert(0, str(CORPUS_TOOLS))
import jsonschema_mini  # noqa: E402

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


# ---------------------------------------------------------------------------
# Hardened transport
# ---------------------------------------------------------------------------
#
# Every request below carries a provider credential, and the URL it goes to is
# named by an untrusted discovery source. That is the whole threat: a catalog
# row is a string somebody else wrote, and `urllib`'s defaults will happily send
# a bearer token over plaintext http, to a host embedded in userinfo, or to
# wherever a 302 points — the last one silently, after the key has already left.
#
# So there is exactly one transport, used by `probe` and `qualify` alike, and it
# refuses the endpoint before the key is attached rather than reporting an
# interesting classification afterwards.

COMPLETIONS_PATH = "/chat/completions"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

REGISTRY_SCHEMA = "qodec-provider-registry-v1"
REGISTRY_PATH = Path(__file__).resolve().parent / "trusted-providers.json"

# Headers providers use to name the generation. Kept because it is the only
# handle support has when a body is lost after the headers arrived.
REQUEST_ID_HEADERS = ("x-request-id", "x-groq-request-id", "openai-request-id", "request-id")


class EndpointRejected(ValueError):
    """The catalog named an endpoint this transport will not send a key to."""


def load_registry(path: Path | None = None) -> dict[str, Any]:
    """The trusted `provider -> origin + key_env` binding, from outside the catalog.

    `https` and a valid certificate prove that the connection to
    `steal.example` is confidential. They prove nothing about whether
    `steal.example` is Groq. A row naming provider `groq` with an `api_base`
    somebody else chose is a correctly encrypted delivery of our credential to a
    stranger, and every URL rule in this file passes it.

    So origin and key are not the catalog's to supply. They live here, in a file
    that changes only by reviewed commit; discovery contributes the provider
    name, the model, the free-tier metadata and its own provenance, and nothing
    that carries authority.
    """
    registry = read_json(path or REGISTRY_PATH)
    if registry.get("schema") != REGISTRY_SCHEMA:
        raise ValueError(f"expected {REGISTRY_SCHEMA}, got {registry.get('schema')!r}")
    providers = registry.get("providers")
    if not isinstance(providers, dict) or not providers:
        raise ValueError("the trusted registry declares no providers")
    for name, entry in providers.items():
        for field in ("api_base", "api_style", "key_env"):
            if not isinstance(entry.get(field), str) or not entry[field].strip():
                raise ValueError(f"trusted provider {name!r} is missing {field}")
        completions_url(entry["api_base"])
    return registry


def trusted_entry(registry: dict[str, Any], provider: str) -> dict[str, Any]:
    entry = registry["providers"].get(provider)
    if entry is None:
        known = ", ".join(sorted(registry["providers"]))
        raise EndpointRejected(
            f"provider {provider!r} is not in the trusted registry (known: {known}); "
            "add it in a reviewed commit rather than through a catalog row"
        )
    return entry


def bind_to_registry(row: dict[str, Any], provider: str, model: str, registry: dict[str, Any]) -> dict[str, Any]:
    """Take origin, key name and dialect from the registry — never from the row.

    A row that also carries them is not quietly overruled: disagreement is
    reported. Silently ignoring a hostile `api_base` would mean a tampered
    catalog produces a perfectly valid plan and nobody ever learns it was
    tampered with.
    """
    entry = trusted_entry(registry, provider)
    for field in ("api_base", "key_env", "api_style"):
        claimed = row.get(field)
        if isinstance(claimed, str) and claimed.strip().rstrip("/") != entry[field].rstrip("/"):
            raise EndpointRejected(
                f"{provider}/{model}: catalog claims {field}={claimed.strip()!r}, "
                f"trusted registry says {entry[field]!r}"
            )
    return entry


def verify_against_registry(target: dict[str, Any], registry: dict[str, Any]) -> None:
    """Re-check a planned target immediately before the key is attached.

    Intake is the first gate, not the only one: a plan is a reviewed file that
    still sits on disk afterwards, and an edited one must not be able to point a
    provider name at somebody else's host.
    """
    entry = trusted_entry(registry, target["provider"])
    for field in ("api_base", "key_env", "api_style"):
        if str(target.get(field, "")).rstrip("/") != entry[field].rstrip("/"):
            raise EndpointRejected(
                f"{target['target_id']}: {field}={target.get(field)!r} does not match the "
                f"trusted registry ({entry[field]!r})"
            )


def completions_url(api_base: str) -> str:
    """Turn a catalog `api_base` into the one URL we are willing to POST to.

    Fail-closed on every axis a hostile row could use to redirect the
    credential: scheme, host, userinfo, query, fragment. Rejected at intake and
    again at send time, because a plan file can be hand-edited after review.
    """
    parts = urllib.parse.urlsplit(api_base)
    if parts.scheme != "https":
        raise EndpointRejected(f"api_base must be https, got {parts.scheme or '(none)'!r}")
    if not parts.hostname:
        raise EndpointRejected("api_base must name a host")
    if parts.username or parts.password:
        raise EndpointRejected("api_base must not carry userinfo")
    if parts.query:
        raise EndpointRejected("api_base must not carry a query string")
    if parts.fragment:
        raise EndpointRejected("api_base must not carry a fragment")
    path = parts.path.rstrip("/")
    if not path.endswith(COMPLETIONS_PATH):
        path += COMPLETIONS_PATH
    return urllib.parse.urlunsplit(("https", parts.netloc, path, "", ""))


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect instead of resending the credential elsewhere.

    Returning `None` makes urllib raise the 3xx as an `HTTPError`, so the status
    is recorded and classified rather than followed to a host the catalog never
    named. `build_opener` drops the default redirect handler in favour of this
    one, so there is no path left that follows a `Location`.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


_OPENER = urllib.request.build_opener(_NoRedirects)


class SendResult(NamedTuple):
    """What one HTTP attempt established, including *when* it stopped.

    `stage` is the part a bare `(status, body)` cannot express. A failure before
    any headers arrived means the request may never have been served and is
    retryable; a failure while reading the body means the provider already
    generated, already billed, and the response is simply lost. Calling the
    second one "unavailable" would invite a retry that pays twice.

    `status is None` means one thing only: **no headers were ever received.** A
    body lost after the headers keeps the status, because by then the provider
    has already said something — losing a 401 and filing it as a nameless
    capture failure discards the most useful fact in the exchange. `request_id`
    and `body_bytes_observed` are kept for the same reason: when the body is
    gone, they are all support has to go on.
    """

    status: int | None
    body: bytes | None
    detail: str = ""
    stage: str = "before-response"  # before-response | after-headers | completed
    body_bytes_observed: int | None = None
    request_id: str | None = None


class BodyTooLarge(ValueError):
    """Carries how much was seen, so the receipt is not left saying only "lost"."""

    def __init__(self, observed: int, limit: int) -> None:
        super().__init__(f"response body exceeded {limit} bytes (stopped after {observed})")
        self.observed = observed


def as_send_result(value: Any) -> SendResult:
    """Accept a `SendResult`, or a positional tuple from an injected `send`.

    A three-field tuple carries no stage, and only one reading of it is
    consistent: a status means the exchange completed, no status means nothing
    arrived. Spelled out here rather than as a NamedTuple default, because a
    default cannot depend on another field — and defaulting to "completed"
    unconditionally would quietly turn every transport failure into a 200.
    """
    if isinstance(value, SendResult):
        return value
    fields = tuple(value)
    result = SendResult(*fields)
    if len(fields) >= 4:
        return result
    return result._replace(stage="completed" if result.status is not None else "before-response")


def read_bounded(stream: Any, limit: int) -> bytes:
    """Read at most `limit` bytes, and say so rather than truncating in silence."""
    raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise BodyTooLarge(len(raw), limit)
    return raw


def request_id_of(headers: Any) -> str | None:
    for name in REQUEST_ID_HEADERS:
        try:
            value = headers.get(name)
        except AttributeError:
            return None
        if value:
            return str(value)
    return None


def send_json(url: str, body: bytes, key: str, timeout: float, limit: int = MAX_RESPONSE_BYTES) -> SendResult:
    """POST `body` to `url` with the credential attached. The only network call."""
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        response = _OPENER.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        # Headers arrived. The body is the provider's own words about why, and
        # 3xx lands here too because the redirect handler refused to follow it.
        request_id = request_id_of(exc.headers)
        try:
            with exc:
                raw = read_bounded(exc, limit)
        except (OSError, ValueError) as read_exc:
            observed = getattr(read_exc, "observed", None)
            return SendResult(exc.code, None, str(read_exc), "after-headers", observed, request_id)
        return SendResult(exc.code, raw, "", "completed", len(raw), request_id)
    except TimeoutError:
        return SendResult(None, None, "timeout", "before-response")
    except urllib.error.URLError as exc:
        reason = exc.reason
        detail = "timeout" if isinstance(reason, TimeoutError) else str(reason)
        return SendResult(None, None, detail, "before-response")

    status = None
    request_id = None
    try:
        with response:
            status = response.status
            request_id = request_id_of(getattr(response, "headers", None))
            raw = read_bounded(response, limit)
    except (OSError, ValueError) as exc:
        observed = getattr(exc, "observed", None)
        return SendResult(status, None, str(exc), "after-headers", observed, request_id)
    return SendResult(status, raw, "", "completed", len(raw), request_id)


def key_bound_sender(key_env: str):
    """A `send` closed over the env var that holds the key — never over the key.

    The credential is read at call time and stays inside `send_json`. Nothing
    that gets recorded, hashed, or written to a receipt has ever seen it.
    """

    def send(url: str, body: bytes, timeout: float) -> SendResult:
        key = os.environ.get(key_env)
        if not key:
            return SendResult(None, None, f"missing env {key_env}", "no-credential")
        return send_json(url, body, key, timeout)

    return send


def normalize_target(row: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
    provider = required_text(row, "provider").lower()
    model = required_text(row, "model")
    entry = bind_to_registry(row, provider, model, registry)
    api_style = entry["api_style"]
    if api_style != "openai-chat":
        raise ValueError(f"unsupported api_style {api_style!r}; only openai-chat is qualified")
    api_base = entry["api_base"].rstrip("/")
    try:
        completions_url(api_base)
    except EndpointRejected as exc:
        raise EndpointRejected(f"{provider}/{model}: {exc}") from exc
    key_env = entry["key_env"]
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


def import_catalog(source: Path, observed_at: str, registry: dict[str, Any] | None = None) -> dict[str, Any]:
    registry = registry if registry is not None else load_registry()
    raw_bytes = source.read_bytes()
    rows = source_rows(json.loads(raw_bytes))
    targets = [normalize_target(row, registry) for row in rows]
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
        # The registry the origins came from, so a catalog cannot be replayed
        # later against a different one without the change being visible.
        "registry_sha256": sha256_bytes(canonical_bytes(registry)),
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
    if 300 <= status <= 399:
        return "REDIRECT_NOT_FOLLOWED"
    if status in (401, 403):
        return "AUTH_FAILURE"
    if status == 404:
        return "MODEL_NOT_FOUND"
    if status == 429:
        return "RATE_LIMITED"
    if 500 <= status <= 599:
        return "PROVIDER_5XX"
    return "HTTP_FAILURE"


def probe_target(
    target: dict[str, Any],
    timeout: float,
    send: Any = None,
    registry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    registry = registry if registry is not None else load_registry()
    started = time.time()
    request_body = canonical_bytes({
        "model": target["model"],
        "messages": [{"role": "user", "content": "Return exactly: QODEC_PROBE_OK"}],
        "temperature": 0,
        "max_tokens": 16,
    })
    result: dict[str, Any] = {
        "schema": PROBE_SCHEMA,
        "target_id": target["target_id"],
        "provider": target["provider"],
        "requested_model": target["model"],
        "request_sha256": sha256_bytes(request_body),
    }
    try:
        verify_against_registry(target, registry)
        url = completions_url(target["api_base"])
    except EndpointRejected as exc:
        result.update(classification="ENDPOINT_REJECTED", detail=str(exc))
        return result
    result["endpoint"] = url

    send = send if send is not None else key_bound_sender(target["key_env"])
    sent = as_send_result(send(url, request_body, timeout))
    latency = round((time.time() - started) * 1000)
    if sent.request_id:
        result["request_id"] = sent.request_id
    if sent.stage != "completed":
        # A body-read failure is not unavailability: the provider answered, the
        # generation exists, and it will appear on the bill. Retrying it is a
        # decision, not a formality, so it gets its own name — and keeps the
        # status the provider already sent.
        if sent.stage == "no-credential":
            kind = "AUTH_FAILURE"
        elif sent.stage == "after-headers":
            kind = "RESPONSE_CAPTURE_FAILED"
        else:
            kind = "TIMEOUT" if sent.detail == "timeout" else "TRANSPORT_FAILURE"
        result.update(classification=kind, detail=sent.detail, latency_ms=latency)
        if sent.status is not None:
            result["http_status"] = sent.status
            result["detail"] = f"HTTP {sent.status}: {sent.detail}"
        if sent.body_bytes_observed is not None:
            result["body_bytes_observed"] = sent.body_bytes_observed
        return result

    status, raw = sent.status, sent.body or b""
    if not 200 <= status < 300:
        result.update(
            classification=classify_http(status),
            http_status=status,
            response_sha256=sha256_bytes(raw),
            latency_ms=latency,
        )
        return result

    result.update(
        http_status=status,
        response_sha256=sha256_bytes(raw),
        latency_ms=latency,
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
    # Three-valued, like the qualification side. The old `if reported_model and
    # ...` let a response that named no model fall through to PASS whenever the
    # text happened to be right, so a target whose identity was never
    # established could satisfy the "PASS on both probes" gate.
    status_of_model = model_status_of(target["model"], reported_model)
    result["model_status"] = status_of_model
    if status_of_model == "drifted":
        result["classification"] = "PROVIDER_SUBSTITUTED"
    elif status_of_model == "missing":
        result["classification"] = "MODEL_IDENTITY_MISSING"
        result["detail"] = "the response named no model; identity unestablished"
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
    "ENDPOINT_REJECTED",
    "UNAVAILABLE",
    "RESPONSE_CAPTURE_FAILED",
    "REDIRECT_NOT_FOLLOWED",
    "AUTH_FAILED",
    "RATE_LIMITED",
    "PROVIDER_REJECTED",
    # `MODEL_MISSING` is HTTP 404: the provider has no such model. It is not the
    # same finding as a 200 that never says which model produced it, which is
    # why that one is `MODEL_IDENTITY_MISSING` and not a reuse of this name.
    "MODEL_MISSING",
    "MODEL_IDENTITY_MISSING",
    "PROVIDER_SUBSTITUTED",
    "TOOL_CHOICE_UNSUPPORTED",
    "TOOL_RESULT_REJECTED",
    "DIALECT_MISMATCH",
    "MALFORMED_TOOL_ARGUMENTS",
    "PROTOCOL_VIOLATION",
    "NO_TERMINAL_ANSWER",
    "CANARY_ANSWER_MISMATCH",
    "PASS",
)

# Only a verified identity may pass. `drifted` and `missing` are different
# failures — one names the wrong model, the other names none — and both make the
# run say nothing about the target that was asked for.
MODEL_STATUS_VERDICT = {
    "verified": "PASS",
    "drifted": "PROVIDER_SUBSTITUTED",
    "missing": "MODEL_IDENTITY_MISSING",
}

# A transport that stopped before any headers may not have been served at all;
# one that stopped after them produced a generation somebody is paying for.
STAGE_CAUSE = {
    "no-credential": "AUTH_FAILED",
    "before-response": "UNAVAILABLE",
    "after-headers": "RESPONSE_CAPTURE_FAILED",
}
STAGE_OUTCOME = {
    "no-credential": "no-credential",
    "before-response": "transport-failure",
    "after-headers": "response-capture-failure",
}

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

# The one answer the canned results support. Deterministic on purpose: the
# canary asks a question whose answer is fixed by the data it hands back, so
# "did the model actually read the result" is decidable without a grader.
CANARY_ANSWER_BYTES = b"alpha"


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


def fold_reported_models(turns: list[dict[str, Any]]) -> list[Any]:
    """Every distinct model the provider named, in the order it named them.

    A single top-level `reported_model` overwritten each turn loses exactly the
    evidence that matters: a run that drifted on turn one and was correct on
    turn two folds to `drifted`, and then the detail line reads "requested X,
    provider reported X" because the last write won. The substituted model is
    the whole finding — it has to survive the fold.

    Turns that never reached a payload contribute nothing, rather than a `null`
    that would read as "the provider named no model".
    """
    seen: list[Any] = []
    for turn in turns:
        if "reported_model" not in turn:
            continue
        value = turn["reported_model"]
        if value not in seen:
            seen.append(value)
    return seen


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


def classify_qualify_http(status: int, body: bytes, carried_tool_results: bool) -> tuple[str, str]:
    """Map a non-success status to a cause, with the provider's own words kept.

    Whether the rejected request carried `role: tool` messages matters: a
    rejection of one that did not is about the tools or the forcing, while a
    rejection of one that did is about the result shape. Same status, different
    thing to fix. Asked of the request itself rather than inferred from the turn
    number, which is only a proxy for it.
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

    if 300 <= status <= 399:
        # The transport refused to follow it, so the credential stayed put. This
        # is an endpoint to correct, not a provider that said no.
        return "REDIRECT_NOT_FOLLOWED", detail or f"{status} redirect not followed"
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
        if carried_tool_results:
            return "TOOL_RESULT_REJECTED", detail
        return "PROVIDER_REJECTED", detail
    return "PROVIDER_REJECTED", detail


def parse_tool_calls(message: dict[str, Any]) -> tuple[list[dict[str, Any]], tuple[str, str] | None]:
    """Read `assistant.tool_calls` under the OpenAI-chat contract, strictly.

    This vertical qualifies `api_style: openai-chat`, and the adapter that will
    consume a PASS is `OpenAiChatCompletions`. A canary that accepted a looser
    shape than the adapter would hand out a PASS for a response the adapter
    rejects — the same defect as paraphrasing the schemas, moved to the response
    side. So the contract is exactly what a strict mapper requires:

        message.role == "assistant"
        tool_calls is a non-empty array
        every tool_call.type == "function"
        every id is a non-empty string, and unique within the response
        function.name is a non-empty string
        function.arguments is a JSON *string* (not an object)

    Returns `(calls, problem)`, where `problem` is `(classification, detail)`.
    """
    role = message.get("role")
    if role != "assistant":
        return [], ("PROTOCOL_VIOLATION", f"tool calls arrived under role {role!r}, not 'assistant'")
    raw = message.get("tool_calls")
    if raw is None:
        return [], ("NO_TERMINAL_ANSWER", "assistant message carried no tool_calls")
    if not isinstance(raw, list):
        return [], ("PROTOCOL_VIOLATION", f"tool_calls was {type(raw).__name__}, not an array")
    if not raw:
        return [], ("NO_TERMINAL_ANSWER", "assistant message carried an empty tool_calls array")

    calls: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            return [], ("PROTOCOL_VIOLATION", "a tool call was not an object")
        kind = entry.get("type")
        if kind != "function":
            # Not pedantry: a strict mapper switches on this field, and a call
            # arriving as anything else is a shape it will not deserialize.
            return [], ("PROTOCOL_VIOLATION", f"tool call type was {kind!r}, not 'function'")
        call_id = entry.get("id")
        if not isinstance(call_id, str) or not call_id:
            return [], ("PROTOCOL_VIOLATION", "a tool call lacked a non-empty string id")
        if call_id in seen_ids:
            # Results are returned keyed by id. Two calls sharing one id make the
            # linkage ambiguous, and the ambiguity is resolved by whichever
            # result happens to be written last.
            return [], ("PROTOCOL_VIOLATION", f"tool call id {call_id!r} appeared more than once")
        seen_ids.add(call_id)
        function = entry.get("function")
        if not isinstance(function, dict):
            return [], ("PROTOCOL_VIOLATION", f"tool call {call_id} lacked a function object")
        name = function.get("name")
        if not isinstance(name, str) or not name:
            return [], ("PROTOCOL_VIOLATION", f"tool call {call_id} lacked a function name")
        arguments = function.get("arguments")
        if isinstance(arguments, (dict, list)):
            # A coherent other dialect — Anthropic sends arguments as an object —
            # not a malformed OpenAI response. Named separately because the fix
            # is a different adapter, not a better prompt.
            return [], (
                "DIALECT_MISMATCH",
                f"{name} arguments arrived as a JSON {type(arguments).__name__}; "
                "openai-chat requires a JSON string",
            )
        if not isinstance(arguments, str):
            return [], (
                "PROTOCOL_VIOLATION",
                f"{name} arguments were {type(arguments).__name__}, not a string",
            )
        calls.append({"id": call_id, "name": name, "raw_arguments": arguments})
    return calls, None


def decode_arguments(call: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """Decode the JSON string `parse_tool_calls` already insisted on."""
    raw = call["raw_arguments"]
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"arguments for {call['name']} are not valid JSON: {exc}"
    if not isinstance(parsed, dict):
        return None, f"arguments for {call['name']} decoded to {type(parsed).__name__}, not an object"
    return parsed, None


def schema_for(surface: dict[str, Any], name: str) -> dict[str, Any] | None:
    """The declared input schema for a tool, or None if it was never declared."""
    if name == ANSWER_TOOL:
        return surface["terminal_answer"]["schema"]
    for op in surface["operations"]:
        if op["name"] == name:
            return op["input_schema"]
    return None


def validate_arguments(surface: dict[str, Any], name: str, args: dict[str, Any]) -> list[str]:
    """Check arguments against the schema the request actually declared.

    Presence of the required keys is the least of it. `{"index": 123,
    "sections": "not-a-list", "extra": true}` has both required keys and is
    nonsense the adapter would refuse; a canary that called it valid would
    report PASS for a target the arm cannot use. The declared schemas carry
    types, enums, patterns, minimums, nested objects, `additionalProperties:
    false` and local `$ref` — so all of that is what gets checked.
    """
    schema = schema_for(surface, name)
    if schema is None:
        return [f"{name} is not a declared tool"]
    return jsonschema_mini.validate(args, schema)


def b64url_decode(data: str) -> bytes:
    """base64url without padding, as every byte envelope in the surface uses."""
    if not isinstance(data, str):
        raise ValueError("expected a string")
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def canary_answer_errors(args: dict[str, Any]) -> list[str]:
    """Did the target answer the question, or merely satisfy the schema?

    Kept apart from the protocol causes on purpose. A model that speaks the
    dialect perfectly and cites a handle it was never given has qualified the
    wire and failed the task; folding the two together would hide whichever
    happened to be checked second, and they call for opposite actions — one is
    a target to drop, the other a prompt to fix.
    """
    errors: list[str] = []

    envelope = args.get("answer")
    data = envelope.get("data") if isinstance(envelope, dict) else None
    try:
        decoded = b64url_decode(data)
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        errors.append(f"answer data is not base64url: {exc}")
    else:
        if decoded != CANARY_ANSWER_BYTES:
            errors.append(f"answer bytes {decoded!r}, expected {CANARY_ANSWER_BYTES!r}")

    if args.get("handle") != CANNED_HANDLE:
        errors.append(f"cited handle {args.get('handle')!r} was never returned by any operation")

    support = {json.dumps(row, sort_keys=True) for row in CANNED_RESULT["support"]}
    cited = args.get("cited")
    for citation in cited if isinstance(cited, list) else []:
        if json.dumps(citation, sort_keys=True) not in support:
            errors.append(f"citation {json.dumps(citation, sort_keys=True)} is not in the result support")
    return errors


def canned_result_for(name: str) -> dict[str, Any]:
    return CANNED_RECORDS if name == "qodec_materialize" else CANNED_RESULT


def qualify_target(
    target: dict[str, Any],
    surface: dict[str, Any],
    timeout: float,
    max_turns: int,
    send: Any,
    registry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the C1 protocol shape against one provider × model target.

    `send` is injected so every classification is reachable without a network.
    A qualification whose failure paths can only be exercised against a real
    provider is a qualification whose failure paths are never exercised.
    """
    registry = registry if registry is not None else load_registry()
    base = target["api_base"]
    receipt: dict[str, Any] = {
        "schema": QUALIFY_SCHEMA,
        "target_id": target["target_id"],
        "provider": target["provider"],
        "requested_model": target["model"],
        "reported_model": None,
        "reported_models": [],
        "model_status": "missing",
        "transport_target": {
            "api_style": target["api_style"],
            "endpoint": base,
            "path": COMPLETIONS_PATH,
            "content_type": "application/json",
            "timeout_secs": timeout,
            "redirects_allowed": 0,
            "max_response_bytes": MAX_RESPONSE_BYTES,
        },
        "turns": [],
        "turn_count": 0,
        "tool_result_roundtrip": False,
        "classification": "UNAVAILABLE",
        "detail": "",
    }

    try:
        # Identity of the destination before anything else: a valid https URL is
        # not evidence that the host behind it is the provider the target names.
        verify_against_registry(target, registry)
        url = completions_url(base)
    except EndpointRejected as exc:
        receipt.update(classification="ENDPOINT_REJECTED", detail=str(exc))
        return receipt

    # The two facts the terminal answer is only meaningful after. `awaiting`
    # says results were handed back and the next completion is the provider's
    # verdict on them; `roundtrip_seen` says that verdict was a success. Without
    # them a target that opens with `qodec_answer` — never running an operation,
    # never being shown a `role: tool` message — would collect a PASS for the
    # one thing the forced-query arm most needs and this canary never tested.
    awaiting_roundtrip = False
    roundtrip_seen = False

    messages = opening_messages()
    for turn in range(max_turns):
        body = canonical_bytes(canonical_request(surface, target["model"], messages))
        record: dict[str, Any] = {
            "ordinal": turn,
            "request_sha256": sha256_bytes(body),
            "request_bytes": len(body),
            "carried_tool_results": awaiting_roundtrip,
        }
        sent = as_send_result(send(url, body, timeout))
        status, raw, detail = sent.status, sent.body, sent.detail
        record["response_sha256"] = sha256_bytes(raw) if raw is not None else None
        # Whatever the provider managed to say is kept, even when the exchange
        # failed. `http_status` is present here whenever headers arrived, which
        # is exactly when it exists.
        if status is not None:
            record["http_status"] = status
        if sent.request_id:
            record["request_id"] = sent.request_id
        if sent.body_bytes_observed is not None:
            record["body_bytes_observed"] = sent.body_bytes_observed
        if sent.stage != "completed":
            kind = STAGE_CAUSE.get(sent.stage, "UNAVAILABLE")
            record["outcome"] = STAGE_OUTCOME.get(sent.stage, "transport-failure")
            record["detail"] = detail
            receipt["turns"].append(record)
            if status is not None:
                # The status is the most useful thing left when the body is
                # gone; burying it in a turn record and reporting a bare cause
                # would throw away what the provider already told us.
                detail = f"HTTP {status}: {detail}"
            receipt.update(classification=kind, detail=detail, turn_count=turn + 1)
            return receipt
        if not 200 <= status < 300:
            kind, message = classify_qualify_http(status, raw or b"", awaiting_roundtrip)
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

        # A successful, readable completion in answer to a request that carried
        # `role: tool` messages is the provider accepting the result shape. That
        # — not the mere fact that we sent them — is the roundtrip.
        if awaiting_roundtrip:
            roundtrip_seen = True
            awaiting_roundtrip = False
        record["tool_result_roundtrip"] = roundtrip_seen
        receipt["tool_result_roundtrip"] = roundtrip_seen

        reported = payload.get("model")
        record["reported_model"] = reported
        record["model_status"] = model_status_of(target["model"], reported)
        # Worst turn decides, exactly as the Rust side does: a cell is only as
        # identified as its least identified turn. Folded from the per-turn
        # values at the end rather than accumulated here, so a run with no turns
        # is `missing` — unknown — instead of inheriting a seed nobody set.
        receipt["model_status"] = fold_model_status(receipt["turns"] + [record])
        # Same reason the fold exists, applied to the names themselves: keep all
        # of them, and offer a single top-level value only when there is exactly
        # one to offer. An overwritten scalar reports the last turn as if it were
        # the run.
        receipt["reported_models"] = fold_reported_models(receipt["turns"] + [record])
        receipt["reported_model"] = (
            receipt["reported_models"][0] if len(receipt["reported_models"]) == 1 else None
        )
        if isinstance(payload.get("usage"), dict):
            record["reported_usage"] = payload["usage"]

        calls, problem = parse_tool_calls(message)
        if problem:
            kind, why = problem
            record["outcome"] = "no-tool-call" if kind == "NO_TERMINAL_ANSWER" else "dialect-violation"
            record["detail"] = why
            receipt["turns"].append(record)
            receipt.update(classification=kind, detail=why, turn_count=turn + 1)
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
            errors = validate_arguments(surface, call["name"], args)
            if errors:
                why = f"{call['name']} arguments violate the declared schema: " + "; ".join(errors)
                record["outcome"] = "malformed-arguments"
                record["detail"] = why
                record["argument_errors"] = errors
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
            if not roundtrip_seen:
                # The arm's whole shape is query, read the result, then answer.
                # A target that answers immediately has demonstrated that it can
                # emit one forced tool call — which the RAW arm also does — and
                # nothing about the loop the forced-query arm is made of.
                why = "terminal answer before any operation/tool-result roundtrip"
                record["outcome"] = "protocol-violation"
                record["detail"] = why
                receipt["turns"].append(record)
                receipt.update(classification="PROTOCOL_VIOLATION", detail=why, turn_count=turn + 1)
                return receipt

            answer_args = next(a for c, a in decoded if c["name"] == ANSWER_TOOL)
            answer_errors = canary_answer_errors(answer_args)
            record["outcome"] = "terminal-answer"
            record["terminal_answer_valid"] = True
            record["canary_answer_matches"] = not answer_errors
            if answer_errors:
                record["canary_answer_errors"] = answer_errors
            receipt["turns"].append(record)
            receipt.update(classification="PASS", turn_count=turn + 1)
            if answer_errors:
                receipt["classification"] = "CANARY_ANSWER_MISMATCH"
                receipt["detail"] = "; ".join(answer_errors)
            # Identity outranks both a protocol pass and a wrong answer. A run
            # that satisfied every structural rule tells us nothing about the
            # target unless we know which model produced it — and "the provider
            # named none" is not a milder version of that than "it named another
            # one". Both fail; only `verified` may pass.
            status = receipt["model_status"]
            if status == "drifted":
                substituted = [
                    name for name in receipt["reported_models"]
                    if isinstance(name, str) and name != target["model"]
                ]
                receipt["classification"] = MODEL_STATUS_VERDICT["drifted"]
                receipt["detail"] = (
                    f"requested {target['model']}, provider reported {', '.join(substituted)}"
                )
            elif status != "verified":
                receipt["classification"] = MODEL_STATUS_VERDICT.get(status, "MODEL_IDENTITY_MISSING")
                receipt["detail"] = (
                    f"requested {target['model']}, and no successful response named a model; "
                    "the protocol held but the identity of what produced it is unestablished"
                )
            return receipt

        record["outcome"] = "operations"
        receipt["turns"].append(record)
        awaiting_roundtrip = True
        # The provider's own `tool_calls` array, echoed by reference rather than
        # rebuilt from the parsed view. Reconstructing it would drop whatever
        # fields the parser does not model and re-encode the arguments, so a
        # provider that only accepts its own emission back would fail here for a
        # reason this canary invented. Strictness above is what makes echoing
        # safe: the array reached this point only by satisfying the contract.
        messages.append({
            "role": "assistant",
            "content": message.get("content"),
            "tool_calls": message["tool_calls"],
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


def add_registry_flag(parser_: argparse.ArgumentParser) -> None:
    parser_.add_argument(
        "--registry", type=Path, default=REGISTRY_PATH,
        help="trusted provider -> origin + key_env bindings (default: the committed registry)",
    )


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import")
    imp.add_argument("--source", type=Path, required=True)
    add_registry_flag(imp)
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
    add_registry_flag(probe)
    qualify = sub.add_parser("qualify")
    qualify.add_argument("--plan", type=Path, required=True)
    qualify.add_argument("--surface", type=Path, required=True)
    qualify.add_argument("--out-dir", type=Path, required=True)
    qualify.add_argument("--timeout", type=float, default=60.0)
    qualify.add_argument("--max-turns", type=int, default=6)
    add_registry_flag(qualify)
    return p


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "import":
            write_json(args.out, import_catalog(args.source, args.observed_at, load_registry(args.registry)))
        elif args.command == "plan":
            write_json(args.out, build_plan(read_json(args.catalog), args))
        elif args.command == "probe":
            plan = read_json(args.plan)
            if plan.get("schema") != PLAN_SCHEMA:
                raise ValueError(f"expected {PLAN_SCHEMA}")
            registry = load_registry(args.registry)
            args.out_dir.mkdir(parents=True, exist_ok=True)
            for target in plan["selected"]:
                write_json(
                    args.out_dir / receipt_filename(target["target_id"]),
                    probe_target(target, args.timeout, None, registry),
                )
        else:
            plan = read_json(args.plan)
            if plan.get("schema") != PLAN_SCHEMA:
                raise ValueError(f"expected {PLAN_SCHEMA}")
            surface = load_surface(args.surface)
            registry = load_registry(args.registry)
            args.out_dir.mkdir(parents=True, exist_ok=True)
            for target in plan["selected"]:
                receipt = qualify_target(
                    target, surface, args.timeout, args.max_turns,
                    key_bound_sender(target["key_env"]), registry,
                )
                write_json(args.out_dir / receipt_filename(target["target_id"]), receipt)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"provider-matrix: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
