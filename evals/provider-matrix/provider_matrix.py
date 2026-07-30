#!/usr/bin/env python3
"""Qodec provider/model discovery and qualification primitives.

ModelHubby is an untrusted discovery source. This tool turns an exported JSON
catalog into a canonical, reviewable snapshot; plans explicit provider×model
runs with fail-closed policy filters; and probes OpenAI-compatible endpoints
without fallback or model substitution.
"""
from __future__ import annotations

import argparse
import codecs
import hashlib
import http.client
import json
import math
import os
import re
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


# ---------------------------------------------------------------------------
# The durable projection boundary
# ---------------------------------------------------------------------------
#
#   raw provider response
#           ↓
#   ephemeral protocol state    — whatever the loop needs, in memory only
#           ↓
#   typed, sanitised evidence   — this section
#           ↓
#   durable receipt             — committed, and read by more people than the
#                                 credential is
#
# Two review rounds found the same defect in two different fields: `usage`
# copied whole into a receipt, and `request_id` taken verbatim from a
# provider-controlled header. Either could have been closed with an `if`, and
# the `if` is the wrong repair — the next review finds the tool call id, then
# the substituted model name, then whatever a creative gateway decides to put in
# the next field, one per round, forever. The provider has already seen the
# bearer token; every string it sends back is a channel for returning it.
#
# So the contract is about the boundary, not the field: **nothing the provider
# chose is copied into durable evidence.** What crosses is one of four shapes:
#
#   * a value that matched a trusted local one → the local value
#   * a value from a local enum                → the enum member
#   * a bounded numeric scalar                 → after a type check
#   * an arbitrary identifier or text          → a digest, a length, and a
#                                                local classification
#
# An unrecognised object or list does not cross at all. Diagnostics lose some
# convenience to this and that is the trade being made deliberately: a raw
# request id is genuinely useful to support, and belongs in a secret-scoped
# artifact that does not exist yet, not in a file that gets committed.

# One domain per kind of value, so two fields cannot be correlated by digest.
# Without the prefix, a request id and a tool call id that happen to be the same
# string hash identically, and anyone holding the receipt learns that the
# provider reflected one into the other. A small leak, and a free one to close.
EVIDENCE_DOMAINS = {
    "request-id": b"qodec-provider-request-id-v1\0",
    "tool-call-id": b"qodec-provider-tool-call-id-v1\0",
    "tool-name": b"qodec-provider-tool-name-v1\0",
    "model-name": b"qodec-provider-model-name-v1\0",
    "handle": b"qodec-provider-handle-v1\0",
    "answer-bytes": b"qodec-provider-answer-bytes-v1\0",
    "citation": b"qodec-provider-citation-v1\0",
    "argument-errors": b"qodec-provider-argument-errors-v1\0",
    "json-value": b"qodec-provider-json-value-v1\0",
}


def evidence_bytes(value: Any) -> bytes:
    """The bytes a provider-chosen value is hashed as, canonically.

    `default=repr` rather than letting `json.dumps` raise: this runs on values
    the provider chose, and a projection that can fail on one of them is a
    projection that stops projecting exactly when it matters.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8", "surrogatepass")
    return json.dumps(value, sort_keys=True, default=repr).encode("utf-8", "surrogatepass")


def evidence_digest(domain: str, value: Any) -> str:
    """`sha256(domain-prefix || value)`."""
    return hashlib.sha256(EVIDENCE_DOMAINS[domain] + evidence_bytes(value)).hexdigest()


def opaque(prefix: str, domain: str, value: Any) -> dict[str, Any]:
    """Evidence *about* a provider-chosen value. Never the value.

    Three fields, because all three are things support actually needs and none
    of them is the string itself: whether there was one at all, which one it was
    (comparably, across turns and across runs), and how long it was.
    """
    if value is None:
        return {f"{prefix}_present": False}
    return {
        f"{prefix}_present": True,
        f"{prefix}_sha256": evidence_digest(domain, value),
        f"{prefix}_bytes": len(evidence_bytes(value)),
    }


def opaque_ref(domain: str, value: Any) -> str:
    """Name a provider-chosen value inside a local message without repeating it.

    Messages end up in `detail`, and `detail` ends up on disk. A message that
    interpolates what the provider sent is the same leak as a field that copies
    it, with better camouflage.
    """
    return f"<{domain} sha256:{evidence_digest(domain, value)[:16]} {len(evidence_bytes(value))}B>"


# The counters, and nothing else. Anything outside this tuple is discarded
# rather than recorded, however plausible it looks.
USAGE_COUNTERS = ("prompt_tokens", "completion_tokens", "total_tokens")


def normalize_provider_usage(value: Any) -> dict[str, int]:
    """The provider's token counters, and nothing else it decided to send.

    An allowlist, not a filter. `usage` is a JSON object the provider fills in,
    so `{"prompt_tokens": 12, "echo": "Bearer …"}` is a shape it can choose, and
    copying the object whole put that second field into a committed receipt — on
    a PASS, where nobody would think to look.

    `type(n) is int` rather than `isinstance`, because `True` is an `int` in
    Python and would otherwise be recorded as a token count of 1. A negative
    count is refused for the same reason a status of 700 is: it is not a
    measurement, and keeping it would be recording a claim.

    Usage is descriptive telemetry. It never reaches a verdict, in either path.
    """
    if not isinstance(value, dict):
        return {}
    counts: dict[str, int] = {}
    for name in USAGE_COUNTERS:
        count = value.get(name)
        if type(count) is int and count >= 0:
            counts[name] = count
    return counts


def model_evidence(requested: str, reported: Any) -> dict[str, Any]:
    """The reported model, kept as text only when it is the one we asked for.

    `verified` means the string equalled a value we already had, so recording it
    records nothing new about the provider. Any other string is the provider's
    choice — including, if it likes, the bearer token — and crosses as evidence.
    `model_status` beside it says which case this is.
    """
    if isinstance(reported, str) and reported == requested:
        return {"reported_model": requested, "reported_model_present": True}
    return {"reported_model": None, **opaque("reported_model", "model-name", reported)}


# The vocabulary `jsonschema_mini` and the envelope oracle emit. Matching on it
# is matching on *our* words, not the provider's: the messages interpolate the
# instance (`{instance!r}`, `additional property '{key}'`), so the text cannot
# be kept, but which rule fired is a local fact and is worth keeping.
ARGUMENT_ERROR_KINDS = (
    ("expected type", "type"),
    ("not in enum", "enum"),
    ("fails pattern", "pattern"),
    ("shorter than minLength", "min-length"),
    ("below minimum", "minimum"),
    ("missing required field", "required"),
    ("additional property", "additional-property"),
    ("fewer than minItems", "min-items"),
    ("items not unique", "unique-items"),
    ("unsupported $ref", "ref"),
    ("is not a declared tool", "undeclared-tool"),
    ("envelope", "envelope"),
    ("canonical spelling", "envelope-canonicality"),
    ("display_utf8", "envelope-display"),
    ("encoding must be", "envelope-encoding"),
)


def argument_error_kind(message: str) -> str:
    for marker, kind in ARGUMENT_ERROR_KINDS:
        if marker in message:
            return kind
    return "other"


def error_evidence(prefix: str, errors: list[str]) -> dict[str, Any]:
    """Validation failures as counts, kinds and a digest — never as their text.

    `jsonschema_mini` is not this module's to rewrite and its messages carry the
    offending instance, so the free text cannot cross. What crosses is what a
    reader actually acts on: how many rules failed, which rules, and a digest
    that makes two runs comparable without either of them being readable.
    """
    kinds: list[str] = []
    for message in errors:
        kind = argument_error_kind(message)
        if kind not in kinds:
            kinds.append(kind)
    return {
        f"{prefix}_count": len(errors),
        f"{prefix}_kinds": sorted(kinds),
        f"{prefix}_sha256": evidence_digest("argument-errors", "\n".join(errors)),
    }


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """`json.loads` keeps the last of two identical keys, silently.

    That silence is a tamper channel, not a curiosity. A catalog row spelled

        {"api_base": "https://steal.example/v1",
         "api_base": "https://api.groq.com/openai/v1"}

    reaches `bind_to_registry` as a single agreeing value, and the hostile claim
    is gone before anything can refuse it — so "any authority value that is
    present is checked" is satisfied only because the check never sees it. The
    same trick hides a duplicate field in a hand-edited plan.

    Duplicate detection is only possible while parsing text. Once JSON has
    become a dict the evidence has already been destroyed, which is why this is
    a parser hook and not a validation step.
    """
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise DuplicateJsonKey(f"duplicate key {key!r}")
        seen.add(key)
    return dict(pairs)


class StrictJsonError(ValueError):
    """A document that decides something did not arrive in an acceptable form."""


class DuplicateJsonKey(StrictJsonError):
    """One JSON object named the same field twice."""


class InvalidJsonEncoding(StrictJsonError):
    """Bytes that are not the encoding the consumer of this JSON accepts."""


class UnadmittedJsonValue(StrictJsonError):
    """Valid Python JSON that `serde_json` refuses to parse at all."""


# `json.loads` speaks a dialect, not JSON. It admits `NaN`, `Infinity` and
# `-Infinity` as bare constants, turns an overflowing literal like `1e400` into
# `inf`, and accepts an unpaired `\ud800` escape as a lone surrogate in a `str`.
# `serde_json::from_slice::<Value>` — which the adapter runs over the whole body
# before it reads a single field — refuses all of them. Measured, not recalled;
# see `json-admission-corpus.json` and the oracle that regenerates its verdicts.
#
# The gap is a false PASS waiting to happen: a completion carrying `"unused":
# NaN` in a field the canary never reads still parses here, still yields a model
# and tool calls, and is rejected outright by the consumer.
#
# Being *stricter* than the consumer is safe and deliberate — duplicate keys are
# admitted by `serde_json` and refused here. Being more liberal is the defect,
# so the parity check is one-directional: everything this gate admits, the
# consumer must admit too.
SURROGATE_RANGE = ("\ud800", "\udfff")

# Measured against the pinned `serde_json`, whose deserializer starts with a
# remaining depth of 128 and returns `RecursionLimitExceeded` when it runs out:
# 127 levels of array or object are admitted, 128 are refused. Python's decoder
# admits far more and then dies of `RecursionError` — which is not a
# `ValueError`, so it would escape every except tuple here and be filed as
# `INTERNAL_ERROR`, blaming the matrix for a body the provider sent.
#
# So the depth is measured *before* parsing, by scanning the text. That refuses
# the case the consumer refuses, and it means the decoder is never handed
# anything deep enough to overflow its own stack.
MAX_JSON_DEPTH = 127


def json_nesting_depth(text: str) -> int:
    """Deepest nesting in a JSON text, counted without parsing it.

    Iterative on purpose: a recursive measurement of a deeply nested document
    is the very failure it exists to prevent. Bracket characters inside strings
    do not nest, so the scan tracks string state and escapes.
    """
    depth = deepest = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest


def _refuse_non_finite(constant: str) -> Any:
    raise UnadmittedJsonValue(f"{constant} is not a JSON value")


def _admissible_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise UnadmittedJsonValue(f"{text} is out of range for a JSON number")
    return value


def _admissible_int(text: str) -> int:
    """An integer literal the consumer's number type can hold.

    `serde_json` keeps an integer while it fits `u64`/`i64` and falls back to
    `f64` past that, refusing only when the fallback overflows to infinity. So
    `u64::MAX + 1` is admitted — measured, and a rule banning "anything past
    u64" would have been a tidy invention the consumer does not have — while a
    309-digit literal is not.

    The rule is the fallback's finiteness, not a digit count: 308 nines are
    admitted and `1` followed by 308 zeros is too, though the latter is longer.

    `float` runs first on purpose. Python refuses `int()` on a literal past
    `sys.get_int_max_str_digits()` with a bare `ValueError`, which is not a
    `JSONDecodeError` and would escape every except tuple to be filed as
    `INTERNAL_ERROR`. Anything that long overflows `f64` anyway, so it is
    refused here — as the provider's fault, which it is — before `int` is asked.
    """
    if not math.isfinite(float(text)):
        raise UnadmittedJsonValue(
            f"{text[:32]}… has {len(text.lstrip('-'))} digits; the consumer's f64 "
            "fallback overflows and it refuses the number"
        )
    return int(text)


def _refuse_lone_surrogates(value: Any) -> None:
    """A `str` holding U+D800..U+DFFF came from an unpaired escape.

    Python's decoder combines a valid pair into one non-surrogate character, so
    a surviving surrogate is exactly the case `serde_json` rejects — and the one
    that cannot be represented in a Rust `String` at all.

    Walked with an explicit stack rather than by recursion: a check that itself
    overflows on a deep document has swapped one uncaught failure for another.
    """
    stack: list[tuple[Any, str]] = [(value, "<root>")]
    while stack:
        node, where = stack.pop()
        if isinstance(node, str):
            if any(SURROGATE_RANGE[0] <= ch <= SURROGATE_RANGE[1] for ch in node):
                raise UnadmittedJsonValue(f"lone surrogate in {where}")
        elif isinstance(node, dict):
            for key, sub in node.items():
                stack.append((key, "an object key"))
                stack.append((sub, f"{where}.{key}" if where != "<root>" else key))
        elif isinstance(node, list):
            for index, sub in enumerate(node):
                stack.append((sub, f"{where}[{index}]"))


def strict_json_loads(raw: str | bytes, what: str) -> Any:
    """Parse anything that decides something, refusing duplicate object keys.

    The line is not "ours versus theirs" — it is *decides* versus *describes*.
    On that test a successful provider completion is firmly on the deciding
    side: its `model` settles identity and therefore whether a target may PASS,
    and its `function.arguments` are the tool call being qualified. A body
    spelled

        {"model": "wrong-model", "model": "openai/gpt-oss-120b", ...}

    resolves to the second value, and the run reports `verified` about a
    generation whose origin the response stated twice and differently.

    So this covers the source export, the catalog, the plan, the surface, the
    trusted registry, every successful 2xx completion, and the JSON string
    inside `function.arguments`.

    What stays lenient is the **HTTP error body**, and only that. It is read to
    pick a local reason code, it never becomes a tool call, and it cannot earn
    a PASS — refusing to read a sloppy error would turn the provider's
    untidiness into our transport failure.

    Encoding is decided here too, and decided by the consumer rather than by
    taste. `json.loads` accepts *bytes* and sniffs UTF-8, UTF-16 and UTF-32, and
    tolerates a UTF-8 BOM. The adapter that will consume a PASS reads bodies
    with `serde_json::from_slice`, which was measured against all four:

        utf-8         Ok
        utf-8 + BOM   Err(expected value at line 1 column 1)
        utf-16le      Err(expected value at line 1 column 1)
        broken utf-8  Err(invalid unicode code point)

    So the rule is UTF-8 with no BOM, and nothing else — RFC 8259 requires UTF-8
    for JSON exchanged between systems, and a receiver *may* ignore a BOM but is
    not obliged to. Sniffing here would qualify a body the mapper refuses, which
    is the same liberality as before, moved from structure to encoding.
    """
    if isinstance(raw, (bytes, bytearray, memoryview)):
        raw = bytes(raw)
        # Checked before decoding: a BOM is valid UTF-8 (`﻿`), so decoding
        # first would hide it and `json.loads` would then skip it silently.
        if raw.startswith(codecs.BOM_UTF8):
            raise InvalidJsonEncoding(f"{what}: a UTF-8 BOM is not accepted")
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidJsonEncoding(f"{what}: not valid UTF-8 ({exc.reason})") from None
    # Before parsing, not after: Python's decoder recurses, and a body deep
    # enough would raise `RecursionError` — not a `ValueError` — straight past
    # every except tuple below.
    depth = json_nesting_depth(raw)
    if depth > MAX_JSON_DEPTH:
        raise UnadmittedJsonValue(
            f"{what}: nested {depth} deep; the consumer refuses more than {MAX_JSON_DEPTH}"
        )
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=_refuse_non_finite,
            parse_float=_admissible_float,
            parse_int=_admissible_int,
        )
    except DuplicateJsonKey as exc:
        raise DuplicateJsonKey(f"{what}: {exc}") from None
    except UnadmittedJsonValue as exc:
        raise UnadmittedJsonValue(f"{what}: {exc}") from None
    try:
        _refuse_lone_surrogates(parsed)
    except UnadmittedJsonValue as exc:
        raise UnadmittedJsonValue(f"{what}: {exc}") from None
    return parsed


def read_json(path: Path) -> Any:
    return strict_json_loads(path.read_text(encoding="utf-8"), path.name)


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
AUTHORITY_FIELDS = ("api_base", "key_env", "api_style")
KEY_ENV_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*\Z")

# Headers providers use to name the generation. Kept because it is the only
# handle support has when a body is lost after the headers arrived.
REQUEST_ID_HEADERS = ("x-request-id", "x-groq-request-id", "openai-request-id", "request-id")


class EndpointRejected(ValueError):
    """The catalog named an endpoint this transport will not send a key to."""


# ---------------------------------------------------------------------------
# The byte envelope, decoded exactly as the crate decodes it
# ---------------------------------------------------------------------------
#
# `base64.urlsafe_b64decode` is not the rule this project uses. It accepts
# padding, and it does not care about non-zero trailing bits — so `YWxwaGE=`
# and a nonsense-tailed spelling both decode to `alpha`, and a value with two
# spellings has no business in a content address. `canon.rs` refuses both, and
# `KeyBytes::from_envelope` additionally refuses unknown fields and a
# `display_utf8` that disagrees with the decoded bytes.
#
# A canary that accepts what the mapper refuses qualifies a response the mapper
# will reject. That is the same defect as paraphrasing the schemas, so the rule
# is ported rather than approximated, and the negative corpus below is the
# evidence that the two agree.

B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
B64URL_VALUE = {ch: index for index, ch in enumerate(B64URL_ALPHABET)}
ENVELOPE_FIELDS = ("encoding", "data", "display_utf8")
ENVELOPE_ENCODING = "base64url-nopad"


class NoncanonicalEncoding(ValueError):
    """`data` is not the one canonical spelling of the bytes it denotes."""


def b64url_nopad_decode(text: str) -> bytes:
    """Decode strictly: no padding, no `+/`, no whitespace, no trailing bits.

    A transcription of `canon.rs::base64url_nopad_decode`. Kept as a bit
    accumulator rather than delegated to `base64` precisely because the standard
    decoder is lenient about the two things that matter here.
    """
    acc = 0
    bits = 0
    out = bytearray()
    for ch in text:
        value = B64URL_VALUE.get(ch)
        if value is None:
            raise NoncanonicalEncoding(
                f"base64url-nopad rejects {ch!r}; padding and '+/' are not accepted"
            )
        acc = (acc << 6) | value
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 6:
        raise NoncanonicalEncoding("base64url-nopad input has a dangling character")
    if bits > 0 and (acc & ((1 << bits) - 1)) != 0:
        raise NoncanonicalEncoding(
            "base64url-nopad input has non-zero trailing bits; encoding is not canonical"
        )
    return bytes(out)


def b64url_nopad_encode(raw: bytes) -> str:
    out = []
    acc = 0
    bits = 0
    for byte in raw:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 6:
            bits -= 6
            out.append(B64URL_ALPHABET[(acc >> bits) & 0x3F])
    if bits:
        out.append(B64URL_ALPHABET[(acc << (6 - bits)) & 0x3F])
    return "".join(out)


def envelope_errors(value: Any, label: str) -> tuple[list[str], bytes | None]:
    """Validate one byte envelope with the strictness the crate applies.

    Schema keywords can reject an obviously wrong shape, but they cannot express
    trailing-bit canonicality or agreement between `data` and `display_utf8`.
    Those need a procedure, so this is one — and it returns the decoded bytes so
    the caller does not decode a second time with a different rule.
    """
    if not isinstance(value, dict):
        return [f"{label}: byte value envelope must be an object"], None

    errors = [
        f"{label}: unknown field {key!r} in byte value envelope"
        for key in value
        if key not in ENVELOPE_FIELDS
    ]
    if value.get("encoding") != ENVELOPE_ENCODING:
        errors.append(f"{label}: encoding must be {ENVELOPE_ENCODING!r}, got {value.get('encoding')!r}")

    data = value.get("data")
    if not isinstance(data, str):
        errors.append(f"{label}: envelope needs a string `data`")
        return errors, None

    try:
        decoded = b64url_nopad_decode(data)
    except NoncanonicalEncoding as exc:
        errors.append(f"{label}: {exc}")
        return errors, None

    # Belt and braces over the bit checks above: if any spelling other than the
    # canonical one survived, the round trip is where it shows.
    if b64url_nopad_encode(decoded) != data:
        errors.append(f"{label}: {data!r} is not the canonical spelling of the bytes it decodes to")

    if "display_utf8" in value:
        shown = value["display_utf8"]
        if not isinstance(shown, str):
            errors.append(f"{label}: `display_utf8` must be a string")
        else:
            try:
                if decoded.decode("utf-8") != shown:
                    errors.append(f"{label}: `display_utf8` disagrees with the decoded bytes")
            except UnicodeDecodeError:
                errors.append(f"{label}: `display_utf8` present but the bytes are not UTF-8")
    return errors, decoded


def walk_envelopes(value: Any, path: str = "") -> list[tuple[str, Any]]:
    """Every byte envelope inside a decoded argument object.

    Found structurally — any object carrying an `encoding` key — rather than by
    a list of field names, so an envelope added to the surface later is checked
    the day it appears instead of the day somebody remembers to add it here.
    """
    found: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        if "encoding" in value:
            found.append((path or "<envelope>", value))
            return found
        for key, sub in value.items():
            found.extend(walk_envelopes(sub, f"{path}.{key}" if path else key))
    elif isinstance(value, list):
        for index, sub in enumerate(value):
            found.extend(walk_envelopes(sub, f"{path}[{index}]"))
    return found


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
    path = path or REGISTRY_PATH
    return normalize_registry(strict_json_loads(path.read_text(encoding="utf-8"), path.name))


def normalize_registry(raw: Any) -> dict[str, Any]:
    """Validate a registry and return a fresh normalized object.

    Applied to a caller-supplied dict exactly as to the committed file — a
    registry that skipped validation because it arrived as an object rather than
    a path would be a trust boundary with a side door. The result is newly
    built, so nothing downstream holds a reference to a mutable object somebody
    else can still change.

    One check cannot be repeated here: duplicate JSON keys. By the time a
    registry is a dict, Python has already discarded the losing value, so that
    refusal belongs to `strict_json_loads` and applies to text only.
    """
    if not isinstance(raw, dict):
        raise ValueError("a trusted registry must be an object")
    if raw.get("schema") != REGISTRY_SCHEMA:
        raise ValueError(f"expected {REGISTRY_SCHEMA}, got {raw.get('schema')!r}")
    unknown = sorted(set(raw) - {"schema", "providers"})
    if unknown:
        raise ValueError(f"unknown registry fields {unknown}")
    providers = raw.get("providers")
    if not isinstance(providers, dict) or not providers:
        raise ValueError("the trusted registry declares no providers")

    normalized: dict[str, Any] = {}
    for name, entry in providers.items():
        if not isinstance(name, str) or name != name.strip().lower() or not name:
            raise ValueError(f"provider name {name!r} must be a non-empty lowercase string")
        if not isinstance(entry, dict):
            raise ValueError(f"trusted provider {name!r} must be an object")
        extra = sorted(set(entry) - set(AUTHORITY_FIELDS))
        if extra:
            raise ValueError(f"trusted provider {name!r} has unknown fields {extra}")
        for field in AUTHORITY_FIELDS:
            if not isinstance(entry.get(field), str) or not entry[field].strip():
                raise ValueError(f"trusted provider {name!r} is missing {field}")
        if entry["api_style"] != "openai-chat":
            raise ValueError(f"trusted provider {name!r} has unsupported api_style {entry['api_style']!r}")
        if not KEY_ENV_PATTERN.match(entry["key_env"]):
            raise ValueError(f"trusted provider {name!r} has an implausible key_env {entry['key_env']!r}")
        completions_url(entry["api_base"])
        normalized[name] = {
            "api_base": entry["api_base"].rstrip("/"),
            "api_style": entry["api_style"],
            "key_env": entry["key_env"],
        }
    return {"schema": REGISTRY_SCHEMA, "providers": normalized}


def registry_digest(registry: dict[str, Any]) -> str:
    return sha256_bytes(canonical_bytes(registry))


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

    Absence is allowed; *presence* is always validated. An earlier version
    checked only `isinstance(claimed, str)`, so `"api_base": {"host":
    "steal.example"}` slipped past as "not a string, therefore no
    disagreement" — which is precisely the quiet overrule the rule exists to
    prevent.
    """
    entry = trusted_entry(registry, provider)
    for field in AUTHORITY_FIELDS:
        if field not in row:
            continue
        claimed = row[field]
        if not isinstance(claimed, str):
            raise EndpointRejected(
                f"{provider}/{model}: catalog {field} is a {type(claimed).__name__}, not a string; "
                "a value that cannot be compared to the registry cannot be accepted"
            )
        if claimed.strip().rstrip("/") != entry[field].rstrip("/"):
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
    # `detail` is free text and stays in memory. These two are what may
    # cross into a receipt, and both are local *by construction* rather
    # than by inspection: `reason` comes from a fixed vocabulary, and
    # `failure_type` is a Python class name, which no peer can choose.
    # An `SSLCertVerificationError` message carries fields the peer
    # picked; its class name does not.
    reason: str | None = None
    failure_type: str | None = None


# Why an exchange did not complete, in this module's own words. A reason is
# only ever assigned where the failure happens, so nothing downstream has to
# decide whether a string is safe to keep.
TRANSPORT_REASONS = (
    "timeout",
    "connection-failed",
    "http-framing-failure",
    "body-capture-failure",
    "credential-missing",
    "credential-not-header-safe",
    "request-not-constructed",
)


class BodyTooLarge(ValueError):
    """Carries how much was seen, so the receipt is not left saying only "lost"."""

    def __init__(self, observed: int, limit: int) -> None:
        super().__init__(f"response body exceeded {limit} bytes (stopped after {observed})")
        self.observed = observed


# Every stage, and the exact (status, body) shape it asserts. A stage is a claim
# about what happened, so a result whose fields contradict its own stage is not a
# fact about an exchange — it is two facts, and no rule can say which one to
# believe. Inferring the stage only for legacy tuples left the explicit form
# unchecked, so `(503, None, "lost", "completed")` promoted a billed
# after-headers loss to a success through the front door instead of the back.
# Every stage against **every** field, not just status and body. Checking two
# fields and merely type-checking the other two let this through:
#
#     SendResult(None, None, "…", "before-response", 123, "req-1")
#
# which asserts that no headers ever arrived *and* that 123 response bytes and a
# provider request id were observed. Both impossibilities then went into a
# receipt. `response_derived` marks the fields that cannot exist until the
# provider has answered.
#
# `response-framing` is a fourth answer to "how far did this get", and it exists
# because the other three cannot express it. `BadStatusLine` and `LineTooLong`
# out of `_OPENER.open` mean the request was sent and *something* came back that
# was not a parseable HTTP response. There are no valid headers, so it is not
# `after-headers`; but the request was served, so calling it `before-response`
# would claim that nothing was generated and nothing will be billed — a claim
# this transport cannot support, and one that invites a retry that pays twice.
SEND_STAGE_SHAPES = {
    "before-response": {"status": False, "body": False, "response_derived": False},
    "no-credential": {"status": False, "body": False, "response_derived": False},
    "response-framing": {"status": False, "body": False, "response_derived": False},
    "after-headers": {"status": True, "body": False, "response_derived": True},
    "completed": {"status": True, "body": True, "response_derived": True},
}


def is_http_status(value: Any) -> bool:
    """A real status code. `type(...) is int` because `True` is not a status.

    Python's `bool` subclasses `int`, so `isinstance(True, int)` is true and
    `True == 1`. A `SendResult(True, ...)` would then compare, hash and format
    like an HTTP status all the way into a receipt.
    """
    return type(value) is int and 100 <= value <= 599


def validate_send_result(result: SendResult) -> SendResult:
    """Refuse a `SendResult` that disagrees with itself, however it was built.

    The shape table says `status=int, body=bytes`, so that is what is checked —
    not merely whether the fields are present. Presence alone let `("503", None,
    "lost", "after-headers")` through to fail later on a status comparison, and
    `(200, "not bytes", ...)` through to fail on hashing. A value that is going
    to be rejected is better rejected where the contract is written down than
    three frames away in whatever happens to touch it first.
    """
    shape = SEND_STAGE_SHAPES.get(result.stage)
    if shape is None:
        raise ValueError(f"unknown send stage {result.stage!r}")
    if (result.status is not None) != shape["status"]:
        raise ValueError(
            f"send stage {result.stage!r} requires status="
            f"{'an int' if shape['status'] else 'None'}; got {result.status!r}"
        )
    if (result.body is not None) != shape["body"]:
        raise ValueError(
            f"send stage {result.stage!r} requires body="
            f"{'bytes' if shape['body'] else 'None'}; got {type(result.body).__name__}"
        )
    if result.status is not None and not is_http_status(result.status):
        raise ValueError(f"status must be an int in 100..599, got {result.status!r}")
    # `bytearray` and `memoryview` are refused too: the body is hashed and its
    # length recorded, and a mutable view of it is not the thing that arrived.
    if result.body is not None and type(result.body) is not bytes:
        raise ValueError(f"body must be bytes, got {type(result.body).__name__}")

    observed = result.body_bytes_observed
    if observed is not None:
        if not shape["response_derived"]:
            raise ValueError(
                f"send stage {result.stage!r} means nothing was received, so it cannot "
                f"also report {observed!r} observed body bytes"
            )
        if type(observed) is not int or observed < 0:
            raise ValueError(f"body_bytes_observed must be a non-negative int, got {observed!r}")
        # On a completed exchange the body is right there, so a count that
        # disagrees with it is a number nobody checks and everybody believes.
        if result.body is not None and observed != len(result.body):
            raise ValueError(
                f"body_bytes_observed {observed} disagrees with the {len(result.body)} bytes present"
            )

    if result.reason is not None and result.reason not in TRANSPORT_REASONS:
        raise ValueError(f"unknown transport reason {result.reason!r}")
    # A Python identifier, because that is all a class name can be. Cheap to
    # check and it makes "this field is local" an assertion rather than a
    # convention somebody has to keep.
    if result.failure_type is not None and not (
        isinstance(result.failure_type, str) and result.failure_type.isidentifier()
    ):
        raise ValueError(f"failure_type must be a class name, got {result.failure_type!r}")
    if result.request_id is not None:
        if not shape["response_derived"]:
            raise ValueError(
                f"send stage {result.stage!r} means no headers arrived, so it cannot "
                f"also carry the request id {opaque_ref('request-id', result.request_id)}"
            )
        if not isinstance(result.request_id, str):
            raise ValueError(f"request_id must be a string, got {type(result.request_id).__name__}")
    return result


def infer_stage(status: int | None, body: bytes | None) -> str:
    """The stage a legacy tuple implies — a table, not a guess.

    | status | body  | stage                                    |
    | ------ | ----- | ---------------------------------------- |
    | None   | None  | before-response: nothing ever arrived     |
    | int    | None  | after-headers: the body was lost          |
    | int    | bytes | completed                                 |
    | None   | bytes | impossible; a body without a status       |

    `b""` is a **complete empty body**, not a lost one — a provider that returns
    200 with nothing in it has been fully received and simply fails to parse,
    which is a different fact from a read that died halfway. Inferring purely
    from "is there a status" promoted `(503, None)` to `completed`, so a billed
    after-headers loss was reported as retryable `UNAVAILABLE`.
    """
    if status is None:
        if body is not None:
            raise ValueError("invalid send result: a response body without a status")
        return "before-response"
    return "completed" if body is not None else "after-headers"


def as_send_result(value: Any) -> SendResult:
    """Accept a `SendResult`, or a positional tuple from an injected `send`.

    Deliberately narrow: this is the test-injection boundary, not a general
    coercion. Everything inside this module builds a `SendResult` directly.
    """
    if isinstance(value, SendResult):
        return validate_send_result(value)
    fields = tuple(value)
    result = SendResult(*fields)
    if len(fields) < 4:
        result = result._replace(stage=infer_stage(result.status, result.body))
    # Validated on every path, including the explicit one. A stage supplied by
    # hand is a claim like any other and gets no more credit for being written
    # down than for being deduced.
    return validate_send_result(result)


def bytes_seen(exc: BaseException) -> int | None:
    """How much of the body arrived, from whichever exception knows.

    `BodyTooLarge` carries its own count; `IncompleteRead` carries the bytes it
    managed to read. Neither partial body is kept — a truncated response is not
    a response — but its length is evidence about a generation that was billed.
    """
    if isinstance(exc, http.client.IncompleteRead):
        return len(exc.partial)
    observed = getattr(exc, "observed", None)
    return observed if isinstance(observed, int) else None


def capture_detail(prefix: str, exc: BaseException) -> str:
    """A local, bounded description of a read that failed.

    Never `str(exc)` for an `http.client.HTTPException`: `BadStatusLine`'s
    message *is* the bytes the peer chose to send, and this string goes into a
    turn record and then into a receipt on disk. The exception's **type** is a
    fact about our own stack and says everything the reader needs; the malformed
    wire is the provider's choice and has no business being kept.
    """
    if isinstance(exc, http.client.HTTPException):
        return f"{prefix}: {type(exc).__name__}"
    return str(exc)


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


def credential_is_header_safe(key: str) -> bool:
    """Printable ASCII, no spaces, no control bytes — a bearer token's shape."""
    return bool(key) and all("\x21" <= ch <= "\x7e" for ch in key)


def send_json(url: str, body: bytes, key: str, timeout: float, limit: int = MAX_RESPONSE_BYTES) -> SendResult:
    """POST `body` to `url` with the credential attached. The only network call."""
    # Validated *before* the header exists. `http.client` raises
    # `ValueError: Invalid header value b'Bearer sk-...'` for a key carrying a
    # stray newline — an exception whose message is the secret, which `main`
    # would then print to stderr and CI would keep forever. The check is on the
    # value; the error never repeats it.
    if not credential_is_header_safe(key):
        return SendResult(None, None, "credential is not a valid header value",
                          "no-credential", reason="credential-not-header-safe")
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
        except (OSError, ValueError, http.client.HTTPException) as read_exc:
            return SendResult(
                exc.code, None, capture_detail("HTTP body capture failure", read_exc),
                "after-headers", bytes_seen(read_exc), request_id,
                "body-capture-failure", type(read_exc).__name__,
            )
        return SendResult(exc.code, raw, "", "completed", len(raw), request_id)
    except TimeoutError as exc:
        return SendResult(None, None, "timeout", "before-response",
                          reason="timeout", failure_type=type(exc).__name__)
    except urllib.error.URLError as exc:
        reason = exc.reason
        detail = "timeout" if isinstance(reason, TimeoutError) else str(reason)
        return SendResult(
            None, None, detail, "before-response",
            reason="timeout" if isinstance(reason, TimeoutError) else "connection-failed",
            failure_type=type(reason).__name__ if isinstance(reason, BaseException) else None,
        )
    except http.client.HTTPException as exc:
        # `BadStatusLine`, `LineTooLong` and the rest of the framing family
        # derive from `HTTPException`, not from `OSError`, and urllib re-raises
        # them rather than wrapping them in `URLError` — so they escaped every
        # handler here and `guarded_receipt` filed provider-controlled wire
        # corruption as `INTERNAL_ERROR`, a defect in this tool.
        return SendResult(
            None, None, capture_detail("HTTP framing failure", exc), "response-framing",
            reason="http-framing-failure", failure_type=type(exc).__name__,
        )

    # Read outside the try: these are attribute accesses on an object we already
    # hold, and they must not be inside the block whose failure means "the body
    # was lost". An `after-headers` result without a status would contradict its
    # own stage, and `validate_send_result` would refuse it.
    status = response.status
    request_id = request_id_of(getattr(response, "headers", None))
    try:
        with response:
            raw = read_bounded(response, limit)
    except (OSError, ValueError, http.client.HTTPException) as exc:
        # `IncompleteRead` — the provider closed before `Content-Length` was
        # satisfied — derives from `HTTPException`, so it is neither an
        # `OSError` nor a `ValueError` and escaped both handlers into
        # `INTERNAL_ERROR`, discarding a status and request id we already had.
        # Catching only `IncompleteRead` fixed one member of that family and
        # left `LineTooLong` and the others exactly where they were; the base
        # class is the contract, because the class is what "the provider broke
        # the framing" means.
        return SendResult(
            status, None, capture_detail("HTTP body capture failure", exc),
            "after-headers", bytes_seen(exc), request_id,
            "body-capture-failure", type(exc).__name__,
        )
    return SendResult(status, raw, "", "completed", len(raw), request_id)


def key_bound_sender(key_env: str):
    """A `send` closed over the env var that holds the key — never over the key.

    The credential is read at call time and stays inside `send_json`. Nothing
    that gets recorded, hashed, or written to a receipt has ever seen it.
    """

    def send(url: str, body: bytes, timeout: float) -> SendResult:
        key = os.environ.get(key_env)
        if not key:
            return SendResult(None, None, f"missing env {key_env}", "no-credential",
                              reason="credential-missing")
        try:
            return send_json(url, body, key, timeout)
        except ValueError as exc:
            # Last resort. `send_json` validates the key first, so this should be
            # unreachable — but an exception carrying a header value must never
            # escape toward `main`, which prints `ValueError` to stderr.
            del exc
            return SendResult(None, None, "the request could not be constructed",
                              "before-response", reason="request-not-constructed")

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
    registry = normalize_registry(registry) if registry is not None else load_registry()
    raw_bytes = source.read_bytes()
    rows = source_rows(strict_json_loads(raw_bytes, source.name))
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
        "registry_sha256": registry_digest(registry),
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
    registry = normalize_registry(registry) if registry is not None else load_registry()
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
    # The header is provider-controlled and the provider has seen the bearer
    # token, so `x-request-id` is a channel for handing it back. The raw value
    # stays in `sent`, in memory; the artifact gets evidence about it.
    result.update(opaque("request_id", "request-id", sent.request_id))
    if sent.stage != "completed":
        # A body-read failure is not unavailability: the provider answered, the
        # generation exists, and it will appear on the bill. Retrying it is a
        # decision, not a formality, so it gets its own name — and keeps the
        # status the provider already sent.
        if sent.stage == "no-credential":
            kind = "AUTH_FAILURE"
        elif sent.stage in ("after-headers", "response-framing"):
            # `response-framing` joins it rather than falling through to
            # `TRANSPORT_FAILURE`: the request was served and the reply was
            # unreadable, which is a capture failure without a status, not an
            # endpoint that was never reached.
            kind = "RESPONSE_CAPTURE_FAILED"
        else:
            kind = "TIMEOUT" if sent.detail == "timeout" else "TRANSPORT_FAILURE"
        reason = transport_reason(sent)
        if sent.failure_type is not None:
            result["transport_failure_type"] = sent.failure_type
            reason = f"{reason} ({sent.failure_type})"
        if sent.reason == "credential-missing":
            reason = f"{reason}: {target['key_env']}"
        result.update(classification=kind, detail=reason, latency_ms=latency)
        if sent.status is not None:
            result["http_status"] = sent.status
            result["detail"] = f"HTTP {sent.status}: {reason}"
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
        # Strict: this body decides the reported model, and therefore whether
        # the target may pass. `[]`, `null` and `5` are valid JSON too, and
        # `payload.get` on any of them raises `AttributeError`, which nothing
        # caught — so one provider returning a bare array ended the whole matrix
        # run and every later target lost its receipt.
        payload = strict_json_loads(raw, "completion")
        if not isinstance(payload, dict):
            raise TypeError(f"completion was a {type(payload).__name__}, not an object")
        reported_model = payload.get("model")
        choices = payload.get("choices", [])
        content = choices[0]["message"]["content"] if choices else None
    except (StrictJsonError, json.JSONDecodeError, KeyError, TypeError, IndexError, AttributeError):
        result["classification"] = "INVALID_OUTPUT"
        return result
    result.update(model_evidence(target["model"], reported_model))
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
        result["provider_usage"] = normalize_provider_usage(payload["usage"])
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
    # A 2xx the canary cannot map is not a refusal: the provider accepted the
    # request, generated, and will bill for it. Filing that under
    # `PROVIDER_REJECTED` would lose the difference between "it said no" and
    # "it said something we cannot read".
    "INVALID_OUTPUT",
    "NO_TERMINAL_ANSWER",
    "CANARY_ANSWER_MISMATCH",
    # Reserved for a defect in this tool, so one target's crash cannot deprive
    # every later target of a receipt.
    "INTERNAL_ERROR",
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
    # No headers ever parsed, and yet not retryable: the request went out and
    # the reply was unreadable, so nothing here can say the provider did not
    # generate and will not charge. `UNAVAILABLE` would say exactly that.
    "response-framing": "RESPONSE_CAPTURE_FAILED",
    "after-headers": "RESPONSE_CAPTURE_FAILED",
}
STAGE_OUTCOME = {
    "no-credential": "no-credential",
    "before-response": "transport-failure",
    "response-framing": "response-capture-failure",
    "after-headers": "response-capture-failure",
}


def transport_reason(sent: SendResult) -> str:
    """A local reason code for a failed exchange — never the transport's prose.

    `SendResult.detail` is free text, and free text on this path is not as local
    as it looks: an `SSLCertVerificationError` message carries fields the peer
    chose, and an injected `send` can put anything there at all. Copying it into
    a receipt is the same defect as copying `usage` — one field further down.

    So the reason is assigned where the failure happens, from a fixed
    vocabulary, and read from the field here. Nothing downstream has to judge
    whether a string is safe to keep.
    """
    if sent.reason is not None:
        return sent.reason
    # An injected `send` that supplied no reason gets the stage's own name,
    # which is local too. Its `detail` is never consulted.
    return STAGE_OUTCOME.get(sent.stage, "transport-failure")

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


MODEL_EVIDENCE_FIELDS = (
    "reported_model", "reported_model_present",
    "reported_model_sha256", "reported_model_bytes",
)


def model_evidence_of(turn: dict[str, Any]) -> dict[str, Any] | None:
    """One turn's projected identity, or `None` if it never reached a payload."""
    if "reported_model_present" not in turn:
        return None
    return {key: turn[key] for key in MODEL_EVIDENCE_FIELDS if key in turn}


def fold_reported_models(turns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every distinct model the provider named, in the order it named them.

    A single top-level `reported_model` overwritten each turn loses exactly the
    evidence that matters: a run that drifted on turn one and was correct on
    turn two folds to `drifted`, and then the detail line reads "requested X,
    provider reported X" because the last write won. The substituted model is
    the whole finding — it has to survive the fold.

    It survives as *evidence*, not as the provider's string. Two different
    substituted models still produce two entries, because their digests differ;
    what nobody gets from the receipt is the names themselves, which the
    provider chose and could have chosen to be the credential.

    Turns that never reached a payload contribute nothing, rather than a `null`
    that would read as "the provider named no model".
    """
    seen: list[dict[str, Any]] = []
    for turn in turns:
        entry = model_evidence_of(turn)
        if entry is not None and entry not in seen:
            seen.append(entry)
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


# The reasons a receipt is allowed to state. Fixed, local strings: a provider
# error body is untrusted text that ends up in a committed artifact, and a
# gateway that echoes a rejected `Authorization` header into `error.message`
# would write the credential straight into evidence. The body is *read* — that
# is how a dialect rejection is told from a missing model — but what gets
# recorded is our conclusion plus the status, request id, byte count and digest.
# Scrubbing arbitrary provider prose with a regex is a losing game: a key can
# come back base64'd, JSON-escaped, or split across fields.
QUALIFY_REASONS = (
    "redirect-not-followed",
    "auth-rejected",
    "model-not-found",
    "rate-limited",
    "server-error",
    "tools-or-tool-choice-named-in-a-400",
    "tool-results-rejected",
    "request-rejected",
)


def classify_qualify_http(status: int, body: bytes, carried_tool_results: bool) -> tuple[str, str]:
    """Map a non-success status to a cause and a local reason code.

    Whether the rejected request carried `role: tool` messages matters: a
    rejection of one that did not is about the tools or the forcing, while a
    rejection of one that did is about the result shape. Same status, different
    thing to fix. Asked of the request itself rather than inferred from the turn
    number, which is only a proxy for it.
    """
    if 300 <= status <= 399:
        # The transport refused to follow it, so the credential stayed put. This
        # is an endpoint to correct, not a provider that said no.
        return "REDIRECT_NOT_FOLLOWED", "redirect-not-followed"
    if status in (401, 403):
        return "AUTH_FAILED", "auth-rejected"
    if status == 404:
        return "MODEL_MISSING", "model-not-found"
    if status == 429:
        return "RATE_LIMITED", "rate-limited"
    if 500 <= status <= 599:
        return "UNAVAILABLE", "server-error"
    if status == 400 and provider_named_the_tools(body):
        # Named by the provider, not guessed from the shape of the failure.
        return "TOOL_CHOICE_UNSUPPORTED", "tools-or-tool-choice-named-in-a-400"
    if status == 400 and carried_tool_results:
        return "TOOL_RESULT_REJECTED", "tool-results-rejected"
    return "PROVIDER_REJECTED", "request-rejected"


def provider_named_the_tools(body: bytes) -> bool:
    """Did the provider blame the tools or the forcing? Read, never retained.

    Total by contract: **any** bytes in, a `bool` out, never an exception. This
    is the one deliberately lenient parse, and lenient was taken to mean "do not
    impose the consumer's dialect" — not "let Python throw the process out of a
    window". It did both: a 5000-digit integer in an unused field raised a bare
    `ValueError` from `int()`, and deep nesting raised `RecursionError`, and each
    escaped to be filed as `INTERNAL_ERROR` — blaming the matrix for bytes the
    provider chose.
    """
    try:
        text = body.decode("utf-8", "replace")
        # The depth pre-scan, for the same reason the strict path has one:
        # `json.loads` recurses, and `RecursionError` is not a `ValueError`.
        if json_nesting_depth(text) > MAX_JSON_DEPTH:
            return False
        payload = json.loads(text)
    except (ValueError, TypeError) as exc:
        # `JSONDecodeError` is a `ValueError`, and so is the decoder's
        # integer-length refusal — which is the one that got out.
        del exc
        return False
    if not isinstance(payload, dict):
        return False
    error = payload.get("error")
    if isinstance(error, dict):
        haystack = f"{error.get('param', '')} {error.get('message', '')}"
    else:
        haystack = str(payload.get("message", ""))
    haystack = haystack.lower()
    return "tool_choice" in haystack or "tool choice" in haystack or "tools" in haystack


class ParsedAssistant(NamedTuple):
    """Everything the loop is allowed to use from one assistant message.

    Three fields rather than two because `content` used to be read straight off
    the original dict at replay time, several hundred lines away from the parser
    that claimed to have validated the message. Checking one object and
    consuming another is how a contract becomes decorative: the check passed,
    the consumer took a different value, and both were right about their own
    input. Whatever replay sends back comes from here.
    """

    calls: list[dict[str, Any]]
    content: str | None
    problem: tuple[str, str] | None


def parse_tool_calls(message: dict[str, Any]) -> ParsedAssistant:
    """Read the whole assistant message under the OpenAI-chat contract, strictly.

    This vertical qualifies `api_style: openai-chat`, and the adapter that will
    consume a PASS is a strict openai-chat mapper. A canary that accepted a
    looser shape than the adapter would hand out a PASS for a response the
    adapter rejects — the same defect as paraphrasing the schemas, moved to the
    response side. So the contract is exactly what a strict mapper requires:

        message.role == "assistant"
        message.content is absent, null, or a string
        tool_calls is a non-empty array
        every tool_call.type == "function"
        every id is a non-empty string, and unique within the response
        function.name is a non-empty string
        function.arguments is a JSON *string* (not an object)

    `content` is checked here and returned here. It is the field replay echoes,
    and it was the one field the old contract never looked at: `{"role":
    "assistant", "content": 123, "tool_calls": [...]}` passed, was echoed into
    the next request, and a run could finish `PASS` for a message a strict
    mapper deserializes into nothing at all.

    Returns `(calls, content, problem)`, where `problem` is
    `(classification, detail)` and, when set, nothing else may be used.
    """
    role = message.get("role")
    if role != "assistant":
        return ParsedAssistant(
            [], None,
            ("PROTOCOL_VIOLATION", f"tool calls arrived under role {role!r}, not 'assistant'"),
        )
    # Before anything else about the calls: a message whose own fields are the
    # wrong type is malformed whatever it happens to be asking for, and this
    # verdict has to land before an operation runs, before a roundtrip is
    # acknowledged, and before the message can be replayed.
    content = message.get("content")
    if content is not None and not isinstance(content, str):
        return ParsedAssistant(
            [], None,
            (
                "PROTOCOL_VIOLATION",
                f"assistant content was {type(content).__name__}; openai-chat admits a "
                "string, null, or no content at all",
            ),
        )
    raw = message.get("tool_calls")
    if raw is None:
        return ParsedAssistant(
            [], content, ("NO_TERMINAL_ANSWER", "assistant message carried no tool_calls")
        )
    if not isinstance(raw, list):
        return ParsedAssistant(
            [], content,
            ("PROTOCOL_VIOLATION", f"tool_calls was {type(raw).__name__}, not an array"),
        )
    if not raw:
        return ParsedAssistant(
            [], content,
            ("NO_TERMINAL_ANSWER", "assistant message carried an empty tool_calls array"),
        )

    calls: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            return ParsedAssistant([], content, ("PROTOCOL_VIOLATION", "a tool call was not an object"))
        kind = entry.get("type")
        if kind != "function":
            # Not pedantry: a strict mapper switches on this field, and a call
            # arriving as anything else is a shape it will not deserialize.
            return ParsedAssistant(
                [], content,
                ("PROTOCOL_VIOLATION", f"tool call type was {kind!r}, not 'function'"),
            )
        call_id = entry.get("id")
        if not isinstance(call_id, str) or not call_id:
            return ParsedAssistant(
                [], content, ("PROTOCOL_VIOLATION", "a tool call lacked a non-empty string id")
            )
        if call_id in seen_ids:
            # Results are returned keyed by id. Two calls sharing one id make the
            # linkage ambiguous, and the ambiguity is resolved by whichever
            # result happens to be written last.
            return ParsedAssistant(
                [], content,
                ("PROTOCOL_VIOLATION",
                 f"a tool call id appeared more than once: {opaque_ref('tool-call-id', call_id)}"),
            )
        seen_ids.add(call_id)
        function = entry.get("function")
        if not isinstance(function, dict):
            return ParsedAssistant(
                [], content,
                ("PROTOCOL_VIOLATION",
                 f"tool call {opaque_ref('tool-call-id', call_id)} lacked a function object"),
            )
        name = function.get("name")
        if not isinstance(name, str) or not name:
            return ParsedAssistant(
                [], content,
                ("PROTOCOL_VIOLATION",
                 f"tool call {opaque_ref('tool-call-id', call_id)} lacked a function name"),
            )
        arguments = function.get("arguments")
        if isinstance(arguments, (dict, list)):
            # A coherent other dialect — Anthropic sends arguments as an object —
            # not a malformed OpenAI response. Named separately because the fix
            # is a different adapter, not a better prompt.
            return ParsedAssistant([], content, (
                "DIALECT_MISMATCH",
                f"{opaque_ref('tool-name', name)} arguments arrived as a JSON "
                f"{type(arguments).__name__}; openai-chat requires a JSON string",
            ))
        if not isinstance(arguments, str):
            return ParsedAssistant([], content, (
                "PROTOCOL_VIOLATION",
                f"{opaque_ref('tool-name', name)} arguments were "
                f"{type(arguments).__name__}, not a string",
            ))
        calls.append({"id": call_id, "name": name, "raw_arguments": arguments})
    return ParsedAssistant(calls, content, None)


def decode_arguments(call: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """Decode the JSON string `parse_tool_calls` already insisted on.

    Strict about duplicate keys: these arguments *are* the tool call being
    qualified, and `{"handle": "invented", "handle": "sha256:00…"}` would let
    the schema validator and the observed-only grading see only the second
    value. A canary that accepts an ambiguous call has qualified a shape a
    strict mapper may refuse — the defect this vertical exists to avoid.
    """
    # The tool name and every one of these exception messages are the
    # provider's words: `DuplicateJsonKey` names the repeated key, and
    # `UnadmittedJsonValue` quotes the literal. Both would otherwise reach a
    # receipt through `detail`, which is the leak the projection boundary
    # exists to close — so what is reported is the *class* of failure and a
    # reference to the value, not the value.
    named = opaque_ref("tool-name", call["name"])
    raw = call["raw_arguments"]
    try:
        parsed = strict_json_loads(raw, "arguments")
    except DuplicateJsonKey:
        return None, f"arguments for {named} name a field twice"
    except StrictJsonError as exc:
        return None, f"arguments for {named} are not acceptable JSON: {type(exc).__name__}"
    except json.JSONDecodeError:
        return None, f"arguments for {named} are not valid JSON"
    if not isinstance(parsed, dict):
        return None, f"arguments for {named} decoded to {type(parsed).__name__}, not an object"
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
    errors = jsonschema_mini.validate(args, schema)
    # Schema keywords cannot express trailing-bit canonicality or agreement
    # between `data` and `display_utf8`, so every envelope also goes through the
    # oracle that matches the crate.
    for label, envelope in walk_envelopes(args):
        errors.extend(envelope_errors(envelope, label)[0])
    return errors


class Observed:
    """What the operations of *this run* actually handed back.

    Grading against module constants let a script that ran only
    `qodec_materialize` — whose result carries `records` and no handle at all —
    cite `CANNED_HANDLE` and pass, because the comparison was to a global truth
    rather than to anything the provider had been shown. That is not a
    qualification of the protocol, it is a reward for guessing a constant.

    So the observable set is accumulated as results are returned, and the
    terminal answer may only cite what is in it.
    """

    def __init__(self) -> None:
        self.handles: set[str] = set()
        self.support: set[str] = set()
        self.bytes: set[bytes] = set()

    def record(self, result: dict[str, Any]) -> None:
        handle = result.get("handle")
        if isinstance(handle, str):
            self.handles.add(handle)
        for row in result.get("support", []):
            self.support.add(json.dumps(row, sort_keys=True))
        for envelope in list(result.get("preview", [])) + list(result.get("records", [])):
            errors, decoded = envelope_errors(envelope, "canned")
            if not errors and decoded is not None:
                self.bytes.add(decoded)


def canary_answer_errors(args: dict[str, Any], observed: Observed) -> list[str]:
    """Did the target answer the question, or merely satisfy the schema?

    Kept apart from the protocol causes on purpose. A model that speaks the
    dialect perfectly and cites a handle it was never given has qualified the
    wire and failed the task; folding the two together would hide whichever
    happened to be checked second, and they call for opposite actions — one is
    a target to drop, the other a prompt to fix.

    Every comparison below is against `observed`, never against a constant.
    """
    errors: list[str] = []

    # Every value named below came out of the provider's `arguments`, so none of
    # them is spelled out: these strings reach `detail` and `detail` reaches a
    # committed receipt. A digest is enough to compare two runs, or to compare a
    # cited handle against one the operator can hash themselves.
    envelope_problems, decoded = envelope_errors(args.get("answer"), "answer")
    errors.extend(envelope_problems)
    if decoded is not None and decoded not in observed.bytes:
        errors.append(
            f"answer bytes {opaque_ref('answer-bytes', decoded)} were not in "
            "any result this run returned"
        )

    handle = args.get("handle")
    named = opaque_ref("handle", handle)
    if not observed.handles:
        errors.append(f"cited handle {named} but no operation in this run returned a handle")
    elif handle not in observed.handles:
        errors.append(f"cited handle {named} was never returned by any operation in this run")

    cited = args.get("cited")
    for citation in cited if isinstance(cited, list) else []:
        spelled = json.dumps(citation, sort_keys=True)
        if spelled not in observed.support:
            errors.append(
                f"citation {opaque_ref('citation', spelled)} is not in the "
                "support this run returned"
            )
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
    registry = normalize_registry(registry) if registry is not None else load_registry()
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
    observed = Observed()

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
        record.update(opaque("request_id", "request-id", sent.request_id))
        if sent.body_bytes_observed is not None:
            record["body_bytes_observed"] = sent.body_bytes_observed
        if sent.stage != "completed":
            kind = STAGE_CAUSE.get(sent.stage, "UNAVAILABLE")
            reason = transport_reason(sent)
            record["outcome"] = STAGE_OUTCOME.get(sent.stage, "transport-failure")
            record["transport_reason"] = reason
            if sent.failure_type is not None:
                record["transport_failure_type"] = sent.failure_type
            if reason == "credential-missing":
                # The env var name comes from the trusted registry by way of
                # the target, never from the transport's message.
                record["key_env"] = target["key_env"]
            receipt["turns"].append(record)
            # The status is the most useful thing left when the body is
            # gone; burying it in a turn record and reporting a bare cause
            # would throw away what the provider already told us. The
            # reason beside it is a local enum, not the transport's words.
            detail = f"HTTP {status}: {reason}" if status is not None else reason
            if sent.failure_type is not None:
                detail = f"{detail} ({sent.failure_type})"
            if reason == "credential-missing":
                detail = f"{detail}: {target['key_env']}"
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
            # Strict: everything the rest of this loop reads comes from here —
            # the reported model, the chosen message, the tool calls and their
            # ids. A field stated twice makes all of it ambiguous.
            payload = strict_json_loads(raw, "completion")
            if not isinstance(payload, dict):
                raise TypeError(f"completion was a {type(payload).__name__}, not an object")
            message = payload["choices"][0]["message"]
            if not isinstance(message, dict):
                raise TypeError("choices[0].message was not an object")
        except (StrictJsonError, json.JSONDecodeError, KeyError, IndexError, TypeError, AttributeError) as exc:
            why = f"unmappable 2xx completion: {type(exc).__name__}"
            record["outcome"] = "unreadable-response"
            record["detail"] = why
            receipt["turns"].append(record)
            receipt.update(classification="INVALID_OUTPUT", detail=why, turn_count=turn + 1)
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
        record["model_status"] = model_status_of(target["model"], reported)
        record.update(model_evidence(target["model"], reported))
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
        # The top-level convenience field keeps its old meaning — a single
        # consistent value — but only ever holds a model that matched the one
        # requested. Any other string is the provider's, and lives in
        # `reported_models` as a digest.
        only = receipt["reported_models"][0] if len(receipt["reported_models"]) == 1 else None
        receipt["reported_model"] = only.get("reported_model") if only else None
        if isinstance(payload.get("usage"), dict):
            record["reported_usage"] = normalize_provider_usage(payload["usage"])

        parsed = parse_tool_calls(message)
        calls, problem = parsed.calls, parsed.problem
        if problem:
            kind, why = problem
            record["outcome"] = "no-tool-call" if kind == "NO_TERMINAL_ANSWER" else "dialect-violation"
            record["detail"] = why
            receipt["turns"].append(record)
            receipt.update(classification=kind, detail=why, turn_count=turn + 1)
            return receipt
        # Names and call ids are both provider-chosen. A name that matches one
        # we declared is a value we already had, so it crosses as itself; any
        # other name is the provider's text and crosses as a digest. Call ids
        # are never one of ours, so nothing is lost by never keeping them: the
        # ordinal links a call to its result, and replay still uses the real id
        # in memory where it belongs.
        known = {op["name"] for op in surface["operations"]} | {ANSWER_TOOL}
        record["tool_calls"] = [
            {
                "ordinal": index,
                "name": c["name"] if c["name"] in known else None,
                **({} if c["name"] in known else opaque("name", "tool-name", c["name"])),
                **opaque("call_id", "tool-call-id", c["id"]),
            }
            for index, c in enumerate(calls)
        ]
        record["tool_names"] = [c["name"] for c in calls if c["name"] in known]

        unknown = [c["name"] for c in calls if c["name"] not in known]
        if unknown:
            why = (
                f"called {len(unknown)} tool(s) that were never declared: "
                + ", ".join(opaque_ref("tool-name", name) for name in unknown)
            )
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
                # `jsonschema_mini` interpolates the offending instance —
                # `{instance!r}`, `additional property '{key}'` — so the
                # messages themselves are provider text and cannot be kept.
                # What a reader acts on survives: how many rules failed, which
                # rules, and a digest that makes two runs comparable.
                evidence = error_evidence("argument_errors", errors)
                why = (
                    f"{opaque_ref('tool-name', call['name'])} arguments violate the "
                    f"declared schema: {evidence['argument_errors_count']} error(s), "
                    f"{', '.join(evidence['argument_errors_kinds'])}"
                )
                record["outcome"] = "malformed-arguments"
                record["detail"] = why
                record.update(evidence)
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
            answer_errors = canary_answer_errors(answer_args, observed)
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
            identity = receipt["model_status"]
            if identity == "drifted":
                # Which model was substituted is the finding, and it survives
                # as a digest rather than as the name: a provider that returns
                # the bearer token in `model` would otherwise have written it
                # into the detail line of a committed receipt.
                substituted = [
                    entry for entry in receipt["reported_models"]
                    if entry.get("reported_model") is None and entry.get("reported_model_present")
                ]
                receipt["classification"] = MODEL_STATUS_VERDICT["drifted"]
                receipt["detail"] = (
                    f"requested {target['model']}, provider reported "
                    f"{len(substituted)} other model(s): "
                    + ", ".join(entry["reported_model_sha256"][:16] for entry in substituted)
                )
            elif identity != "verified":
                receipt["classification"] = MODEL_STATUS_VERDICT.get(identity, "MODEL_IDENTITY_MISSING")
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
        #
        # `content` comes from `parsed`, not from `message`, and the difference
        # is the whole point. Reading the original dict again here meant the
        # validator and the consumer were two slightly different programs, and
        # only one of them had the contract. `parsed.content` is the value that
        # was checked; there is no second value to take instead.
        messages.append({
            "role": "assistant",
            "content": parsed.content,
            "tool_calls": message["tool_calls"],
        })
        for call, _args in decoded:
            result = canned_result_for(call["name"])
            # The grading set grows only from results the provider was actually
            # shown. `qodec_materialize` returns records and no handle, so a
            # materialize-only run establishes no handle to cite.
            observed.record(result)
            messages.append({
                "role": "tool",
                "tool_call_id": call["id"],
                "content": json.dumps(result, sort_keys=True),
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


def guarded_receipt(schema: str, target: dict[str, Any], run: Any) -> dict[str, Any]:
    """One target's failure must not cost every later target its receipt.

    Receipts are written in a loop, so an exception anywhere in a single
    target's path used to abort the run and leave the remaining targets with no
    evidence at all — the least informative possible outcome, produced by the
    least interesting possible cause. A crash is now a receipt like any other.

    The exception *type* is recorded and its message is not: an exception raised
    while building a request can carry the credential, and this receipt is
    written to disk.
    """
    try:
        return run()
    except Exception as exc:  # noqa: BLE001 — deliberate: see the docstring
        return {
            "schema": schema,
            "target_id": target.get("target_id"),
            "provider": target.get("provider"),
            "requested_model": target.get("model"),
            "classification": "INTERNAL_ERROR",
            "detail": f"provider-matrix raised {type(exc).__name__}",
        }


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
                    guarded_receipt(PROBE_SCHEMA, target,
                                    lambda t=target: probe_target(t, args.timeout, None, registry)),
                )
        else:
            plan = read_json(args.plan)
            if plan.get("schema") != PLAN_SCHEMA:
                raise ValueError(f"expected {PLAN_SCHEMA}")
            surface = load_surface(args.surface)
            registry = load_registry(args.registry)
            args.out_dir.mkdir(parents=True, exist_ok=True)
            for target in plan["selected"]:
                receipt = guarded_receipt(QUALIFY_SCHEMA, target, lambda t=target: qualify_target(
                    t, surface, args.timeout, args.max_turns,
                    key_bound_sender(t["key_env"]), registry,
                ))
                write_json(args.out_dir / receipt_filename(target["target_id"]), receipt)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"provider-matrix: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
