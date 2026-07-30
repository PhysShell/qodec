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
from dataclasses import dataclass
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
    "message-role": b"qodec-provider-message-role-v1\0",
    "tool-call-type": b"qodec-provider-tool-call-type-v1\0",
    "response-body": b"qodec-provider-response-body-v1\0",
    "failure-class": b"qodec-provider-failure-class-v1\0",
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


# One local ceiling per kind of provider-chosen string. Not a default anywhere:
# `opaque_text` and `opaque_ref` both take `max_bytes` as a keyword with no
# default, so a new call site cannot forget to name one and quietly reopen the
# channel. The lengths are generous — these are identifiers, not documents.
EVIDENCE_MAX_BYTES = {
    "request-id": 256,
    "tool-call-id": 256,
    "tool-name": 128,
    "model-name": 256,
    "handle": 256,
    "answer-bytes": 4096,
    "citation": 1024,
    "message-role": 128,
    "tool-call-type": 128,
    "failure-class": 256,
    # An envelope field name, a claimed encoding, a base64 spelling, a single
    # rejected character, a walked path. All provider-chosen, all named in a
    # message rather than repeated in one.
    "json-value": 4096,
}


def opaque_text(prefix: str, domain: str, value: Any, *, max_bytes: int) -> dict[str, Any]:
    """Evidence *about* a provider-chosen value. Never the value.

    Four fields, because all four are things support actually needs and none of
    them is the string itself: whether there was one, which one it was
    (comparably, across turns and runs), how long it was, and whether that
    length is the real one.

    `max_bytes` has no default on purpose. `body_bytes_observed` was bounded and
    `request_id_bytes` was not, and the difference was that nobody had to say
    anything to leave the second one open — a length is a number the provider
    chooses, and an unbounded number is a channel whatever field it sits in.
    Past the bound the length is clamped and marked rather than recorded, so the
    integer that reaches the artifact is always one this module is willing to
    stand behind. The digest still crosses: it is fixed-width, so it carries no
    length however long its input was.
    """
    if value is None:
        return {f"{prefix}_present": False}
    size = len(evidence_bytes(value))
    return {
        f"{prefix}_present": True,
        f"{prefix}_sha256": evidence_digest(domain, value),
        f"{prefix}_bytes": min(size, max_bytes),
        f"{prefix}_oversize": size > max_bytes,
    }


def opaque(prefix: str, domain: str, value: Any) -> dict[str, Any]:
    """`opaque_text` with the bound this domain declares."""
    return opaque_text(prefix, domain, value, max_bytes=EVIDENCE_MAX_BYTES[domain])


# ---------------------------------------------------------------------------
# Typed values a message may be built from
# ---------------------------------------------------------------------------
#
# A detail line used to be an f-string, and the check that it was safe was a
# lexical one: no foreign word, no byte outside a local alphabet. That proves a
# line *could* have been written here. It does not prove it *was* — `"timeout"`,
# `"the completion carried the probe token"` and sixteen hex characters are all
# things a provider can send verbatim, and all three satisfy a lexical check.
#
# This vertical has already withdrawn that argument twice: `str.isidentifier()`
# for a failure class, then sixty-four hex characters for a digest. Syntax is
# not provenance, and buying the lesson a third time would be a choice.
#
# So a message is not assembled from text at all. It is a registered template
# plus typed arguments, and the only way a provider-chosen value can appear in
# one is as an `OpaqueRef` — which carries a digest, a bounded length and a
# domain, and no way to spell anything else.


@dataclass(frozen=True)
class OpaqueRef:
    """A reference to a provider-chosen value. The only foreign thing in a line.

    Constructed by `opaque_ref` and nowhere else; an AST gate refuses a string
    literal shaped like one, because a hand-written `f"<handle sha256:{x} 4B>"`
    would be a channel wearing the wrapper that exists to close it.
    """

    domain: str
    digest16: str
    shown_bytes: int
    oversize: bool

    def render(self) -> str:
        return (f"<{self.domain} sha256:{self.digest16} "
                f"{self.shown_bytes}{'+' if self.oversize else ''}B>")


@dataclass(frozen=True)
class DigestRef:
    """A truncated digest of something already digested. One constructor."""

    digest16: str

    @classmethod
    def of(cls, digest: str) -> "DigestRef":
        """The only place a digest is shortened. `[:16]` elsewhere is refused."""
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("a digest reference is built from a sha256 digest")
        return cls(digest[:16])

    def render(self) -> str:
        return self.digest16


@dataclass(frozen=True)
class TypeName:
    """A JSON or Python type name — a local word about a foreign thing."""

    name: str

    def __post_init__(self) -> None:
        if self.name not in LOCAL_TYPE_NAMES:
            raise ValueError(f"{self.name!r} is not a type name this module names")

    @classmethod
    def of(cls, value: Any) -> "TypeName":
        name = type(value).__name__
        return cls(name if name in LOCAL_TYPE_NAMES else "unknown")

    def render(self) -> str:
        return self.name


@dataclass(frozen=True)
class LocalValue:
    """A value that came from a trusted local source, carrying which one.

    `key_env` is the only member so far. The source travels with the value so
    the durable-field inventory can check it against the registry rather than
    against the receipt it is auditing.
    """

    source: str
    value: str

    def __post_init__(self) -> None:
        if self.source not in LOCAL_VALUE_SOURCES:
            raise ValueError(f"{self.source!r} is not a declared local source")

    def render(self) -> str:
        return self.value


LOCAL_VALUE_SOURCES = ("key_env",)

# Every type name this module is willing to write into a message. Closed,
# because `type(x).__name__` is a provenance argument only for objects this
# module built, and the ones it names here are the strict reader's own output.
LOCAL_TYPE_NAMES = (
    "dict", "list", "str", "int", "float", "bool", "NoneType", "bytes", "unknown",
)


def opaque_ref(domain: str, value: Any, *, max_bytes: int | None = None) -> OpaqueRef:
    """Name a provider-chosen value inside a local message without repeating it.

    Messages end up in `detail`, and `detail` ends up on disk. A message that
    interpolates what the provider sent is the same leak as a field that copies
    it, with better camouflage. The length in the reference is bounded for the
    same reason the field's is.
    """
    ceiling = EVIDENCE_MAX_BYTES[domain] if max_bytes is None else max_bytes
    size = len(evidence_bytes(value))
    return OpaqueRef(domain, evidence_digest(domain, value)[:16], min(size, ceiling), size > ceiling)


JSON_TYPE_NAMES = (
    (bool, "boolean"), (int, "number"), (float, "number"), (str, "string"),
    (list, "array"), (dict, "object"),
)


def json_type_name(value: Any) -> str:
    """The JSON type of a provider value — a local word about a foreign thing."""
    if value is None:
        return "null"
    for kind, name in JSON_TYPE_NAMES:
        if isinstance(value, kind):
            return name
    return "unknown"


# The discriminators this dialect switches on. A value that is one of these is a
# value we already had; anything else is the provider's.
MESSAGE_ROLES = ("assistant", "system", "user", "tool")
TOOL_CALL_TYPES = ("function",)


@dataclass(frozen=True)
class Discriminator:
    """A provider-controlled discriminator, named safely. One constructor."""

    domain: str
    known: str | None = None
    ref: OpaqueRef | None = None
    json_type: str | None = None

    def render(self) -> str:
        if self.known is not None:
            return repr(self.known)
        if self.ref is not None:
            return self.ref.render()
        return f"<{self.domain} {self.json_type}>"


def discriminator(domain: str, value: Any, known: tuple[str, ...]) -> Discriminator:
    """Name a provider-controlled discriminator in a message, safely.

    `f"role {role!r}"` reads like a harmless diagnostic and is a copy: `role`
    and `tool_call.type` are strings the provider fills in, so either can be the
    bearer token, and `detail` goes to disk. A discriminator that matched one of
    ours is worth naming outright — it is a value we already had. Anything else
    crosses as a reference, and a non-string crosses as its JSON type, because
    the contract is that unrecognised objects and lists do not cross at all.
    """
    if isinstance(value, str) and value in known:
        return Discriminator(domain, known=value)
    if isinstance(value, str):
        return Discriminator(domain, ref=opaque_ref(domain, value))
    return Discriminator(domain, json_type=json_type_name(value))


# The counters, and nothing else. Anything outside this tuple is discarded
# rather than recorded, however plausible it looks.
# The generation ceilings this module asks for. Named here because the usage
# bounds are derived from them, and a bound that drifts from the request it
# describes is not a bound.
PROBE_MAX_TOKENS = 16
QUALIFY_MAX_TOKENS = 1024

USAGE_COUNTERS = ("prompt_tokens", "completion_tokens", "total_tokens")


def usage_bounds(request_bytes: int, max_tokens: int) -> dict[str, int]:
    """The largest each counter could honestly be, computed from our own request.

    Every bound here comes from something this module decided. `prompt_tokens`
    cannot exceed the number of bytes we sent, because no tokenizer emits more
    than one token per byte; `completion_tokens` cannot exceed the `max_tokens`
    we asked for; `total_tokens` cannot exceed their sum. Conservative on
    purpose — the point is not to audit the provider's arithmetic, it is that an
    unbounded integer field is an unbounded channel.
    """
    return {
        "prompt_tokens": request_bytes,
        "completion_tokens": max_tokens,
        "total_tokens": request_bytes + max_tokens,
    }


def normalize_provider_usage(value: Any, bounds: dict[str, int]) -> dict[str, int]:
    """The provider's token counters, and nothing else it decided to send.

    An allowlist, not a filter. `usage` is a JSON object the provider fills in,
    so `{"prompt_tokens": 12, "echo": "Bearer …"}` is a shape it can choose, and
    copying the object whole put that second field into a committed receipt — on
    a PASS, where nobody would think to look.

    `type(n) is int` rather than `isinstance`, because `True` is an `int` in
    Python and would otherwise be recorded as a token count of 1. A negative
    count is refused for the same reason a status of 700 is: it is not a
    measurement, and keeping it would be recording a claim.

    And the range is bounded at both ends, which the first version was not.
    "Bounded numeric scalar" with no upper bound is an arbitrary-precision
    integer wearing a type check: `int.from_bytes(secret.encode(), "big")` in
    `prompt_tokens` is a perfectly well-typed non-negative integer, and a sweep
    for a *string* sentinel would never see it. The bounds come from `bounds`,
    which is computed from the request this module sent — never from anything
    in the response.

    Usage is descriptive telemetry. It never reaches a verdict, in either path.
    """
    if not isinstance(value, dict):
        return {}
    counts: dict[str, int] = {}
    for name in USAGE_COUNTERS:
        count = value.get(name)
        if type(count) is int and 0 <= count <= bounds[name]:
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
    if isinstance(reported, str):
        return {"reported_model": None, **opaque("reported_model", "model-name", reported)}
    if reported is None:
        return {"reported_model": None, "reported_model_present": False}
    # An object or a list in `model` is not an identifier to hash — the
    # contract says unrecognised structures do not cross, and hashing one
    # would have been the boundary quietly making an exception for itself.
    # Its JSON type is a local word and is all that crosses.
    return {
        "reported_model": None,
        "reported_model_present": True,
        "reported_model_type": json_type_name(reported),
    }


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
# The largest request this tool will compose. It builds every byte of it — the
# frozen surface, the canned results, its own messages — so the number is local
# in the strongest sense available. It is bounded anyway, because "we built it"
# is a claim about provenance and `request_bytes` is a durable integer: a
# multi-turn loop that grew one without limit would put an unbounded number in
# a receipt with an impeccable pedigree.
MAX_REQUEST_BYTES = 4 * 1024 * 1024

REGISTRY_SCHEMA = "qodec-provider-registry-v1"
REGISTRY_PATH = Path(__file__).resolve().parent / "trusted-providers.json"
AUTHORITY_FIELDS = ("api_base", "key_env", "api_style")
KEY_ENV_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*\Z")

# Headers providers use to name the generation. Kept because it is the only
# handle support has when a body is lost after the headers arrived.
REQUEST_ID_HEADERS = ("x-request-id", "x-groq-request-id", "openai-request-id", "request-id")


# Why an endpoint was refused, in this module's own words. The message beside
# the reason is for a human reading a terminal; it interpolates the plan's own
# text and stays ephemeral. The *reason* is what reaches a receipt, because a
# durable field whose vocabulary is open is a durable field nobody can audit.
ENDPOINT_REJECTION_REASONS = (
    "unknown-provider",
    "authority-mismatch",
    "scheme-not-https",
    "no-host",
    "userinfo-present",
    "query-present",
    "fragment-present",
)


class EndpointRejected(ValueError):
    """The catalog named an endpoint this transport will not send a key to.

    Carries a reason from a closed vocabulary alongside its message. `str(exc)`
    used to go straight into `detail`, which made the durable field's content
    whatever the next `raise` site felt like writing — the same open channel as
    a copied provider string, differing only in who fills it.
    """

    def __init__(self, reason: str, message: str) -> None:
        if reason not in ENDPOINT_REJECTION_REASONS:
            raise ValueError(f"unknown endpoint rejection reason {reason!r}")
        super().__init__(message)
        self.reason = reason


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


# Why a spelling is not the canonical one, in this module's own words. The
# offending character used to be interpolated into the message, and that message
# reached `detail` through the canary's grading — a provider-chosen byte in a
# committed receipt, wearing a sentence.
NONCANONICAL_REASONS = (
    "character-not-in-the-alphabet",
    "dangling-character",
    "non-zero-trailing-bits",
)

# Where an envelope was found. `answer` and `canned` are this module's own
# words; a path walked out of provider-supplied arguments is not, so it crosses
# as a reference.
ENVELOPE_LABELS = ("answer", "canned")


@dataclass(frozen=True)
class EnvelopeLabel:
    """Which envelope a complaint is about — a local word or a reference."""

    known: str | None = None
    ref: OpaqueRef | None = None

    def __post_init__(self) -> None:
        if (self.known is None) == (self.ref is None):
            raise ValueError("an envelope label is either a local word or a reference")
        if self.known is not None and self.known not in ENVELOPE_LABELS:
            raise ValueError(f"{self.known!r} is not a declared envelope label")

    def render(self) -> str:
        return self.known if self.known is not None else self.ref.render()


class NoncanonicalEncoding(ValueError):
    """`data` is not the one canonical spelling of the bytes it denotes.

    Carries a reason from a closed vocabulary and, when the cause is a single
    character the provider chose, a reference to it — never the character.
    """

    def __init__(self, reason: str, ref: OpaqueRef | None = None) -> None:
        if reason not in NONCANONICAL_REASONS:
            raise ValueError(f"unknown noncanonical reason {reason!r}")
        super().__init__(reason)
        self.reason = reason
        self.ref = ref

    def detail(self, label: "EnvelopeLabel") -> "LocalDetail":
        if self.ref is not None:
            return LocalDetail("envelope-noncanonical-character", (label, self.ref))
        return LocalDetail("envelope-noncanonical", (label, self.reason))


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
            # The character is the provider's, so it crosses as a reference.
            # Interpolated, it reached `detail` through the canary's grading.
            raise NoncanonicalEncoding(
                "character-not-in-the-alphabet", opaque_ref("json-value", ch))
        acc = (acc << 6) | value
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 6:
        raise NoncanonicalEncoding("dangling-character")
    if bits > 0 and (acc & ((1 << bits) - 1)) != 0:
        raise NoncanonicalEncoding("non-zero-trailing-bits")
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


def envelope_errors(value: Any, label: EnvelopeLabel) -> tuple[list[LocalDetail], bytes | None]:
    """Validate one byte envelope with the strictness the crate applies.

    Schema keywords can reject an obviously wrong shape, but they cannot express
    trailing-bit canonicality or agreement between `data` and `display_utf8`.
    Those need a procedure, so this is one — and it returns the decoded bytes so
    the caller does not decode a second time with a different rule.
    """
    if not isinstance(value, dict):
        return [LocalDetail("envelope-not-object", (label,))], None

    # Field names, the claimed encoding and `data` itself are all provider-chosen
    # and were all interpolated here. These messages reach `detail` through the
    # canary's grading, so each of the three now crosses as a reference.
    errors = [
        LocalDetail("envelope-unknown-field", (label, opaque_ref("json-value", key)))
        for key in value
        if key not in ENVELOPE_FIELDS
    ]
    if value.get("encoding") != ENVELOPE_ENCODING:
        errors.append(LocalDetail("envelope-encoding", (
            label, discriminator("json-value", value.get("encoding"), (ENVELOPE_ENCODING,)))))

    data = value.get("data")
    if not isinstance(data, str):
        errors.append(LocalDetail("envelope-data-not-string", (label,)))
        return errors, None

    try:
        decoded = b64url_nopad_decode(data)
    except NoncanonicalEncoding as exc:
        errors.append(exc.detail(label))
        return errors, None

    # Belt and braces over the bit checks above: if any spelling other than the
    # canonical one survived, the round trip is where it shows.
    if b64url_nopad_encode(decoded) != data:
        errors.append(LocalDetail("envelope-not-canonical-spelling", (
            label, opaque_ref("json-value", data))))

    if "display_utf8" in value:
        shown = value["display_utf8"]
        if not isinstance(shown, str):
            errors.append(LocalDetail("envelope-display-not-string", (label,)))
        else:
            try:
                if decoded.decode("utf-8") != shown:
                    errors.append(LocalDetail("envelope-display-disagrees", (label,)))
            except UnicodeDecodeError:
                errors.append(LocalDetail("envelope-display-not-utf8", (label,)))
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
            "unknown-provider",
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
                "authority-mismatch",
                f"{provider}/{model}: catalog {field} is a {type(claimed).__name__}, not a string; "
                "a value that cannot be compared to the registry cannot be accepted"
            )
        if claimed.strip().rstrip("/") != entry[field].rstrip("/"):
            raise EndpointRejected(
                "authority-mismatch",
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
                "authority-mismatch",
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
        raise EndpointRejected(
            "scheme-not-https", f"api_base must be https, got {parts.scheme or '(none)'!r}")
    if not parts.hostname:
        raise EndpointRejected("no-host", "api_base must name a host")
    if parts.username or parts.password:
        raise EndpointRejected("userinfo-present", "api_base must not carry userinfo")
    if parts.query:
        raise EndpointRejected("query-present", "api_base must not carry a query string")
    if parts.fragment:
        raise EndpointRejected("fragment-present", "api_base must not carry a fragment")
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
    # `detail` is free text and stays in memory. These are what may cross
    # into a receipt, and each is local because its *vocabulary* is local,
    # not because of where it was produced. "It is a Python class name"
    # was the earlier argument and it did not hold: `SendResult` is
    # constructible by an injected sender, `"BearerSecretValue"` satisfies
    # `str.isidentifier()`, and syntax is not provenance.
    reason: str | None = None
    failure_kind: str | None = None
    # The exception class as it was raised, kept **raw** and ephemeral. An
    # earlier version carried the digest, and validation checked that it was
    # 64 hex characters — which is the same mistake as the `isidentifier()`
    # check it replaced, in a longer alphabet. A 64-hex credential passes a
    # 64-hex check. Producers report observations; the consumer projects.
    failure_class: str | None = None


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

# What kind of thing went wrong, closed. The concrete exception class is often
# worth knowing — `BadStatusLine` and `LineTooLong` are different problems — so
# it crosses beside this as a digest, which anyone can recompute for a class
# they suspect without the field being able to carry anything else.
TRANSPORT_FAILURE_KINDS = (
    "timeout-error",
    "url-error",
    "http-framing-error",
    "body-read-error",
    "os-error",
    "request-construction-error",
)

# Every kind of failure this module is willing to name, transport and internal
# alike. `project_exception` refuses anything outside it, so a new catch site
# cannot invent a classification on its way to a receipt.
INTERNAL_FAILURE_KINDS = ("internal-error",)

FAILURE_KINDS = TRANSPORT_FAILURE_KINDS + INTERNAL_FAILURE_KINDS


# A class name is short. The bound is here so that closing the numeric channel
# on the right does not open a textual one on the left for symmetry.
FAILURE_CLASS_MAX_BYTES = 256


def project_exception(prefix: str, kind: str, exc: BaseException) -> dict[str, Any]:
    """The durable form of a caught exception, for **every** path that catches one.

    `SendResult` got this treatment first and `guarded_receipt` did not, so a
    dynamically named class — `type("BearerSecretValue", (Exception,), {})` —
    still reached a receipt verbatim through the second path. Two projections
    for one fact is how a class of defect keeps one instance alive. There is one
    now, and the durable-field inventory requires every exception-class field to
    carry the same domain.
    """
    if kind not in FAILURE_KINDS:
        raise ValueError(f"unknown failure kind {kind!r}")
    return {
        f"{prefix}_kind": kind,
        **opaque(f"{prefix}_class", "failure-class", type(exc).__name__),
    }


def failure_evidence(kind: str, exc: BaseException | None) -> dict[str, str | None]:
    """What the transport observed: a local kind, and the class it caught.

    Deliberately *not* a digest. Projection belongs to the consumer that
    writes the receipt, not to the producer that hands it a value — otherwise
    an injected sender can submit a finished digest and the boundary has
    nothing left to check but its spelling.
    """
    return {"failure_kind": kind, "failure_class": type(exc).__name__ if exc is not None else None}


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


def validate_send_result(result: SendResult, response_limit: int = MAX_RESPONSE_BYTES) -> SendResult:
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
    if result.body is not None and len(result.body) > response_limit:
        raise ValueError("body is longer than the local response limit")

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
        # And when there is no body, nothing local contradicts the number — which
        # is the whole opening. `int.from_bytes(secret, "big")` is a perfectly
        # non-negative integer, and an `after-headers` result carries it straight
        # into a receipt. The transport's own limit is the only fact that bounds
        # it: `read_bounded` reads `limit + 1` deliberately, to prove overflow,
        # so one past the limit is the largest count this contract can produce.
        # The message never repeats the number.
        if observed > response_limit + 1:
            raise ValueError("body_bytes_observed exceeds the local response limit")

    if result.reason is not None and result.reason not in TRANSPORT_REASONS:
        raise ValueError(f"unknown transport reason {result.reason!r}")
    # A Python identifier, because that is all a class name can be. Cheap to
    # check and it makes "this field is local" an assertion rather than a
    # convention somebody has to keep.
    if result.failure_kind is not None and result.failure_kind not in TRANSPORT_FAILURE_KINDS:
        raise ValueError(f"unknown transport failure kind {result.failure_kind!r}")
    if result.failure_class is not None:
        if not isinstance(result.failure_class, str):
            raise ValueError(
                f"failure_class must be a string, got {type(result.failure_class).__name__}")
        if len(result.failure_class.encode("utf-8", "surrogatepass")) > FAILURE_CLASS_MAX_BYTES:
            raise ValueError("failure_class is longer than the local bound")
    if result.request_id is not None:
        if not shape["response_derived"]:
            raise ValueError(
                f"send stage {result.stage!r} means no headers arrived, so it cannot "
                f"also carry the request id "
                f"{opaque_ref('request-id', result.request_id).render()}"
            )
        if not isinstance(result.request_id, str):
            raise ValueError(f"request_id must be a string, got {type(result.request_id).__name__}")
        # A length is a number the provider picks. `body_bytes_observed` was
        # bounded and this was not, which is the same channel one field over.
        if len(result.request_id.encode("utf-8", "surrogatepass")) > EVIDENCE_MAX_BYTES["request-id"]:
            raise ValueError("request_id is longer than the local bound")
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


def as_send_result(value: Any, response_limit: int = MAX_RESPONSE_BYTES) -> SendResult:
    """Accept a `SendResult`, or a positional tuple from an injected `send`.

    Deliberately narrow: this is the test-injection boundary, not a general
    coercion. Everything inside this module builds a `SendResult` directly.
    """
    if isinstance(value, SendResult):
        return validate_send_result(value, response_limit)
    fields = tuple(value)
    result = SendResult(*fields)
    if len(fields) < 4:
        result = result._replace(stage=infer_stage(result.status, result.body))
    # Validated on every path, including the explicit one. A stage supplied by
    # hand is a claim like any other and gets no more credit for being written
    # down than for being deduced.
    return validate_send_result(result, response_limit)


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
                "body-capture-failure", **failure_evidence("body-read-error", read_exc),
            )
        return SendResult(exc.code, raw, "", "completed", len(raw), request_id)
    except TimeoutError as exc:
        return SendResult(None, None, "timeout", "before-response",
                          reason="timeout", **failure_evidence("timeout-error", exc))
    except urllib.error.URLError as exc:
        reason = exc.reason
        detail = "timeout" if isinstance(reason, TimeoutError) else str(reason)
        timed_out = isinstance(reason, TimeoutError)
        return SendResult(
            None, None, detail, "before-response",
            reason="timeout" if timed_out else "connection-failed",
            **failure_evidence(
                "timeout-error" if timed_out else "url-error",
                reason if isinstance(reason, BaseException) else exc,
            ),
        )
    except http.client.HTTPException as exc:
        # `BadStatusLine`, `LineTooLong` and the rest of the framing family
        # derive from `HTTPException`, not from `OSError`, and urllib re-raises
        # them rather than wrapping them in `URLError` — so they escaped every
        # handler here and `guarded_receipt` filed provider-controlled wire
        # corruption as `INTERNAL_ERROR`, a defect in this tool.
        return SendResult(
            None, None, capture_detail("HTTP framing failure", exc), "response-framing",
            reason="http-framing-failure", **failure_evidence("http-framing-error", exc),
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
            "body-capture-failure", **failure_evidence("body-read-error", exc),
        )
    return SendResult(status, raw, "", "completed", len(raw), request_id)


def key_bound_sender(key_env: str, response_limit: int = MAX_RESPONSE_BYTES):
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
            return send_json(url, body, key, timeout, response_limit)
        except ValueError as exc:
            # Last resort. `send_json` validates the key first, so this should be
            # unreachable — but an exception carrying a header value must never
            # escape toward `main`, which prints `ValueError` to stderr.
            del exc
            return SendResult(None, None, "the request could not be constructed",
                              "before-response", reason="request-not-constructed",
                              failure_kind="request-construction-error")

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
        raise EndpointRejected(exc.reason, f"{provider}/{model}: {exc}") from exc
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


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------
#
# `classification` decides whether a target may be spent money on, so the set of
# places allowed to write it is a security property of this file. It used to be
# eighteen `receipt.update(classification=...)` calls spread over four hundred
# lines, each pairing a verdict with a detail string composed on the spot. Every
# review round found one of them out of step with the others — a stale free-text
# detail here, `sent.detail` consulted instead of `sent.reason` there — and each
# was repaired where it was found.
#
# The repairs were right and the method was not: a contract checked at the sites
# a reviewer happened to visit is a contract with as many exceptions as there are
# sites nobody visited. So a verdict is now a value:
#
#     facts (all local, all typed)  ->  reduce_*  ->  Decision  ->  apply_decision
#
# `apply_decision` is the only writer of `classification`, `decision_reason` and
# `detail`, an AST gate in the test suite enforces that rather than trusting it,
# and both vocabularies are closed per schema. A verdict this module has not
# enumerated cannot be recorded, and a reason it has not enumerated cannot
# either.

# The seed a receipt carries before anything has been decided. It is never the
# value of a returned receipt — every exit runs through `apply_decision` — and
# the suite asserts that rather than leaving it as a hope.
PENDING_CLASSIFICATION = "UNAVAILABLE"

# Availability probing and qualification answer different questions and have
# always had different verdict vocabularies: a probe says `AUTH_FAILURE` where a
# qualification says `AUTH_FAILED`, `MODEL_NOT_FOUND` where the other says
# `MODEL_MISSING`. The qualification set was written down five rounds ago; the
# probe's was not, so a typo there would have produced a receipt with a
# classification no consumer knows and nothing would have objected.
PROBE_CLASSIFICATIONS = (
    "ENDPOINT_REJECTED",
    "AUTH_FAILURE",
    "RESPONSE_CAPTURE_FAILED",
    "TIMEOUT",
    "TRANSPORT_FAILURE",
    "REDIRECT_NOT_FOLLOWED",
    "MODEL_NOT_FOUND",
    "RATE_LIMITED",
    "PROVIDER_5XX",
    "HTTP_FAILURE",
    "INVALID_OUTPUT",
    "PROVIDER_SUBSTITUTED",
    "MODEL_IDENTITY_MISSING",
    "INTERNAL_ERROR",
    "PASS",
)

# Why the verdict is what it is, in this module's own words, closed. A
# classification says what to do about a target; a reason says which rule fired,
# and two rules that reach the same classification are two different findings.
DECISION_REASONS = (
    "endpoint-rejected",
    "transport-failed",
    "provider-rejected-request",
    "probe-token-matched",
    "probe-token-mismatched",
    "probe-unmappable-completion",
    "unmappable-completion",
    "assistant-message-rejected",
    "undeclared-tools-called",
    "tool-arguments-unparseable",
    "tool-arguments-schema-violation",
    "multiple-terminal-answers",
    "terminal-answer-with-operations",
    "terminal-answer-before-roundtrip",
    "no-terminal-answer-within-budget",
    "protocol-and-identity-verified",
    "canary-answer-mismatched",
    "identity-substituted",
    "identity-unestablished",
    "internal-exception",
)

# Keyed by schema, because the two receipt kinds answer different questions and
# have always had different verdict words. The qualification entry is added
# where that vocabulary is declared, a few hundred lines below.
SCHEMA_CLASSIFICATIONS: dict[str, tuple[str, ...]] = {
    PROBE_SCHEMA: PROBE_CLASSIFICATIONS,
}


@dataclass(frozen=True)
class Decision:
    """A verdict, the rule that produced it, and the line a reader sees.

    The three travel together because they are one fact. Held apart they drift:
    a detail written at one exit outlived the classification beside it for three
    rounds, and read as a transport failure on a receipt classified `PASS`.
    """

    classification: str
    reason: str
    # A `LocalDetail`, not a string. `apply_decision` is the only caller of
    # `render()`, so no exit can hand a receipt a line it composed itself — the
    # hole a purely lexical check on the finished string could not close.
    detail: "LocalDetail"


def admissible_classifications(schema: str) -> tuple[str, ...]:
    known = SCHEMA_CLASSIFICATIONS.get(schema)
    if known is None:
        raise ValueError(f"no classification vocabulary for schema {schema!r}")
    return known


def apply_decision(receipt: dict[str, Any], decision: Decision, **extra: Any) -> dict[str, Any]:
    """Record a decision. **The only writer of `classification` in this module.**

    Both vocabularies are checked against the receipt's own schema, so a probe
    cannot be handed a qualification verdict and a new exit cannot invent one.
    `extra` carries the fields that belong to the same moment — `turn_count`,
    `latency_ms` — because a verdict written without the count of turns it took
    is a receipt that has to be read in two places to be believed.
    """
    if decision.classification not in admissible_classifications(receipt.get("schema", "")):
        raise ValueError(
            f"{decision.classification!r} is not a classification of "
            f"{receipt.get('schema')!r}"
        )
    if decision.reason not in DECISION_REASONS:
        raise ValueError(f"unknown decision reason {decision.reason!r}")
    receipt.update(extra)
    receipt["classification"] = decision.classification
    receipt["decision_reason"] = decision.reason
    # The template travels with the line. It is what makes the durable-field
    # inventory able to *rebuild* the string from the vocabulary each slot
    # declares, rather than inspect the finished text and guess at its origin.
    receipt["detail_template"] = decision.detail.template
    receipt["detail"] = decision.detail.render()
    return receipt


# --- rendered detail lines ------------------------------------------------
#
# A registered template plus typed arguments, and nothing else. `detail` used to
# be an f-string built at each exit and checked lexically afterwards, which
# proves a line could have been written here — not that it was. A provider can
# send `"timeout"`, or `"the completion carried the probe token"`, or sixteen
# hex characters, and all three pass any check made of words and bytes.
#
# So the check is made of construction instead. A `LocalDetail` names a template
# from the closed table below and carries arguments that are *typed*: a member
# of a named local vocabulary, a bounded count, an HTTP status, a type name, a
# trusted local value, or an `OpaqueRef`/`DigestRef`. Validation happens in
# `__post_init__`, so an inadmissible line cannot be constructed at all — and
# the receipt records which template it came from, so the durable-field
# inventory can rebuild the pattern and check the string against it.

# The largest number a rendered line may state, for the same reason every
# durable integer is bounded: an unbounded number is an unbounded channel, and
# a sentence is where nobody looks for one.
DETAIL_MAX_COUNT = 9_999_999

# The vocabularies a slot may draw on, by name. Resolved when a value is
# checked rather than when the table is built, because they are declared all
# over this file and an import-order constraint is not a design.
DETAIL_VOCABULARIES = (
    "ENDPOINT_REJECTION_REASONS",
    "TRANSPORT_REASONS",
    "TRANSPORT_FAILURE_KINDS",
    "QUALIFY_REASONS",
    "COMPLETION_PARSE_KINDS",
    "NONCANONICAL_REASONS",
    "ENVELOPE_LABELS",
)


def vocabulary(name: str) -> tuple[str, ...]:
    if name not in DETAIL_VOCABULARIES:
        raise ValueError(f"{name!r} is not a vocabulary a detail slot may name")
    return globals()[name]


def slot_problem(slot: str, value: Any) -> str | None:
    """What is wrong with one argument, given the slot it is filling."""
    if slot == "ref":
        return None if isinstance(value, OpaqueRef) else "is not an opaque reference"
    if slot == "refs":
        return (None if isinstance(value, tuple) and all(isinstance(v, OpaqueRef) for v in value)
                else "is not a tuple of opaque references")
    if slot == "digests":
        return (None if isinstance(value, tuple) and all(isinstance(v, DigestRef) for v in value)
                else "is not a tuple of digest references")
    if slot == "type":
        return None if isinstance(value, TypeName) else "is not a type name"
    if slot == "discriminator":
        return None if isinstance(value, Discriminator) else "is not a discriminator"
    if slot == "label":
        return None if isinstance(value, EnvelopeLabel) else "is not an envelope label"
    if slot == "key-env":
        return (None if isinstance(value, LocalValue) and value.source == "key_env"
                else "is not the trusted key_env")
    if slot == "detail":
        return None if isinstance(value, LocalDetail) else "is not a local detail"
    if slot == "details":
        return (None if isinstance(value, tuple) and all(isinstance(v, LocalDetail) for v in value)
                else "is not a tuple of local details")
    if slot == "kinds":
        known = tuple(kind for _, kind in ARGUMENT_ERROR_KINDS) + ("other",)
        return (None if isinstance(value, tuple) and all(v in known for v in value)
                else "is not a tuple of argument error kinds")
    if slot == "count":
        return (None if type(value) is int and 0 <= value <= DETAIL_MAX_COUNT
                else "is not a bounded count")
    if slot == "status":
        return None if is_http_status(value) else "is not an HTTP status"
    if slot.startswith("enum:"):
        return None if value in vocabulary(slot[5:]) else f"is not a member of {slot[5:]}"
    raise ValueError(f"unknown detail slot kind {slot!r}")


def render_slot(slot: str, value: Any) -> str:
    if slot in ("ref", "type", "discriminator", "label", "key-env", "detail"):
        return value.render()
    if slot in ("refs", "digests"):
        return ", ".join(item.render() for item in value)
    if slot == "details":
        return "; ".join(item.render() for item in value)
    if slot == "kinds":
        return ", ".join(value)
    return str(value)


# name -> (text, slot kinds). The closed world of things a receipt may say.
# Adding a line means adding a row here; there is no other way to reach `detail`.
DETAIL_TEMPLATES: dict[str, tuple[str, tuple[str, ...]]] = {
    # -- transport and endpoint --
    "endpoint-rejected": ("endpoint rejected: {0}", ("enum:ENDPOINT_REJECTION_REASONS",)),
    "transport": ("{0}", ("enum:TRANSPORT_REASONS",)),
    "transport-kind": ("{0} ({1})", ("enum:TRANSPORT_REASONS", "enum:TRANSPORT_FAILURE_KINDS")),
    "transport-key": ("{0}: {1}", ("enum:TRANSPORT_REASONS", "key-env")),
    "transport-kind-key": ("{0} ({1}): {2}",
                           ("enum:TRANSPORT_REASONS", "enum:TRANSPORT_FAILURE_KINDS", "key-env")),
    # One wrapper rather than eight combinations: the status is a fact about the
    # exchange and the line inside it is a fact about the failure.
    "http": ("HTTP {0}: {1}", ("status", "detail")),
    "provider-rejected": ("{0}", ("enum:QUALIFY_REASONS",)),

    # -- probe grading --
    "probe-unmappable": ("the 2xx body could not be mapped to a completion", ()),
    "probe-substituted": ("the response named a model other than the one requested", ()),
    "probe-identity-missing": ("the response named no model; identity unestablished", ()),
    "probe-token-mismatch": ("the completion did not carry the probe token", ()),
    "probe-token-matched": ("the completion carried the probe token", ()),

    # -- qualification outcome --
    "unmappable-completion": ("unmappable 2xx completion: {0}", ("enum:COMPLETION_PARSE_KINDS",)),
    "identity-substituted": ("the provider reported {0} other model(s): {1}", ("count", "digests")),
    "identity-unestablished": (
        "no successful response named a model; the protocol held but the identity "
        "of what produced it is unestablished", ()),
    "canary-mismatch": ("{0}", ("details",)),
    "qualified": ("the protocol held and the identity was verified", ()),
    "no-terminal-answer": ("no terminal answer within {0} turns", ("count",)),
    "internal-exception": ("provider-matrix raised an internal exception", ()),

    # -- the assistant message contract --
    "role-not-assistant": ("tool calls arrived under role {0}, not 'assistant'", ("discriminator",)),
    "assistant-content-type": (
        "assistant content was {0}; openai-chat admits a string, null, or no content at all",
        ("type",)),
    "no-tool-calls": ("assistant message carried no tool_calls", ()),
    "tool-calls-not-array": ("tool_calls was {0}, not an array", ("type",)),
    "empty-tool-calls": ("assistant message carried an empty tool_calls array", ()),
    "call-not-object": ("a tool call was not an object", ()),
    "call-type-not-function": ("tool call type was {0}, not 'function'", ("discriminator",)),
    "call-id-missing": ("a tool call lacked a non-empty string id", ()),
    "duplicate-call-id": ("a tool call id appeared more than once: {0}", ("ref",)),
    "call-without-function": ("tool call {0} lacked a function object", ("ref",)),
    "call-without-name": ("tool call {0} lacked a function name", ("ref",)),
    "arguments-object-dialect": (
        "{0} arguments arrived as a JSON {1}; openai-chat requires a JSON string", ("ref", "type")),
    "arguments-not-string": ("{0} arguments were {1}, not a string", ("ref", "type")),

    # -- the arguments themselves --
    "arguments-duplicate-key": ("arguments for {0} name a field twice", ("ref",)),
    "arguments-unacceptable-json": (
        "arguments for {0} are not acceptable JSON: {1}", ("ref", "enum:COMPLETION_PARSE_KINDS")),
    "arguments-invalid-json": ("arguments for {0} are not valid JSON", ("ref",)),
    "arguments-not-object": ("arguments for {0} decoded to {1}, not an object", ("ref", "type")),
    "arguments-schema-violation": (
        "{0} arguments violate the declared schema: {1} error(s), {2}", ("ref", "count", "kinds")),

    # -- the loop's own protocol rules --
    "undeclared-tools": ("called {0} tool(s) that were never declared: {1}", ("count", "refs")),
    "multiple-answers": ("{0} terminal answers in one response", ("count",)),
    "answer-with-operations": ("a terminal answer alongside {0} operation(s)", ("count",)),
    "answer-before-roundtrip": ("terminal answer before any operation/tool-result roundtrip", ()),

    # -- the canary's grading --
    "answer-bytes-unseen": ("answer bytes {0} were not in any result this run returned", ("ref",)),
    "handle-with-no-handles": (
        "cited handle {0} but no operation in this run returned a handle", ("ref",)),
    "handle-never-returned": (
        "cited handle {0} was never returned by any operation in this run", ("ref",)),
    "citation-unsupported": ("citation {0} is not in the support this run returned", ("ref",)),

    # -- the byte envelope --
    "envelope-not-object": ("{0}: byte value envelope must be an object", ("label",)),
    "envelope-unknown-field": ("{0}: unknown field {1} in byte value envelope", ("label", "ref")),
    "envelope-encoding": ("{0}: encoding must be 'base64url-nopad', got {1}",
                          ("label", "discriminator")),
    "envelope-data-not-string": ("{0}: envelope needs a string `data`", ("label",)),
    "envelope-noncanonical": ("{0}: {1}", ("label", "enum:NONCANONICAL_REASONS")),
    "envelope-noncanonical-character": (
        "{0}: base64url-nopad rejects {1}; padding and '+/' are not accepted", ("label", "ref")),
    "envelope-not-canonical-spelling": (
        "{0}: {1} is not the canonical spelling of the bytes it decodes to", ("label", "ref")),
    "envelope-display-not-string": ("{0}: `display_utf8` must be a string", ("label",)),
    "envelope-display-disagrees": ("{0}: `display_utf8` disagrees with the decoded bytes", ("label",)),
    "envelope-display-not-utf8": (
        "{0}: `display_utf8` present but the bytes are not UTF-8", ("label",)),
}


@dataclass(frozen=True)
class LocalDetail:
    """A line this module composed, as the template and the values it composed it from.

    Validated on construction rather than on inspection: a line that cannot be
    built is better than a line that has to be recognised afterwards, and
    recognising-afterwards is exactly what the lexical check could only do.
    """

    template: str
    args: tuple[Any, ...] = ()

    def __post_init__(self) -> None:
        spec = DETAIL_TEMPLATES.get(self.template)
        if spec is None:
            raise ValueError(f"unregistered detail template {self.template!r}")
        _text, slots = spec
        if len(self.args) != len(slots):
            raise ValueError(
                f"{self.template} takes {len(slots)} argument(s), got {len(self.args)}")
        for value, slot in zip(self.args, slots):
            problem = slot_problem(slot, value)
            if problem is not None:
                raise ValueError(f"{self.template}: the {slot} argument {problem}")

    def render(self) -> str:
        text, slots = DETAIL_TEMPLATES[self.template]
        return text.format(*(render_slot(slot, value)
                             for slot, value in zip(slots, self.args)))


def endpoint_rejected_detail(reason: str) -> LocalDetail:
    return LocalDetail("endpoint-rejected", (reason,))


def transport_detail(
    status: int | None, reason: str, failure_kind: str | None, key_env: LocalValue | None
) -> LocalDetail:
    """One renderer for both paths, because it was one line written twice.

    The probe built `HTTP {status}: {reason}` by overwriting `detail` after the
    fact; qualification built the same string forward. Two spellings of one
    sentence is how a fix to one of them stops being a fix.
    """
    if failure_kind is not None and key_env is not None:
        line = LocalDetail("transport-kind-key", (reason, failure_kind, key_env))
    elif failure_kind is not None:
        line = LocalDetail("transport-kind", (reason, failure_kind))
    elif key_env is not None:
        line = LocalDetail("transport-key", (reason, key_env))
    else:
        line = LocalDetail("transport", (reason,))
    return line if status is None else LocalDetail("http", (status, line))


# --- reducers -------------------------------------------------------------


@dataclass(frozen=True)
class TransportFacts:
    """What a failed exchange established. Every field local, every field typed."""

    schema: str
    stage: str
    reason: str
    failure_kind: str | None
    status: int | None
    key_env: str


# The probe's stage table, beside the qualification's `STAGE_CAUSE`. Written out
# rather than shared because the two vocabularies genuinely differ; what is
# shared is that both are total over `SEND_STAGE_SHAPES` and the suite checks it.
PROBE_STAGE_CAUSE = {
    "no-credential": "AUTH_FAILURE",
    "response-framing": "RESPONSE_CAPTURE_FAILED",
    "after-headers": "RESPONSE_CAPTURE_FAILED",
}


def reduce_transport(facts: TransportFacts) -> Decision:
    """A failed exchange, graded from its stage and its reason — never its prose.

    The probe used to read `sent.detail == "timeout"` here. `detail` is free
    text an injected sender fills in, so a verdict switched on it is a verdict
    the producer chooses; `reason` is a closed local vocabulary and was already
    beside it. That the qualification path had been moved off `detail` a round
    earlier and this one had not is the whole reason this function exists once.
    """
    if facts.schema == PROBE_SCHEMA:
        kind = PROBE_STAGE_CAUSE.get(facts.stage)
        if kind is None:
            kind = "TIMEOUT" if facts.reason == "timeout" else "TRANSPORT_FAILURE"
    else:
        kind = STAGE_CAUSE.get(facts.stage, "UNAVAILABLE")
    key_env = (LocalValue("key_env", facts.key_env)
               if facts.reason == "credential-missing" else None)
    return Decision(
        kind,
        "transport-failed",
        transport_detail(facts.status, facts.reason, facts.failure_kind, key_env),
    )


@dataclass(frozen=True)
class ProbeFacts:
    """The probe's grading inputs. Note what is absent: `detail`.

    A reducer that can read a free-text field will eventually branch on one.
    """

    model_status: str
    output_state: str  # matched | mismatched | unmappable


PROBE_OUTPUT_STATES = ("matched", "mismatched", "unmappable")


def reduce_probe(facts: ProbeFacts) -> Decision:
    """Grade a completed 2xx probe. Identity outranks content, as it must.

    A response whose text is right but whose `model` names another model tells
    us about that other model. The old chain reached the same answer; it reached
    it through four `elif`s interleaved with the writes they guarded, which is
    why the order was checkable only by reading them all.
    """
    if facts.output_state not in PROBE_OUTPUT_STATES:
        raise ValueError(f"unknown probe output state {facts.output_state!r}")
    if facts.output_state == "unmappable":
        return Decision(
            "INVALID_OUTPUT", "probe-unmappable-completion", LocalDetail("probe-unmappable"))
    if facts.model_status == "drifted":
        return Decision(
            "PROVIDER_SUBSTITUTED", "identity-substituted", LocalDetail("probe-substituted"))
    if facts.model_status == "missing":
        return Decision(
            "MODEL_IDENTITY_MISSING", "identity-unestablished",
            LocalDetail("probe-identity-missing"))
    if facts.output_state == "mismatched":
        return Decision(
            "INVALID_OUTPUT", "probe-token-mismatched", LocalDetail("probe-token-mismatch"))
    return Decision("PASS", "probe-token-matched", LocalDetail("probe-token-matched"))


def reduce_probe_http(status: int) -> Decision:
    """A non-2xx probe response: one classifier, one rendered line."""
    return Decision(
        classify_http(status), "provider-rejected-request",
        LocalDetail("http", (status, LocalDetail("provider-rejected", ("request-rejected",)))),
    )


@dataclass(frozen=True)
class AnswerFacts:
    """What a terminal answer established, once the protocol had held."""

    model_status: str
    canary_errors: tuple["LocalDetail", ...]
    substituted_digests: tuple["DigestRef", ...]


def reduce_qualification(facts: AnswerFacts) -> Decision:
    """Grade a run that reached a terminal answer.

    Identity outranks both a protocol pass and a right answer, and `missing` is
    not a milder `drifted`: a run nobody can attribute to the requested model
    says nothing about it whichever way the canary went.
    """
    if facts.model_status == "drifted":
        return Decision(
            MODEL_STATUS_VERDICT["drifted"], "identity-substituted",
            LocalDetail("identity-substituted",
                        (len(facts.substituted_digests), facts.substituted_digests)),
        )
    if facts.model_status != "verified":
        return Decision(
            MODEL_STATUS_VERDICT.get(facts.model_status, "MODEL_IDENTITY_MISSING"),
            "identity-unestablished", LocalDetail("identity-unestablished"),
        )
    if facts.canary_errors:
        return Decision(
            "CANARY_ANSWER_MISMATCH", "canary-answer-mismatched",
            LocalDetail("canary-mismatch", (facts.canary_errors,)),
        )
    return Decision("PASS", "protocol-and-identity-verified", LocalDetail("qualified"))


# The exception classes this module is willing to name in a durable field. They
# are all local — the strict JSON reader's own, and the builtins a malformed
# payload raises — but "local" is asserted here rather than assumed from the
# fact that a class name looks like an identifier, which is an argument this
# vertical has already had to withdraw twice.
COMPLETION_PARSE_KINDS = (
    "DuplicateJsonKey",
    "InvalidJsonEncoding",
    "UnadmittedJsonValue",
    "StrictJsonError",
    "JSONDecodeError",
    "KeyError",
    "IndexError",
    "TypeError",
    "AttributeError",
    "other",
)


def completion_parse_kind(exc: BaseException) -> str:
    name = type(exc).__name__
    return name if name in COMPLETION_PARSE_KINDS else "other"


# The latency a receipt is willing to state. `round((time.time() - started) *
# 1000)` is a local measurement and was still the one unbounded integer left in
# a probe receipt: a clock stepped backwards makes it negative, and nothing
# downstream had a rule to notice. A day is far past any timeout this tool
# accepts, so the clamp only ever fires on a broken clock — which is exactly
# when a receipt should say something bounded rather than something interesting.
LATENCY_MAX_MS = 24 * 60 * 60 * 1000

# The largest timeout and turn budget a receipt will record. Both arrive from
# the command line, which is local and reviewed, and both are still bounded:
# every durable integer is bounded or it is not durable evidence.
TIMEOUT_MAX_SECS = 3600.0
MAX_TURNS_BOUND = 1024


def latency_ms_since(started: float) -> int:
    return min(max(round((time.time() - started) * 1000), 0), LATENCY_MAX_MS)


def bounded_timeout(timeout: float) -> float:
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
        raise ValueError(f"timeout must be a number, got {type(timeout).__name__}")
    if not math.isfinite(timeout) or not 0 < timeout <= TIMEOUT_MAX_SECS:
        raise ValueError(f"timeout must be in (0, {TIMEOUT_MAX_SECS}]")
    return float(timeout)


def bounded_turns(max_turns: int) -> int:
    if type(max_turns) is not int or not 0 < max_turns <= MAX_TURNS_BOUND:
        raise ValueError(f"max_turns must be an int in 1..{MAX_TURNS_BOUND}")
    return max_turns


def probe_target(
    target: dict[str, Any],
    timeout: float,
    send: Any = None,
    registry: dict[str, Any] | None = None,
    response_limit: int = MAX_RESPONSE_BYTES,
) -> dict[str, Any]:
    registry = normalize_registry(registry) if registry is not None else load_registry()
    started = time.time()
    request_body = canonical_bytes({
        "model": target["model"],
        "messages": [{"role": "user", "content": "Return exactly: QODEC_PROBE_OK"}],
        "temperature": 0,
        "max_tokens": PROBE_MAX_TOKENS,
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
        # From the registry, not from the row. The row agreeing with the
        # registry is what `verify_against_registry` just established; taking
        # the value from the row afterwards makes the plan the source of a
        # durable field anyway, one line past the check that was supposed to
        # settle it.
        url = completions_url(trusted_entry(registry, target["provider"])["api_base"])
    except EndpointRejected as exc:
        # The message is for whoever is watching the run; the receipt gets the
        # reason, which is a closed vocabulary. `str(exc)` interpolates the
        # plan's own text, and a durable field with an open vocabulary is a
        # durable field no policy can enumerate.
        return apply_decision(
            result,
            Decision("ENDPOINT_REJECTED", "endpoint-rejected", endpoint_rejected_detail(exc.reason)),
        )
    result["endpoint"] = url

    send = send if send is not None else key_bound_sender(target["key_env"], response_limit)
    sent = as_send_result(send(url, request_body, timeout), response_limit)
    latency = latency_ms_since(started)
    # The header is provider-controlled and the provider has seen the bearer
    # token, so `x-request-id` is a channel for handing it back. The raw value
    # stays in `sent`, in memory; the artifact gets evidence about it.
    result.update(opaque("request_id", "request-id", sent.request_id))
    if sent.stage != "completed":
        # A body-read failure is not unavailability: the provider answered, the
        # generation exists, and it will appear on the bill. Which stage maps to
        # which verdict is `PROBE_STAGE_CAUSE`'s to say, not this function's —
        # the chain of `elif`s that used to live here read `sent.detail`, which
        # is free text an injected sender fills in.
        failure = project_transport_failure(sent, response_limit)
        result.update(failure)
        if sent.status is not None:
            result["http_status"] = sent.status
        if sent.body_bytes_observed is not None:
            result["body_bytes_observed"] = sent.body_bytes_observed
        return apply_decision(
            result,
            reduce_transport(TransportFacts(
                schema=PROBE_SCHEMA,
                stage=sent.stage,
                reason=failure["transport_reason"],
                failure_kind=sent.failure_kind,
                status=sent.status,
                key_env=target["key_env"],
            )),
            latency_ms=latency,
        )

    status, raw = sent.status, sent.body or b""
    if not 200 <= status < 300:
        result.update(
            http_status=status,
            response_sha256=evidence_digest("response-body", raw),
            response_bytes=len(raw),
        )
        return apply_decision(result, reduce_probe_http(status), latency_ms=latency)

    result.update(
        http_status=status,
        response_sha256=evidence_digest("response-body", raw),
        response_bytes=len(raw),
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
    except (StrictJsonError, json.JSONDecodeError, KeyError, TypeError, IndexError, AttributeError) as exc:
        result["completion_parse_kind"] = completion_parse_kind(exc)
        return apply_decision(
            result, reduce_probe(ProbeFacts(model_status="missing", output_state="unmappable")))
    result.update(model_evidence(target["model"], reported_model))
    # Three-valued, like the qualification side. The old `if reported_model and
    # ...` let a response that named no model fall through to PASS whenever the
    # text happened to be right, so a target whose identity was never
    # established could satisfy the "PASS on both probes" gate.
    status_of_model = model_status_of(target["model"], reported_model)
    result["model_status"] = status_of_model
    if isinstance(payload.get("usage"), dict):
        result["provider_usage"] = normalize_provider_usage(
            payload["usage"], usage_bounds(len(request_body), PROBE_MAX_TOKENS))
    # The token comparison is the only place the provider's text is read, and
    # what leaves it is one of three local words. The grading itself is
    # `reduce_probe`'s, which never sees the completion at all.
    return apply_decision(result, reduce_probe(ProbeFacts(
        model_status=status_of_model,
        output_state="matched" if content == "QODEC_PROBE_OK" else "mismatched",
    )))


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

# Late-bound because the qualification vocabulary is declared here, several
# hundred lines below the machinery that enforces it. A dict entry rather than a
# second constant, so there is exactly one table to consult and no way to add a
# schema to one half of the pair.
SCHEMA_CLASSIFICATIONS[QUALIFY_SCHEMA] = CLASSIFICATIONS


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
# The reason a stage implies, for a sender that supplied none. Same vocabulary
# as `TRANSPORT_REASONS`, because `transport_reason` is declared over it and a
# fallback that answers in another language is not a fallback.
STAGE_REASON = {
    "no-credential": "credential-missing",
    "before-response": "connection-failed",
    "response-framing": "http-framing-failure",
    "after-headers": "body-capture-failure",
}

STAGE_OUTCOME = {
    "no-credential": "no-credential",
    "before-response": "transport-failure",
    "response-framing": "response-capture-failure",
    "after-headers": "response-capture-failure",
}


def project_transport_failure(sent: SendResult, response_limit: int) -> dict[str, Any]:
    """The durable form of a failed exchange, computed **here**.

    The consumer owns the boundary. `SendResult` is constructible by an injected
    sender, so anything it hands over is a raw observation to be checked against
    local facts and local bounds — never a finished artifact to be copied. That
    is why the digest is taken at this line rather than accepted from the field:
    a producer that submits `failure_class_sha256` leaves this boundary with
    nothing to verify except that the string looks like a digest, and a 64-hex
    credential looks exactly like a digest.

    Re-validating here is deliberate belt behind brace: `as_send_result` already
    ran, and this is the last place before the value becomes a file.
    """
    validate_send_result(sent, response_limit)
    fields: dict[str, Any] = {"transport_reason": transport_reason(sent)}
    if sent.failure_kind is not None:
        fields["failure_kind"] = sent.failure_kind
    fields.update(opaque("failure_class", "failure-class", sent.failure_class))
    return fields


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
    # An injected `send` that supplied no reason gets the reason its stage
    # implies — from `TRANSPORT_REASONS`, the vocabulary this field is declared
    # over. It used to fall back to `STAGE_OUTCOME`, whose words are the *turn
    # outcome* vocabulary, so one durable field could hold a member of either of
    # two enums depending on which sender produced it. Two vocabularies in one
    # field is a field with no vocabulary; the inventory found it the first time
    # it ran.
    return STAGE_REASON.get(sent.stage, "connection-failed")

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
        "max_tokens": QUALIFY_MAX_TOKENS,
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
    problem: tuple[str, "LocalDetail"] | None


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
            ("PROTOCOL_VIOLATION", LocalDetail("role-not-assistant", (
                discriminator("message-role", role, MESSAGE_ROLES),))),
        )
    # Before anything else about the calls: a message whose own fields are the
    # wrong type is malformed whatever it happens to be asking for, and this
    # verdict has to land before an operation runs, before a roundtrip is
    # acknowledged, and before the message can be replayed.
    content = message.get("content")
    if content is not None and not isinstance(content, str):
        return ParsedAssistant(
            [], None,
            ("PROTOCOL_VIOLATION",
             LocalDetail("assistant-content-type", (TypeName.of(content),))),
        )
    raw = message.get("tool_calls")
    if raw is None:
        return ParsedAssistant(
            [], content, ("NO_TERMINAL_ANSWER", LocalDetail("no-tool-calls"))
        )
    if not isinstance(raw, list):
        return ParsedAssistant(
            [], content,
            ("PROTOCOL_VIOLATION", LocalDetail("tool-calls-not-array", (TypeName.of(raw),))),
        )
    if not raw:
        return ParsedAssistant(
            [], content, ("NO_TERMINAL_ANSWER", LocalDetail("empty-tool-calls")),
        )

    calls: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            return ParsedAssistant(
                [], content, ("PROTOCOL_VIOLATION", LocalDetail("call-not-object")))
        kind = entry.get("type")
        if kind != "function":
            # Not pedantry: a strict mapper switches on this field, and a call
            # arriving as anything else is a shape it will not deserialize.
            return ParsedAssistant(
                [], content,
                ("PROTOCOL_VIOLATION", LocalDetail("call-type-not-function", (
                    discriminator("tool-call-type", kind, TOOL_CALL_TYPES),))),
            )
        call_id = entry.get("id")
        if not isinstance(call_id, str) or not call_id:
            return ParsedAssistant(
                [], content, ("PROTOCOL_VIOLATION", LocalDetail("call-id-missing"))
            )
        if call_id in seen_ids:
            # Results are returned keyed by id. Two calls sharing one id make the
            # linkage ambiguous, and the ambiguity is resolved by whichever
            # result happens to be written last.
            return ParsedAssistant(
                [], content,
                ("PROTOCOL_VIOLATION", LocalDetail("duplicate-call-id", (
                    opaque_ref("tool-call-id", call_id),))),
            )
        seen_ids.add(call_id)
        function = entry.get("function")
        if not isinstance(function, dict):
            return ParsedAssistant(
                [], content,
                ("PROTOCOL_VIOLATION", LocalDetail("call-without-function", (
                    opaque_ref("tool-call-id", call_id),))),
            )
        name = function.get("name")
        if not isinstance(name, str) or not name:
            return ParsedAssistant(
                [], content,
                ("PROTOCOL_VIOLATION", LocalDetail("call-without-name", (
                    opaque_ref("tool-call-id", call_id),))),
            )
        arguments = function.get("arguments")
        if isinstance(arguments, (dict, list)):
            # A coherent other dialect — Anthropic sends arguments as an object —
            # not a malformed OpenAI response. Named separately because the fix
            # is a different adapter, not a better prompt.
            return ParsedAssistant([], content, (
                "DIALECT_MISMATCH",
                LocalDetail("arguments-object-dialect", (
                    opaque_ref("tool-name", name), TypeName.of(arguments))),
            ))
        if not isinstance(arguments, str):
            return ParsedAssistant([], content, (
                "PROTOCOL_VIOLATION",
                LocalDetail("arguments-not-string", (
                    opaque_ref("tool-name", name), TypeName.of(arguments))),
            ))
        calls.append({"id": call_id, "name": name, "raw_arguments": arguments})
    return ParsedAssistant(calls, content, None)


def decode_arguments(call: dict[str, Any]) -> tuple[dict[str, Any] | None, "LocalDetail | None"]:
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
        return None, LocalDetail("arguments-duplicate-key", (named,))
    except StrictJsonError as exc:
        return None, LocalDetail(
            "arguments-unacceptable-json", (named, completion_parse_kind(exc)))
    except json.JSONDecodeError:
        return None, LocalDetail("arguments-invalid-json", (named,))
    if not isinstance(parsed, dict):
        return None, LocalDetail("arguments-not-object", (named, TypeName.of(parsed)))
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
    #
    # These messages are counted, classified and digested by `error_evidence`
    # and never reach a receipt as text, so they are rendered here. The path a
    # label names is walked out of provider-supplied arguments, so it crosses as
    # a reference even on this path.
    for label, envelope in walk_envelopes(args):
        errors.extend(problem.render() for problem in
                      envelope_errors(envelope, EnvelopeLabel(
                          ref=opaque_ref("json-value", label)))[0])
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
            errors, decoded = envelope_errors(envelope, EnvelopeLabel(known="canned"))
            if not errors and decoded is not None:
                self.bytes.add(decoded)


def canary_answer_errors(args: dict[str, Any], observed: Observed) -> list[LocalDetail]:
    """Did the target answer the question, or merely satisfy the schema?

    Kept apart from the protocol causes on purpose. A model that speaks the
    dialect perfectly and cites a handle it was never given has qualified the
    wire and failed the task; folding the two together would hide whichever
    happened to be checked second, and they call for opposite actions — one is
    a target to drop, the other a prompt to fix.

    Every comparison below is against `observed`, never against a constant.
    """
    errors: list[LocalDetail] = []

    # Every value named below came out of the provider's `arguments`, so none of
    # them is spelled out: these lines reach `detail` and `detail` reaches a
    # committed receipt. A digest is enough to compare two runs, or to compare a
    # cited handle against one the operator can hash themselves.
    envelope_problems, decoded = envelope_errors(
        args.get("answer"), EnvelopeLabel(known="answer"))
    errors.extend(envelope_problems)
    if decoded is not None and decoded not in observed.bytes:
        errors.append(LocalDetail("answer-bytes-unseen", (opaque_ref("answer-bytes", decoded),)))

    handle = args.get("handle")
    named = opaque_ref("handle", handle)
    if not observed.handles:
        errors.append(LocalDetail("handle-with-no-handles", (named,)))
    elif handle not in observed.handles:
        errors.append(LocalDetail("handle-never-returned", (named,)))

    cited = args.get("cited")
    for citation in cited if isinstance(cited, list) else []:
        spelled = json.dumps(citation, sort_keys=True)
        if spelled not in observed.support:
            errors.append(LocalDetail("citation-unsupported", (opaque_ref("citation", spelled),)))
    return errors


def canned_result_for(name: str) -> dict[str, Any]:
    return CANNED_RECORDS if name == "qodec_materialize" else CANNED_RESULT


def record_detail(record: dict[str, Any], why: LocalDetail) -> None:
    """A turn's own line, and the template it came from.

    Written through one function for the same reason `apply_decision` exists:
    `record["detail"] = why` at nine sites is nine places for a raw string to
    creep back in, and the durable-field inventory needs the template beside the
    text to rebuild it.
    """
    record["detail_template"] = why.template
    record["detail"] = why.render()


def qualify_target(
    target: dict[str, Any],
    surface: dict[str, Any],
    timeout: float,
    max_turns: int,
    send: Any,
    registry: dict[str, Any] | None = None,
    response_limit: int = MAX_RESPONSE_BYTES,
) -> dict[str, Any]:
    """Run the C1 protocol shape against one provider × model target.

    `send` is injected so every classification is reachable without a network.
    A qualification whose failure paths can only be exercised against a real
    provider is a qualification whose failure paths are never exercised.
    """
    registry = normalize_registry(registry) if registry is not None else load_registry()
    receipt: dict[str, Any] = {
        "schema": QUALIFY_SCHEMA,
        "target_id": target["target_id"],
        "provider": target["provider"],
        "requested_model": target["model"],
        "reported_model": None,
        "reported_models": [],
        "model_status": "missing",
        "transport_target": {
            # Both come from the trusted registry once verification has run,
            # never from the plan row. A hand-edited `api_base` used to be
            # copied in here before anything checked it, so a receipt that
            # correctly classified `ENDPOINT_REJECTED` still carried the
            # rejected host as a durable field.
            "api_style": None,
            "endpoint": None,
            "path": COMPLETIONS_PATH,
            "content_type": "application/json",
            "timeout_secs": bounded_timeout(timeout),
            "redirects_allowed": 0,
            # The same number the transport was given and the same number
            # every observed count is checked against. One source of truth,
            # because two copies of a constant eventually lead separate lives.
            "max_response_bytes": response_limit,
        },
        "turns": [],
        "turn_count": 0,
        "tool_result_roundtrip": False,
        # A placeholder, never a verdict. Every exit below runs through
        # `apply_decision`, and the suite asserts that no returned receipt still
        # carries the seed rather than trusting the reading.
        "classification": PENDING_CLASSIFICATION,
        "decision_reason": None,
        "detail_template": None,
        "detail": "",
    }
    max_turns = bounded_turns(max_turns)

    try:
        # Identity of the destination before anything else: a valid https URL is
        # not evidence that the host behind it is the provider the target names.
        verify_against_registry(target, registry)
        entry = trusted_entry(registry, target["provider"])
        url = completions_url(entry["api_base"])
    except EndpointRejected as exc:
        return apply_decision(
            receipt,
            Decision("ENDPOINT_REJECTED", "endpoint-rejected", endpoint_rejected_detail(exc.reason)),
        )
    receipt["transport_target"]["api_style"] = entry["api_style"]
    receipt["transport_target"]["endpoint"] = entry["api_base"]

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
        if len(body) > MAX_REQUEST_BYTES:
            # A defect in this tool, not in the provider, so it is raised and
            # `guarded_receipt` files it as `INTERNAL_ERROR` — the one
            # classification reserved for us.
            raise ValueError("the composed request exceeded the local request bound")
        record: dict[str, Any] = {
            "ordinal": turn,
            "request_sha256": sha256_bytes(body),
            "request_bytes": len(body),
            "carried_tool_results": awaiting_roundtrip,
        }
        sent = as_send_result(send(url, body, timeout), response_limit)
        status, raw, detail = sent.status, sent.body, sent.detail
        # Domain-separated like every other provider-chosen value. The prefix
        # is a public constant, so anyone holding the body can still verify
        # the digest; what they cannot do is match it against a digest of the
        # same bytes taken somewhere else in the artifact.
        record["response_sha256"] = (
            evidence_digest("response-body", raw) if raw is not None else None)
        record["response_bytes"] = len(raw) if raw is not None else None
        # Whatever the provider managed to say is kept, even when the exchange
        # failed. `http_status` is present here whenever headers arrived, which
        # is exactly when it exists.
        if status is not None:
            record["http_status"] = status
        record.update(opaque("request_id", "request-id", sent.request_id))
        if sent.body_bytes_observed is not None:
            record["body_bytes_observed"] = sent.body_bytes_observed
        if sent.stage != "completed":
            failure = project_transport_failure(sent, response_limit)
            reason = failure["transport_reason"]
            record["outcome"] = STAGE_OUTCOME.get(sent.stage, "transport-failure")
            record.update(failure)
            if reason == "credential-missing":
                # The env var name comes from the trusted registry by way of
                # the target, never from the transport's message.
                record["key_env"] = target["key_env"]
            receipt["turns"].append(record)
            # The status is the most useful thing left when the body is gone,
            # and the same reducer that grades the probe's transport failures
            # grades this one — one table, one rendered line, two callers.
            return apply_decision(
                receipt,
                reduce_transport(TransportFacts(
                    schema=QUALIFY_SCHEMA,
                    stage=sent.stage,
                    reason=reason,
                    failure_kind=sent.failure_kind,
                    status=status,
                    key_env=target["key_env"],
                )),
                turn_count=turn + 1,
            )
        if not 200 <= status < 300:
            kind, message = classify_qualify_http(status, raw or b"", awaiting_roundtrip)
            record["outcome"] = "provider-rejected"
            record_detail(record, LocalDetail("provider-rejected", (message,)))
            receipt["turns"].append(record)
            return apply_decision(
                receipt,
                Decision(kind, "provider-rejected-request", LocalDetail(
                    "http", (status, LocalDetail("provider-rejected", (message,))))),
                turn_count=turn + 1,
            )

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
            # The class name goes through a closed local table rather than
            # straight into the line. Every member of it is this module's own or
            # a builtin, but "it is a Python class name" is the provenance
            # argument this vertical has already withdrawn twice.
            kind = completion_parse_kind(exc)
            why = LocalDetail("unmappable-completion", (kind,))
            record["outcome"] = "unreadable-response"
            record["completion_parse_kind"] = kind
            record_detail(record, why)
            receipt["turns"].append(record)
            return apply_decision(
                receipt,
                Decision("INVALID_OUTPUT", "unmappable-completion", why),
                turn_count=turn + 1,
            )

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
            record["reported_usage"] = normalize_provider_usage(
                payload["usage"], usage_bounds(len(body), QUALIFY_MAX_TOKENS))

        parsed = parse_tool_calls(message)
        calls, problem = parsed.calls, parsed.problem
        if problem:
            kind, why = problem
            record["outcome"] = "no-tool-call" if kind == "NO_TERMINAL_ANSWER" else "dialect-violation"
            record_detail(record, why)
            receipt["turns"].append(record)
            return apply_decision(
                receipt,
                Decision(kind, "assistant-message-rejected", why),
                turn_count=turn + 1,
            )
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
            why = LocalDetail("undeclared-tools", (
                len(unknown), tuple(opaque_ref("tool-name", name) for name in unknown)))
            record["outcome"] = "protocol-violation"
            record_detail(record, why)
            receipt["turns"].append(record)
            return apply_decision(
                receipt,
                Decision("PROTOCOL_VIOLATION", "undeclared-tools-called", why),
                turn_count=turn + 1,
            )

        decoded = []
        for call in calls:
            args, why = decode_arguments(call)
            if why:
                record["outcome"] = "malformed-arguments"
                record_detail(record, why)
                receipt["turns"].append(record)
                return apply_decision(
                    receipt,
                    Decision("MALFORMED_TOOL_ARGUMENTS", "tool-arguments-unparseable", why),
                    turn_count=turn + 1,
                )
            errors = validate_arguments(surface, call["name"], args)
            if errors:
                # `jsonschema_mini` interpolates the offending instance —
                # `{instance!r}`, `additional property '{key}'` — so the
                # messages themselves are provider text and cannot be kept.
                # What a reader acts on survives: how many rules failed, which
                # rules, and a digest that makes two runs comparable.
                evidence = error_evidence("argument_errors", errors)
                why = LocalDetail("arguments-schema-violation", (
                    opaque_ref("tool-name", call["name"]),
                    evidence["argument_errors_count"],
                    tuple(evidence["argument_errors_kinds"]),
                ))
                record["outcome"] = "malformed-arguments"
                record_detail(record, why)
                record.update(evidence)
                receipt["turns"].append(record)
                return apply_decision(
                    receipt,
                    Decision("MALFORMED_TOOL_ARGUMENTS", "tool-arguments-schema-violation", why),
                    turn_count=turn + 1,
                )
            decoded.append((call, args))
        record["arguments_valid"] = True

        answers = [c for c, _ in decoded if c["name"] == ANSWER_TOOL]
        operations = [(c, a) for c, a in decoded if c["name"] != ANSWER_TOOL]
        if len(answers) > 1:
            why = LocalDetail("multiple-answers", (len(answers),))
            record["outcome"] = "protocol-violation"
            record_detail(record, why)
            receipt["turns"].append(record)
            return apply_decision(
                receipt,
                Decision("PROTOCOL_VIOLATION", "multiple-terminal-answers", why),
                turn_count=turn + 1,
            )
        if answers and operations:
            why = LocalDetail("answer-with-operations", (len(operations),))
            record["outcome"] = "protocol-violation"
            record_detail(record, why)
            receipt["turns"].append(record)
            return apply_decision(
                receipt,
                Decision("PROTOCOL_VIOLATION", "terminal-answer-with-operations", why),
                turn_count=turn + 1,
            )

        if answers:
            if not roundtrip_seen:
                # The arm's whole shape is query, read the result, then answer.
                # A target that answers immediately has demonstrated that it can
                # emit one forced tool call — which the RAW arm also does — and
                # nothing about the loop the forced-query arm is made of.
                why = LocalDetail("answer-before-roundtrip")
                record["outcome"] = "protocol-violation"
                record_detail(record, why)
                receipt["turns"].append(record)
                return apply_decision(
                    receipt,
                    Decision("PROTOCOL_VIOLATION", "terminal-answer-before-roundtrip", why),
                    turn_count=turn + 1,
                )

            answer_args = next(a for c, a in decoded if c["name"] == ANSWER_TOOL)
            answer_errors = canary_answer_errors(answer_args, observed)
            record["outcome"] = "terminal-answer"
            record["terminal_answer_valid"] = True
            record["canary_answer_matches"] = not answer_errors
            if answer_errors:
                record["canary_answer_errors"] = [why.render() for why in answer_errors]
                record["canary_answer_error_templates"] = [why.template for why in answer_errors]
            receipt["turns"].append(record)
            # Three verdicts used to be written here in sequence, each
            # overwriting the last: `PASS`, then maybe the canary's, then maybe
            # identity's. Reading it required holding the whole chain in mind to
            # know which one survived. One reducer decides, with the precedence
            # written down where it can be tested on its own: identity outranks
            # both a protocol pass and a wrong answer, and "the provider named
            # none" is not a milder finding than "it named another one".
            #
            # Which model was substituted survives as a digest rather than a
            # name: a provider that returns the bearer token in `model` would
            # otherwise write it into the detail line of a committed receipt.
            substituted = tuple(
                DigestRef.of(entry["reported_model_sha256"])
                for entry in receipt["reported_models"]
                if entry.get("reported_model") is None and entry.get("reported_model_present")
            )
            return apply_decision(
                receipt,
                reduce_qualification(AnswerFacts(
                    model_status=receipt["model_status"],
                    canary_errors=tuple(answer_errors),
                    substituted_digests=substituted,
                )),
                turn_count=turn + 1,
            )

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

    return apply_decision(
        receipt,
        Decision(
            "NO_TERMINAL_ANSWER", "no-terminal-answer-within-budget",
            LocalDetail("no-terminal-answer", (max_turns,)),
        ),
        turn_count=max_turns,
    )


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
        # The class name is the provider's choice as surely as `usage` was:
        # `type("BearerSecretValue", (Exception,), {})` is a class an injected
        # sender can raise. It goes through the same projection as every other
        # caught exception rather than into prose.
        receipt = {
            "schema": schema,
            "target_id": target.get("target_id"),
            "provider": target.get("provider"),
            "requested_model": target.get("model"),
            "classification": PENDING_CLASSIFICATION,
            "decision_reason": None,
            "detail_template": None,
            "detail": "",
            **project_exception("internal_failure", "internal-error", exc),
        }
        return apply_decision(
            receipt,
            Decision("INTERNAL_ERROR", "internal-exception", LocalDetail("internal-exception")),
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
