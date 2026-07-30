#!/usr/bin/env python3
"""A closed, machine-checkable inventory of every leaf a receipt may contain.

Five review rounds closed five instances of one defect: a value the provider
chose reached a durable artifact. `usage` copied whole. `request_id` taken from
a header. A tool call id. A substituted model name. A failure class name. Each
was closed where it was found, and each round found the next one.

The repairs were right. The method was not — a contract enforced at the sites a
reviewer happened to visit has exactly as many exceptions as there are sites
nobody visited. What was missing is not another `if`; it is the statement that
the set of durable leaves is *closed*:

    every leaf that reaches a receipt is named here, with one policy, and a leaf
    that is not named stops the gate.

The policy kinds are the four admissible shapes the projection boundary already
declared, made into types:

    Local      — a value this module or the trusted registry already had
    Enum       — a member of a closed local vocabulary
    BoundedInt — an integer, with a range, both ends
    Digest     — a fixed-width digest under a declared domain, with its
                 companions: presence, a bounded length, an overflow flag
    Prose      — a line composed from this module's own words, in which foreign
                 material appears only as an `opaque_ref`

`Prose` is the one that needs its warrant stated. Its vocabulary is derived from
the string literals of `provider_matrix.py` itself rather than hand-listed: the
question a detail line has to answer is "could this module have written this?",
and the module's literals are the complete answer to it. A credential, a model
name, an error message from a gateway — none of them appear in the source, so
none of them can appear in a detail line without a reference wrapper. The cost
is that adding a word to a message does not stop the gate; the benefit is that
the vocabulary cannot rot, and rotting vocabularies are how this kind of check
becomes decoration.

    python3 evals/provider-matrix/receipt_policy.py --self-test

Exit 0 when the policy table is internally consistent and the built-in defective
specimens are all refused, 1 otherwise.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

import provider_matrix as pm

HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Flattening
# ---------------------------------------------------------------------------


def flatten(value: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    """Every leaf of a receipt, as `(path, value)`.

    List indices collapse to `[]`, because a policy is about a *kind* of place
    and `turns[3]` is not a different kind of place from `turns[0]`. An empty
    list or object yields nothing: it has no leaves, and inventing one would
    make the inventory report on something the artifact does not contain.
    """
    if isinstance(value, dict):
        for key in value:
            child = f"{prefix}.{key}" if prefix else str(key)
            yield from flatten(value[key], child)
    elif isinstance(value, list):
        for item in value:
            yield from flatten(item, f"{prefix}[]")
    else:
        yield prefix, value


# ---------------------------------------------------------------------------
# The local vocabulary a `Prose` line may draw on
# ---------------------------------------------------------------------------

# Names that reach a message through `type(x).__name__`. Not literals, so they
# are declared — and declared as a closed tuple, because "it came from `type()`"
# is a provenance argument only for values this module constructed. The strict
# JSON reader produces exactly these.
LOCAL_TYPE_NAMES = (
    "dict", "list", "str", "int", "float", "bool", "NoneType", "bytes", "tuple",
)

# The residue of a detail line, once every `opaque_ref` has been removed, may
# contain only these characters. A byte outside the set is not a word this
# module failed to declare — it is material from somewhere else.
PROSE_ALPHABET = re.compile(r"^[A-Za-z0-9 _.,;:()'\"/+\-\n]*$")

# A reference as `opaque_ref` spells it: a declared domain, sixteen hex, and a
# bounded length. Anything shaped like a reference but not spelled like one is
# left in the residue on purpose, where the vocabulary check will refuse it.
REFERENCE = re.compile(r"<([a-z0-9-]+) sha256:([0-9a-f]{16}) (\d{1,10})(\+?)B>")

# A digest reference with no domain wrapper — `entry["reported_model_sha256"][:16]`
# as `reduce_qualification` renders it. Sixteen hex on its own is not a channel
# (it is a truncated digest of something already digested), but it has to be
# recognised, or it lands in the residue as a nonsense word.
BARE_DIGEST = re.compile(r"\b[0-9a-f]{16}\b")

# Tokens the vocabulary check looks at. Slashes and dots stay inside a token so
# that `openai/gpt-oss-120b` is one word to be refused rather than four to be
# waved through.
TOKEN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./+-]*")

# The largest number a detail line may state. Counts of turns, errors and
# operations are all small; a seven-digit integer in a sentence is the same
# unbounded channel as a seven-digit integer in a field, and the sentence is
# where nobody looks for one.
PROSE_MAX_NUMBER = 9_999_999


def module_literals(path: Path) -> set[str]:
    """Every word that appears in a string literal of the given module.

    Parsed rather than read line by line so that the static parts of f-strings
    are included and the interpolations are not: `f"HTTP {status}: {reason}"`
    contributes `HTTP`, and contributes nothing at all about what `status` may
    hold.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    words: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            words.update(TOKEN.findall(node.value))
    return words


def local_vocabulary() -> frozenset[str]:
    words = module_literals(HERE / "provider_matrix.py")
    words.update(LOCAL_TYPE_NAMES)
    return frozenset(words)


LOCAL_WORDS = local_vocabulary()


# ---------------------------------------------------------------------------
# Policy kinds
# ---------------------------------------------------------------------------


class Kind:
    """A shape a durable leaf is allowed to have."""

    def problems(self, value: Any, context: dict[str, Any]) -> list[str]:  # pragma: no cover
        raise NotImplementedError

    def describe(self) -> str:
        return type(self).__name__.lower()

    def declaration_problems(self) -> list[str]:
        """What is wrong with the *policy*, before any value is seen."""
        return []


@dataclass(frozen=True)
class Local(Kind):
    """A value this module or the trusted registry already had.

    `source` names the local fact, and the fact is supplied by the caller of
    `audit`. A policy that claimed a value was local without naming what it must
    equal would be a comment.
    """

    source: str

    def problems(self, value: Any, context: dict[str, Any]) -> list[str]:
        if self.source not in context:
            return [f"no local fact named {self.source!r} was supplied"]
        expected = context[self.source]
        if isinstance(expected, (set, frozenset, tuple, list)):
            return [] if value in expected else [f"{value!r} is not one of the local {self.source}"]
        return [] if value == expected else [f"{value!r} is not the local {self.source}"]

    def describe(self) -> str:
        return f"local:{self.source}"


@dataclass(frozen=True)
class Enum(Kind):
    """A member of a closed local vocabulary, named so the table can be read."""

    name: str
    values: tuple[Any, ...]

    def problems(self, value: Any, context: dict[str, Any]) -> list[str]:
        return [] if value in self.values else [f"{value!r} is not a member of {self.name}"]

    def declaration_problems(self) -> list[str]:
        return [] if self.values else [f"{self.name} is empty"]

    def describe(self) -> str:
        return f"enum:{self.name}"


@dataclass(frozen=True)
class BoundedInt(Kind):
    """An integer with both ends bounded. `bool` is not an integer here.

    `type(v) is int` rather than `isinstance`, for the reason `is_http_status`
    gives: `True` is an `int` in Python and would otherwise be recorded as a
    count of one. The upper bound may name a context fact — `response_limit`,
    `max_turns` — because those are the numbers the bound is actually made of.
    """

    low: int
    high: int | str

    def ceiling(self, context: dict[str, Any]) -> int | None:
        if isinstance(self.high, str):
            return context.get(self.high)
        return self.high

    def problems(self, value: Any, context: dict[str, Any]) -> list[str]:
        if type(value) is not int:
            return [f"{type(value).__name__} is not an integer"]
        top = self.ceiling(context)
        if top is None:
            return [f"no local bound named {self.high!r} was supplied"]
        if not self.low <= value <= top:
            return [f"integer outside {self.low}..{top}"]
        return []

    def describe(self) -> str:
        return f"int:{self.low}..{self.high}"


@dataclass(frozen=True)
class BoundedNumber(Kind):
    """A finite real with both ends bounded — `timeout_secs` and nothing else."""

    low: float
    high: float

    def problems(self, value: Any, context: dict[str, Any]) -> list[str]:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return [f"{type(value).__name__} is not a number"]
        if value != value or value in (float("inf"), float("-inf")):
            return ["number is not finite"]
        if not self.low <= value <= self.high:
            return [f"number outside {self.low}..{self.high}"]
        return []

    def describe(self) -> str:
        return f"number:{self.low}..{self.high}"


@dataclass(frozen=True)
class Digest(Kind):
    """A hex digest, under a domain this module declared.

    `domain=None` is a digest of bytes this module composed itself — a request
    body it built — where there is nothing to separate from anything else. Any
    other domain must be in `EVIDENCE_DOMAINS`; declaring one that is not is a
    defect in the *table*, caught before a single receipt is read, because a
    digest with an undeclared domain is a digest nobody can recompute and
    therefore a field nobody can audit.
    """

    domain: str | None = None
    # A digest of an identifier travels beside a length, and that length is what
    # `EVIDENCE_MAX_BYTES` bounds. A digest of *content* — a response body, a
    # concatenation of validator messages — travels alone: it is fixed-width, so
    # it states nothing about how much it consumed and needs no ceiling.
    sized: bool = True

    def problems(self, value: Any, context: dict[str, Any]) -> list[str]:
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            return ["not a sha256 digest"]
        return []

    def declaration_problems(self) -> list[str]:
        if self.domain is None:
            return []
        if self.domain not in pm.EVIDENCE_DOMAINS:
            return [f"domain {self.domain!r} is not declared in EVIDENCE_DOMAINS"]
        if self.sized and self.domain not in pm.EVIDENCE_MAX_BYTES:
            return [f"domain {self.domain!r} declares no length bound"]
        return []

    def describe(self) -> str:
        return f"digest:{self.domain or 'local-bytes'}"


@dataclass(frozen=True)
class Flag(Kind):
    """Exactly `True` or `False`. Not "truthy", which `1` and `"yes"` also are."""

    def problems(self, value: Any, context: dict[str, Any]) -> list[str]:
        return [] if value is True or value is False else [f"{value!r} is not a boolean"]


@dataclass(frozen=True)
class Prose(Kind):
    """A line this module composed, in which foreign material is a reference.

    Three checks, in order. The references are removed first, and each must be
    spelled the way `opaque_ref` spells it — a well-formed reference is not
    material, it is a statement *about* material. What is left must lie in the
    local alphabet, and every word in it must be a word this module's source
    contains. A bearer token satisfies none of the three.
    """

    max_bytes: int

    def problems(self, value: Any, context: dict[str, Any]) -> list[str]:
        if not isinstance(value, str):
            return [f"{type(value).__name__} is not a string"]
        if len(value.encode("utf-8", "surrogatepass")) > self.max_bytes:
            return [f"longer than the {self.max_bytes}-byte bound"]
        found: list[str] = []
        for domain, _digest, size, overflow in REFERENCE.findall(value):
            if domain not in pm.EVIDENCE_DOMAINS:
                found.append(f"reference to undeclared domain {domain!r}")
            elif not overflow and int(size) > pm.EVIDENCE_MAX_BYTES.get(domain, 0):
                found.append(f"reference to {domain!r} states an unbounded length")
        residue = BARE_DIGEST.sub(" ", REFERENCE.sub(" ", value))
        if not PROSE_ALPHABET.match(residue):
            outside = sorted({ch for ch in residue if not PROSE_ALPHABET.match(ch)})
            found.append(f"characters outside the local alphabet: {outside!r}")
        allowed = LOCAL_WORDS | set(context.get("local_words", ()))
        for token in TOKEN.findall(residue):
            if token.isdigit():
                if int(token) > PROSE_MAX_NUMBER:
                    found.append("states a number past the prose bound")
            elif token not in allowed:
                found.append(f"the word {token!r} is not one this module wrote")
        return found

    def describe(self) -> str:
        return f"prose:{self.max_bytes}"


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DurableFieldPolicy:
    """One place a value may reach a receipt, and the only shape it may take."""

    path: str
    kind: Kind
    nullable: bool = False
    why: str = ""

    def validate(self, value: Any, context: dict[str, Any]) -> list[str]:
        if value is None:
            return [] if self.nullable else [f"{self.path}: null is not admitted here"]
        return [f"{self.path}: {problem}" for problem in self.kind.problems(value, context)]


DETAIL_MAX_BYTES = 4096

# The evidence quartet `opaque_text` writes, as four policies. Written by a
# function rather than by hand because it appears eleven times and eleven
# hand-copies is eleven chances for one of them to differ silently.
def opaque_policies(path: str, domain: str) -> list[DurableFieldPolicy]:
    return [
        DurableFieldPolicy(f"{path}_present", Flag()),
        DurableFieldPolicy(f"{path}_sha256", Digest(domain)),
        DurableFieldPolicy(f"{path}_bytes", BoundedInt(0, pm.EVIDENCE_MAX_BYTES[domain])),
        DurableFieldPolicy(f"{path}_oversize", Flag()),
    ]


def model_evidence_policies(path: str) -> list[DurableFieldPolicy]:
    """The projected identity of a reported model, wherever it appears."""
    return [
        DurableFieldPolicy(
            f"{path}reported_model", Local("requested_model"), nullable=True,
            why="text only when it equalled the model we asked for",
        ),
        *opaque_policies(f"{path}reported_model", "model-name"),
        DurableFieldPolicy(
            f"{path}reported_model_type",
            Enum("JSON type names", tuple(name for _, name in pm.JSON_TYPE_NAMES) + ("null", "unknown")),
            why="an object or a list in `model` crosses as its type and nothing else",
        ),
    ]


def usage_policies(path: str) -> list[DurableFieldPolicy]:
    return [
        DurableFieldPolicy(f"{path}.{counter}", BoundedInt(0, "usage_ceiling"))
        for counter in pm.USAGE_COUNTERS
    ]


TRANSPORT_POLICIES: Callable[[str], list[DurableFieldPolicy]] = lambda path: [
    DurableFieldPolicy(f"{path}transport_reason", Enum("TRANSPORT_REASONS", pm.TRANSPORT_REASONS)),
    DurableFieldPolicy(f"{path}failure_kind", Enum("TRANSPORT_FAILURE_KINDS", pm.TRANSPORT_FAILURE_KINDS)),
    *opaque_policies(f"{path}failure_class", "failure-class"),
]


def build_policies() -> list[DurableFieldPolicy]:
    """Every leaf of both receipt kinds. The closed world itself."""
    shared = [
        DurableFieldPolicy("schema", Local("schema")),
        DurableFieldPolicy("target_id", Local("target_id")),
        DurableFieldPolicy("provider", Local("provider")),
        DurableFieldPolicy("requested_model", Local("requested_model")),
        DurableFieldPolicy("classification", Local("classifications")),
        DurableFieldPolicy("decision_reason", Enum("DECISION_REASONS", pm.DECISION_REASONS), nullable=True),
        DurableFieldPolicy("detail", Prose(DETAIL_MAX_BYTES)),
        DurableFieldPolicy(
            "internal_failure_kind", Enum("INTERNAL_FAILURE_KINDS", pm.INTERNAL_FAILURE_KINDS)),
        *opaque_policies("internal_failure_class", "failure-class"),
        # The identity fields sit at the top level of both receipt kinds and
        # mean the same thing in both. Listed once, because two identical
        # entries would be two owners of one field — the state `policy_problems`
        # exists to refuse.
        DurableFieldPolicy("model_status", Enum("model statuses", tuple(pm.MODEL_STATUS_SEVERITY))),
        *model_evidence_policies(""),
    ]

    probe = [
        DurableFieldPolicy("request_sha256", Digest()),
        DurableFieldPolicy("endpoint", Local("endpoint")),
        DurableFieldPolicy("latency_ms", BoundedInt(0, pm.LATENCY_MAX_MS)),
        DurableFieldPolicy("http_status", BoundedInt(100, 599)),
        DurableFieldPolicy("response_sha256", Digest("response-body", sized=False)),
        DurableFieldPolicy("response_bytes", BoundedInt(0, "response_limit")),
        DurableFieldPolicy("body_bytes_observed", BoundedInt(0, "observed_ceiling")),
        DurableFieldPolicy(
            "completion_parse_kind", Enum("COMPLETION_PARSE_KINDS", pm.COMPLETION_PARSE_KINDS)),
        *opaque_policies("request_id", "request-id"),
        *TRANSPORT_POLICIES(""),
        *usage_policies("provider_usage"),
    ]

    qualification = [
        DurableFieldPolicy("turn_count", BoundedInt(0, "max_turns")),
        DurableFieldPolicy("tool_result_roundtrip", Flag()),
        DurableFieldPolicy("transport_target.api_style", Local("api_style"), nullable=True),
        DurableFieldPolicy("transport_target.endpoint", Local("api_base"), nullable=True),
        DurableFieldPolicy("transport_target.path", Local("completions_path")),
        DurableFieldPolicy("transport_target.content_type", Local("content_type")),
        DurableFieldPolicy("transport_target.timeout_secs", BoundedNumber(0, pm.TIMEOUT_MAX_SECS)),
        DurableFieldPolicy("transport_target.redirects_allowed", BoundedInt(0, 0)),
        DurableFieldPolicy("transport_target.max_response_bytes", BoundedInt(0, "response_limit")),
        *model_evidence_policies("reported_models[]."),
        # -- one turn --
        DurableFieldPolicy("turns[].ordinal", BoundedInt(0, "max_turns")),
        DurableFieldPolicy("turns[].request_sha256", Digest()),
        DurableFieldPolicy("turns[].request_bytes", BoundedInt(0, "request_ceiling")),
        DurableFieldPolicy("turns[].carried_tool_results", Flag()),
        DurableFieldPolicy("turns[].response_sha256", Digest("response-body", sized=False), nullable=True),
        DurableFieldPolicy("turns[].response_bytes", BoundedInt(0, "response_limit"), nullable=True),
        DurableFieldPolicy("turns[].http_status", BoundedInt(100, 599)),
        DurableFieldPolicy("turns[].body_bytes_observed", BoundedInt(0, "observed_ceiling")),
        DurableFieldPolicy("turns[].key_env", Local("key_env")),
        DurableFieldPolicy("turns[].outcome", Enum("turn outcomes", TURN_OUTCOMES)),
        DurableFieldPolicy("turns[].detail", Prose(DETAIL_MAX_BYTES)),
        DurableFieldPolicy(
            "turns[].completion_parse_kind", Enum("COMPLETION_PARSE_KINDS", pm.COMPLETION_PARSE_KINDS)),
        DurableFieldPolicy("turns[].model_status", Enum("model statuses", tuple(pm.MODEL_STATUS_SEVERITY))),
        DurableFieldPolicy("turns[].tool_result_roundtrip", Flag()),
        DurableFieldPolicy("turns[].arguments_valid", Flag()),
        DurableFieldPolicy("turns[].terminal_answer_valid", Flag()),
        DurableFieldPolicy("turns[].canary_answer_matches", Flag()),
        DurableFieldPolicy("turns[].canary_answer_errors[]", Prose(DETAIL_MAX_BYTES)),
        DurableFieldPolicy("turns[].argument_errors_count", BoundedInt(0, "error_ceiling")),
        DurableFieldPolicy(
            "turns[].argument_errors_kinds[]",
            Enum("argument error kinds", tuple(k for _, k in pm.ARGUMENT_ERROR_KINDS) + ("other",))),
        DurableFieldPolicy("turns[].argument_errors_sha256", Digest("argument-errors", sized=False)),
        DurableFieldPolicy("turns[].tool_names[]", Local("declared_tools")),
        DurableFieldPolicy("turns[].tool_calls[].ordinal", BoundedInt(0, "call_ceiling")),
        DurableFieldPolicy("turns[].tool_calls[].name", Local("declared_tools"), nullable=True),
        *opaque_policies("turns[].tool_calls[].name", "tool-name"),
        *opaque_policies("turns[].tool_calls[].call_id", "tool-call-id"),
        *opaque_policies("turns[].request_id", "request-id"),
        *model_evidence_policies("turns[]."),
        *TRANSPORT_POLICIES("turns[]."),
        *usage_policies("turns[].reported_usage"),
    ]
    return shared + probe + qualification


# The outcome vocabulary, which the loop writes and nothing else declares. It is
# here rather than in `provider_matrix` for the same reason `PROBE_STAGE_CAUSE`
# is not: it exists to be checked against what the loop produces, and a
# vocabulary imported from the code it audits proves only that the code agrees
# with itself.
TURN_OUTCOMES = (
    "no-credential",
    "transport-failure",
    "response-capture-failure",
    "provider-rejected",
    "unreadable-response",
    "no-tool-call",
    "dialect-violation",
    "protocol-violation",
    "malformed-arguments",
    "operations",
    "terminal-answer",
)


POLICIES = build_policies()


def policy_problems(policies: list[DurableFieldPolicy]) -> list[str]:
    """What is wrong with the table itself, before any receipt is read.

    Two policies for one path is the interesting case: it means two people
    each believed they owned a field, which is the state this whole module
    exists to make impossible.
    """
    problems: list[str] = []
    seen: dict[str, int] = {}
    for policy in policies:
        seen[policy.path] = seen.get(policy.path, 0) + 1
        problems.extend(f"{policy.path}: {issue}" for issue in policy.kind.declaration_problems())
    for path, count in sorted(seen.items()):
        if count > 1:
            problems.append(f"{path}: {count} policies claim this path; exactly one may")
    return problems


def exactly_one_policy_for(
    path: str, policies: list[DurableFieldPolicy] | None = None
) -> DurableFieldPolicy:
    """The single policy for a path, or an error naming which rule was broken."""
    matches = [policy for policy in (POLICIES if policies is None else policies) if policy.path == path]
    if not matches:
        raise KeyError(f"no policy names the durable field {path!r}")
    if len(matches) > 1:
        raise KeyError(f"{len(matches)} policies name the durable field {path!r}")
    return matches[0]


def audit(
    receipt: dict[str, Any],
    context: dict[str, Any],
    policies: list[DurableFieldPolicy] | None = None,
) -> list[str]:
    """Every leaf of one receipt, against the closed table.

    An unnamed path is a finding, not a skip. That is the whole difference
    between an inventory and a spot check: a field added next round without a
    policy stops the gate on the commit that adds it, rather than on the review
    round that eventually notices it.
    """
    findings: list[str] = []
    for path, value in flatten(receipt):
        try:
            policy = exactly_one_policy_for(path, policies)
        except KeyError as exc:
            findings.append(str(exc).strip("'"))
            continue
        findings.extend(policy.validate(value, context))
    return findings


def context_for(
    schema: str,
    target: dict[str, Any],
    registry_entry: dict[str, Any],
    *,
    response_limit: int = pm.MAX_RESPONSE_BYTES,
    max_turns: int = pm.MAX_TURNS_BOUND,
    declared_tools: set[str] | None = None,
) -> dict[str, Any]:
    """The local facts a receipt is checked against.

    Assembled from the plan, the registry and the caller's own expectation —
    never from the receipt. A context read out of the artifact being audited
    would confirm whatever the artifact said, and every `Local` policy would
    degrade to "this value equals itself". The schema is the caller's claim
    about *which* receipt it asked for, which is why it is a parameter and not a
    lookup.
    """
    return {
        "schema": schema,
        "target_id": target["target_id"],
        "provider": target["provider"],
        "requested_model": target["model"],
        "key_env": registry_entry["key_env"],
        "api_style": registry_entry["api_style"],
        "api_base": registry_entry["api_base"],
        "endpoint": pm.completions_url(registry_entry["api_base"]),
        "completions_path": pm.COMPLETIONS_PATH,
        "content_type": "application/json",
        "classifications": set(pm.SCHEMA_CLASSIFICATIONS.get(schema, ())),
        "declared_tools": (declared_tools or set()) | {pm.ANSWER_TOOL},
        "response_limit": response_limit,
        # `read_bounded` reads `limit + 1` deliberately, to prove overflow, so
        # one past the limit is the largest count the transport can produce.
        "observed_ceiling": response_limit + 1,
        "request_ceiling": pm.MAX_REQUEST_BYTES,
        "usage_ceiling": response_limit + pm.QUALIFY_MAX_TOKENS,
        "max_turns": max_turns,
        "error_ceiling": 1024,
        "call_ceiling": 1024,
        # Words that are local to *this run* rather than to the module: the
        # environment variable name the registry chose. The model id is
        # deliberately absent — no detail line names it any more.
        "local_words": {registry_entry["key_env"]},
    }


# ---------------------------------------------------------------------------
# The positive control
# ---------------------------------------------------------------------------
#
# A validator that has never refused anything is a validator nobody has tested.
# Each specimen below is a receipt with exactly one defect, and each defect is
# one this vertical actually shipped at some point.

SPECIMEN_CONTEXT = {
    "schema": pm.PROBE_SCHEMA,
    "target_id": "p--m",
    "provider": "p",
    "requested_model": "m",
    "classifications": set(pm.PROBE_CLASSIFICATIONS),
    "response_limit": 4096,
    "observed_ceiling": 4097,
    "local_words": set(),
}


def sound_specimen() -> dict[str, Any]:
    return {
        "schema": pm.PROBE_SCHEMA,
        "target_id": "p--m",
        "provider": "p",
        "requested_model": "m",
        "classification": "PASS",
        "decision_reason": "probe-token-matched",
        "detail": "the completion carried the probe token",
        "http_status": 200,
        "body_bytes_observed": 12,
    }


def defective_specimens() -> list[tuple[str, dict[str, Any], str]]:
    """`(name, receipt, the phrase the refusal must contain)`."""
    unknown = sound_specimen()
    unknown["provider_hint"] = "gpt-4o-mini"

    unbounded = sound_specimen()
    unbounded["body_bytes_observed"] = int.from_bytes(b"sk-secret", "big")

    prose = sound_specimen()
    prose["detail"] = "the provider said: sk-live-4f9c2a"

    typed = sound_specimen()
    typed["http_status"] = True

    reason = sound_specimen()
    reason["decision_reason"] = "looked-fine-to-me"

    # Every word local, every byte not: a line assembled somewhere else differs
    # in its punctuation long before it differs in its nouns.
    alphabet = sound_specimen()
    alphabet["detail"] = "the completion carried the probe token \u2014 probably"

    # The check that makes `Local` mean anything. Audited against a context read
    # out of the receipt, this specimen would pass.
    elsewhere = sound_specimen()
    elsewhere["provider"] = "somebody-else"

    return [
        ("an unnamed leaf", unknown, "no policy names"),
        ("an unbounded integer", unbounded, "outside 0.."),
        ("a foreign word in prose", prose, "is not one this module wrote"),
        ("a byte outside the local alphabet", alphabet, "outside the local alphabet"),
        ("a boolean wearing a status", typed, "not an integer"),
        ("an invented decision reason", reason, "not a member of DECISION_REASONS"),
        ("a value that is not the local one", elsewhere, "is not the local provider"),
    ]


def self_test() -> int:
    problems = policy_problems(POLICIES)
    if problems:
        print("FAIL the policy table is not internally consistent")
        for problem in problems[:20]:
            print(f"  {problem}")
        return 1

    findings = audit(sound_specimen(), SPECIMEN_CONTEXT)
    if findings:
        print("FAIL a receipt this module produces was refused by its own policy")
        for finding in findings[:20]:
            print(f"  {finding}")
        return 1

    for name, specimen, expected in defective_specimens():
        found = audit(specimen, SPECIMEN_CONTEXT)
        if not any(expected in finding for finding in found):
            print(f"FAIL {name} was not refused")
            print(f"  expected a finding containing {expected!r}")
            print(f"  got: {found}")
            return 1

    # And the table's own positive control: a duplicated policy must be a
    # finding about the table, not a silent first-match-wins.
    doubled = POLICIES + [DurableFieldPolicy("detail", Flag())]
    if not any("exactly one may" in problem for problem in policy_problems(doubled)):
        print("FAIL two policies for one path were not reported")
        return 1
    if not any("not declared in EVIDENCE_DOMAINS" in problem for problem in
               policy_problems([DurableFieldPolicy("x", Digest("no-such-domain"))])):
        print("FAIL a digest policy naming an undeclared domain was not reported")
        return 1

    print(f"OK {len(POLICIES)} durable-field policies, "
          f"{len(defective_specimens())} defective specimens refused, "
          "duplicate and undeclared-domain policies reported")
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    print(f"{len(POLICIES)} durable-field policies")
    for policy in sorted(POLICIES, key=lambda p: p.path):
        null = " (nullable)" if policy.nullable else ""
        print(f"  {policy.path:<48} {policy.kind.describe()}{null}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
