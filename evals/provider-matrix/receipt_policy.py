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

`Prose` needs its warrant stated carefully, because the first version of it
overstated one. Its vocabulary is derived from the string literals of
`provider_matrix.py`, which answers *could this module have written this line?*
— and that is a strictly weaker question than *did it?*. A provider can send
`"timeout"`, or `"the completion carried the probe token"`, or sixteen hex
characters, and every one of those satisfies a check made of words and bytes.
This vertical has withdrawn that argument twice already, for `isidentifier()`
and then for sixty-four hex characters. Syntax is not provenance.

So `Prose` is kept as a lexical defence in depth and is **not** the provenance
proof. The proof is the second inventory below: every `detail` travels with the
`detail_template` it was rendered from, and `detail_provenance_problems`
rebuilds the line's pattern from that template's declared slots — each slot's
own vocabulary, the reference grammar, the bounded counts, the trusted local
values from the *context* rather than from the artifact — and requires the
string to match it. A line that was not constructed from those parts cannot.

    python3 evals/provider-matrix/receipt_policy.py --self-test

Exit 0 when the policy table is internally consistent and the built-in defective
specimens are all refused, 1 otherwise.
"""

from __future__ import annotations

import ast
import re
import sys
import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

import provider_matrix as pm

HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Flattening
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Key:
    """One object member, by name. Never concatenated into a sentence."""

    value: str


@dataclass(frozen=True)
class Each:
    """Any member of an array. `turns[3]` is not a different *kind* of place."""


@dataclass(frozen=True)
class BadKey:
    """A dictionary key that is not a string.

    JSON has no such thing, but a receipt is built in Python before it is
    serialised, and `str(key)` would launder an integer or a tuple into a path
    component that looks exactly like a declared one. No policy can name a
    `BadKey`, so it always stops the gate — and its rendering carries the key's
    *type*, never its value.
    """

    json_type: str


EACH = Each()

# A path is a tuple of steps, not a string. `"turns[].detail"` was ambiguous:
# it is what `(Key("turns"), Each(), Key("detail"))` renders as, and it is also
# what a single provider-chosen top-level key spelled `turns[].detail` renders
# as — so a JSON key could impersonate a structural path and satisfy the policy
# meant for a different place entirely. Escaping `.` and `[]` would have been
# the third patch on a representation problem; the representation is the
# problem. Strings appear when a finding is printed and nowhere else.
FieldPath = tuple


def P(*parts: str | Each) -> FieldPath:
    """Build a path from named steps. `P("turns", EACH, "detail")`."""
    return tuple(part if isinstance(part, Each) else Key(part) for part in parts)


def extend(prefix: FieldPath, *parts: str | Each) -> FieldPath:
    return prefix + P(*parts)


def suffixed(prefix: FieldPath, name: str) -> FieldPath:
    """`prefix` with `name` appended as a member. The only place names join."""
    return prefix + (Key(name),)


@dataclass(frozen=True)
class Node:
    """A container in the artifact, as a value the inventory can be handed.

    The first version of `flatten` yielded leaves only, and said so as a
    principle: an empty list or object *has* no leaves, so inventing one would
    report on something the artifact does not contain. That was wrong, and a
    reviewer produced the counterexample to the round's own theorem:

        receipt["provider_said"] = {"sk-live-secret": {}}

    yielded nothing at all, so the closed-world audit answered `[]` for an
    artifact carrying a provider-chosen **key**. A JSON key is as durable as a
    JSON value — it is written to the file either way — and calling it "not a
    leaf" removes it from the check without removing it from disk.

    So every container is a node with a path, and the table describes the shape
    of the artifact rather than only its scalars.
    """

    kind: str  # object | array
    empty: bool = False

    def __str__(self) -> str:
        return f"an empty {self.kind}" if self.empty else f"an {self.kind}"


OBJECT_NODE = Node("object")
EMPTY_OBJECT = Node("object", empty=True)
ARRAY_NODE = Node("array")
EMPTY_ARRAY = Node("array", empty=True)


def flatten(value: Any, prefix: FieldPath = ()) -> Iterator[tuple[FieldPath, Any]]:
    """Every node and every leaf of a receipt, as `(path, value)`.

    The root is not yielded: it is the receipt itself, and its existence is not
    the question. Everything below it is, including containers, including empty
    ones — see `Node` — and including keys that are not strings, which become a
    step no policy can name rather than a `str()` call nobody reviews.
    """
    if isinstance(value, dict):
        if prefix:
            yield prefix, (EMPTY_OBJECT if not value else OBJECT_NODE)
        for key in value:
            step = Key(key) if isinstance(key, str) else BadKey(pm.json_type_name(key))
            yield from flatten(value[key], prefix + (step,))
    elif isinstance(value, list):
        yield prefix, (EMPTY_ARRAY if not value else ARRAY_NODE)
        for item in value:
            yield from flatten(item, prefix + (EACH,))
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
class Shape(Kind):
    """A container this artifact is allowed to have, and whether it may be empty.

    A node policy is not decoration. Without one, a writer that adds a key whose
    value is `{}` adds a durable path the inventory never sees — and if the key
    is provider-chosen, a provider-chosen string reaches the file with the
    closed-world gate reporting nothing.
    """

    kind: str  # object | array
    may_be_empty: bool = True

    def problems(self, value: Any, context: dict[str, Any]) -> list[str]:
        if not isinstance(value, Node):
            return [f"{type(value).__name__} is not a container"]
        if value.kind != self.kind:
            return [f"an {value.kind} where an {self.kind} belongs"]
        if value.empty and not self.may_be_empty:
            return [f"an empty {self.kind} where this path always carries entries"]
        return []

    def describe(self) -> str:
        return f"{self.kind}{'' if self.may_be_empty else ' (non-empty)'}"


@dataclass(frozen=True)
class Prose(Kind):
    """A lexical defence in depth over a rendered line. **Not the provenance proof.**

    Three checks, in order. The references are removed first, and each must be
    spelled the way `opaque_ref` spells it — a well-formed reference is not
    material, it is a statement *about* material. What is left must lie in the
    local alphabet, and every word in it must be a word this module's source
    contains. A bearer token satisfies none of the three.

    What it cannot do, and what the first version of this module wrongly claimed
    it did: distinguish a line this module rendered from one that merely reads
    like it. `"timeout"` is a member of a local vocabulary, `"the completion
    carried the probe token"` is a sentence from the source, and sixteen hex
    characters are erased by `BARE_DIGEST` — a provider can send all three
    verbatim. Right shape is not proven origin, which is the same substitution
    this vertical withdrew for `isidentifier()` and then for sixty-four hex
    characters.

    Origin is proven by `detail_provenance_problems`, which rebuilds the line
    from the template the receipt says produced it. This check runs beside it
    and catches a different class of thing: material in a field the template
    pass does not cover, and a template whose own text has drifted somewhere
    foreign.
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


# Which receipt kind a path can appear in. Coverage is asked per kind, because
# "every policy is exercised" over the union is a weaker claim than it looks:
# a qualification-only path is trivially satisfied by a qualification scenario
# and says nothing about the probe, and vice versa.
#
# An enum rather than two strings, and checked at runtime rather than trusted to
# the annotation. `schemas=("proeb",)` — one transposition — put a policy in
# neither universe: it was demanded of no kind and declared for no kind, so both
# directions of the coverage proof went green by the policy simply vanishing.
# That is the escape hatch `coverage_required=False` was made to require an
# argument for, reachable by typo instead of by intent.
class ReceiptKind(enum.Enum):
    # `enum.Enum` spelled out, because this module already has a policy kind
    # named `Enum` — and a class statement that silently picked the wrong base
    # produced a `ReceiptKind` whose members were plain strings, which is
    # exactly the confusion this type exists to remove.
    PROBE = "probe"
    QUALIFICATION = "qualification"

    def __str__(self) -> str:
        return self.value


PROBE = ReceiptKind.PROBE
QUALIFICATION = ReceiptKind.QUALIFICATION
BOTH = (PROBE, QUALIFICATION)

SCHEMA_KINDS = {pm.PROBE_SCHEMA: PROBE, pm.QUALIFY_SCHEMA: QUALIFICATION}


@dataclass(frozen=True)
class DurableFieldPolicy:
    """One place a value may reach a receipt, and the only shape it may take.

    `schemas` says which receipt kinds the path can occur in, and
    `coverage_required` says whether a real pipeline run must be able to produce
    it. Both exist because the first version of this table asserted coverage
    over *classifications* and called it coverage of the table — so twelve of a
    hundred and nine policies were never exercised by any generated receipt, and
    weakening any of them left the suite green.
    """

    path: FieldPath
    kind: Kind
    schemas: tuple[str, ...] = BOTH
    nullable: bool = False
    coverage_required: bool = True
    why: str = ""

    def named(self) -> str:
        return render_path(self.path)

    def validate(self, value: Any, context: dict[str, Any]) -> list[str]:
        if value is None:
            return [] if self.nullable else [f"{self.named()}: null is not admitted here"]
        return [f"{self.named()}: {problem}" for problem in self.kind.problems(value, context)]


DETAIL_MAX_BYTES = 4096

# The evidence quartet `opaque_text` writes, as four policies. Written by a
# function rather than by hand because it appears eleven times and eleven
# hand-copies is eleven chances for one of them to differ silently.
def opaque_policies(
    prefix: FieldPath, name: str, domain: str, schemas: tuple[str, ...] = BOTH
) -> list[DurableFieldPolicy]:
    """The evidence quartet `opaque_text` writes, wherever it writes it."""
    return [
        DurableFieldPolicy(suffixed(prefix, f"{name}_present"), Flag(), schemas),
        DurableFieldPolicy(suffixed(prefix, f"{name}_sha256"), Digest(domain), schemas),
        DurableFieldPolicy(
            suffixed(prefix, f"{name}_bytes"),
            BoundedInt(0, pm.EVIDENCE_MAX_BYTES[domain]), schemas),
        DurableFieldPolicy(suffixed(prefix, f"{name}_oversize"), Flag(), schemas),
    ]


def model_evidence_policies(
    prefix: FieldPath, schemas: tuple[str, ...] = BOTH, fields: tuple[str, ...] | None = None
) -> list[DurableFieldPolicy]:
    """The projected identity of a reported model, wherever it appears.

    `fields` exists because `fold_reported_models` copies a *subset*:
    `MODEL_EVIDENCE_FIELDS` carries the name, its presence, its digest and its
    length, and deliberately not `_oversize` or `_type`. Generating the full
    quartet there declared two policies for paths nothing can produce — dead
    entries the coverage gate would then have to be told to ignore. A policy for
    a path that cannot exist is not caution, it is noise that looks like rigour.
    """
    everything = {
        "reported_model": DurableFieldPolicy(
            suffixed(prefix, "reported_model"), Local("requested_model"), schemas,
            nullable=True, why="text only when it equalled the model we asked for",
        ),
        "reported_model_type": DurableFieldPolicy(
            suffixed(prefix, "reported_model_type"),
            Enum("JSON type names", tuple(name for _, name in pm.JSON_TYPE_NAMES) + ("null", "unknown")),
            schemas,
            why="an object or a list in `model` crosses as its type and nothing else",
        ),
    }
    for policy in opaque_policies(prefix, "reported_model", "model-name", schemas):
        everything[policy.path[-1].value] = policy
    wanted = fields if fields is not None else (
        "reported_model", "reported_model_present", "reported_model_sha256",
        "reported_model_bytes", "reported_model_oversize", "reported_model_type")
    return [everything[name] for name in wanted]


def usage_policies(prefix: FieldPath, schemas: tuple[str, ...]) -> list[DurableFieldPolicy]:
    """One ceiling per counter, each derived from the bound the producer applies.

    A single `usage_ceiling` was computed from `response_limit`, which is a
    fact about the *response* — and `usage_bounds` bounds the counters by the
    size of the **request** this module sent. A caller passing a small response
    limit therefore made the auditor refuse a `prompt_tokens` the producer had
    every reason to admit. One shared ceiling would also have been slack for the
    other two: `completion_tokens` cannot exceed the `max_tokens` asked for, and
    saying only "some number under a shared bound" throws that away.
    """
    ceilings = {
        "prompt_tokens": "prompt_ceiling",
        "completion_tokens": "completion_ceiling",
        "total_tokens": "usage_ceiling",
    }
    return [
        DurableFieldPolicy(suffixed(prefix, counter), BoundedInt(0, ceilings[counter]), schemas)
        for counter in pm.USAGE_COUNTERS
    ]


def transport_policies(prefix: FieldPath, schemas: tuple[str, ...]) -> list[DurableFieldPolicy]:
    return [
        DurableFieldPolicy(
            suffixed(prefix, "transport_reason"),
            Enum("TRANSPORT_REASONS", pm.TRANSPORT_REASONS), schemas),
        DurableFieldPolicy(
            suffixed(prefix, "failure_kind"),
            Enum("TRANSPORT_FAILURE_KINDS", pm.TRANSPORT_FAILURE_KINDS), schemas),
        *opaque_policies(prefix, "failure_class", "failure-class", schemas),
    ]


def build_policies() -> list[DurableFieldPolicy]:
    """Every node and every leaf of both receipt kinds. The closed world itself.

    Container nodes are named too, so the table describes the *shape* of the
    artifact rather than only its scalars — which is what makes a
    provider-chosen key with an empty object under it a finding rather than a
    silence.
    """
    root: FieldPath = ()
    turn = P("turns", EACH)
    reported = P("reported_models", EACH)
    call = P("turns", EACH, "tool_calls", EACH)

    shared = [
        DurableFieldPolicy(P("schema"), Local("schema")),
        DurableFieldPolicy(P("target_id"), Local("target_id")),
        DurableFieldPolicy(P("provider"), Local("provider")),
        DurableFieldPolicy(P("requested_model"), Local("requested_model")),
        DurableFieldPolicy(P("classification"), Local("classifications")),
        DurableFieldPolicy(
            P("decision_reason"), Enum("DECISION_REASONS", pm.DECISION_REASONS), nullable=True),
        DurableFieldPolicy(P("detail"), Prose(DETAIL_MAX_BYTES)),
        DurableFieldPolicy(
            P("detail_template"), Enum("DETAIL_TEMPLATES", tuple(pm.DETAIL_TEMPLATES)),
            nullable=True,
            why="the template the line was rendered from; the provenance pass rebuilds it",
        ),
        DurableFieldPolicy(
            P("internal_failure_kind"),
            Enum("INTERNAL_FAILURE_KINDS", pm.INTERNAL_FAILURE_KINDS)),
        *opaque_policies(root, "internal_failure_class", "failure-class"),
        DurableFieldPolicy(
            P("model_status"), Enum("model statuses", tuple(pm.MODEL_STATUS_SEVERITY))),
        # `reported_model` is the one identity field both receipt kinds write at
        # the top level. The projected companions beside it are the probe's
        # alone: qualification folds identity into `reported_models[]` and keeps
        # only the single agreed name up here. The coverage gate found that —
        # the table had claimed all five for both kinds, and five paths one
        # receipt kind cannot produce were passing on the other one's evidence.
        *model_evidence_policies(root, BOTH, ("reported_model",)),
    ]

    probe = [
        DurableFieldPolicy(P("request_sha256"), Digest(), (PROBE,)),
        DurableFieldPolicy(P("endpoint"), Local("endpoint"), (PROBE,)),
        DurableFieldPolicy(P("latency_ms"), BoundedInt(0, pm.LATENCY_MAX_MS), (PROBE,)),
        DurableFieldPolicy(P("http_status"), BoundedInt(100, 599), (PROBE,)),
        DurableFieldPolicy(
            P("response_sha256"), Digest("response-body", sized=False), (PROBE,)),
        DurableFieldPolicy(P("response_bytes"), BoundedInt(0, "response_limit"), (PROBE,)),
        DurableFieldPolicy(
            P("body_bytes_observed"), BoundedInt(0, "observed_ceiling"), (PROBE,)),
        DurableFieldPolicy(
            P("completion_parse_kind"),
            Enum("COMPLETION_PARSE_KINDS", pm.COMPLETION_PARSE_KINDS), (PROBE,)),
        *opaque_policies(root, "request_id", "request-id", (PROBE,)),
        *model_evidence_policies(root, (PROBE,), (
            "reported_model_present", "reported_model_sha256",
            "reported_model_bytes", "reported_model_oversize", "reported_model_type")),
        *transport_policies(root, (PROBE,)),
        DurableFieldPolicy(P("provider_usage"), Shape("object"), (PROBE,)),
        *usage_policies(P("provider_usage"), (PROBE,)),
    ]

    qualification = [
        DurableFieldPolicy(P("turn_count"), BoundedInt(0, "max_turns"), (QUALIFICATION,)),
        DurableFieldPolicy(P("tool_result_roundtrip"), Flag(), (QUALIFICATION,)),
        DurableFieldPolicy(
            P("transport_target"), Shape("object", may_be_empty=False), (QUALIFICATION,)),
        DurableFieldPolicy(
            P("transport_target", "api_style"), Local("api_style"), (QUALIFICATION,), nullable=True),
        DurableFieldPolicy(
            P("transport_target", "endpoint"), Local("api_base"), (QUALIFICATION,), nullable=True),
        DurableFieldPolicy(
            P("transport_target", "path"), Local("completions_path"), (QUALIFICATION,)),
        DurableFieldPolicy(
            P("transport_target", "content_type"), Local("content_type"), (QUALIFICATION,)),
        DurableFieldPolicy(
            P("transport_target", "timeout_secs"),
            BoundedNumber(0, pm.TIMEOUT_MAX_SECS), (QUALIFICATION,)),
        DurableFieldPolicy(
            P("transport_target", "redirects_allowed"), BoundedInt(0, 0), (QUALIFICATION,)),
        DurableFieldPolicy(
            P("transport_target", "max_response_bytes"),
            BoundedInt(0, "response_limit"), (QUALIFICATION,)),
        DurableFieldPolicy(P("reported_models"), Shape("array"), (QUALIFICATION,)),
        DurableFieldPolicy(reported, Shape("object", may_be_empty=False), (QUALIFICATION,)),
        # Exactly the fields `fold_reported_models` copies — `MODEL_EVIDENCE_FIELDS`
        # and no more.
        *model_evidence_policies(reported, (QUALIFICATION,), pm.MODEL_EVIDENCE_FIELDS),
        # -- one turn --
        DurableFieldPolicy(P("turns"), Shape("array"), (QUALIFICATION,)),
        DurableFieldPolicy(turn, Shape("object", may_be_empty=False), (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(turn, "ordinal"), BoundedInt(0, "max_turns"), (QUALIFICATION,)),
        DurableFieldPolicy(suffixed(turn, "request_sha256"), Digest(), (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(turn, "request_bytes"), BoundedInt(0, "request_ceiling"), (QUALIFICATION,)),
        DurableFieldPolicy(suffixed(turn, "carried_tool_results"), Flag(), (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(turn, "response_sha256"), Digest("response-body", sized=False),
            (QUALIFICATION,), nullable=True),
        DurableFieldPolicy(
            suffixed(turn, "response_bytes"), BoundedInt(0, "response_limit"),
            (QUALIFICATION,), nullable=True),
        DurableFieldPolicy(suffixed(turn, "http_status"), BoundedInt(100, 599), (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(turn, "body_bytes_observed"),
            BoundedInt(0, "observed_ceiling"), (QUALIFICATION,)),
        DurableFieldPolicy(suffixed(turn, "key_env"), Local("key_env"), (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(turn, "outcome"), Enum("turn outcomes", TURN_OUTCOMES), (QUALIFICATION,)),
        DurableFieldPolicy(suffixed(turn, "detail"), Prose(DETAIL_MAX_BYTES), (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(turn, "detail_template"),
            Enum("DETAIL_TEMPLATES", tuple(pm.DETAIL_TEMPLATES)), (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(turn, "completion_parse_kind"),
            Enum("COMPLETION_PARSE_KINDS", pm.COMPLETION_PARSE_KINDS), (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(turn, "model_status"),
            Enum("model statuses", tuple(pm.MODEL_STATUS_SEVERITY)), (QUALIFICATION,)),
        DurableFieldPolicy(suffixed(turn, "tool_result_roundtrip"), Flag(), (QUALIFICATION,)),
        DurableFieldPolicy(suffixed(turn, "arguments_valid"), Flag(), (QUALIFICATION,)),
        DurableFieldPolicy(suffixed(turn, "terminal_answer_valid"), Flag(), (QUALIFICATION,)),
        DurableFieldPolicy(suffixed(turn, "canary_answer_matches"), Flag(), (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(turn, "canary_answer_errors"),
            Shape("array", may_be_empty=False), (QUALIFICATION,)),
        DurableFieldPolicy(
            extend(turn, "canary_answer_errors", EACH),
            Prose(DETAIL_MAX_BYTES), (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(turn, "canary_answer_error_templates"),
            Shape("array", may_be_empty=False), (QUALIFICATION,)),
        DurableFieldPolicy(
            extend(turn, "canary_answer_error_templates", EACH),
            Enum("DETAIL_TEMPLATES", tuple(pm.DETAIL_TEMPLATES)), (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(turn, "argument_errors_count"),
            BoundedInt(0, "error_ceiling"), (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(turn, "argument_errors_truncated"), Flag(), (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(turn, "argument_errors_kinds"), Shape("array"), (QUALIFICATION,)),
        DurableFieldPolicy(
            extend(turn, "argument_errors_kinds", EACH),
            Enum("argument error kinds", tuple(k for _, k in pm.ARGUMENT_ERROR_KINDS) + ("other",)),
            (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(turn, "argument_errors_sha256"),
            Digest("argument-errors", sized=False), (QUALIFICATION,)),
        DurableFieldPolicy(suffixed(turn, "tool_names"), Shape("array"), (QUALIFICATION,)),
        DurableFieldPolicy(
            extend(turn, "tool_names", EACH), Local("declared_tools"), (QUALIFICATION,)),
        DurableFieldPolicy(suffixed(turn, "tool_calls"), Shape("array"), (QUALIFICATION,)),
        DurableFieldPolicy(call, Shape("object", may_be_empty=False), (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(call, "ordinal"), BoundedInt(0, "max_call_ordinal"), (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(call, "name"), Local("declared_tools"), (QUALIFICATION,), nullable=True),
        *opaque_policies(call, "name", "tool-name", (QUALIFICATION,)),
        *opaque_policies(call, "call_id", "tool-call-id", (QUALIFICATION,)),
        *opaque_policies(turn, "request_id", "request-id", (QUALIFICATION,)),
        *model_evidence_policies(turn, (QUALIFICATION,)),
        *transport_policies(turn, (QUALIFICATION,)),
        DurableFieldPolicy(suffixed(turn, "reported_usage"), Shape("object"), (QUALIFICATION,)),
        *usage_policies(suffixed(turn, "reported_usage"), (QUALIFICATION,)),
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


# ---------------------------------------------------------------------------
# The second inventory: a detail must be rebuildable from its template
# ---------------------------------------------------------------------------

REFERENCE_PATTERN = r"<[a-z0-9-]+ sha256:[0-9a-f]{16} \d{1,10}\+?B>"
DIGEST_PATTERN = r"[0-9a-f]{16}"


def joined(pattern: str, separator: str) -> str:
    return f"(?:{pattern})(?:{re.escape(separator)}(?:{pattern}))*"


def alternation(values) -> str:
    return "|".join(re.escape(str(value)) for value in sorted(values, key=len, reverse=True))


def slot_pattern(slot: str, context: dict[str, Any], depth: int = 0) -> str:
    """The regex one slot's declared kind admits — and nothing wider.

    Every branch is built from something outside the artifact: a vocabulary
    declared in `provider_matrix`, the reference grammar, or a local fact the
    caller supplied. Nothing here is read from the receipt being audited, which
    is the whole difference between this and a lexical check.
    """
    if slot == "ref":
        return REFERENCE_PATTERN
    if slot == "refs":
        return joined(REFERENCE_PATTERN, ", ")
    if slot == "digests":
        return joined(DIGEST_PATTERN, ", ")
    if slot == "type":
        return alternation(pm.LOCAL_TYPE_NAMES)
    if slot == "types":
        return joined(alternation(
            tuple(name for _, name in pm.JSON_TYPE_NAMES) + ("null", "unknown")), ", ")
    if slot == "discriminator":
        known = alternation(f"'{word}'" for word in
                            set(pm.MESSAGE_ROLES) | set(pm.TOOL_CALL_TYPES) | {pm.ENVELOPE_ENCODING})
        return f"(?:{known}|{REFERENCE_PATTERN}|<[a-z0-9-]+ [a-z]+>)"
    if slot == "label":
        return f"(?:{alternation(pm.ENVELOPE_LABELS)}|{REFERENCE_PATTERN})"
    if slot == "key-env":
        # From the registry by way of the caller. A receipt naming any other
        # environment variable is a receipt that did not come from this plan.
        return re.escape(context["key_env"])
    if slot == "count":
        return r"\d{1,7}"
    if slot == "status":
        return r"\d{3}"
    if slot == "kinds":
        return joined(alternation(tuple(k for _, k in pm.ARGUMENT_ERROR_KINDS) + ("other",)), ", ")
    if slot.startswith("enum:"):
        return alternation(pm.vocabulary(slot[5:]))
    if slot in ("detail", "details"):
        # One level of nesting is all the table has, and a nested slot admits
        # only the templates that do not themselves nest — so the pattern stays
        # finite and the closure stays visible.
        if depth:
            raise ValueError("detail templates nest one level deep")
        inner = "|".join(
            f"(?:{template_pattern(name, context, depth + 1)})"
            for name in sorted(DETAIL_TEMPLATES_WITHOUT_NESTING))
        return inner if slot == "detail" else joined(inner, "; ")
    raise ValueError(f"unknown detail slot kind {slot!r}")


DETAIL_TEMPLATES_WITHOUT_NESTING = tuple(
    name for name, (_text, slots) in pm.DETAIL_TEMPLATES.items()
    if not any(slot in ("detail", "details") for slot in slots)
)


def template_pattern(name: str, context: dict[str, Any], depth: int = 0) -> str:
    text, slots = pm.DETAIL_TEMPLATES[name]
    # The literal parts are escaped and the slots are not; splitting on the
    # placeholders rather than formatting into them is what keeps a template's
    # own punctuation from being read as regex.
    parts = re.split(r"\{(\d+)\}", text)
    out = []
    for index, piece in enumerate(parts):
        if index % 2 == 0:
            out.append(re.escape(piece))
        else:
            out.append(f"(?:{slot_pattern(slots[int(piece)], context, depth)})")
    return "".join(out)


def detail_provenance_problems(receipt: dict[str, Any], context: dict[str, Any]) -> list[str]:
    """Every rendered line, against the pattern its own template declares.

    This is the provenance proof. `Prose` asks whether a string is made of local
    words; this asks whether it could have come out of `LocalDetail.render()`
    for the template the receipt says it came from, with arguments of the
    declared kinds and local facts taken from outside the artifact.
    """
    problems: list[str] = []
    for where, node in detail_bearing_nodes(receipt):
        template = node.get("detail_template")
        text = node.get("detail")
        if template is None:
            if text:
                problems.append(f"{where}: a detail with no template to rebuild it from")
            continue
        if template not in pm.DETAIL_TEMPLATES:
            problems.append(f"{where}: {template!r} is not a registered detail template")
            continue
        if not isinstance(text, str) or not re.fullmatch(template_pattern(template, context), text):
            problems.append(
                f"{where}: the detail does not match what template {template!r} renders")
    for where, node in detail_bearing_nodes(receipt):
        templates = node.get("canary_answer_error_templates")
        lines = node.get("canary_answer_errors")
        if templates is None and lines is None:
            continue
        if templates is None or lines is None or len(templates) != len(lines):
            problems.append(f"{where}: canary answer lines and their templates do not correspond")
            continue
        for index, (name, line) in enumerate(zip(templates, lines)):
            if name not in pm.DETAIL_TEMPLATES:
                problems.append(f"{where}: canary line {index} names an unregistered template")
            elif not re.fullmatch(template_pattern(name, context), line):
                problems.append(f"{where}: canary line {index} is not what {name!r} renders")
    return problems


def detail_bearing_nodes(receipt: dict[str, Any]):
    """The places a rendered line can land, over an artifact of any shape.

    Defensive about `turns` on purpose. This walks an artifact that may be
    malformed — that is the whole point of an auditor — and `for turn in
    receipt["turns"]` raised `TypeError` the first time a test handed it a
    scalar. A gate that dies on the input it exists to refuse reports nothing,
    which is the failure mode round eleven closed everywhere except here.
    """
    yield "receipt", receipt
    turns = receipt.get("turns")
    if not isinstance(turns, list):
        return
    for index, turn in enumerate(turns):
        if isinstance(turn, dict):
            yield f"turns[{index}]", turn


def policy_problems(policies: list[DurableFieldPolicy]) -> list[str]:
    """What is wrong with the table itself, before any receipt is read.

    Two policies for one path is the interesting case: it means two people
    each believed they owned a field, which is the state this whole module
    exists to make impossible.
    """
    problems: list[str] = []
    seen: dict[FieldPath, int] = {}
    for policy in policies:
        seen[policy.path] = seen.get(policy.path, 0) + 1
        problems.extend(
            f"{policy.named()}: {issue}" for issue in policy.kind.declaration_problems())
        if not policy.schemas:
            problems.append(f"{policy.named()}: applies to no receipt kind")
        for kind in policy.schemas:
            if not isinstance(kind, ReceiptKind):
                problems.append(
                    f"{policy.named()}: {kind!r} is not a receipt kind")
        # An opt-out from the coverage gate is a hole in the closed world, so it
        # has to be argued for in writing. `mutations.py` has required a stated
        # reason for every deliberately unmutated check since round nine; the
        # same rule belongs here, before someone reaches for the escape hatch
        # with a label reading "internal use".
        if not policy.coverage_required and not policy.why:
            problems.append(
                f"{policy.named()}: excused from coverage without a stated reason")
    for path, count in sorted(seen.items(), key=lambda entry: render_path(entry[0])):
        if count > 1:
            problems.append(
                f"{render_path(path)}: {count} policies claim this path; exactly one may")
    return problems


def policy_trie(policies: list[DurableFieldPolicy]) -> dict:
    """The declared paths as a tree, so a step can be judged *in its position*."""
    trie: dict = {}
    for policy in policies:
        node = trie
        for step in policy.path:
            node = node.setdefault(step, {})
    return trie


def render_step(step: Any) -> str:
    if isinstance(step, Each):
        return "[]"
    if isinstance(step, BadKey):
        return f"<non-string key: {step.json_type}>"
    return step.value


def render_path(path: FieldPath) -> str:
    """A declared path as a line. Diagnostics only — never used for matching."""
    out: list[str] = []
    for step in path:
        if isinstance(step, Each):
            out[-1] = out[-1] + "[]" if out else "[]"
        else:
            out.append(render_step(step))
    return ".".join(out)


def projected_path(path: FieldPath, policies: list[DurableFieldPolicy]) -> str:
    """A path, with every step the table does not declare **in that position**
    turned into a reference.

    Prefix-sensitive on purpose. The first version asked whether a component
    appeared anywhere in the table, so `provider_said.detail.name.ordinal`
    printed three provider-chosen keys verbatim — every one of them a declared
    word somewhere else in the tree, none of them declared *there*. A name known
    in another branch is not a name known here.

    Once a step is unrecognised the walk is lost, and every step after it is
    foreign too: nothing below an undeclared key can be a place this module
    named. `Each` keeps rendering as `[]` because it is the auditor's own
    structural marker rather than anything a provider chose.
    """
    node = policy_trie(policies)
    out: list[str] = []
    lost = False
    for step in path:
        if isinstance(step, Each):
            marker = "[]"
            if out and not lost:
                out[-1] = out[-1] + marker
            elif out:
                out[-1] = out[-1] + marker
            else:
                out.append(marker)
            node = node.get(step, {}) if not lost else {}
            continue
        if not lost and isinstance(step, Key) and step in node:
            out.append(step.value)
            node = node[step]
            continue
        lost = True
        if isinstance(step, BadKey):
            out.append(render_step(step))
        else:
            out.append(pm.opaque_ref("json-value", step.value).render())
    return ".".join(out)


def exactly_one_policy_for(
    path: FieldPath, policies: list[DurableFieldPolicy] | None = None
) -> DurableFieldPolicy:
    """The single policy for a path, or an error naming which rule was broken."""
    table = POLICIES if policies is None else policies
    matches = [policy for policy in table if policy.path == path]
    if not matches:
        raise KeyError(f"no policy names the durable field {projected_path(path, table)}")
    if len(matches) > 1:
        raise KeyError(
            f"{len(matches)} policies name the durable field {render_path(path)!r}")
    return matches[0]


def require_receipt_kind(value: object) -> ReceiptKind:
    """The coverage API's own door, checked at runtime.

    `ReceiptKind` closed the *table* and left the queries annotated `kind: str`,
    which Python does not enforce — an annotation stands beside a program and
    offers moral support while it does as it pleases. `coverage("probe", ...)`
    therefore matched no policy at all, so `declared` and `applicable` were both
    empty and both directions of the proof reported nothing wrong. A green
    answer produced by asking about a universe that does not exist is the same
    defect `schemas=("proeb",)` was, moved from the declaration to the query.
    """
    if not isinstance(value, ReceiptKind):
        raise TypeError(
            f"a receipt kind is a ReceiptKind, not {type(value).__name__}; "
            f"got {value!r}"
        )
    return value


def policies_for(
    kind: ReceiptKind, policies: list[DurableFieldPolicy] | None = None
) -> list[DurableFieldPolicy]:
    """The rows a receipt kind names — and the one place the kind is checked.

    The guard was first written at all four public queries, which sounds like
    defence in depth and is not: `coverage` calls `applicable_paths`, and
    `coverage_gaps` calls `coverage`, so three of the four checks could be
    deleted one at a time without a single proof going red. A check no proof
    can distinguish from its own absence is not a check — it is a comment with
    a runtime cost, and the mutation table said so.

    So selection is the door, and every query goes through it. Bypassing this
    function is now the mutation, and it is one each query can be caught doing.
    """
    kind = require_receipt_kind(kind)
    return [
        policy for policy in (POLICIES if policies is None else policies)
        if kind in policy.schemas
    ]


def declared_paths(
    kind: ReceiptKind, policies: list[DurableFieldPolicy] | None = None
) -> frozenset[FieldPath]:
    """Every path this receipt kind is *allowed* to contain."""
    return frozenset(policy.path for policy in policies_for(kind, policies))


def applicable_paths(
    kind: ReceiptKind, policies: list[DurableFieldPolicy] | None = None
) -> frozenset[FieldPath]:
    """Every path a receipt of this kind must be able to produce."""
    return frozenset(
        policy.path for policy in policies_for(kind, policies)
        if policy.coverage_required
    )


@dataclass(frozen=True)
class Coverage:
    """What a receipt kind failed to produce, and what it produced regardless.

    Two directions, because the first version only had one. `missing` finds a
    policy no run exercises — a policy nothing exercises is a policy nothing
    defends. `wrong_schema` finds the opposite lie: a path a real run *did*
    produce for a kind whose policy says that kind does not produce it. Marking
    a shared policy probe-only would leave qualification writing the field and
    the coverage gate perfectly green, because subtracting in one direction
    cannot see a declaration that is simply false.
    """

    missing: list[str]
    wrong_schema: list[str]

    def problems(self) -> list[str]:
        return ([f"no run produces {path}" for path in self.missing]
                + [f"a run produced {path}, which this kind does not declare"
                   for path in self.wrong_schema])


def coverage(
    kind: ReceiptKind, reached: set[FieldPath],
    policies: list[DurableFieldPolicy] | None = None
) -> Coverage:
    # No guard of its own: both queries below select through `policies_for`,
    # which is where the kind is checked. A second check here would be one
    # nothing could tell from its own absence.
    table = POLICIES if policies is None else policies
    required = applicable_paths(kind, policies)
    declared = declared_paths(kind, policies)
    return Coverage(
        missing=sorted(render_path(path) for path in required - reached),
        # A path no policy names at all is `audit`'s finding, not this one:
        # reporting it here too would make one defect look like two.
        wrong_schema=sorted(
            render_path(path) for path in (reached - declared)
            if any(policy.path == path for policy in table)
        ),
    )


def coverage_gaps(
    kind: ReceiptKind, reached: set[FieldPath],
    policies: list[DurableFieldPolicy] | None = None
) -> list[str]:
    return coverage(kind, reached, policies).problems()


def reached_paths(receipt: dict[str, Any]) -> set[FieldPath]:
    return {path for path, _ in flatten(receipt)}


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
    # And the provenance pass, which is a claim about how a value was *built*
    # and therefore cannot be made leaf by leaf.
    findings.extend(detail_provenance_problems(receipt, context))
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
    kind = SCHEMA_KINDS.get(schema)
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
        # From the request bound and the generation ceiling, which is what
        # `usage_bounds` uses — never from `response_limit`, which describes
        # something else entirely and made a legitimate count a finding.
        "prompt_ceiling": pm.MAX_REQUEST_BYTES,
        "completion_ceiling": (
            pm.PROBE_MAX_TOKENS if kind is PROBE else pm.QUALIFY_MAX_TOKENS),
        "usage_ceiling": pm.MAX_REQUEST_BYTES + (
            pm.PROBE_MAX_TOKENS if kind is PROBE else pm.QUALIFY_MAX_TOKENS),
        "max_turns": max_turns,
        # Derived, not declared. Both were literal `1024`s here and nowhere
        # else, so the producer had never heard of them and could compose a
        # receipt this table then refused — an artifact failing the audit of
        # the module that wrote it. The bound belongs where it is enforced;
        # this is the reader of it.
        "error_ceiling": pm.MAX_ARGUMENT_ERRORS,
        # An ordinal, not a cardinality. `call_ceiling: 1024` admitted ordinals
        # 0..1024 — one more call than the producer's bound allows — and the
        # name is what hid the difference.
        "max_call_ordinal": pm.MAX_CALL_ORDINAL,
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
        "detail_template": "probe-token-matched",
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

    # The specimen the lexical check cannot refuse and the provenance pass can:
    # every word is one this module wrote, in a line it never renders.
    forged = sound_specimen()
    forged["detail"] = "the completion carried the probe token, not an object"

    # And a line whose template says it should look like something else. A
    # provider value copied into `detail` keeps whatever template was in flight.
    mismatched = sound_specimen()
    mismatched["detail_template"] = "no-terminal-answer"

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
        ("local words in a line this module never renders", forged, "does not match what template"),
        ("a line that disagrees with its own template", mismatched, "does not match what template"),
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
    doubled = POLICIES + [DurableFieldPolicy(P("detail"), Flag())]
    if not any("exactly one may" in problem for problem in policy_problems(doubled)):
        print("FAIL two policies for one path were not reported")
        return 1
    excused = [DurableFieldPolicy(P("x"), Flag(), coverage_required=False)]
    if not any("without a stated reason" in problem for problem in policy_problems(excused)):
        print("FAIL a policy excused from coverage without a reason was not reported")
        return 1
    # One transposition put a policy in neither universe, and both directions of
    # the coverage proof went green by the policy simply vanishing.
    mistyped = [DurableFieldPolicy(P("x"), Flag(), ("proeb",))]
    if not any("is not a receipt kind" in problem for problem in policy_problems(mistyped)):
        print("FAIL a policy declaring an unknown receipt kind was not reported")
        return 1
    if not any("applies to no receipt kind" in problem
               for problem in policy_problems([DurableFieldPolicy(P("x"), Flag(), ())])):
        print("FAIL a policy applying to no receipt kind was not reported")
        return 1
    if not any("not declared in EVIDENCE_DOMAINS" in problem for problem in
               policy_problems([DurableFieldPolicy(P("x"), Digest("no-such-domain"))])):
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
    for policy in sorted(POLICIES, key=lambda p: p.named()):
        null = " (nullable)" if policy.nullable else ""
        print(f"  {policy.named():<52} {policy.kind.describe()}{null}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
