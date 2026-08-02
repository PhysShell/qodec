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
import json
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
        # A context carrying a *string* where a ceiling belongs is a caller
        # defect, and comparing against it raised `TypeError` out of the
        # auditor. The bound is read as a number or reported as absent.
        if not isinstance(top, (int, float)) or isinstance(top, bool):
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
        # Read as a collection of words, not taken on trust: `local_words: 0`
        # made `set()` raise out of the auditor, and a context is a caller's
        # claim like any other.
        extra = context.get("local_words") if isinstance(context, dict) else None
        allowed = LOCAL_WORDS | {
            word for word in (extra if isinstance(extra, (set, frozenset, tuple, list)) else ())
            if isinstance(word, str)}
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


# Read from the producer rather than restated. Two literals agree only until
# somebody edits one of them, which is the whole of rounds eighteen to twenty.
DETAIL_MAX_BYTES = pm.DETAIL_MAX_BYTES

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
        DurableFieldPolicy(P("request_bytes"), BoundedInt(0, "request_ceiling"), (PROBE,)),
        DurableFieldPolicy(P("endpoint"), Local("endpoint"), (PROBE,)),
        DurableFieldPolicy(P("latency_ms"), BoundedInt(0, pm.LATENCY_MAX_MS), (PROBE,)),
        DurableFieldPolicy(P("http_status"),
                           BoundedInt(pm.HTTP_STATUS_MIN, pm.HTTP_STATUS_MAX),
                           (PROBE,)),
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
        DurableFieldPolicy(suffixed(turn, "http_status"),
                           BoundedInt(pm.HTTP_STATUS_MIN, pm.HTTP_STATUS_MAX),
                           (QUALIFICATION,)),
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
            suffixed(turn, "canary_answer_errors_count"),
            BoundedInt(0, "canary_ceiling"), (QUALIFICATION,)),
        DurableFieldPolicy(
            suffixed(turn, "canary_answer_errors_truncated"), Flag(), (QUALIFICATION,)),
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


# ---------------------------------------------------------------------------
# Who applies each bound
# ---------------------------------------------------------------------------
#
# A ceiling written here and nowhere else is not a bound; it is an opinion the
# producer has never been told about. That was found three times — the tool-call
# ordinal, the argument-error count, and the canary diagnostics — and each was
# closed where a reviewer pointed. Three instances of one class, repaired one at
# a time, is the method this vertical spent five rounds retiring.
#
# So the class is closed instead. Every policy that states a *quantity* — a byte
# bound, an integer ceiling, a bounded number — names a producer-side strategy,
# and `policy_problems` refuses a bounded policy that names none. There are
# exactly three strategies, and the difference between them is what happens when
# a provider goes past the bound:
#
#   Refuse   the overrun changes the verdict; the ordinary artifact is not built
#   Project  bounded evidence is kept, with an explicit truncation or overflow
#            flag, and every neighbouring field describes that same kept part
#   Derive   the value cannot exceed the bound, because this module computes it
#            from something already bounded
#
# `Derive` is the one that can rot quietly, so it costs a sentence naming *what*
# bounds it. "It is local" is not an answer — round fourteen retired that
# argument for `request_bytes`, which this module also composed.


@dataclass(frozen=True)
class Refuse:
    """Past the bound, the run gets a different verdict rather than a big field.

    `source` names who can push the value past the bound, and it decides what a
    correct refusal looks like. A quantity a *provider* can choose must end in a
    classification about the exchange: filing it as `INTERNAL_ERROR` says this
    tool broke, which is the round-nine mistake in a new field. A quantity only
    an injected *sender* can produce is a broken caller, and `INTERNAL_ERROR` is
    then the honest answer — the contract it violated is ours.
    """

    why: str
    source: str = "sender"


@dataclass(frozen=True)
class Project:
    """Past the bound, a bounded prefix is kept and says that it is one."""

    why: str


@dataclass(frozen=True)
class Derive:
    """The value is computed from something already bounded. `why` names it."""

    why: str


BoundStrategy = Refuse | Project | Derive


def bounded_kinds(kind: Kind) -> bool:
    """Whether a policy states a quantity a provider could try to exceed."""
    return isinstance(kind, (BoundedInt, BoundedNumber, Prose))


def bounded_paths(policies: list[DurableFieldPolicy] | None = None) -> frozenset[FieldPath]:
    return frozenset(
        policy.path for policy in (POLICIES if policies is None else policies)
        if bounded_kinds(policy.kind))


POLICIES = build_policies()


def _bound_enforcement() -> dict[FieldPath, BoundStrategy]:
    """One entry per bounded policy, naming who keeps the value inside it.

    Written out rather than generated, because a table generated from the thing
    it checks agrees with it by construction and proves nothing.
    """
    turn = P("turns", EACH)
    call = extend(turn, "tool_calls", EACH)
    projected = Project("`opaque_text` keeps a bounded length and sets `_oversize`")
    counted = Refuse(
        "`normalize_provider_usage` drops a counter outside the bounds the "
        "request produced; a receipt never carries an out-of-range one",
        source="provider")
    status = Refuse(
        "`validate_send_result` refuses a status outside the three digits the "
        "wire can carry. Past the bound is a *sender*, not a peer: "
        "`http.client._read_status` raises `BadStatusLine` for anything outside "
        "100..999, so a four-digit status arrives as a framing failure and never "
        "as a status. Inside the bound is the provider's, and an unassigned code "
        "is classified by `classify_http` rather than refused — which it was not "
        "until this table asked who could reach 600")
    observed = Refuse(
        "`validate_send_result` refuses a count past `response_limit + 1`, "
        "which is the largest `read_bounded` can produce")
    read = Derive("`read_bounded` stops at `response_limit + 1`")
    sender_class = Refuse(
        "`validate_send_result` refuses a `failure_class` past "
        "`FAILURE_CLASS_MAX_BYTES` — unlike a provider header, this one is the "
        "sender's, and the real sender derives it from a local exception class")
    request = Refuse(
        "`bounded_request` refuses a body past `MAX_REQUEST_BYTES` before it "
        "is sent, so an oversized body never becomes a durable count",
        source="provider")
    return {
        # -- the top-level receipt --
        P("detail"): Derive(
            "`pm.unbounded_templates()` computes the longest line every "
            "registered template can render and requires it under "
            "`pm.DETAIL_MAX_BYTES`; the sentence that used to stand here said "
            "the same thing and was false"),
        P("latency_ms"): Derive("`latency_ms_since` clamps to `LATENCY_MAX_MS`"),
        P("turn_count"): Derive("the loop runs `bounded_turns(max_turns)` times"),
        P("http_status"): status,
        P("response_bytes"): read,
        P("body_bytes_observed"): observed,
        P("request_bytes"): request,
        P("internal_failure_class_bytes"): projected,
        P("request_id_bytes"): projected,
        P("reported_model_bytes"): projected,
        P("failure_class_bytes"): sender_class,
        P("reported_models", EACH, "reported_model_bytes"): projected,
        P("provider_usage", "prompt_tokens"): counted,
        P("provider_usage", "completion_tokens"): counted,
        P("provider_usage", "total_tokens"): counted,
        P("transport_target", "redirects_allowed"): Derive(
            "a local constant; this module never follows a redirect"),
        P("transport_target", "max_response_bytes"): Derive(
            "the caller's `response_limit`, which is the bound itself"),
        P("transport_target", "timeout_secs"): Derive(
            "`bounded_timeout` refuses anything past `TIMEOUT_MAX_SECS`"),
        # -- one turn --
        suffixed(turn, "ordinal"): Derive("the loop index, under `bounded_turns`"),
        suffixed(turn, "detail"): Derive("the same computed certificate as `detail`"),
        suffixed(turn, "http_status"): status,
        suffixed(turn, "response_bytes"): read,
        suffixed(turn, "body_bytes_observed"): observed,
        suffixed(turn, "request_bytes"): request,
        suffixed(turn, "request_id_bytes"): projected,
        suffixed(turn, "reported_model_bytes"): projected,
        suffixed(turn, "failure_class_bytes"): sender_class,
        suffixed(turn, "argument_errors_count"): Project(
            "`error_evidence` keeps `MAX_ARGUMENT_ERRORS` and sets "
            "`argument_errors_truncated`"),
        extend(turn, "canary_answer_errors", EACH): Project(
            "`canary_evidence` keeps `MAX_CANARY_ERRORS` lines and sets "
            "`canary_answer_errors_truncated`"),
        suffixed(turn, "canary_answer_errors_count"): Project(
            "the length of the kept prefix `canary_evidence` recorded, with "
            "`canary_answer_errors_truncated` beside it"),
        extend(turn, "reported_usage", "prompt_tokens"): counted,
        extend(turn, "reported_usage", "completion_tokens"): counted,
        extend(turn, "reported_usage", "total_tokens"): counted,
        suffixed(call, "ordinal"): Refuse(
            "`parse_tool_calls` refuses a response carrying more than "
            "`MAX_TOOL_CALLS`, before an ordinal is assigned", source="provider"),
        suffixed(call, "name_bytes"): projected,
        suffixed(call, "call_id_bytes"): projected,
    }


BOUND_ENFORCEMENT: dict[FieldPath, BoundStrategy] = _bound_enforcement()


def enforcement_problems(
    policies: list[DurableFieldPolicy] | None = None,
    enforcement: dict[FieldPath, BoundStrategy] | None = None,
) -> list[str]:
    """Every bounded field names a producer strategy, and every strategy a field.

    Set equality in both directions, for the reason coverage is asked in both:
    a bound nobody applies is the defect this exists for, and a strategy naming
    no bounded field is a claim about a place that no longer has a ceiling.
    """
    table = BOUND_ENFORCEMENT if enforcement is None else enforcement
    bounded = bounded_paths(policies)
    problems = [
        f"{render_path(path)}: bounded by the table and enforced by nobody"
        for path in sorted(bounded - set(table), key=render_path)
    ]
    problems.extend(
        f"{render_path(path)}: an enforcement entry for a field with no bound"
        for path in sorted(set(table) - bounded, key=render_path)
    )
    problems.extend(
        f"{render_path(path)}: {type(strategy).__name__} without a stated reason"
        for path, strategy in sorted(table.items(), key=lambda e: render_path(e[0]))
        if not strategy.why.strip()
    )
    # A `Derive` on a `Prose` field is a claim about how long a line can get,
    # and that is a claim arithmetic settles. The nineteenth round wrote the
    # claim as a sentence, the sentence passed this gate, and it was false: two
    # templates joined a collection whose size a provider chooses. So the
    # sentence no longer counts as evidence — the certificate does, and a field
    # whose lines cannot be certified may not be `Derive` at all.
    uncertified = pm.unbounded_templates()
    if uncertified:
        kinds = {policy.path: policy.kind for policy in (POLICIES if policies is None else policies)}
        for path, strategy in sorted(table.items(), key=lambda e: render_path(e[0])):
            if isinstance(strategy, Derive) and isinstance(kinds.get(path), Prose):
                problems.append(
                    f"{render_path(path)}: Derive on a Prose field, but "
                    f"{len(uncertified)} template(s) have no certificate")
        problems.extend(f"detail template {line}" for line in uncertified)
    return problems


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
        # A context with no `key_env` is the caller's defect, and it is reported
        # as one: a pattern that matches nothing turns every line carrying the
        # slot into a finding, where substituting an empty string would have
        # made the neighbours prove a context nobody supplied.
        supplied = context_str(context, "key_env")
        return r"(?!)" if supplied is None else re.escape(supplied)
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
        template = node.get("detail_template") if isinstance(node, dict) else None
        text = node.get("detail") if isinstance(node, dict) else None
        if template is None:
            if text:
                problems.append(f"{where}: a detail with no template to rebuild it from")
            continue
        # Read as a string before it is looked up: `detail_template: []` is a
        # receipt somebody can write, and `[] in {...}` raises rather than
        # answering no.
        if read_str(template) is None or template not in pm.DETAIL_TEMPLATES:
            problems.append(f"{where}: {template!r} is not a registered detail template")
            continue
        if not isinstance(text, str) or not re.fullmatch(template_pattern(template, context), text):
            problems.append(
                f"{where}: the detail does not match what template {template!r} renders")
    for where, node in detail_bearing_nodes(receipt):
        if not isinstance(node, dict) or (
                "canary_answer_error_templates" not in node
                and "canary_answer_errors" not in node):
            continue
        templates = read_list(node, "canary_answer_error_templates")
        lines = read_list(node, "canary_answer_errors")
        # Read as lists before either is counted. `len()` on whatever the
        # artifact happened to carry raised `TypeError` out of the auditor, and
        # `canary_answer_error_templates: 5` is a receipt somebody can write.
        if templates is None or lines is None or len(templates) != len(lines):
            problems.append(f"{where}: canary answer lines and their templates do not correspond")
            continue
        for index, (name, line) in enumerate(zip(templates, lines)):
            text = read_str(line)
            # The *element*, not just the list. Twelve lines up the same lookup
            # reads its value first and says why; here the list was read and its
            # members were not, so `["", []] in {...}` raised straight out of
            # the auditor. Reading the container is not reading what is in it.
            registered = read_str(name)
            if registered is None or registered not in pm.DETAIL_TEMPLATES:
                problems.append(f"{where}: canary line {index} names an unregistered template")
            elif text is None or not re.fullmatch(template_pattern(registered, context), text):
                problems.append(
                    f"{where}: canary line {index} is not what {registered!r} renders")
    return problems


# ---------------------------------------------------------------------------
# What the auditor will read, and what it does with what it cannot
# ---------------------------------------------------------------------------
#
# An auditor walks artifacts that may be malformed — that is the whole job — so
# dying on one is the failure mode, not an edge case. Two of them were found on
# the head that shipped the bounded-field closure: `len()` on a value taken
# straight from the receipt, and `context["key_env"]` on a context that need not
# carry it. Both raise out of `audit()` and a gate that raises reports nothing.
#
# Wrapping the whole thing in `except Exception` would make it total the way
# unplugging a server makes it secure: every programming error becomes an
# indistinguishable finding. So totality is built rather than caught.
#
#   1. An admission boundary. "Any JSON" includes trees that end in
#      `RecursionError` before the auditor gets an opinion, so depth and node
#      count are bounded and going past them is a finding.
#   2. Typed readers. Nothing calls `len`, `zip`, `re`, `in` or `[...]` on a
#      value that has not been read as the type it is supposed to be.
#   3. A malformed corpus, generated rather than listed, run by the shipped
#      self-test as a subprocess so a traceback is a red build.
#
# One malformed leaf must not stop the rest: an early return would swap a crash
# for a silence, which is tidier and proves the same amount.

AUDIT_MAX_DEPTH = 64
AUDIT_MAX_NODES = 100_000


def admissible(receipt: Any) -> str | None:
    """Whether this artifact is one the auditor can walk to a verdict.

    Bounded rather than trusted: a receipt is written by this module, but
    `audit` is also handed hostile and hand-edited ones, and "it fits in
    memory" is not a contract anybody stated.
    """
    nodes = 0
    stack = [(receipt, 0)]
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > AUDIT_MAX_NODES:
            return f"the receipt carries more than {AUDIT_MAX_NODES} nodes"
        if depth > AUDIT_MAX_DEPTH:
            return f"the receipt nests deeper than {AUDIT_MAX_DEPTH}"
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
    return None


MISSING = object()


def read_list(node: Any, key: str) -> list | None:
    """A member that must be a list, or `None` for absent-or-not-a-list."""
    value = node.get(key) if isinstance(node, dict) else None
    return value if isinstance(value, list) else None


def read_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def context_str(context: dict[str, Any], key: str) -> str | None:
    """A local fact the caller was supposed to supply, or `None`.

    `None` is the honest answer and the callers act on it. Substituting an
    empty string would make the neighbouring checks prove a context nobody
    supplied, which is worse than the `KeyError` it replaces.
    """
    value = context.get(key) if isinstance(context, dict) else None
    return value if isinstance(value, str) else None


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
            # One branch, not two. The first version tested `lost` here and did
            # the same thing either way — a distinction written down and then
            # not made, which reads as though being lost changes the rendering.
            # It does not: `[]` is this module's own structural marker, so it
            # renders identically wherever the walk is. `lost` still decides the
            # descent below, where it does change the answer.
            if out:
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
    if not isinstance(receipt, dict):
        return [f"a receipt is an object, not {pm.json_type_name(receipt)}"]
    inadmissible = admissible(receipt)
    if inadmissible is not None:
        # Refused rather than walked. "Any JSON" includes trees that end in a
        # `RecursionError` before this function has an opinion, and a bound
        # nobody stated is a bound nobody keeps.
        return [inadmissible]
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
        "canary_ceiling": pm.MAX_CANARY_ERRORS,
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


# The JSON values a field can be replaced by. Not a list of the two malformed
# shapes a review happened to find — a generator, so the corpus grows with the
# artifact instead of with the review history.
HOSTILE_VALUES: tuple[Any, ...] = (
    None, True, 0, -1, 3.5, "", "text", [], {}, [[]], {"k": {}}, [{"k": []}],
)

HOSTILE_CONTEXT_VALUES: tuple[Any, ...] = (None, 0, "", [], {})


def canned_sender(replies: list):
    replies = list(replies)

    def send(_url, _body, _timeout):
        return replies.pop(0)

    return send


def fixture_row() -> dict[str, Any]:
    entry = pm.load_registry()["providers"]["groq"]
    return {"target_id": "groq--m", "provider": "groq", "model": "m",
            "api_base": entry["api_base"], "key_env": entry["key_env"],
            "api_style": entry["api_style"]}


def fixtures() -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    """Real receipts of both kinds, produced by the real pipeline.

    Hand-written ones were the first version's mistake in a second form: the
    corpus claimed to mutate `turns[]` and the only specimen it was handed was
    a flat probe receipt, so the branch existed and never ran. Fixtures are
    produced rather than spelled, and the coverage report below counts what was
    actually mutated rather than what the generator is capable of.
    """
    surface = pm.load_surface(HERE / "c1-panel-surface.json")
    registry = pm.load_registry()
    row = fixture_row()
    entry = registry["providers"]["groq"]
    limit = 4096

    def qualify(replies):
        return pm.qualify_target(row, surface, 30.0, 6, canned_sender(replies),
                                 response_limit=limit)

    def context(schema):
        return context_for(schema, row, entry, response_limit=limit, max_turns=6,
                           declared_tools={op["name"] for op in surface["operations"]})

    probe_ok = json.dumps({"model": "m", "usage": {"prompt_tokens": 7},
                           "choices": [{"message": {"content": "QODEC_PROBE_OK"}}]}).encode()
    probe = pm.probe_target(row, 5.0, canned_sender([(200, probe_ok, "", "completed")]),
                            registry, response_limit=limit)

    def one_call(name, arguments, call_id):
        return {"id": call_id, "type": "function",
                "function": {"name": name, "arguments": arguments}}

    def completion(calls):
        return json.dumps({"model": "m", "choices": [{"message": {
            "role": "assistant", "content": None, "tool_calls": calls}}]}).encode()

    operation = (200, completion([one_call(
        "qodec_intersect", json.dumps({"index": "i", "sections": ["a"]}), "c1")]), "")
    answer = (200, completion([one_call("qodec_answer", json.dumps({
        "handle": pm.CANNED_HANDLE,
        "answer": {"encoding": "base64url-nopad", "data": "YWxwaGE"},
        "cited": [{"store": pm.CANNED_HANDLE, "section": "absent", "ordinal": 0}],
    }), "c2")]), "")

    return [
        ("probe", probe, context(pm.PROBE_SCHEMA)),
        # Enough replies for the whole budget: the run ends on the turn limit
        # rather than on an empty script, so the receipt carries every turn the
        # loop can produce.
        ("qualification with turns", qualify([operation] * 6),
         context(pm.QUALIFY_SCHEMA)),
        ("qualification with canary findings", qualify([operation, answer]),
         context(pm.QUALIFY_SCHEMA)),
    ]


# The places the corpus commits to reaching, as structural paths rather than as
# bare member names. Written out rather than derived from the fixtures: derived,
# deleting a fixture would delete the requirement along with the coverage it
# stopped providing, and the gate would stay green while the reach shrank —
# which is the illusion this round keeps finding in new clothes. Every entry is
# checked below against the policy table, so the list cannot name a place the
# auditor has no opinion about either.
WITNESS_REQUIRED: tuple[FieldPath, ...] = (
    P("schema"),
    P("target_id"),
    P("provider"),
    P("classification"),
    P("detail"),
    P("detail_template"),
    P("provider_usage"),
    P("transport_target"),
    P("reported_models"),
    P("reported_models", EACH),
    P("reported_models", EACH, "reported_model"),
    P("reported_models", EACH, "reported_model_present"),
    P("turns"),
    P("turns", EACH),
    P("turns", EACH, "ordinal"),
    P("turns", EACH, "outcome"),
    P("turns", EACH, "tool_calls"),
    P("turns", EACH, "tool_calls", EACH),
    P("turns", EACH, "tool_calls", EACH, "ordinal"),
    P("turns", EACH, "tool_calls", EACH, "name"),
    P("turns", EACH, "tool_calls", EACH, "call_id_sha256"),
    P("turns", EACH, "tool_names"),
    P("turns", EACH, "tool_names", EACH),
    P("turns", EACH, "canary_answer_errors"),
    P("turns", EACH, "canary_answer_errors", EACH),
    P("turns", EACH, "canary_answer_error_templates"),
    P("turns", EACH, "canary_answer_error_templates", EACH),
)


@dataclass
class Reached:
    """What the corpus actually mutated, as opposed to what it can mutate.

    Paths, not names. `ordinal` appears three times in a qualification receipt —
    on the receipt's turns, on each turn's tool calls, and nowhere the two mean
    the same thing — so a tally keyed by the bare word said "ordinal covered"
    after mutating exactly one of them.
    """

    paths: set = field(default_factory=set)
    context_keys: set = field(default_factory=set)
    root_shapes: int = 0
    specimens: int = 0


def fixture_paths(node: Any, prefix: FieldPath = ()) -> set:
    """Every normalized structural path a value contains.

    Arrays collapse: `turns[3]` is not a different *kind* of place than
    `turns[0]`, and the auditor does not treat it as one. But the union runs
    over every element, not over the first — the canary fields exist only on the
    turn that ends the exchange, so a walk that stopped at `turns[0]` reported
    that no fixture contains them and would have been believed.
    """
    found = {prefix} if prefix else set()
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str):
                found |= fixture_paths(value, prefix + (Key(key),))
    elif isinstance(node, list):
        for element in node:
            found |= fixture_paths(element, prefix + (EACH,))
    return found


def locate(node: Any, path: FieldPath):
    """The container and last step of a path's first occurrence.

    Returns `(container, step)` where `step` is a dict key or a list index, or
    `None` when the path is nowhere in the value. One occurrence is enough: the
    corpus is a statement about kinds of places, and a receipt whose *second*
    tool call is a string is the same question as one whose first is.
    """
    if not path:
        return None
    step, rest = path[0], path[1:]
    if isinstance(step, Each):
        if not isinstance(node, list):
            return None
        for index, element in enumerate(node):
            if not rest:
                return node, index
            found = locate(element, rest)
            if found is not None:
                return found
        return None
    if not isinstance(node, dict) or step.value not in node:
        return None
    if not rest:
        return node, step.value
    return locate(node[step.value], rest)


def malformed_specimens(receipt: dict[str, Any], seen: "Reached | None" = None):
    """One receipt per way a single place in it can be the wrong thing.

    Recursive over normalized paths. The first version walked the receipt's own
    members and `turns[0]`'s, which stopped exactly where the nesting starts: a
    tool call's `ordinal`, a canary error's string, a reported model's flag were
    all beyond it, and those are the shapes a provider's own values reach.
    """
    import copy

    tally = Reached() if seen is None else seen
    for path in sorted(fixture_paths(receipt), key=render_path):
        where = render_path(path)
        without = copy.deepcopy(receipt)
        found = locate(without, path)
        if found is None:
            # The path was discovered by the walk and cannot be addressed by
            # the locator: the two disagree, and recording it as reached would
            # let the coverage report answer for specimens nobody produced.
            continue
        tally.paths.add(path)
        container, step = found
        # `del` reads the same on a member and on an element; the container
        # decides what the step means.
        del container[step]
        yield f"{where} absent", without
        for value in HOSTILE_VALUES:
            swapped = copy.deepcopy(receipt)
            container, step = locate(swapped, path)
            container[step] = copy.deepcopy(value)
            yield f"{where} = {value!r}", swapped
    hostile_key = copy.deepcopy(receipt)
    hostile_key[7] = "an integer key"
    yield "a key that is not a string", hostile_key
    for value in HOSTILE_VALUES:
        tally.root_shapes += 1
        yield f"the receipt itself is {value!r}", value


def hostile_contexts(context: dict[str, Any], seen: "Reached | None" = None):
    """The context, with each local fact missing and each of the wrong type."""
    import copy
    tally = Reached() if seen is None else seen
    for key in list(context):
        tally.context_keys.add(key)
        without = copy.deepcopy(context)
        del without[key]
        yield f"context.{key} absent", without
        for value in HOSTILE_CONTEXT_VALUES:
            swapped = copy.deepcopy(context)
            swapped[key] = copy.deepcopy(value)
            yield f"context.{key} = {value!r}", swapped


def totality_problems(auditor: Callable[..., list[str]] | None = None,
                      cases: list | None = None,
                      corpus: list | None = None) -> tuple[list[str], Reached]:
    """Run the whole malformed corpus and report anything that is not a verdict.

    A raise here is the finding. So is a non-deterministic answer: an auditor
    that reports different things about the same artifact is one nobody can act
    on, and dict ordering is exactly the kind of thing that makes that happen
    without anybody noticing.
    """
    check = audit if auditor is None else auditor
    tally = Reached()
    if cases is None:
        cases = []
        for _name, receipt, context in (fixtures() if corpus is None else corpus):
            cases.extend((why, bad, context)
                         for why, bad in malformed_specimens(receipt, tally))
            cases.extend((why, receipt, bad)
                         for why, bad in hostile_contexts(context, tally))
    problems: list[str] = []
    for name, receipt, context in cases:
        tally.specimens += 1
        try:
            first = check(receipt, context)
            second = check(receipt, context)
        except Exception as exc:  # noqa: BLE001 — the raise *is* the finding
            problems.append(f"{name}: audit raised {type(exc).__name__}")
            continue
        if not isinstance(first, list) or not all(isinstance(x, str) for x in first):
            problems.append(f"{name}: audit did not return a list of findings")
        elif first != second:
            problems.append(f"{name}: audit is not deterministic")
    return problems, tally


def declared_places(policies: list[DurableFieldPolicy] | None = None) -> set:
    """Every path the policy table names.

    This was written as "every path, *together with its containers*", expanding
    each policy path into all its prefixes so that `turns[].tool_calls[]` would
    count as declared even if only its members were. The mutation aimed at that
    expansion survived, and the reason is that it produced no path the table did
    not already contain: `declared_places() - {p.path for p in POLICIES}` is
    empty, exactly and always.

    Which means the expansion was not a convenience — it was hiding a stronger
    fact. The table is a closed world: every container on a declared path is
    itself declared, by a policy that says what shape it must be. Expanding
    prefixes here would let a leaf sit under a container nobody named and still
    look accounted for. So the expansion is gone and the property it was
    papering over is checked below instead.
    """
    return {policy.path for policy in (POLICIES if policies is None else policies)}


def unnamed_containers(policies: list[DurableFieldPolicy] | None = None) -> list[str]:
    """Declared paths whose containers the table does not name.

    A leaf under an unnamed container is a place the auditor descends through
    with no opinion about what it is. `turns[].tool_calls[].ordinal` bounded by
    an ordinal ceiling says nothing at all if `turns[].tool_calls[]` may be a
    string, and every reader of the deeper path would have to re-derive the
    shape of the shallower one for itself.
    """
    rows = POLICIES if policies is None else policies
    named = {policy.path for policy in rows}
    problems = []
    for path in sorted(named, key=render_path):
        for stop in range(1, len(path)):
            if path[:stop] not in named:
                problems.append(f"{render_path(path)} sits under {render_path(path[:stop])}, "
                                "which no policy names")
    return problems


def coverage_problems(tally: Reached, required: tuple = WITNESS_REQUIRED) -> list[str]:
    """What the corpus claims to reach, checked against what it reached.

    Two closures, in both directions. Every required path must be one the policy
    table actually reads — otherwise the requirement is a sentence about a place
    that does not exist — and every one of them must have received a hostile
    value from the real generator over the real fixtures.

    A third check was written here and taken out again: "no production fixture
    contains this path". `tally.paths` is filled *from* `fixture_paths`, so on
    the shipped corpus that set is the same set, the message could only ever
    duplicate the one below it, and it would have been a check indistinguishable
    from its own absence — added, in this very function, by the round whose
    subject is that defect.

    The first version of the tally said "every member of the receipt and of each
    turn" and mutated no turn at all, because the only fixture it was handed had
    none. The second reached turns and stopped: `turns[].tool_calls[].ordinal`
    was covered by a claim about `turns[0]` and by nothing else.
    """
    problems = []
    if not tally.root_shapes:
        problems.append("the receipt was never replaced wholesale")

    declared = declared_places()
    fictional = sorted(set(required) - declared, key=render_path)
    problems.extend(f"{render_path(path)} is required of the corpus but no "
                    f"policy reads it" for path in fictional)

    unwitnessed = sorted(set(required) - tally.paths, key=render_path)
    problems.extend(f"{render_path(path)} never received a hostile value"
                    for path in unwitnessed)

    wanted = set()
    for _name, _receipt, context in fixtures():
        wanted |= set(context)
    uncovered = sorted(wanted - tally.context_keys)
    problems.extend(f"context fact {key!r} is never given a hostile value"
                    for key in uncovered)
    return problems


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

    unowned = enforcement_problems()
    if unowned:
        print("FAIL a bound is stated here and applied by nobody")
        for problem in unowned[:20]:
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

    # Totality, run here rather than only in the suite. A unit test can check a
    # helper while the shipped path dies on the formatter next to it — the
    # clean-tree and discovery gates each performed that trick once, and this
    # module is now a critical program in its own right.
    fragile, reach = totality_problems()
    if fragile:
        print("FAIL the auditor did not survive its own malformed corpus")
        for problem in fragile[:20]:
            print(f"  {problem}")
        return 1
    # And the corpus's own positive control: an auditor that cannot raise is an
    # auditor nobody has driven off the road.
    # The corpus's own positive controls: the runner is handed an auditor that
    # raises, and one that answers differently each time, and must report both.
    # An earlier version of this control raised and formatted the line itself,
    # which exercised nothing — a check that fakes its own subject.
    def fragile(_receipt, _context):
        raise TypeError("a deliberately fragile checker")

    answers = iter(range(1000))

    def unstable(_receipt, _context):
        return [f"finding {next(answers)}"]

    if not any("raised TypeError" in problem for problem in totality_problems(fragile)[0]):
        print("FAIL the totality corpus cannot detect an auditor that raises")
        return 1
    if not any("not deterministic" in problem for problem in totality_problems(unstable)[0]):
        print("FAIL the totality corpus cannot detect an auditor that wanders")
        return 1

    # What the corpus reached, counted rather than described. The first version
    # claimed to mutate every member of each turn and mutated none, because the
    # only fixture it was handed had no turns; the number it printed was true
    # and read as wider coverage than existed.
    unreached = coverage_problems(reach)
    if unreached:
        print("FAIL the malformed corpus does not reach what it claims to")
        for problem in unreached[:20]:
            print(f"  {problem}")
        return 1
    # And the controls that matter more than another raising auditor. Each one
    # runs the real generator over a real corpus that has been narrowed in one
    # way, and the gate has to name the exact structural path that narrowing
    # took away — not report "coverage dropped".
    #
    # (1) The terminal-answer turn removed. Everything the canary produces lives
    # only on that turn, so a corpus without it is silent about the fields that
    # decide whether a provider answered the question at all.
    without_canary = [row for row in fixtures()
                      if "canary" not in row[0]]
    _problems, narrowed = totality_problems(corpus=without_canary)
    gaps = coverage_problems(narrowed)
    if not any("turns[].canary_answer_errors[] never received" in problem
               for problem in gaps):
        print("FAIL the coverage gate does not notice a missing canary turn")
        for problem in gaps[:10]:
            print(f"  {problem}")
        return 1

    # (2) One nested list emptied, everything else intact. This is the shape the
    # previous corpus could not see: `turns[]` was reached, so the tally said
    # turns were covered, while every element *inside* a turn's arrays was
    # untouched. The gate must name the element path, not the array.
    import copy
    hollow = []
    for name, receipt, context in fixtures():
        pruned = copy.deepcopy(receipt)
        for turn in pruned.get("turns", []):
            if isinstance(turn, dict) and isinstance(turn.get("tool_calls"), list):
                turn["tool_calls"] = []
        hollow.append((name, pruned, context))
    _problems, shallow = totality_problems(corpus=hollow)
    gaps = coverage_problems(shallow)
    if not any("turns[].tool_calls[] never received" in problem
               for problem in gaps):
        print("FAIL the coverage gate does not notice an unexercised list element")
        for problem in gaps[:10]:
            print(f"  {problem}")
        return 1
    if not any("turns[].tool_calls[].ordinal never received" in problem
               for problem in gaps):
        print("FAIL the coverage gate stops at the element and not at its members")
        return 1

    # (3) A required path naming a place no policy reads. Without this arm the
    # requirement list could drift into fiction: entries that no auditor code
    # consults would be satisfied by the generator and prove nothing.
    invented = WITNESS_REQUIRED + (P("turns", EACH, "tool_calls", EACH, "provider_said"),)
    if not any("no policy reads it" in problem
               for problem in coverage_problems(reach, invented)):
        print("FAIL the coverage gate accepts a requirement nothing reads")
        return 1

    # (4) A context fact never poisoned, by the same route: the tally is the
    # real one, with one key withheld.
    starved = Reached(paths=set(WITNESS_REQUIRED), root_shapes=1,
                      context_keys=reach.context_keys - {"key_env"})
    if not any("key_env" in problem for problem in coverage_problems(starved)):
        print("FAIL the coverage gate does not notice an uncovered context fact")
        return 1

    # The table is a closed world downward as well as outward: a leaf whose
    # container nobody names is a place the auditor descends through with no
    # opinion about what it is.
    unnamed = unnamed_containers()
    if unnamed:
        print("FAIL a declared path sits under a container no policy names")
        for problem in unnamed[:10]:
            print(f"  {problem}")
        return 1
    orphaned_leaf = [policy for policy in POLICIES
                     if policy.path != P("turns", EACH)] + [
        DurableFieldPolicy(P("turns", EACH, "invented"), Shape("object"), (QUALIFICATION,))]
    if not any("which no policy names" in problem
               for problem in unnamed_containers(orphaned_leaf)):
        print("FAIL a leaf under an unnamed container was not reported")
        return 1

    # The closure's own positive control: a bounded policy nobody enforces must
    # be reported, or the set equality above is a check that cannot fail.
    orphan = POLICIES + [DurableFieldPolicy(P("unowned_count"), BoundedInt(0, 5))]
    if not any("enforced by nobody" in problem
               for problem in enforcement_problems(orphan)):
        print("FAIL a bounded policy with no enforcement entry was not reported")
        return 1
    if not any("no bound" in problem for problem in
               enforcement_problems(POLICIES, {**BOUND_ENFORCEMENT,
                                               P("not_bounded"): Derive("nothing")})):
        print("FAIL an enforcement entry for an unbounded field was not reported")
        return 1

    print(f"OK {len(POLICIES)} durable-field policies, "
          f"{len(defective_specimens())} defective specimens refused, "
          f"{len(BOUND_ENFORCEMENT)} bounds owned by the producer, "
          f"{reach.specimens} malformed specimens survived "
          f"({len(reach.paths)} structural paths, {len(WITNESS_REQUIRED)} of them "
          f"required, {len(reach.context_keys)} context facts), "
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
