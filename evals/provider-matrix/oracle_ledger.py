#!/usr/bin/env python3
"""Counting how often a shipped self-test corpus actually runs.

The mutation harness asks several oracles about one mutated checkout. Two of
them can be the same oracle: the unit suite used to call
`receipt_policy.self_test()` in process, and the harness then ran that same
self-test again as an assigned gate. Two executions, one question, and about
forty seconds of the answer.

A check for that cannot look at commands. All ten duplications found in round
twenty-one ran the corpus *in process*, so a topology verifier searching for a
spawned child would have found none of them and reported a clean bill. Nor can
it look at call graphs: a transitive import three layers down is exactly the
shape that reappears after the next refactor. Nor, as it turned out, can it look
at the source at all — reading found five of the ten, and the other five only
appeared when the running code was asked.

So the count is taken where the corpus begins: at the top of each gate's
`self_test`, before the first specimen and not after the last. A run that dies
on specimen one still ran, and a ledger that recorded completions would file it
as an oracle that never executed, which is a different finding entirely.

Two scopes, and the difference between them is the whole point.

  * The **run scope** belongs to the harness and to one mutant. It is captured
    at import and never read from the environment again, so code under test can
    neither erase it nor point it elsewhere before running a corpus. There is no
    setter; a witness that needs a different run scope starts a child process.
  * The **local scope** is an optional label a caller may set to say where an
    invocation came from. It cannot decide whether the invocation counted.

An earlier version had only the second, and argued that a redirected call which
dies at its first operation is cheap. It is cheap. That is not the property: the
invocation is laundered out of the scope the invariant checks, the verifier
reports a flawless single, and nothing but cost stands between that and a future
refactor which makes the preparation expensive again.

Reading is fail-closed for the same reason writing is. A directory that cannot
be opened is not an oracle that stayed home; the two call for opposite work, so
`Snapshot` keeps them in different fields.
"""

from __future__ import annotations

import os
import pathlib
import sys
import uuid
from dataclasses import dataclass, field

# Set by the harness for one mutant, and captured once — see the module note.
GLOBAL_ENV = "QODEC_ORACLE_LEDGER_RUN"
_RUN_SCOPE = os.environ.get(GLOBAL_ENV) or None

# An optional label. May be redirected freely; changes no tally.
LEDGER_ENV = "QODEC_ORACLE_LEDGER"

# Printed to stderr when a record cannot be written. The harness reads its
# oracles' output already, so the distinction costs nothing to carry.
FAILURE_MARKER = "QODEC-LEDGER-REGISTRATION-FAILED"

# A subdirectory, not a record: written into the captured scope when the
# environment no longer agrees with it. The invocation still counts; the
# disagreement is reported as its own kind, because an erased scope is somebody
# interfering with the measurement rather than an oracle declining to run.
TAMPER_MARKER = "scope-tampered"

# The semantic oracles. An id names a *corpus*, not a file and not a command:
# two entry points into one corpus are one oracle.
POLICY = "receipt-policy-self-test"
CLEAN_TREE = "clean-tree-self-test"
DISCOVERY = "discovery-self-test"
README = "readme-self-test"

ORACLE_IDS = (POLICY, CLEAN_TREE, DISCOVERY, README)


def record(oracle_id: str) -> None:
    """Note that a full shipped corpus is about to run.

    One invocation, one file per scope, created and never read back — so two
    concurrent invocations cannot merge into one the way a read-modify-write
    counter lets them. Scopes are resolved and de-duplicated first: if the run
    scope and the local label name one directory, one invocation stays one
    record rather than one file overwriting another and arriving at the right
    answer by accident.
    """
    stamp = f"{os.getpid()}-{uuid.uuid4().hex}.record"
    tampered = (os.environ.get(GLOBAL_ENV) or None) != _RUN_SCOPE

    seen: set[str] = set()
    scopes: list[str] = []
    for scope in (_RUN_SCOPE, os.environ.get(LEDGER_ENV)):
        if not scope:
            continue
        resolved = os.path.realpath(scope)
        if resolved not in seen:
            seen.add(resolved)
            scopes.append(resolved)
    if not scopes:
        return

    try:
        for scope in scopes:
            folder = pathlib.Path(scope) / oracle_id
            folder.mkdir(parents=True, exist_ok=True)
            (folder / stamp).write_text("", encoding="utf-8")
        if tampered and _RUN_SCOPE:
            marker = pathlib.Path(os.path.realpath(_RUN_SCOPE)) / TAMPER_MARKER
            marker.mkdir(parents=True, exist_ok=True)
            (marker / stamp).write_text("", encoding="utf-8")
    except OSError as exc:
        # A ledger that cannot be written must not take the run down with it —
        # and must not become indistinguishable from an oracle that never ran.
        # The marker goes to stderr, which the harness already captures.
        print(f"{FAILURE_MARKER} {oracle_id} {type(exc).__name__}", file=sys.stderr)


class LedgerUnavailable(RuntimeError):
    """The context could not be established. Not a topology finding."""


def ensure_context(path: pathlib.Path) -> pathlib.Path:
    """Make one execution context, fail-closed.

    Refused rather than reused or emptied if it already exists: a stale record
    can turn one invocation into two, and a cleanup step can turn a missing one
    into an absence nobody notices. A context belongs to exactly one mutation
    specification of exactly one run.
    """
    if path.exists():
        raise LedgerUnavailable(f"{path.name} already exists; a ledger context "
                                "belongs to one specification of one run")
    try:
        path.mkdir(parents=True)
        probe = path / ".writable"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        raise LedgerUnavailable(
            f"the ledger context is not usable: {type(exc).__name__}") from exc
    return path


@dataclass
class Snapshot:
    """What a context says, with the things it could not say kept apart.

    Reading used to answer zero for a directory it could not open, which reads
    exactly like an oracle that never ran — a broken verifier reporting on
    itself in the vocabulary of a topology defect.
    """

    # False when the context itself could not be inspected. Nothing about any
    # oracle is then known — and "nothing is known" must not be spelled the same
    # way as "the oracle did not run", which is the conflation this whole class
    # exists to prevent and which the first version of `problems` committed one
    # level further out.
    usable: bool = True
    counts: dict[str, int] = field(default_factory=dict)
    unknown: list[str] = field(default_factory=list)
    infrastructure: list[str] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    tampered: int = 0


def snapshot(context: pathlib.Path | str) -> Snapshot:
    place = pathlib.Path(context)
    if not place.exists():
        return Snapshot(usable=False, infrastructure=[
            f"the ledger context {place.name!r} does not exist, so nothing about "
            "it is known either way"])
    try:
        entries = sorted(entry.name for entry in place.iterdir() if entry.is_dir())
    except OSError as exc:
        return Snapshot(usable=False, infrastructure=[
            f"the ledger context could not be read ({type(exc).__name__}), so "
            "nothing about it is known either way"])

    counts: dict[str, int] = {}
    trouble: list[str] = []
    unreadable: list[str] = []
    for oracle in ORACLE_IDS:
        folder = place / oracle
        if not folder.exists():
            counts[oracle] = 0
            continue
        try:
            counts[oracle] = sum(1 for entry in folder.iterdir()
                                 if entry.suffix == ".record")
        except OSError as exc:
            unreadable.append(oracle)
            trouble.append(f"{oracle}: its records could not be read "
                           f"({type(exc).__name__}), so its count says nothing")

    tampered = 0
    marker = place / TAMPER_MARKER
    if marker.exists():
        try:
            tampered = sum(1 for entry in marker.iterdir()
                           if entry.suffix == ".record")
        except OSError:
            trouble.append("the tamper record could not be read")

    unknown = [name for name in entries
               if name not in ORACLE_IDS and name != TAMPER_MARKER]
    return Snapshot(True, counts, unknown, trouble, unreadable, tampered)


def read(context: pathlib.Path | str) -> dict[str, int]:
    """Counts alone. A verifier should ask `judge`."""
    taken = snapshot(context)
    return {oracle: taken.counts.get(oracle, 0) for oracle in ORACLE_IDS}


def unknown_records(context: pathlib.Path | str) -> list[str]:
    return snapshot(context).unknown


def problems(counts: dict[str, int], assigned: set[str],
             unknown: list[str] | None = None,
             failed: list[str] | None = None,
             infrastructure: list[str] | None = None,
             unreadable: list[str] | None = None,
             tampered: int = 0, context_usable: bool = True) -> list[str]:
    """One execution context, judged, with every kind named as itself.

    A verifier that only refused *duplicates* would accept an oracle that
    stopped running altogether, which is the oldest way to make a slow test
    fast. One that folded an unreadable directory into a zero would report
    infrastructure damage as a topology defect. One that ignored a changed run
    scope would report an interfered-with measurement as a clean one.
    """
    found: list[str] = []
    found.extend(sorted(infrastructure or []))
    if tampered:
        found.append(f"the run scope was changed or removed after import, "
                     f"{tampered} time(s): the measurement was interfered with")
    for oracle in sorted(failed or []):
        found.append(f"{oracle}: ledger registration failed, so its count says "
                     "nothing either way")
    for name in sorted(unknown or []):
        found.append(f"the context carries records for {name!r}, which names no "
                     "declared semantic oracle")

    if not context_usable:
        # Nothing was inspected, so nothing is claimed about any oracle. The
        # infrastructure line above is the whole finding.
        return found
    silent = set(failed or []) | set(unreadable or [])
    for oracle in ORACLE_IDS:
        if oracle in silent:
            continue
        count = counts.get(oracle, 0)
        if oracle in assigned and count == 0:
            found.append(f"{oracle} is assigned and never ran")
        elif oracle in assigned and count > 1:
            found.append(f"{oracle} is assigned and ran {count} times, "
                         "a duplicate semantic invocation")
        if oracle not in assigned and count:
            found.append(f"{oracle} is not assigned and ran {count} time(s)")
    return found


def judge(context: pathlib.Path | str, assigned: set[str]) -> list[str]:
    """`snapshot` and `problems` together, which is how a verifier should ask."""
    taken = snapshot(context)
    return problems(taken.counts, assigned, taken.unknown,
                    infrastructure=taken.infrastructure,
                    unreadable=taken.unreadable, tampered=taken.tampered,
                    context_usable=taken.usable)
