#!/usr/bin/env python3
"""Counting how often a shipped self-test corpus actually runs.

The mutation harness asks several oracles about one mutated checkout. Two of
them can be the same oracle: the unit suite used to call
`receipt_policy.self_test()` in process, and the harness then ran that same
self-test again as an assigned gate. Two executions, one question, and about
forty seconds of the answer.

A check for that cannot look at commands. All five duplications found in round
twenty-one ran the corpus *in process*, so a topology verifier searching for a
spawned child would have found none of them and reported a clean bill. Nor can
it look at call graphs: a transitive import three layers down is exactly the
shape that reappears after the next refactor.

So the count is taken where the corpus begins — at the top of each gate's
`self_test`, before the first specimen and not after the last. A run that dies
on specimen one still ran, and a ledger that recorded completions would file it
as an oracle that never executed, which is a different finding entirely.

Five properties this shape is chosen for:

  * **The ledger lives outside the checkout.** The harness copies the tree for
    each mutant and then asserts the tree is byte-clean; a ledger written inside
    it would be dirt of the verifier's own making, and would survive into the
    next specification.
  * **One invocation is one file.** A shared counter read and rewritten by two
    processes lets both read zero and both write one, turning a duplicate into a
    flawless single.
  * **A context must be named.** Without one nothing is recorded, so a CI step
    or a developer's hand run cannot leak into a mutant's tally.
  * **Registration precedes execution**, per the first paragraph.
  * **Nothing here can take a run down.** A ledger that cannot be written is
    reported by the verifier as a missing count, which is a finding rather than
    a crash.
"""

from __future__ import annotations

import os
import pathlib
import sys
import uuid

# Points at one execution context: a directory the harness makes *outside* the
# mutant checkout, conventionally <root>/<run id>/<mutation fingerprint>.
LEDGER_ENV = "QODEC_ORACLE_LEDGER"

# The run-global scope. Set by the harness for one mutant and never by a test:
# a local context can say *where* an invocation came from, and must not be able
# to decide whether it counted. Without this, a test could point `LEDGER_ENV` at
# a directory of its own, run the real corpus, and leave the verifier reporting
# a flawless single while one semantic entrypoint executed twice on one
# checkout. The cost of such a call proves it is cheap, not that the topology is
# closed — and the next refactor is free to make it expensive again.
GLOBAL_ENV = "QODEC_ORACLE_LEDGER_RUN"

# Printed to stderr when a record cannot be written. The harness reads its
# oracles' output already, so the distinction costs nothing to carry.
FAILURE_MARKER = "QODEC-LEDGER-REGISTRATION-FAILED"

# The semantic oracles. An id names a *corpus*, not a file and not a command:
# two entry points into one corpus are one oracle.
POLICY = "receipt-policy-self-test"
CLEAN_TREE = "clean-tree-self-test"
DISCOVERY = "discovery-self-test"
README = "readme-self-test"

ORACLE_IDS = (POLICY, CLEAN_TREE, DISCOVERY, README)


def record(oracle_id: str) -> None:
    """Note that a full shipped corpus is about to run.

    One invocation, one file, created and never read back — so two concurrent
    invocations cannot merge into one the way a read-modify-write counter lets
    them.
    """
    # Both scopes, and the global one is not optional when it is set. A caller
    # that redirects the local label still lands in the run's tally.
    stamp = f"{os.getpid()}-{uuid.uuid4().hex}.record"
    scopes = [os.environ.get(GLOBAL_ENV), os.environ.get(LEDGER_ENV)]
    if not any(scopes):
        return
    try:
        for scope in scopes:
            if not scope:
                continue
            folder = pathlib.Path(scope) / oracle_id
            folder.mkdir(parents=True, exist_ok=True)
            (folder / stamp).write_text("", encoding="utf-8")
    except OSError as exc:
        # A ledger that cannot be written must not take the run down with it —
        # and must not become indistinguishable from an oracle that never ran.
        # An empty directory has two causes and they are not the same finding:
        # one is a topology defect, the other is a broken verifier reporting on
        # itself. The marker goes to stderr, which the harness already captures.
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


def unknown_records(context: pathlib.Path | str) -> list[str]:
    """Directories in the context that name no oracle this module declares."""
    try:
        entries = sorted(entry.name for entry in pathlib.Path(context).iterdir()
                         if entry.is_dir())
    except OSError:
        return []
    return [name for name in entries if name not in ORACLE_IDS]


def read(context: pathlib.Path | str) -> dict[str, int]:
    counts = {}
    for oracle in ORACLE_IDS:
        folder = pathlib.Path(context) / oracle
        try:
            counts[oracle] = sum(1 for entry in folder.iterdir()
                                 if entry.suffix == ".record")
        except OSError:
            counts[oracle] = 0
    return counts


def problems(counts: dict[str, int], assigned: set[str],
             unknown: list[str] | None = None,
             failed: list[str] | None = None) -> list[str]:
    """One execution context, judged.

    Both directions, and the second matters more than it looks: a verifier that
    only refused *duplicates* would accept an oracle that stopped running
    altogether, which is the oldest way to make a slow test fast.
    """
    found = []
    # Registration failures first, and named as their own kind. A broken ledger
    # reported as "the oracle never ran" is an infrastructure defect wearing a
    # topology defect's clothes; both are red and they call for opposite work.
    for oracle in sorted(failed or []):
        found.append(f"{oracle}: ledger registration failed, so its count says "
                     "nothing either way")
    for name in sorted(unknown or []):
        found.append(f"the context carries records for {name!r}, which names no "
                     "declared semantic oracle")
    reported = set(failed or [])
    for oracle in ORACLE_IDS:
        if oracle in reported:
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
