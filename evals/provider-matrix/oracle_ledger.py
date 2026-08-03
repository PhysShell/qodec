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
import uuid

# Points at one execution context: a directory the harness makes *outside* the
# mutant checkout, conventionally <root>/<run id>/<mutation fingerprint>.
LEDGER_ENV = "QODEC_ORACLE_LEDGER"

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
    context = os.environ.get(LEDGER_ENV)
    if not context:
        return
    try:
        folder = pathlib.Path(context) / oracle_id
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"{os.getpid()}-{uuid.uuid4().hex}.record").write_text(
            "", encoding="utf-8")
    except OSError:
        # A ledger that cannot be written must not take the run down with it.
        pass


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


def problems(counts: dict[str, int], assigned: set[str]) -> list[str]:
    """One execution context, judged.

    Both directions, and the second matters more than it looks: a verifier that
    only refused *duplicates* would accept an oracle that stopped running
    altogether, which is the oldest way to make a slow test fast.
    """
    found = []
    for oracle in ORACLE_IDS:
        count = counts.get(oracle, 0)
        if oracle in assigned and count != 1:
            found.append(f"{oracle} is assigned and ran {count} time(s), not once")
        if oracle not in assigned and count:
            found.append(f"{oracle} is not assigned and ran {count} time(s)")
    return found
