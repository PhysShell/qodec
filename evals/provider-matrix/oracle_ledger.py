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

So the count is taken where the corpus begins. Each gate's `self_test` — the
function that runs the full hostile corpus, not the CLI wrapper around it —
records one invocation. A direct call, a `--self-test` command line, an assigned
gate and any future wrapper all arrive at the same place and are all counted.

Scope is one *execution context*, named by the harness for one mutant. A CI step
running a gate, and a developer running it by hand, are different contexts and
do not interact: the invariant is that within one mutant's evaluation an
assigned oracle runs once and an unassigned one does not run at all.

Silent when `QODEC_ORACLE_LEDGER` is unset, which is every ordinary run.
"""

from __future__ import annotations

import json
import os
import pathlib

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

    Appended rather than counted in memory: the corpora run in different
    processes — the suite's copy in one, the assigned gate's in another — and a
    counter in either would only ever see its own.
    """
    path = os.environ.get(LEDGER_ENV)
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as ledger:
            ledger.write(json.dumps({"oracle": oracle_id, "pid": os.getpid()}) + "\n")
    except OSError:
        # A ledger that cannot be written must not take the run down with it.
        # The verifier reports a missing count as a finding of its own.
        pass


def read(path: pathlib.Path | str) -> dict[str, int]:
    counts = {oracle: 0 for oracle in ORACLE_IDS}
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8")
    except OSError:
        return counts
    for line in text.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        name = entry.get("oracle")
        if name in counts:
            counts[name] += 1
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
