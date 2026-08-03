#!/usr/bin/env python3
"""The README states facts about this code. This asks the code whether they hold.

Documentation drifts in silence, and that is the whole difficulty: a paragraph
that has become false reads exactly like one that is true, so every reviewer who
checks a claim against the source is doing by hand what a machine can do on every
push. Round twenty found one such paragraph before this file existed — the prose
said the classification table's unreached remainder is exactly
`{NO_TERMINAL_ANSWER}` while the suite asserted two names, and it had read as
authoritative for several rounds.

Only facts *about the code* are checked. Prose explaining why a design is the
way it is has no mechanical counterpart and is deliberately not the subject: a
gate that tried to police intent would fail on rewording, and a gate that fails
on rewording gets switched off.

Why a gate rather than a test. A test that compares the README against the code
is a check that cannot fail while the README is right, so a mutation deleting it
survives — the shape this vertical spent three rounds learning to refuse. Here
the comparison is a function over *supplied* text, and the self-test feeds it
deliberately wrong READMEs. Break an arm and a control goes red.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import provider_matrix as pm  # noqa: E402
import receipt_policy  # noqa: E402
import oracle_ledger

# The classifications the one big table does not drive, spelled here and in the
# suite. Two spellings of one fact is the defect this file exists to catch, so
# the suite imports this rather than repeating it.
UNREACHED_BY_THE_TABLE = frozenset({"NO_TERMINAL_ANSWER", "INTERNAL_ERROR"})

# A name in a fenced block. Four characters and up, so `PASS` counts and the
# arrows and prose around it do not.
NAME = re.compile(r"\b[A-Z][A-Z0-9_]{3,}\b")


def prose(text: str) -> str:
    """The README with its wrapping removed.

    A phrase this file looks for is prose, and prose is wrapped at 79 columns,
    so where the break falls would decide whether a check runs at all. That is a
    dependency on typography rather than on the fact — and it broke the first
    time the paragraph below was edited.
    """
    return " ".join(text.split())


def fenced_after(text: str, needle: str) -> str | None:
    """The first fenced block after an anchor, or `None` if the anchor is gone.

    `None` rather than `""`: a README edit that moves a section would otherwise
    turn a comparison off while leaving it looking like it passed, which is the
    failure mode this whole file is about. The caller reports the absence.
    """
    if needle not in text:
        return None
    rest = text[text.index(needle) + len(needle):]
    if "```" not in rest:
        return None
    body = rest[rest.index("```") + 3:]
    return body[:body.index("```")] if "```" in body else None


def named_set(text: str, needle: str) -> tuple[set[str] | None, str]:
    block = fenced_after(text, needle)
    if block is None:
        return None, f"the README no longer carries a fenced block after {needle!r}"
    return set(NAME.findall(block)), ""


def compare(where: str, stated: set[str], emitted: set[str]) -> list[str]:
    problems = []
    for name in sorted(stated - emitted):
        problems.append(f"{where}: the README lists {name}, which this code cannot emit")
    for name in sorted(emitted - stated):
        problems.append(f"{where}: this code can emit {name}, which the README omits")
    return problems


def table_column(text: str, header: str) -> set[str] | None:
    """The first back-ticked identifier in each row of a markdown table.

    A table is a fenced block's cousin: it states a closed set in a place that
    reads as prose, so it drifts the same way and needs the same check.
    """
    if header not in text:
        return None
    rest = text[text.index(header) + len(header):].lstrip("\n")
    names = set()
    for line in rest.splitlines():
        if not line.startswith("|"):
            break
        cell = line.split("|")[1].strip()
        found = re.match(r"`([A-Za-z_][A-Za-z0-9_]*)", cell)
        if found:
            names.add(found.group(1))
    return names or None


def readme_problems(text: str) -> list[str]:
    """Every documented fact that the code contradicts."""
    problems: list[str] = []

    stated, missing = named_set(text, "## Trust boundary")
    if stated is None:
        problems.append(missing)
    else:
        problems.extend(compare("probe outcomes", stated, set(pm.PROBE_CLASSIFICATIONS)))

    stated, missing = named_set(text, "### Causes are kept apart")
    if stated is None:
        problems.append(missing)
    else:
        problems.extend(compare("qualification causes", stated, set(pm.CLASSIFICATIONS)))

    flat = prose(text)
    marker = "the table asserts the remainder is exactly"
    if marker not in flat:
        problems.append("the README no longer states the table's unreached remainder")
    else:
        tail = flat[flat.index(marker) + len(marker):]
        stated = set(NAME.findall(tail[:tail.index("}")] if "}" in tail else tail[:120]))
        problems.extend(compare("unreached remainder", stated, set(UNREACHED_BY_THE_TABLE)))

    # The bound the status paragraph argues from. Stated as a premise there, so
    # a change to the constants that leaves the paragraph behind is a finding.
    if "A three-digit status is an observation." not in flat:
        problems.append("the README no longer explains the three-digit status bound")
    elif len(str(pm.HTTP_STATUS_MAX)) != 3 or pm.HTTP_STATUS_MIN != 100:
        problems.append(
            f"the README argues from three-digit statuses, but the code bounds them at "
            f"{pm.HTTP_STATUS_MIN}..{pm.HTTP_STATUS_MAX}")

    # The policy-kind table. It was missing `Flag` and `BoundedNumber` when this
    # arm was written — two kinds added in later rounds while the table stayed
    # where it was. Patching the table by hand would have left the next kind to
    # drift the same way.
    kinds = table_column(text, "| policy kind | what it admits |")
    if kinds is None:
        problems.append("the README no longer carries the policy-kind table")
    else:
        problems.extend(compare(
            "policy kinds", kinds,
            {kind.__name__ for kind in receipt_policy.Kind.__subclasses__()}))

    # It has carried one, once, from a paragraph about NUL bytes — through two
    # heads and a green CI, because nothing looked.
    if "\x00" in text:
        problems.append("the README carries a literal NUL byte")
    return problems


def self_test() -> int:
    """Each arm, shown refusing a README that is wrong in exactly its way."""
    oracle_ledger.record(oracle_ledger.README)
    real = (HERE / "README.md").read_text(encoding="utf-8")
    controls = [
        ("an outcome the code cannot emit",
         real.replace("REDIRECT_NOT_FOLLOWED / RESPONSE_CAPTURE_FAILED",
                      "REDIRECT_NOT_FOLLOWED / INVENTED_OUTCOME / RESPONSE_CAPTURE_FAILED", 1),
         "cannot emit"),
        ("an outcome the code emits and the README omits",
         real.replace("PROVIDER_5XX / HTTP_FAILURE / ", "PROVIDER_5XX / ", 1),
         "which the README omits"),
        ("a cause dropped from the qualification block",
         real.replace("CANARY_ANSWER_MISMATCH  INTERNAL_ERROR  PASS",
                      "CANARY_ANSWER_MISMATCH  PASS", 1),
         "which the README omits"),
        ("a remainder that names fewer classifications than the suite asserts",
         real.replace("`{NO_TERMINAL_ANSWER, INTERNAL_ERROR}`", "`{NO_TERMINAL_ANSWER}`", 1),
         "unreached remainder"),
        ("the trust-boundary section renamed",
         real.replace("## Trust boundary", "## Where the trust stops", 1),
         "no longer carries a fenced block"),
        ("the remainder paragraph deleted",
         real.replace("the table asserts the remainder is\nexactly", "it asserts something", 1),
         "no longer states the table's unreached remainder"),
        ("a policy kind the code does not have",
         real.replace("| `Flag()` |", "| `Invented()` | nothing |\n| `Flag()` |", 1),
         "policy kinds"),
        ("a policy kind the table forgot",
         real.replace("| `BoundedNumber(low, high)` | a finite number, both ends bounded, "
                      "`bool` refused |\n", "", 1),
         "which the README omits"),
        ("a literal NUL", real + "\x00", "literal NUL"),
    ]
    for name, text, phrase in controls:
        if text == real:
            print(f"FAIL the control {name!r} did not change the README it was built from")
            return 1
        problems = readme_problems(text)
        if not any(phrase in problem for problem in problems):
            print(f"FAIL a README with {name} was not refused")
            for problem in problems[:5]:
                print(f"  {problem}")
            return 1

    problems = readme_problems(real)
    if problems:
        print("FAIL the committed README states what this code does not do:")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print(f"OK the README agrees with the code on "
          f"{len(pm.PROBE_CLASSIFICATIONS)} probe outcomes, "
          f"{len(pm.CLASSIFICATIONS)} qualification causes, "
          f"{len(UNREACHED_BY_THE_TABLE)} unreached, and the status bound; "
          f"{len(controls)} controls refused")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    problems = readme_problems((HERE / "README.md").read_text(encoding="utf-8"))
    if problems:
        print("FAIL the README states what this code does not do:")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print("OK the README agrees with the code")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
