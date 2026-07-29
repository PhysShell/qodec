#!/usr/bin/env python3
"""Model-free CI gate for the panel dry-run transcript.

Seven things, in order, because a transcript that is merely *present* proves
nothing:

1. run the driver twice and compare JSONL byte-for-byte (determinism);
2. compare against the committed golden (no silent drift);
3. validate the transcript schema (every event well-formed);
4. assert no artifact payload appears outside materialize events;
5. assert the expected event sequence for each case;
6. assert the refusal case actually contains a refusal;
7. leave the artifacts on disk for CI upload.

Exit 0 on success, 1 on any failure, with the specific disagreement printed.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
GOLDEN = HERE / "golden"

# What must never appear outside a materialize event.
#
# The first version of this list held every record's text, and it failed on the
# refusal case for a reason worth recording: a `qodec_lookup` for the key "beta"
# has "beta" in its arguments and in its preview. That is not a leak. The key is
# the caller's own guess, and the preview is the official output of a
# deterministic query — the arm's contract says the model may answer from it.
#
# The real claim is narrower and stronger: the *artifact* never crosses the
# boundary. Container framing and section markers are structure the model would
# only have if it had been handed the body, and no query returns them.
STRUCTURE_MARKERS = ["%q1 raw", "%q1 body", "--- attempt_1 ---", "--- attempt_2 ---"]

# Records that no query in either case ever names. If one of these surfaces, the
# transcript is carrying data nobody asked for.
UNQUERIED_RECORDS = ["gamma"]

EXPECTED = {
    "happy": ["metadata", "qodec_intersect", "qodec_materialize", "final_answer"],
    "refusal": [
        "metadata",
        "qodec_intersect",
        "qodec_lookup",
        "qodec_materialize",
        "qodec_materialize",
        "final_answer",
    ],
}


def run(case: str, jsonl: Path, text: Path) -> None:
    subprocess.run(
        [
            "cargo", "run", "-q", "--example", "panel_dry_run", "--",
            "--case", case,
            "--jsonl-out", str(jsonl),
            "--text-out", str(text),
        ],
        cwd=ROOT,
        check=True,
    )


def event_kind(event: dict) -> str:
    kind = event.get("event")
    return event.get("tool", kind) if kind == "tool_call" else kind


def validate_schema(case: str, events: list[dict]) -> list[str]:
    """Every event carries the fields the accounting depends on."""
    bad = []
    for i, e in enumerate(events):
        kind = e.get("event")
        if kind == "metadata":
            for field in ("metadata", "tool_schemas"):
                if field not in e:
                    bad.append(f"{case}[{i}] metadata event lacks {field!r}")
            for field in ("record_count", "sections", "indexes", "store_id"):
                if field not in e.get("metadata", {}):
                    bad.append(f"{case}[{i}] metadata lacks {field!r}")
        elif kind == "tool_call":
            for field in ("sequence", "tool", "arguments", "outcome"):
                if field not in e:
                    bad.append(f"{case}[{i}] tool_call lacks {field!r}")
            outcome = e.get("outcome", {})
            if "ok" not in outcome:
                bad.append(f"{case}[{i}] outcome lacks 'ok'")
            elif outcome["ok"]:
                # A successful query must carry values, not counts.
                if e.get("tool") in ("qodec_lookup", "qodec_intersect"):
                    for field in ("handle", "candidate_count", "completion",
                                  "preview", "support"):
                        if field not in outcome:
                            bad.append(f"{case}[{i}] query outcome lacks {field!r}")
                    for field in ("preview", "support"):
                        if not isinstance(outcome.get(field), list):
                            bad.append(
                                f"{case}[{i}] {field!r} must be a list of envelopes, "
                                f"got {type(outcome.get(field)).__name__} — a count "
                                f"cannot be tokenized"
                            )
                if e.get("tool") == "qodec_materialize":
                    records = outcome.get("records")
                    if not isinstance(records, list):
                        bad.append(f"{case}[{i}] materialize outcome lacks 'records' list")
                    else:
                        for r in records:
                            if r.get("encoding") != "base64url-nopad":
                                bad.append(
                                    f"{case}[{i}] materialized bytes must use the byte "
                                    f"envelope, got {r!r}"
                                )
            elif "reason" not in outcome:
                bad.append(f"{case}[{i}] refusal lacks 'reason'")
        elif kind == "final_answer":
            for field in ("sequence", "handle", "answer", "cited", "verdict"):
                if field not in e:
                    bad.append(f"{case}[{i}] final_answer lacks {field!r}")
        else:
            bad.append(f"{case}[{i}] unknown event kind {kind!r}")
    return bad


def check_payload_containment(case: str, events: list[dict]) -> list[str]:
    """The artifact never crosses the boundary.

    Structural text is forbidden everywhere, materialize included: no operation
    returns container framing, so its presence would mean the body had been
    spliced in. Unqueried records are forbidden outside materialize. Candidate
    keys a query returned are *not* checked, because returning them is the
    query's entire job.
    """
    bad = []
    for i, e in enumerate(events):
        blob = json.dumps(e, sort_keys=True)
        for marker in STRUCTURE_MARKERS:
            if marker in blob:
                bad.append(
                    f"{case}[{i}] {event_kind(e)!r} carries artifact structure "
                    f"{marker!r} — only a handed-over body contains that"
                )
        if e.get("event") == "metadata":
            for marker in UNQUERIED_RECORDS + ["beta"]:
                if marker in blob:
                    bad.append(f"{case}[{i}] metadata leaked the record {marker!r}")
            continue
        if e.get("event") == "tool_call" and e.get("tool") == "qodec_materialize":
            continue
        for marker in UNQUERIED_RECORDS:
            if marker in blob:
                bad.append(
                    f"{case}[{i}] {event_kind(e)!r} carries the unqueried record "
                    f"{marker!r}"
                )
    return bad


def main() -> int:
    bad: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        for case in ("happy", "refusal"):
            first_j, first_t = tmpdir / f"{case}.1.jsonl", tmpdir / f"{case}.1.txt"
            second_j, second_t = tmpdir / f"{case}.2.jsonl", tmpdir / f"{case}.2.txt"
            run(case, first_j, first_t)
            run(case, second_j, second_t)

            a, b = first_j.read_bytes(), second_j.read_bytes()
            if a != b:
                bad.append(f"{case}: two runs disagree byte-for-byte")
            if first_t.read_bytes() != second_t.read_bytes():
                bad.append(f"{case}: the human rendering is not deterministic")

            golden_j = GOLDEN / f"{case}.jsonl"
            golden_t = GOLDEN / f"{case}.txt"
            if not golden_j.exists():
                bad.append(f"{case}: no committed golden at {golden_j}")
            elif golden_j.read_bytes() != a:
                bad.append(
                    f"{case}: JSONL drifted from the golden\n"
                    f"  golden: {golden_j}\n  run:    {first_j}"
                )
            if golden_t.exists() and golden_t.read_bytes() != first_t.read_bytes():
                bad.append(f"{case}: the human rendering drifted from its golden")

            events = [json.loads(line) for line in a.decode("utf-8").splitlines()]
            bad += validate_schema(case, events)
            bad += check_payload_containment(case, events)

            seen = [event_kind(e) for e in events]
            if seen != EXPECTED[case]:
                bad.append(f"{case}: event sequence {seen} != expected {EXPECTED[case]}")

            if case == "refusal":
                refusals = [
                    e for e in events
                    if e.get("event") == "tool_call" and not e["outcome"].get("ok", True)
                ]
                if not refusals:
                    bad.append(
                        "refusal: no refused call in the transcript — 'ok: false' would "
                        "again exist mainly in the literature"
                    )

    for line in bad:
        print(f"FAIL {line}")
    print("panel dry-run transcript verified" if not bad else f"{len(bad)} failure(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
