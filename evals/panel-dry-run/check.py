#!/usr/bin/env python3
"""Model-free CI gate for the panel dry-run transcript.

Seven things, in order, because a transcript that is merely *present* proves
nothing:

1. run the driver twice and compare JSONL byte-for-byte (determinism);
2. compare against the committed golden (no silent drift);
3. validate the transcript schema *exactly* — unknown fields fail;
4. audit every byte envelope by location, and check plaintext containment;
5. assert the expected event sequence for each case;
6. assert the refusal case actually contains a refusal;
7. leave the artifacts on disk for CI upload.

Exit 0 on success, 1 on any failure, with the specific disagreement printed.
"""

from __future__ import annotations

import base64
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


def run(case: str, jsonl: Path, text: Path) -> str | None:
    """Run the driver; return an error string rather than raising.

    A traceback here would replace the gate's report with a stack dump, which is
    how a failing check starts looking like a broken check.
    """
    proc = subprocess.run(
        [
            "cargo", "run", "-q", "--example", "panel_dry_run", "--",
            "--case", case,
            "--jsonl-out", str(jsonl),
            "--text-out", str(text),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        first = (proc.stderr or "").strip().splitlines()
        return f"{case}: driver exited {proc.returncode}: {first[0] if first else '(no stderr)'}"
    return None


def event_kind(event: dict) -> str:
    kind = event.get("event")
    return event.get("tool", kind) if kind == "tool_call" else kind


BYTE_ENVELOPE_KEYS = {"encoding", "data", "display_utf8"}

# Exact key sets. A subset check would accept an added field, which is the shape
# an exfiltration takes: nothing is removed, one thing is quietly added.
EVENT_KEYS = {
    "metadata": {"event", "metadata", "tool_schemas", "answer_schema"},
    "tool_call": {"event", "sequence", "tool", "arguments", "outcome"},
    "final_answer": {"event", "sequence", "handle", "answer", "cited", "verdict"},
}
METADATA_KEYS = {
    "artifact_digest", "store_id", "schema", "decode_layers", "record_count",
    "sections", "indexes", "max_candidates", "max_support_records",
    "max_preview_items",
}
ARGUMENT_KEYS = {
    "qodec_lookup": {"index", "key"},
    "qodec_intersect": {"index", "sections"},
    "qodec_materialize": {"handle", "record_ids"},
}
QUERY_OUTCOME_KEYS = {"ok", "handle", "candidate_count", "completion", "preview", "support"}
MATERIALIZE_OUTCOME_KEYS = {"ok", "records"}
REFUSAL_OUTCOME_KEYS = {"ok", "reason"}
RECORD_ID_KEYS = {"store", "section", "ordinal"}

# The only places a byte envelope may legitimately appear. Anywhere else, bytes
# are being smuggled: metadata, tool schemas, refusal reasons, handles and
# record ids have no business carrying an encoded payload.
TOOL_SCHEMA_KEYS = {"name", "description", "input_schema", "output_schema"}
EXPECTED_TOOL_NAMES = ["qodec_lookup", "qodec_intersect", "qodec_materialize"]

# The exact input contract per tool, and which fields must be byte envelopes
# rather than plain strings. Pinned semantically, not only through the golden:
# golden drift says "something changed", which is true of a typo and of dropping
# a required field, and the two deserve different alarms.
TOOL_INPUT_REQUIRED = {
    "qodec_lookup": ["index", "key"],
    "qodec_intersect": ["index", "sections"],
    "qodec_materialize": ["handle", "record_ids"],
}
BYTE_REF = {"$ref": "#/$defs/byteEnvelope"}
TOOL_BYTE_FIELDS = {"qodec_lookup": ["key"]}

ALLOWED_BYTE_PATHS = {
    "$.arguments.key",              # the caller's own lookup key
    "$.outcome.preview[]",          # candidates a query returned
    "$.outcome.records[]",          # materialize output
    "$.answer",                     # the final answer
}


def exact_keys(case: str, where: str, obj, expected: set) -> list[str]:
    if not isinstance(obj, dict):
        return [f"{case} {where}: expected an object, got {type(obj).__name__}"]
    actual = set(obj)
    bad = []
    for missing in sorted(expected - actual):
        bad.append(f"{case} {where}: missing field {missing!r}")
    for extra in sorted(actual - expected):
        bad.append(
            f"{case} {where}: unknown field {extra!r} — the schema is exact, "
            f"because an added field is what an exfiltration looks like"
        )
    return bad


def validate_schema(case: str, events: list[dict]) -> list[str]:
    """Exact schemas, not a required-field subset."""
    bad = []
    for i, e in enumerate(events):
        kind = e.get("event")
        at = f"[{i}] {kind}"
        if kind not in EVENT_KEYS:
            bad.append(f"{case} {at}: unknown event kind {kind!r}")
            continue
        bad += exact_keys(case, at, e, EVENT_KEYS[kind])
        if kind == "metadata":
            bad += exact_keys(case, f"{at}.metadata", e.get("metadata"), METADATA_KEYS)
            bad += validate_tool_schemas(case, at, e.get("tool_schemas"))
            bad += validate_answer_schema(case, at, e.get("answer_schema"))
        elif kind == "tool_call":
            tool = e.get("tool")
            if tool not in ARGUMENT_KEYS:
                bad.append(f"{case} {at}: unknown tool {tool!r}")
                continue
            bad += exact_keys(case, f"{at}.arguments", e.get("arguments"), ARGUMENT_KEYS[tool])
            outcome = e.get("outcome")
            if not isinstance(outcome, dict) or "ok" not in outcome:
                bad.append(f"{case} {at}: outcome must be an object carrying 'ok'")
                continue
            if not outcome["ok"]:
                bad += exact_keys(case, f"{at}.outcome", outcome, REFUSAL_OUTCOME_KEYS)
            elif tool == "qodec_materialize":
                bad += exact_keys(case, f"{at}.outcome", outcome, MATERIALIZE_OUTCOME_KEYS)
            else:
                bad += exact_keys(case, f"{at}.outcome", outcome, QUERY_OUTCOME_KEYS)
                for field in ("preview", "support"):
                    if not isinstance(outcome.get(field), list):
                        bad.append(
                            f"{case} {at}: {field!r} must be a list of envelopes — "
                            f"a count cannot be tokenized"
                        )
                for rid in outcome.get("support", []) or []:
                    bad += exact_keys(case, f"{at}.outcome.support[]", rid, RECORD_ID_KEYS)
        elif kind == "final_answer":
            for rid in e.get("cited", []) or []:
                bad += exact_keys(case, f"{at}.cited[]", rid, RECORD_ID_KEYS)
    return bad


def validate_json_schema(case: str, where: str, schema) -> list[str]:
    """A JSON Schema object must be exact, not merely present.

    `additionalProperties: false` is the field that carries the weight: a schema
    that omits it accepts anything the model chooses to add, which is the same
    permissiveness the transcript gate exists to refuse one layer up.
    """
    bad = []
    if not isinstance(schema, dict):
        return [f"{case} {where}: schema must be an object"]
    if schema.get("type") != "object":
        bad.append(f"{case} {where}: schema type must be \"object\"")
    required = schema.get("required")
    if not isinstance(required, list) or not required:
        bad.append(f"{case} {where}: schema needs a non-empty 'required' list")
    props = schema.get("properties")
    if not isinstance(props, dict) or not props:
        bad.append(f"{case} {where}: schema needs 'properties'")
    if schema.get("additionalProperties") is not False:
        bad.append(
            f"{case} {where}: schema must set additionalProperties:false — "
            f"an open schema accepts whatever the model adds"
        )
    for name in required or []:
        if isinstance(props, dict) and name not in props:
            bad.append(f"{case} {where}: required field {name!r} has no property")
    # Nested object schemas are held to the same rule. Checking only the top
    # level would let an inner shape stay open, which is the more comfortable
    # place to add a field nobody declared.
    for path, node in walk(schema, where):
        if path == where or not isinstance(node, dict):
            continue
        if node.get("type") == "object" and node.get("additionalProperties") is not False:
            bad.append(
                f"{case} {path}: nested object schema must set "
                f"additionalProperties:false"
            )
    return bad


def validate_tool_schemas(case: str, at: str, schemas) -> list[str]:
    """Exactly the three tools, in canonical order, each fully specified."""
    if not isinstance(schemas, list):
        return [f"{case} {at}: tool_schemas must be a list"]
    bad = []
    names = [s.get("name") if isinstance(s, dict) else None for s in schemas]
    if names != EXPECTED_TOOL_NAMES:
        bad.append(
            f"{case} {at}: tool_schemas names {names} != {EXPECTED_TOOL_NAMES} "
            f"(unknown tools, duplicates and reordering are all refused)"
        )
    for i, schema in enumerate(schemas):
        where = f"{at}.tool_schemas[{i}]"
        bad += exact_keys(case, where, schema, TOOL_SCHEMA_KEYS)
        if not isinstance(schema, dict):
            continue
        if not (schema.get("description") or "").strip():
            bad.append(f"{case} {where}: description must be non-empty")
        for field in ("input_schema", "output_schema"):
            bad += validate_json_schema(case, f"{where}.{field}", schema.get(field))
        name = schema.get("name")
        want = TOOL_INPUT_REQUIRED.get(name)
        got = (schema.get("input_schema") or {}).get("required")
        if want is not None and got != want:
            bad.append(
                f"{case} {where}: input required {got} != {want} — a dropped "
                f"argument makes the tool optional-by-accident"
            )
        for field in TOOL_BYTE_FIELDS.get(name, []):
            prop = ((schema.get("input_schema") or {}).get("properties") or {}).get(field)
            if prop != BYTE_REF:
                bad.append(
                    f"{case} {where}: {field!r} must be {BYTE_REF} — keys are "
                    f"arbitrary bytes, and a plain string cannot carry them"
                )
    return bad


def validate_answer_schema(case: str, at: str, answer) -> list[str]:
    """The terminal answer format is pinned too.

    Without it the tools would be measured precisely while the answer format
    stayed implicit, which is where interface contracts usually leak.
    """
    where = f"{at}.answer_schema"
    bad = exact_keys(case, where, answer, {"description", "schema"})
    if isinstance(answer, dict):
        bad += validate_json_schema(case, f"{where}.schema", answer.get("schema"))
        prop = ((answer.get("schema") or {}).get("properties") or {}).get("answer")
        if prop != BYTE_REF:
            bad.append(f"{case} {where}: 'answer' must be {BYTE_REF}, not a plain string")
    return bad


def walk(node, path: str):
    """Yield (path, object) for every dict, with `[]` collapsing list indices."""
    if isinstance(node, dict):
        yield path, node
        for k, v in node.items():
            yield from walk(v, f"{path}.{k}")
    elif isinstance(node, list):
        for item in node:
            yield from walk(item, f"{path}[]")


def audit_byte_envelopes(case: str, events: list[dict]) -> list[str]:
    """Every byte envelope is decoded and judged by *where* it sits.

    Substring search over the serialized JSON cannot do this job any more, and
    that is not a flaw in the search — it is the transcript doing its job. Byte
    values are deliberately base64url-encoded, so a metadata field holding
    `base64url(artifact_body)` contains no literal `%q1 body` to find. Two
    correct decisions compose into one blind spot; the fix is to stop looking
    for text and start checking locations.
    """
    bad = []
    for i, e in enumerate(events):
        for path, obj in walk(e, "$"):
            if obj.get("encoding") != "base64url-nopad":
                continue
            # A JSON Schema *describing* the envelope is not an envelope: its
            # "encoding" sits under a properties/enum declaration, not as a
            # value. Skipping by path keeps the audit about data.
            if ".input_schema" in path or ".output_schema" in path or ".answer_schema" in path:
                continue
            extra = set(obj) - BYTE_ENVELOPE_KEYS
            if extra:
                bad.append(f"{case}[{i}] byte envelope at {path} has unknown fields {sorted(extra)}")
            allowed = path in ALLOWED_BYTE_PATHS
            if not allowed:
                bad.append(
                    f"{case}[{i}] byte envelope at {path} is not an allowed "
                    f"byte-bearing location {sorted(ALLOWED_BYTE_PATHS)}"
                )
            # Decode regardless. Reporting the location and stopping would say
            # *that* bytes are somewhere they should not be, and never say what
            # they were — which is the half of the answer nobody can act on.
            data = obj.get("data")
            if not isinstance(data, str):
                bad.append(f"{case}[{i}] byte envelope at {path} has no string 'data'")
                continue
            try:
                raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
            except Exception as exc:  # noqa: BLE001 - report, do not raise
                bad.append(f"{case}[{i}] byte envelope at {path} is not base64url: {exc}")
                continue
            text = raw.decode("utf-8", errors="replace")
            for marker in STRUCTURE_MARKERS:
                if marker in text:
                    bad.append(
                        f"{case}[{i}] decoded bytes at {path} carry artifact structure "
                        f"{marker!r} — only a handed-over body contains that"
                    )
            if path != "$.outcome.records[]":
                for marker in UNQUERIED_RECORDS:
                    if marker in text:
                        bad.append(
                            f"{case}[{i}] decoded bytes at {path} carry the unqueried "
                            f"record {marker!r}"
                        )
    return bad


def check_payload_containment(case: str, events: list[dict]) -> list[str]:
    """Plaintext containment, complementing the byte-envelope audit.

    Kept alongside the decode-and-locate pass rather than replaced by it, so a
    leak has to defeat two independent checks: one that reads locations and one
    that reads text.

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


def self_test() -> list[str]:
    """Prove the gate can detect the leak it exists to detect.

    Run against synthetic events rather than the driver, because the driver has
    its own containment guard and would abort first — leaving the gate's
    detection power asserted but never exercised. A check whose sensitivity is
    only claimed is the same shape of problem as a gate that gates nothing.

    The planted leak is a metadata field holding `base64url(artifact_body)`. It
    must be rejected twice, by two independent causes: the exact schema does not
    permit the field, and the envelope audit does not permit bytes at that
    location. One well-phrased string is not a safety property.
    """
    body = "%q1 raw\n%q1 body\n--- attempt_1 ---\nalpha\nbeta\n"
    encoded = base64.urlsafe_b64encode(body.encode()).decode().rstrip("=")
    leaked = {
        "event": "metadata",
        "metadata": {
            "artifact_digest": "sha256:00", "store_id": "sha256:00",
            "schema": "qodec.query.v1", "decode_layers": 1, "record_count": 6,
            "sections": {}, "indexes": {}, "max_candidates": 1,
            "max_support_records": 1, "max_preview_items": 1,
            "artifact_sample": {"encoding": "base64url-nopad", "data": encoded},
        },
        "tool_schemas": [],
    }
    bad = []
    by_schema = validate_schema("self-test", [leaked])
    if not any("artifact_sample" in m for m in by_schema):
        bad.append("self-test: the exact schema failed to reject an added metadata field")
    by_envelope = audit_byte_envelopes("self-test", [leaked])
    if not any("not an allowed byte-bearing location" in m for m in by_envelope):
        bad.append("self-test: the envelope audit failed to reject bytes in metadata")
    if not any("artifact structure" in m for m in by_envelope):
        bad.append("self-test: the envelope audit decoded nothing, or missed the body")

    # And the plaintext pass must NOT be what catches it — otherwise the two
    # causes are one cause wearing two names.
    if any("artifact structure" in m for m in check_payload_containment("self-test", [leaked])):
        bad.append(
            "self-test: plaintext containment caught a base64url'd body, which means "
            "the fixture is not actually testing the blind spot"
        )
    return bad


def main() -> int:
    bad: list[str] = self_test()
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        for case in ("happy", "refusal"):
            first_j, first_t = tmpdir / f"{case}.1.jsonl", tmpdir / f"{case}.1.txt"
            second_j, second_t = tmpdir / f"{case}.2.jsonl", tmpdir / f"{case}.2.txt"
            failure = run(case, first_j, first_t) or run(case, second_j, second_t)
            if failure:
                bad.append(failure)
                continue

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
            bad += audit_byte_envelopes(case, events)
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
