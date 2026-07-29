#!/usr/bin/env python3
"""Model-free CI gate for the 1x3x1 smoke.

The smoke's whole value is that three arms produce comparable rows. A gate that
merely confirms the file exists would let every one of those comparisons rot
quietly, so this checks the properties that make the rows mean anything:

1. run the driver twice and compare JSONL byte-for-byte (determinism);
2. compare against the committed golden (no silent drift);
3. validate the record schema *exactly* — unknown fields fail;
4. containment: the forced-query arm's requests carry no artifact, checked in
   plaintext, JSON-escaped and base64url form, WITH a positive control on the
   RAW arm so a wrong needle fails loudly instead of passing forever;
5. the two accounting planes are present, separate, and never summed;
6. the request digest recomputes from the recorded bytes, and every transport
   attempt within a turn carries that one digest;
7. every arm's model is `verified` and the cell comparable, and the golden is a
   stand-in run — checked on the transport target, not only on the model name,
   since a golden produced against a real endpoint is a live artifact whatever
   the reply claimed to be;
8. a self-test proving the gate can actually catch what it claims to catch.

Exit 0 on success, 1 on any failure, with the specific disagreement printed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
GOLDEN = HERE / "golden" / "smoke.jsonl"
GOLDEN_TXT = HERE / "golden" / "smoke.txt"
DRIVER = ROOT / "examples" / "smoke_1x3x1.rs"

ARMS = ["raw", "squeeze-direct", "forced-query"]
DOMAIN_PROVIDER_REQUEST = b"qodec.provider-request.v1"
STAND_IN_MODEL = "programmed-stand-in"

failures: list[str] = []

# While the self-test drives the checks against a deliberately broken record,
# their complaints are the expected result rather than the gate's verdict.
# Printing them would make a passing run read like a failing one, which is a
# poor property for the thing that decides whether the branch is green.
_capturing = False


def fail(msg: str) -> None:
    failures.append(msg)
    if not _capturing:
        print(f"FAIL {msg}")


def capture(check, *args) -> list[str]:
    """Run a check with its complaints collected instead of printed."""
    global failures, _capturing
    saved, failures = failures, []
    _capturing = True
    try:
        check(*args)
        return list(failures)
    finally:
        failures = saved
        _capturing = False


# ---------------------------------------------------------------------------
# The fixture, parsed from the driver rather than restated here
# ---------------------------------------------------------------------------


def _driver_const(name: str) -> str:
    """Read a `const NAME: &str = "..."` literal out of the driver."""
    src = DRIVER.read_text(encoding="utf-8")
    m = re.search(rf'const {name}: &str = "(.*?)";', src, re.S)
    if not m:
        raise SystemExit(f"FAIL cannot locate {name} in {DRIVER.name}")
    literal = re.sub(r"\\\n\s*", "", m.group(1))
    return literal.encode("utf-8").decode("unicode_escape")


FIXTURE = _driver_const("FIXTURE")
RAW_BODY = FIXTURE.split("%q1 body\n", 1)[1]
MARKERS = [l for l in FIXTURE.split("\n") if l.startswith("%q1 ") or l.startswith("--- ")]
if not MARKERS:
    raise SystemExit("FAIL FIXTURE parsed to no structural markers")


def b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def json_escaped(text: str) -> str:
    """The needle as it appears inside a JSON string field.

    A multi-line payload never appears literally in a JSON body — the wire
    holds a two-character `\\n` — so a plaintext-only search reports "absent"
    for every document with a line break in it, and keeps reporting it after
    the document starts leaking.
    """
    return json.dumps(text)[1:-1]


def forms(needle: str) -> list[tuple[str, str]]:
    """Every shape a needle could take on the wire, labelled."""
    return [
        ("plaintext", needle),
        ("json-escaped", json_escaped(needle)),
        ("base64url", b64url_nopad(needle.encode("utf-8"))),
    ]


# ---------------------------------------------------------------------------
# Running the driver
# ---------------------------------------------------------------------------


def run_driver(out: Path, text_out: Path) -> None:
    proc = subprocess.run(
        [
            "cargo",
            "run",
            "-q",
            "--example",
            "smoke_1x3x1",
            "--",
            "--jsonl-out",
            str(out),
            "--text-out",
            str(text_out),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        # Reported rather than raised as a traceback: a driver that refuses to
        # run is a result, and a CalledProcessError dump buries it.
        raise SystemExit(
            f"FAIL driver exited {proc.returncode}\n"
            f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
        )


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

RECORD_KEYS = {
    "arm",
    "fixture",
    "fixture_source_digest",
    "model_requested",
    "models_reported",
    "model_status",
    "comparable",
    "outcome",
    "accounting",
    "turns",
    "panel_transcript",
}
ACCOUNTING_KEYS = {"provider_reported", "deterministic_local"}
PROVIDER_KEYS = {
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_tokens",
}
LOCAL_KEYS = {
    "request_bytes",
    "response_bytes",
    "model_visible_transcript_bytes",
    "materialized_raw_bytes",
    "tool_call_count",
    "operation_call_count",
}
TURN_KEYS = {"ordinal", "request", "exchange"}
REQUEST_KEYS = {"envelope", "wire_digest", "wire_bytes_len", "wire_body"}
EXCHANGE_KEYS = {"kind", "raw", "normalized", "reason", "attempts", "reported_usage"}
ATTEMPT_KEYS = {"ordinal", "request_digest", "target", "outcome", "status", "body_len", "reason"}
TARGET_KEYS = {"kind", "endpoint", "path", "api_version", "content_type", "timeout_secs"}


def exact_keys(where: str, obj: object, expected: set[str]) -> None:
    if not isinstance(obj, dict):
        fail(f"{where} must be an object, got {type(obj).__name__}")
        return
    got = set(obj)
    for missing in sorted(expected - got):
        fail(f"{where} is missing {missing!r}")
    for extra in sorted(got - expected):
        fail(f"{where} carries unexpected field {extra!r}")


def check_schema(records: list[dict]) -> None:
    if [r.get("arm") for r in records] != ARMS:
        fail(f"expected arms {ARMS} in order, got {[r.get('arm') for r in records]}")
    for record in records:
        arm = record.get("arm", "?")
        exact_keys(f"record[{arm}]", record, RECORD_KEYS)
        exact_keys(f"record[{arm}].accounting", record.get("accounting"), ACCOUNTING_KEYS)
        acc = record.get("accounting", {})
        exact_keys(f"record[{arm}].provider_reported", acc.get("provider_reported"), PROVIDER_KEYS)
        exact_keys(f"record[{arm}].deterministic_local", acc.get("deterministic_local"), LOCAL_KEYS)
        for turn in record.get("turns", []):
            ordinal = turn.get("ordinal", "?")
            exact_keys(f"record[{arm}].turns[{ordinal}]", turn, TURN_KEYS)
            exact_keys(f"record[{arm}].turns[{ordinal}].request", turn.get("request"), REQUEST_KEYS)
            exact_keys(
                f"record[{arm}].turns[{ordinal}].exchange", turn.get("exchange"), EXCHANGE_KEYS
            )
            for attempt in turn.get("exchange", {}).get("attempts", []):
                where = f"record[{arm}].turns[{ordinal}].attempt[{attempt.get('ordinal')}]"
                extra = set(attempt) - ATTEMPT_KEYS
                if extra:
                    fail(f"{where} carries unexpected field(s) {sorted(extra)}")
                exact_keys(f"{where}.target", attempt.get("target"), TARGET_KEYS)


# ---------------------------------------------------------------------------
# Containment
# ---------------------------------------------------------------------------


def wire_text(turn: dict) -> str:
    envelope = turn.get("request", {}).get("wire_body", {})
    data = envelope.get("data", "")
    padded = data + "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(padded).decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 - reported, not raised
        fail(f"could not decode a wire body: {exc}")
        return ""


def check_containment(records: list[dict]) -> None:
    """The forced-query arm carries no artifact; the RAW arm carries it."""
    by_arm = {r.get("arm"): r for r in records}

    forced = by_arm.get("forced-query")
    if not forced:
        fail("no forced-query record to check containment on")
    else:
        if not forced.get("turns"):
            fail("the forced-query arm sent nothing, so containment is vacuous")
        for turn in forced.get("turns", []):
            body = wire_text(turn)
            for needle, label in [(RAW_BODY, "the RAW body")] + [(m, f"marker {m!r}") for m in MARKERS]:
                for form_name, form in forms(needle):
                    if form and form in body:
                        fail(
                            f"forced-query turn {turn.get('ordinal')} carried {label} "
                            f"in {form_name} form"
                        )

    # The positive control. Without it, every assertion above passes just as
    # happily with a wrong needle, and goes on passing after a real leak.
    raw = by_arm.get("raw")
    if not raw:
        fail("no raw record to act as the containment positive control")
    else:
        turns = raw.get("turns", [])
        if not turns:
            fail("the raw arm sent nothing, so the positive control is vacuous")
        for turn in turns[:1]:
            body = wire_text(turn)
            hits = [name for name, form in forms(RAW_BODY) if form and form in body]
            if not hits:
                fail(
                    "the RAW arm did not carry the document in any checked form — "
                    "the containment needle is wrong, not the containment"
                )


# ---------------------------------------------------------------------------
# Accounting
# ---------------------------------------------------------------------------


def check_accounting(records: list[dict]) -> None:
    for record in records:
        arm = record.get("arm", "?")
        acc = record.get("accounting", {})
        local = acc.get("deterministic_local", {})

        # Recomputable from the record it describes.
        expected_request = sum(
            t.get("request", {}).get("wire_bytes_len", 0) for t in record.get("turns", [])
        )
        if local.get("request_bytes") != expected_request:
            fail(
                f"{arm}: request_bytes {local.get('request_bytes')} does not match the "
                f"turns' own lengths ({expected_request})"
            )

        if local.get("tool_call_count", 0) < local.get("operation_call_count", 0):
            fail(f"{arm}: operation calls exceed total tool calls")

        if arm != "forced-query" and local.get("materialized_raw_bytes", 0) != 0:
            fail(f"{arm}: a direct arm cannot materialize records")

        # The provider plane must be the fold of the counters the turns actually
        # recorded. Without this, a salvaged usage could feed the cell total while
        # the file showed nothing to justify it — a number no reader can check.
        # `None` is contagious by design, so a single unreported turn makes the
        # whole field null rather than silently dropping to a smaller sum.
        for field in ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens"):
            per_turn = [
                (t.get("exchange", {}).get("reported_usage") or {}).get(field)
                if t.get("exchange", {}).get("reported_usage") is not None
                else None
                for t in record.get("turns", [])
            ]
            expected = None if not per_turn or any(v is None for v in per_turn) else sum(per_turn)
            got = acc.get("provider_reported", {}).get(field)
            if got != expected:
                fail(
                    f"{arm}: provider_reported.{field} is {got!r} but the turns' own "
                    f"reported_usage folds to {expected!r}"
                )

    # No field anywhere claims to be a total across the two planes; they have
    # different units and a single number would have to reinterpret one.
    blob = json.dumps(records)
    for forbidden in ('"total"', '"total_tokens"', '"total_bytes"'):
        if forbidden in blob:
            fail(f"the record offers {forbidden}, but the planes are not commensurable")


# ---------------------------------------------------------------------------
# Request identity
# ---------------------------------------------------------------------------


def provider_request_digest(body: bytes) -> str:
    preimage = (
        len(DOMAIN_PROVIDER_REQUEST).to_bytes(2, "big")
        + DOMAIN_PROVIDER_REQUEST
        + len(body).to_bytes(8, "big")
        + body
    )
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def check_identity(records: list[dict]) -> None:
    """The recorded digest is the digest of the recorded bytes, independently.

    Recomputed here rather than compared to itself: a digest field checked only
    against the value that produced it agrees with itself no matter what either
    of them is.
    """
    for record in records:
        arm = record.get("arm", "?")
        for turn in record.get("turns", []):
            request = turn.get("request", {})
            envelope = request.get("wire_body", {})
            data = envelope.get("data", "")
            padded = data + "=" * (-len(data) % 4)
            body = base64.urlsafe_b64decode(padded)

            if request.get("wire_bytes_len") != len(body):
                fail(f"{arm} turn {turn.get('ordinal')}: wire_bytes_len disagrees with the body")
            recomputed = provider_request_digest(body)
            if request.get("wire_digest") != recomputed:
                fail(
                    f"{arm} turn {turn.get('ordinal')}: wire_digest {request.get('wire_digest')} "
                    f"is not the digest of the recorded bytes ({recomputed})"
                )

            # A transport retry is the same request tried again, so every
            # attempt in a turn must carry that one identity.
            # A retry is the same body sent to the same place. The digest alone
            # would prove only that identical JSON went somewhere.
            targets = []
            for attempt in turn.get("exchange", {}).get("attempts", []):
                if attempt.get("request_digest") != recomputed:
                    fail(
                        f"{arm} turn {turn.get('ordinal')} attempt {attempt.get('ordinal')} "
                        "carries a different request identity — that is a semantic retry"
                    )
                targets.append(json.dumps(attempt.get("target"), sort_keys=True))
            if len(set(targets)) > 1:
                fail(
                    f"{arm} turn {turn.get('ordinal')}: attempts went to different targets, "
                    "so they are not one request tried again"
                )

            # And the display form, when present, must agree with the bytes.
            shown = envelope.get("display_utf8")
            if shown is not None and shown.encode("utf-8") != body:
                fail(f"{arm} turn {turn.get('ordinal')}: display_utf8 disagrees with the bytes")


def check_text_matches_jsonl(text: str, records: list[dict]) -> None:
    """The human table must be a rendering of the record, not a second opinion.

    The driver derives it from the JSONL by construction; this checks the claim
    from outside, because a committed artifact nobody verifies drifts silently
    and stays convincing the whole time.
    """
    rows = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if parts:
            rows[parts[0]] = parts

    for record in records:
        arm = record.get("arm", "?")
        row = rows.get(arm)
        if row is None:
            fail(f"the text table has no row for {arm}")
            continue
        local = record.get("accounting", {}).get("deterministic_local", {})
        for field in ("model_visible_transcript_bytes", "materialized_raw_bytes", "tool_call_count"):
            value = str(local.get(field))
            if value not in row:
                fail(f"{arm}: text row does not carry {field}={value} from the record")
        expected_correct = "yes" if record.get("outcome", {}).get("correct") else "no"
        if expected_correct not in row:
            fail(f"{arm}: text row disagrees with the record about correctness")

    for arm in rows:
        if arm not in {r.get("arm") for r in records}:
            fail(f"the text table has a row for {arm!r}, which is not in the record")


def check_model_status(records: list[dict]) -> None:
    """Every arm must have run a model we can name, or it is not comparable.

    `missing` is not a weaker `verified`. A row built on a turn where the
    provider named no model asserts something the run never established, and
    the primary smoke is exactly the place that must not happen.
    """
    for record in records:
        arm = record.get("arm", "?")
        status = record.get("model_status")
        if status != "verified":
            fail(f"{arm}: model status is {status!r}; a primary cell needs every turn verified")
        if record.get("comparable") is not True:
            fail(f"{arm}: cell is not comparable, so it cannot stand in a three-arm table")


def check_not_live(records: list[dict]) -> None:
    """A golden holding evidence about a real model is not a model-free golden.

    Checked on the transport target too, not only on the model name: a golden
    produced against a real endpoint is a live artifact whatever the reply said
    its model was.
    """
    for record in records:
        arm = record.get("arm", "?")
        for turn in record.get("turns", []):
            for attempt in turn.get("exchange", {}).get("attempts", []):
                endpoint = attempt.get("target", {}).get("endpoint", "")
                if not endpoint.startswith("stand-in:"):
                    fail(
                        f"{arm}: golden records an attempt against {endpoint!r}; "
                        "a live run must never be committed as a model-free golden"
                    )
        if record.get("model_requested") != STAND_IN_MODEL:
            fail(
                f"{arm}: golden was produced against {record.get('model_requested')!r}, "
                f"not the stand-in — a live run must never be committed as a golden"
            )
        for reported in record.get("models_reported", []):
            if reported is not None and reported != STAND_IN_MODEL:
                fail(f"{arm}: golden records a reply from {reported!r}")


# ---------------------------------------------------------------------------
# The gate's own sensitivity
# ---------------------------------------------------------------------------


def self_test() -> None:
    """Prove the checks fire, on a synthetic record built to be caught.

    Exercising the gate through the driver proves nothing: the driver's own
    guard aborts before a leaking transcript can be written. So the leak is
    constructed here, and the assertions below include one that the *plaintext*
    search does NOT catch it — otherwise the fixture would not be testing the
    blind spot that motivated the escaped and base64url forms.
    """
    leaked_body = json.dumps({"messages": [{"content": RAW_BODY}]}).encode("utf-8")
    assert RAW_BODY not in leaked_body.decode("utf-8"), (
        "the self-test fixture must NOT be catchable in plaintext, or it is not "
        "testing the blind spot"
    )

    synthetic = [
        {
            "arm": "forced-query",
            "fixture": "x",
            "fixture_source_digest": "sha256:" + "0" * 64,
            "model_requested": STAND_IN_MODEL,
            "models_reported": [STAND_IN_MODEL],
            "model_status": "verified",
            "comparable": True,
            "outcome": {"kind": "answered", "correct": True},
            "accounting": {
                "provider_reported": dict.fromkeys(PROVIDER_KEYS),
                "deterministic_local": dict.fromkeys(LOCAL_KEYS, 0),
            },
            "turns": [
                {
                    "ordinal": 0,
                    "request": {
                        "envelope": {},
                        "wire_digest": provider_request_digest(leaked_body),
                        "wire_bytes_len": len(leaked_body),
                        "wire_body": {
                            "encoding": "base64url-nopad",
                            "data": b64url_nopad(leaked_body),
                        },
                    },
                    "exchange": {
                        "kind": "completed",
                        "raw": {},
                        "normalized": {},
                        "reason": None,
                        "reported_usage": None,
                        "attempts": [],
                    },
                }
            ],
            "panel_transcript": [],
        }
    ]

    caught = capture(check_containment, synthetic)

    if not any("in json-escaped form" in c for c in caught):
        fail("self-test: the escaped-form containment check did not fire on a planted leak")
    if not any("positive control" in c or "no raw record" in c for c in caught):
        fail("self-test: the missing positive control was not reported")

    # And a well-formed record must not trip it.
    identity_failures = capture(check_identity, synthetic)
    if identity_failures:
        fail(f"self-test: identity check misfired on a consistent record: {identity_failures}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    self_test()

    with tempfile.TemporaryDirectory() as tmp:
        first = Path(tmp) / "a.jsonl"
        second = Path(tmp) / "b.jsonl"
        first_txt = Path(tmp) / "a.txt"
        second_txt = Path(tmp) / "b.txt"
        run_driver(first, first_txt)
        run_driver(second, second_txt)

        a = first.read_bytes()
        b = second.read_bytes()
        if a != b:
            fail("two runs of the driver disagree — the smoke is not deterministic")
        if first_txt.read_bytes() != second_txt.read_bytes():
            fail("two runs disagree in the text rendering")

        for golden, fresh in ((GOLDEN, a), (GOLDEN_TXT, first_txt.read_bytes())):
            if not golden.exists():
                fail(f"missing golden {golden}")
            elif golden.read_bytes() != fresh:
                fail(f"{golden.name} drifted from a fresh run")

        records = []
        for n, line in enumerate(a.decode("utf-8").splitlines()):
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                fail(f"line {n} is not valid JSON: {exc}")

        if len(records) != 3:
            fail(f"a 1x3x1 smoke has three records, got {len(records)}")

        check_schema(records)
        check_containment(records)
        check_accounting(records)
        check_identity(records)
        check_model_status(records)
        check_not_live(records)
        check_text_matches_jsonl(first_txt.read_text(encoding="utf-8"), records)

    if failures:
        print(f"\n{len(failures)} failure(s)")
        return 1
    print("OK smoke 1x3x1: deterministic, golden matches, contained, accounted, identified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
