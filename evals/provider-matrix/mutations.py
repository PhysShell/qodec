#!/usr/bin/env python3
"""Break each contract in `provider_matrix.py` and confirm the suite turns red.

A green suite proves that the tests pass, not that they would notice. These are
the four hardening contracts stated as their own negations: if the canary can be
made to accept an immediate terminal answer, skip schema validation, send the
credential over plaintext, or lose the model that drifted — and the tests stay
green — then the tests are decoration.

Every mutation verifies that the substitution *actually applied* before
believing the result. An anchor that no longer matches, or a replacement that
changes nothing, runs a green suite and reports "not caught", which is the most
convincing way to be wrong about a test. Those are reported as SKIPPED/NO-OP
failures, never as passes.

    python3 evals/provider-matrix/mutations.py

Exit 0 when every mutation is killed, 1 when any survives, 2 when the baseline
is already red — in which case nothing below means anything.

The source file is restored in a `finally`, including on Ctrl-C. If a crash ever
does leave it mutated, `git diff evals/provider-matrix/provider_matrix.py` shows
exactly what to revert.
"""
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "provider_matrix.py"
BACKUP = SRC.with_suffix(".py.orig")

# (name, exact source to find, what to put there instead). The anchor must match
# exactly once — a pattern that matches twice is mutating something the name
# does not describe, and a pattern that matches zero times is a silent pass.
MUTATIONS = [
    # -- A: the multi-turn roundtrip guard --
    ("A1 terminal answer accepted without a roundtrip",
     "            if not roundtrip_seen:",
     "            if False:"),
    ("A2 roundtrip claimed without the provider accepting the results",
     "        if awaiting_roundtrip:\n            roundtrip_seen = True",
     "        if True:\n            roundtrip_seen = True"),
    ("A3 operations never arm the roundtrip",
     "        awaiting_roundtrip = True",
     "        awaiting_roundtrip = False"),
    ("A4 a rejection of the results blamed on the request shape",
     "        if carried_tool_results:",
     "        if False:"),

    # -- B: schema validation and the canary answer --
    ("B1 validation degraded to required-key presence",
     "    return jsonschema_mini.validate(args, schema)",
     "    return [f\"missing {k}\" for k in schema.get(\"required\", []) if k not in args]"),
    ("B2 arguments never validated at all",
     "            errors = validate_arguments(surface, call[\"name\"], args)",
     "            errors = []"),
    ("B3 canary answer never graded",
     "            answer_errors = canary_answer_errors(answer_args)",
     "            answer_errors = []"),
    ("B4 wrong answer bytes tolerated",
     "        if decoded != CANARY_ANSWER_BYTES:",
     "        if False:"),
    ("B5 citations outside the support tolerated",
     "        if json.dumps(citation, sort_keys=True) not in support:",
     "        if False:"),

    # -- C: transport hardening --
    ("C1 plaintext http accepted",
     "    if parts.scheme != \"https\":",
     "    if parts.scheme not in (\"https\", \"http\"):"),
    ("C2 userinfo accepted",
     "    if parts.username or parts.password:",
     "    if False:"),
    ("C3 query and fragment accepted",
     "    if parts.query:",
     "    if False:"),
    ("C4 redirects followed",
     "    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102\n        return None",
     "    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102\n        return super().redirect_request(req, fp, code, msg, headers, newurl)"),
    ("C5 response body unbounded",
     "    raw = stream.read(limit + 1)",
     "    raw = stream.read()"),
    ("C6 a lost body after headers called unavailability",
     "    \"after-headers\": \"RESPONSE_CAPTURE_FAILED\",",
     "    \"after-headers\": \"UNAVAILABLE\","),
    ("C7 qualify builds the URL without applying the rules",
     "        url = completions_url(base)",
     "        url = base + COMPLETIONS_PATH"),
    ("C8 the probe builds the URL without applying the rules",
     "        url = completions_url(target[\"api_base\"])",
     "        url = target[\"api_base\"] + COMPLETIONS_PATH"),
    ("C9 an unvetted origin admitted at intake",
     "    try:\n        completions_url(api_base)\n    except EndpointRejected as exc:",
     "    try:\n        pass\n    except EndpointRejected as exc:"),
    ("C10 a registry file is loaded without vetting its origins",
     "        completions_url(entry[\"api_base\"])",
     "        pass"),

    # -- D: the drifting model kept in evidence --
    ("D1 reported_model overwritten each turn",
     "        receipt[\"reported_model\"] = (\n            receipt[\"reported_models\"][0] if len(receipt[\"reported_models\"]) == 1 else None\n        )",
     "        receipt[\"reported_model\"] = reported"),
    ("D2 per-turn reported_model dropped",
     "        record[\"reported_model\"] = reported\n        record[\"model_status\"]",
     "        record[\"model_status\"]"),
    ("D3 drift detail names the requested model back at us",
     "                    f\"requested {target['model']}, provider reported {', '.join(substituted)}\"",
     "                    f\"requested {target['model']}, provider reported {receipt['reported_models'][-1]}\""),

    # -- E: the trusted provider registry --
    ("E1 a catalog row's api_base and key_env regain authority",
     "        if isinstance(claimed, str) and claimed.strip().rstrip(\"/\") != entry[field].rstrip(\"/\"):",
     "        if False:"),
    ("E2 an unknown provider gets a default origin instead of a refusal",
     "    entry = registry[\"providers\"].get(provider)",
     "    entry = registry[\"providers\"].get(provider) or "
     "{\"api_base\": \"https://steal.example/v1\", \"api_style\": \"openai-chat\", \"key_env\": \"GROQ_API_KEY\"}"),
    ("E3 the plan is not re-checked against the registry before send",
     "        verify_against_registry(target, registry)\n        url = completions_url(base)",
     "        url = completions_url(base)"),
    ("E4 the probe skips the registry check",
     "        verify_against_registry(target, registry)\n        url = completions_url(target[\"api_base\"])",
     "        url = completions_url(target[\"api_base\"])"),

    # -- F: only a verified model identity may pass --
    ("F1 a run whose model was never named still passes qualification",
     "            elif status != \"verified\":",
     "            elif False:"),
    ("F2 a probe whose model was never named still passes",
     "    elif status_of_model == \"missing\":",
     "    elif False:"),

    # -- G: the status survives a lost body --
    ("G1 an error status is discarded when its body is lost",
     "            return SendResult(exc.code, None, str(read_exc), \"after-headers\", observed, request_id)",
     "            return SendResult(None, None, str(read_exc), \"after-headers\", observed, request_id)"),
    ("G2 a success status is discarded when its body is lost",
     "        return SendResult(status, None, str(exc), \"after-headers\", observed, request_id)",
     "        return SendResult(None, None, str(exc), \"after-headers\", observed, request_id)"),
    ("G3 the receipt drops a status it was handed",
     "        if status is not None:\n            record[\"http_status\"] = status",
     "        if False:\n            record[\"http_status\"] = status"),
    ("G4 observed byte count not carried out of the bounded read",
     "        raise BodyTooLarge(len(raw), limit)",
     "        raise ValueError(f\"response body exceeded {limit} bytes\")"),

    # -- H: the strict openai-chat response contract --
    ("H1 object arguments no longer named as a different dialect",
     "        if isinstance(arguments, (dict, list)):",
     "        if False:"),
    ("H2 tool_call.type not checked",
     "        if kind != \"function\":",
     "        if False:"),
    ("H3 duplicate tool_call ids accepted",
     "        if call_id in seen_ids:",
     "        if False:"),
    ("H4 tool calls accepted under any role",
     "    if role != \"assistant\":",
     "    if False:"),
    ("H5 the replay rebuilds the tool calls instead of echoing them",
     "            \"tool_calls\": message[\"tool_calls\"],",
     "            \"tool_calls\": [{\"id\": c[\"id\"], \"type\": \"function\", \"function\": "
     "{\"name\": c[\"name\"], \"arguments\": c[\"raw_arguments\"]}} for c, _ in decoded],"),
]


def run_suite() -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "test_provider_matrix.py"],
        cwd=HERE, capture_output=True, text=True,
    )
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip().splitlines()[-1]


def main() -> int:
    shutil.copy(SRC, BACKUP)
    original = BACKUP.read_text(encoding="utf-8")
    try:
        ok, verdict = run_suite()
        print(f"baseline: {'GREEN' if ok else 'RED'} ({verdict})")
        if not ok:
            print("baseline is red; nothing below means anything")
            return 2

        failures = []
        for name, old, new in MUTATIONS:
            count = original.count(old)
            if count != 1:
                print(f"  SKIPPED  {name}: anchor matched {count} times, not 1")
                failures.append(name)
                continue
            mutated = original.replace(old, new)
            if mutated == original:
                print(f"  NO-OP    {name}: substitution changed nothing")
                failures.append(name)
                continue
            SRC.write_text(mutated, encoding="utf-8")
            ok, verdict = run_suite()
            SRC.write_text(original, encoding="utf-8")
            if ok:
                print(f"  SURVIVED {name}  <-- the suite did not notice ({verdict})")
                failures.append(name)
            else:
                print(f"  killed   {name}  ({verdict})")

        print()
        if failures:
            print(f"{len(failures)} of {len(MUTATIONS)} mutations unaccounted for:")
            for name in failures:
                print(f"  - {name}")
            return 1
        print(f"all {len(MUTATIONS)} mutations killed")
        return 0
    finally:
        SRC.write_text(original, encoding="utf-8")
        BACKUP.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
