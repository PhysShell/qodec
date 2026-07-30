#!/usr/bin/env python3
"""Break each contract in `provider_matrix.py` and confirm the suite turns red.

A green suite proves that the tests pass, not that they would notice. These are
every hardening contract stated as its own negation: if the canary can be made
to accept an immediate terminal answer, skip schema validation, take a padded
byte envelope, cite a handle nothing returned, let a catalog row choose the
origin, promote a lost body to a completed exchange, or write a provider's error
prose into a receipt — and the tests stay green — then the tests are decoration.

Every mutation verifies that the substitution *actually applied* before
believing the result. An anchor that no longer matches, or a replacement that
changes nothing, runs a green suite and reports "not caught", which is the most
convincing way to be wrong about a test. Those are reported as SKIPPED/NO-OP
failures, never as passes.

    python3 evals/provider-matrix/mutations.py

Exit 0 when every mutation is killed, 1 when any survives, 2 when the baseline
is already red — in which case nothing below means anything.

Mutations are applied to a **throwaway copy** of this directory, never to the
checkout. A harness that edits a tracked file in place and restores it in a
`finally` is one SIGKILL away from leaving a mutated working tree that looks
like deliberate work; copying removes the failure mode instead of apologising
for it. The tree is therefore byte-clean by construction, and CI still runs
`git diff --exit-code` afterwards to say so out loud.
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "provider_matrix.py"
# A spec may carry a fourth element naming the file to mutate. The gates are
# code too, and "this check can fail" is a claim like any other.
DEFAULT_TARGET = "provider_matrix.py"
# `jsonschema_mini` is resolved relative to the real tree, so the working copy
# below reaches it through PYTHONPATH rather than through its own parent.
CORPUS_TOOLS = HERE.parent / "interop" / "v2" / "corpus" / "tools"
SUITE_TIMEOUT = 600

# (name, exact source to find, what to put there instead). The anchor must match
# exactly once — a pattern that matches twice is mutating something the name
# does not describe, and a pattern that matches zero times is a silent pass.
#
# `old` and `new` may be equal-length lists, which removes several guards of the
# *same fact* at once. Two independent guards for one fact are good engineering
# and individually unkillable: whichever is mutated, the other still holds. The
# choice is between deleting the redundancy to make a mutation score look tidy
# and admitting that the unit under test is the fact, not the line.
#
# Three checks are deliberately absent from this list, because after the trusted
# registry landed they became belts behind a brace and no single mutation can
# reach them:
#
#   * `completions_url` at the two send sites and at intake — by then the origin
#     is a registry value that `normalize_registry` already vetted, so the call
#     builds a URL rather than guarding one. `C10` is the mutation that proves
#     the gate, and `test_the_url_rules_still_apply_to_a_registry_built_in_memory`
#     is the test that proves a bypass is refused.
#   * the canonical round-trip in `envelope_errors` — given the dangling and
#     trailing-bit checks, `encode(decode(x)) == x` is provable rather than
#     testable. It stays as an assertion about the pair, not as a third gate.
#   * the `isinstance(payload, dict)` check on the *qualification* path —
#     `[]["choices"]` raises `TypeError` on its own, and that is already in the
#     except tuple, so the subscript is the gate and the check only buys a
#     better message. The probe path is different: `payload.get("model")` on a
#     list raises `AttributeError`, which nothing caught until this round, and
#     `M1` removes both of its guards together to prove it.
#   * reading `response.status` before the block that may lose the body — the
#     assignment happens before `read_bounded` either way, so moving it is
#     behaviourally identical unless `.status` itself raises, which no real
#     response does. It stays because it makes the invariant structural rather
#     than accidental, but `validate_send_result` is the gate, and `O3` is the
#     mutation that proves it.
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
     "    if status == 400 and carried_tool_results:",
     "    if False:"),

    # -- B: schema validation and the canary answer --
    ("B1 validation degraded to required-key presence",
     "    errors = jsonschema_mini.validate(args, schema)",
     "    errors = [f\"missing {k}\" for k in schema.get(\"required\", []) if k not in args]"),
    ("B2 arguments never validated at all",
     "            errors = validate_arguments(surface, call[\"name\"], args)",
     "            errors = []"),
    ("B3 canary answer never graded",
     "            answer_errors = canary_answer_errors(answer_args, observed)",
     "            answer_errors = []"),
    ("B4 wrong answer bytes tolerated",
     "    if decoded is not None and decoded not in observed.bytes:",
     "    if False:"),
    ("B5 citations outside the support tolerated",
     "        if spelled not in observed.support:",
     "        if False:"),
    ("B6 the envelope oracle never reaches tool arguments",
     "    for label, envelope in walk_envelopes(args):",
     "    for label, envelope in []:"),

    # -- C: transport hardening --
    ("C1 plaintext http accepted",
     "    if parts.scheme != \"https\":",
     "    if parts.scheme not in (\"https\", \"http\"):"),
    ("C2 userinfo accepted",
     "    if parts.username or parts.password:",
     "    if False:"),
    ("C3a a query string accepted",
     "    if parts.query:",
     "    if False:"),
    ("C3b a fragment accepted",
     "    if parts.fragment:",
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
     "        if claimed.strip().rstrip(\"/\") != entry[field].rstrip(\"/\"):",
     "        if False:"),
    ("E5 a non-string authority claim is ignored instead of refused",
     "        if not isinstance(claimed, str):",
     "        if False:"),
    ("E6 a caller-supplied registry skips normalization",
     "    registry = normalize_registry(registry) if registry is not None else load_registry()\n    base = target[\"api_base\"]",
     "    registry = registry if registry is not None else load_registry()\n    base = target[\"api_base\"]"),
    ("E7 duplicate provider keys resolved by document order",
     "        if key in seen:",
     "        if False:"),
    ("E8 unknown fields allowed on a registry entry",
     "        extra = sorted(set(entry) - set(AUTHORITY_FIELDS))\n        if extra:",
     "        extra = []\n        if extra:"),
    ("E9 an implausible key_env accepted",
     "        if not KEY_ENV_PATTERN.match(entry[\"key_env\"]):",
     "        if False:"),
    ("E10 a non-lowercase provider name accepted",
     "        if not isinstance(name, str) or name != name.strip().lower() or not name:",
     "        if False:"),
    ("E11 normalization aliases the caller's mutable entry",
     "        normalized[name] = {\n            \"api_base\": entry[\"api_base\"].rstrip(\"/\"),\n            \"api_style\": entry[\"api_style\"],\n            \"key_env\": entry[\"key_env\"],\n        }",
     "        normalized[name] = entry"),
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
     "            elif identity != \"verified\":",
     "            elif False:"),
    ("F2 a probe whose model was never named still passes",
     "    elif status_of_model == \"missing\":",
     "    elif False:"),

    # -- G: the status survives a lost body --
    ("G1 an error status is discarded when its body is lost",
     "                exc.code, None, str(read_exc), \"after-headers\",",
     "                None, None, str(read_exc), \"after-headers\","),
    ("G2 a success status is discarded when its body is lost",
     "        return SendResult(status, None, str(exc), \"after-headers\", bytes_seen(exc), request_id)",
     "        return SendResult(None, None, str(exc), \"after-headers\", bytes_seen(exc), request_id)"),
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
    # -- I: the byte envelope, decoded as the crate decodes it --
    ("I1 the lenient stdlib decoder restored",
     "        decoded = b64url_nopad_decode(data)",
     "        decoded = __import__(\"base64\").urlsafe_b64decode(data + \"=\" * (-len(data) % 4))"),
    ("I2 non-zero trailing bits tolerated",
     "    if bits > 0 and (acc & ((1 << bits) - 1)) != 0:",
     "    if False:"),
    ("I3 a dangling character tolerated",
     "    if bits >= 6:",
     "    if False:"),
    ("I5 a disagreeing display_utf8 tolerated",
     "                if decoded.decode(\"utf-8\") != shown:",
     "                if False:"),
    ("I6 unknown envelope fields tolerated",
     "        f\"{label}: unknown field {key!r} in byte value envelope\"\n        for key in value\n        if key not in ENVELOPE_FIELDS",
     "        f\"{label}: unknown field {key!r} in byte value envelope\"\n        for key in value\n        if False"),
    ("I7 a wrong envelope encoding tolerated",
     "    if value.get(\"encoding\") != ENVELOPE_ENCODING:",
     "    if False:"),

    # -- J: the answer is graded against this run --
    ("J1 an answer may cite a handle no operation returned",
     "    elif handle not in observed.handles:",
     "    elif False:"),
    ("J2 a run that returned no handle still admits a cited one",
     "    if not observed.handles:",
     "    if False:"),
    ("J3 returned results never enter the observable set",
     "            observed.record(result)",
     "            pass"),

    # -- K: transport state is a table, not an inference --
    ("K1 a status without a body promoted to completed",
     "    return \"completed\" if body is not None else \"after-headers\"",
     "    return \"completed\""),
    ("K2 a body without a status silently accepted",
     "        if body is not None:\n            raise ValueError(\"invalid send result: a response body without a status\")",
     "        if False:\n            raise ValueError(\"invalid send result: a response body without a status\")"),

    # -- L: nothing untrusted, and no credential, reaches an artifact --
    ("L1 the provider's error prose written into the receipt",
     "        return \"TOOL_CHOICE_UNSUPPORTED\", \"tools-or-tool-choice-named-in-a-400\"",
     "        return \"TOOL_CHOICE_UNSUPPORTED\", body.decode(\"utf-8\", \"replace\")"),
    ("L2 a malformed credential reaches the header builder",
     "    if not credential_is_header_safe(key):",
     "    if False:"),
    ("L3 the crash receipt repeats the exception message",
     "            \"detail\": f\"provider-matrix raised {type(exc).__name__}\",",
     "            \"detail\": str(exc),"),

    # -- M: one target's failure is one target's receipt --
    # Both guards for one fact, removed together: the explicit shape check and
    # the `AttributeError` that would otherwise catch `[].get`.
    ("M1 nothing stops a non-object probe payload from raising",
     ["        if not isinstance(payload, dict):\n            raise TypeError(f\"completion was a {type(payload).__name__}, not an object\")\n        reported_model = payload.get(\"model\")",
      "    except (StrictJsonError, json.JSONDecodeError, KeyError, TypeError, IndexError, AttributeError):"],
     ["        reported_model = payload.get(\"model\")",
      "    except (StrictJsonError, json.JSONDecodeError, KeyError, TypeError, IndexError):"]),
    ("M3 an unmappable 2xx filed as a refusal",
     "            receipt.update(classification=\"INVALID_OUTPUT\", detail=why, turn_count=turn + 1)",
     "            receipt.update(classification=\"PROVIDER_REJECTED\", detail=why, turn_count=turn + 1)"),
    ("M4 a crashing target ends the matrix",
     "    except Exception as exc:  # noqa: BLE001 — deliberate: see the docstring",
     "    except ZeroDivisionError as exc:"),

    # -- N: duplicate keys at every trust boundary --
    ("N1 the strict loader replaced by plain json.loads",
     "        parsed = json.loads(\n            raw,\n            object_pairs_hook=reject_duplicate_keys,",
     "        parsed = json.loads(\n            raw,\n            object_pairs_hook=None,"),
    ("N2 nothing is ever added to the seen set",
     "        seen.add(key)",
     "        pass"),
    ("N3 the source export parsed leniently",
     "    rows = source_rows(strict_json_loads(raw_bytes, source.name))",
     "    rows = source_rows(json.loads(raw_bytes))"),
    ("N4 files read leniently",
     "    return strict_json_loads(path.read_text(encoding=\"utf-8\"), path.name)",
     "    return json.loads(path.read_text(encoding=\"utf-8\"))"),

    # -- O: an explicit stage is checked like any other claim --
    ("O1 an explicit stage is taken on trust",
     "    if len(fields) < 4:\n        result = result._replace(stage=infer_stage(result.status, result.body))",
     "    if len(fields) < 4:\n        result = result._replace(stage=infer_stage(result.status, result.body))\n    else:\n        return result"),
    ("O2 a SendResult passed straight through unvalidated",
     "        return validate_send_result(value)",
     "        return value"),
    ("O3 the stage/status shape not enforced",
     "    if (result.status is not None) != shape[\"status\"]:",
     "    if False:"),
    ("O3b the stage/body shape not enforced",
     "    if (result.body is not None) != shape[\"body\"]:",
     "    if False:"),

    # -- P: the deciding provider boundaries are strict too --
    ("P1 the completion body parsed leniently in qualify",
     "            payload = strict_json_loads(raw, \"completion\")",
     "            payload = json.loads(raw)"),
    ("P2 the completion body parsed leniently in the probe",
     "        # run and every later target lost its receipt.\n        payload = strict_json_loads(raw, \"completion\")",
     "        # run and every later target lost its receipt.\n        payload = json.loads(raw)"),
    ("P3 tool-call arguments parsed leniently",
     "        parsed = strict_json_loads(raw, f\"{call['name']} arguments\")",
     "        parsed = json.loads(raw)"),
    ("P4 a strictly-refused completion no longer classified",
     "    except (StrictJsonError, json.JSONDecodeError, KeyError, TypeError, IndexError, AttributeError):",
     "    except (json.JSONDecodeError, KeyError, TypeError, IndexError, AttributeError):"),

    # -- R: the encoding the consumer accepts, and no other --
    ("R1 bytes handed to json.loads to sniff",
     "    if isinstance(raw, (bytes, bytearray, memoryview)):\n        raw = bytes(raw)",
     "    if False:\n        raw = bytes(raw)"),
    ("R2 a UTF-8 BOM tolerated",
     "        if raw.startswith(codecs.BOM_UTF8):",
     "        if False:"),
    ("R3 a decode failure escapes instead of classifying",
     "        except UnicodeDecodeError as exc:\n            raise InvalidJsonEncoding(f\"{what}: not valid UTF-8 ({exc.reason})\") from None",
     "        except UnicodeDecodeError:\n            raise"),
    ("R4 sniffing restored by decoding with the wrong strictness",
     "            raw = raw.decode(\"utf-8\")",
     "            raw = raw.decode(\"utf-8\", \"replace\")"),

    # -- Q: the stage table enforces types, not merely presence --
    ("Q1 a non-integer status accepted",
     "    if result.status is not None and not is_http_status(result.status):",
     "    if False:"),
    ("Q2 bool accepted as a status",
     "    return type(value) is int and 100 <= value <= 599",
     "    return isinstance(value, int)"),
    ("Q3 a status outside the HTTP range accepted",
     "    return type(value) is int and 100 <= value <= 599",
     "    return type(value) is int"),
    ("Q4 a non-bytes body accepted",
     "    if result.body is not None and type(result.body) is not bytes:",
     "    if False:"),
    ("Q5 bytearray accepted as a body",
     "    if result.body is not None and type(result.body) is not bytes:",
     "    if result.body is not None and not isinstance(result.body, (bytes, bytearray, memoryview)):"),
    ("Q6 a negative observed byte count accepted",
     "        if type(observed) is not int or observed < 0:",
     "        if False:"),
    ("Q7 a non-string request id accepted",
     "        if not isinstance(result.request_id, str):",
     "        if False:"),

    # -- T: response-derived metadata cannot precede a response --
    ("T1 observed bytes accepted on a stage that received nothing",
     "        if not shape[\"response_derived\"]:\n            raise ValueError(\n                f\"send stage {result.stage!r} means nothing was received, so it cannot \"",
     "        if False:\n            raise ValueError(\n                f\"send stage {result.stage!r} means nothing was received, so it cannot \""),
    ("T2 a request id accepted on a stage where no headers arrived",
     "        if not shape[\"response_derived\"]:\n            raise ValueError(\n                f\"send stage {result.stage!r} means no headers arrived, so it cannot \"",
     "        if False:\n            raise ValueError(\n                f\"send stage {result.stage!r} means no headers arrived, so it cannot \""),
    ("T3 an observed count that disagrees with the body accepted",
     "        if result.body is not None and observed != len(result.body):",
     "        if False:"),

    # -- U: provider-controlled failures end in a local classification --
    ("U1 a truncated body escapes as IncompleteRead",
     "    except (OSError, ValueError, http.client.IncompleteRead) as exc:",
     "    except (OSError, ValueError) as exc:"),
    ("U2 a truncated error body escapes as IncompleteRead",
     "        except (OSError, ValueError, http.client.IncompleteRead) as read_exc:",
     "        except (OSError, ValueError) as read_exc:"),
    ("U3 the partial length of a truncated body is lost",
     "    if isinstance(exc, http.client.IncompleteRead):\n        return len(exc.partial)",
     "    if False:\n        return len(exc.partial)"),
    ("U4 the lenient reader loses its depth pre-scan",
     "        if json_nesting_depth(text) > MAX_JSON_DEPTH:\n            return False",
     "        if False:\n            return False"),
    ("U5 the lenient reader stops catching decoder limits",
     "    except (ValueError, TypeError) as exc:\n        # `JSONDecodeError` is a `ValueError`",
     "    except (json.JSONDecodeError, TypeError) as exc:\n        # `JSONDecodeError` is a `ValueError`"),

    # -- V: the gates themselves must be able to fail --
    ("V1 the clean-tree check stops asserting on output",
     "    lines = [line for line in status.stdout.splitlines() if line.strip()]",
     "    lines = []",
     "check_clean_tree.py"),
    ("V2 the clean-tree check looks at one directory again",
     "    return Path(top.stdout.strip())",
     "    return here",
     "check_clean_tree.py"),
    ("V3 the discovery check stops comparing the two runs",
     "    return sorted(module - direct), sorted(direct - module)",
     "    return [], []",
     "check_test_discovery.py"),

    # -- S: the JSON dialect is the consumer's, not Python's --
    ("S1 NaN and the infinities readmitted",
     "            parse_constant=_refuse_non_finite,\n",
     ""),
    ("S2 an overflowing literal readmitted as inf",
     "            parse_float=_admissible_float,\n",
     ""),
    ("S3 the non-finite float check removed",
     "    if not math.isfinite(value):",
     "    if False:"),
    ("S4 lone surrogates readmitted",
     "        _refuse_lone_surrogates(parsed)",
     "        pass"),
    ("S5 the surrogate scan never fires",
     "            if any(SURROGATE_RANGE[0] <= ch <= SURROGATE_RANGE[1] for ch in node):",
     "            if False:"),
    ("S6 the surrogate scan skips object keys",
     "                stack.append((key, \"an object key\"))\n",
     ""),
    ("S7 the surrogate scan skips nested values",
     "            for index, sub in enumerate(node):\n                stack.append((sub, f\"{where}[{index}]\"))",
     "            for index, sub in enumerate(node):\n                pass"),

    ("S8 the recursion-depth guard removed",
     "    if depth > MAX_JSON_DEPTH:",
     "    if False:"),
    ("S9 depth measured after parsing, too late to help",
     "    depth = json_nesting_depth(raw)",
     "    depth = 0"),
    ("S10 the depth limit raised past what the consumer accepts",
     "MAX_JSON_DEPTH = 127",
     "MAX_JSON_DEPTH = 1000"),
    ("S11 brackets inside strings counted as nesting",
     "        if in_string:\n            if escaped:",
     "        if False:\n            if escaped:"),

    ("S12 integer literals handed to Python's unbounded int",
     "            parse_int=_admissible_int,\n",
     ""),
    ("S13 the integer fallback overflow check removed",
     "    if not math.isfinite(float(text)):\n        raise UnadmittedJsonValue(\n            f\"{text[:32]}… has",
     "    if False:\n        raise UnadmittedJsonValue(\n            f\"{text[:32]}… has"),
    ("S14 int() called before the overflow check, so long literals crash",
     "    if not math.isfinite(float(text)):",
     "    if not math.isfinite(float(int(text))):"),

    ("V4 the mutation list stops noticing duplicate specs",
     "        if len(names) > 1:\n            problems.append(f\"identical anchor and replacement: {', '.join(names)}\")",
     "        if False:\n            problems.append(f\"identical anchor and replacement: {', '.join(names)}\")",
     "mutations.py"),
    ("V5 the mutation list stops noticing duplicate names",
     "        if count > 1:\n            problems.append(f\"the name {name!r} is used {count} times\")",
     "        if False:\n            problems.append(f\"the name {name!r} is used {count} times\")",
     "mutations.py"),

    ("H5 the replay rebuilds the tool calls instead of echoing them",
     "            \"tool_calls\": message[\"tool_calls\"],",
     "            \"tool_calls\": [{\"id\": c[\"id\"], \"type\": \"function\", \"function\": "
     "{\"name\": c[\"name\"], \"arguments\": c[\"raw_arguments\"]}} for c, _ in decoded],"),
]


def spec_problems(specs: list) -> list[str]:
    """Refuse a mutation list that flatters itself.

    `E7` and `N2` carried different names, the same anchor and the same
    replacement. "96 mutations killed" was therefore 95 mutations killed and one
    counted twice, and one of the two names claimed coverage it did not add —
    the same self-flattery the anchor check exists to prevent, one level up.
    """
    problems = []
    by_name: dict[str, int] = {}
    by_edit: dict[tuple, list[str]] = {}
    for spec in specs:
        name, old, new = spec[0], spec[1], spec[2]
        target = spec[3] if len(spec) > 3 else DEFAULT_TARGET
        by_name[name] = by_name.get(name, 0) + 1
        edits = tuple(zip(old, new)) if isinstance(old, list) else ((old, new),)
        by_edit.setdefault((target, edits), []).append(name)
    for name, count in by_name.items():
        if count > 1:
            problems.append(f"the name {name!r} is used {count} times")
    for names in by_edit.values():
        if len(names) > 1:
            problems.append(f"identical anchor and replacement: {', '.join(names)}")
    return problems


# How to ask each mutated file "are you still working". For the module under
# test that is the suite; for a gate it is the gate's own positive control,
# because a gate is proven by its ability to fail, not by the suite passing.
GATE_SELF_TESTS = {
    "check_clean_tree.py": ["check_clean_tree.py", "--self-test"],
    "check_test_discovery.py": ["check_test_discovery.py", "--self-test"],
}


def run_gate(workdir: Path, filename: str) -> tuple[bool, str]:
    argv = GATE_SELF_TESTS.get(filename)
    if argv is None:
        return run_suite(workdir)
    env = dict(os.environ, PYTHONPATH=str(CORPUS_TOOLS), PYTHONDONTWRITEBYTECODE="1")
    try:
        proc = subprocess.run(
            [sys.executable, *argv], cwd=workdir, capture_output=True, text=True,
            env=env, timeout=SUITE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return False, f"timed out after {SUITE_TIMEOUT}s"
    tail = (proc.stdout + proc.stderr).strip().splitlines()
    return proc.returncode == 0, tail[-1] if tail else "(no output)"


def run_suite(workdir: Path) -> tuple[bool, str]:
    env = dict(os.environ, PYTHONPATH=str(CORPUS_TOOLS), PYTHONDONTWRITEBYTECODE="1")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "test_provider_matrix.py"],
            cwd=workdir, capture_output=True, text=True, env=env, timeout=SUITE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        # A mutation that makes the suite loop is not green, and a harness that
        # blocks on it reports nothing at all. Not-green is the honest reading.
        return False, f"timed out after {SUITE_TIMEOUT}s"
    tail = (proc.stdout + proc.stderr).strip().splitlines()
    return proc.returncode == 0, tail[-1] if tail else "(no output)"


def main() -> int:
    original = SRC.read_text(encoding="utf-8")
    problems = spec_problems(MUTATIONS)
    if problems:
        print("FAIL the mutation list is not honest about its own size:")
        for line in problems:
            print(f"  {line}")
        return 2
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "provider-matrix"
        shutil.copytree(HERE, work, ignore=shutil.ignore_patterns("__pycache__"))

        ok, verdict = run_suite(work)
        print(f"baseline: {'GREEN' if ok else 'RED'} ({verdict})")
        if not ok:
            print("baseline is red; nothing below means anything")
            return 2

        for spec in MUTATIONS:
            name, old, new = spec[0], spec[1], spec[2]
            filename = spec[3] if len(spec) > 3 else DEFAULT_TARGET
            source = (HERE / filename).read_text(encoding="utf-8")
            edits = list(zip(old, new)) if isinstance(old, list) else [(old, new)]
            mutated = source
            bad = None
            for find, replace in edits:
                count = mutated.count(find)
                if count != 1:
                    bad = f"anchor {find[:40]!r} matched {count} times, not 1"
                    break
                stepped = mutated.replace(find, replace)
                if stepped == mutated:
                    bad = f"substitution for {find[:40]!r} changed nothing"
                    break
                mutated = stepped
            if bad:
                print(f"  SKIPPED  {name}: {bad}")
                failures.append(name)
                continue
            victim = work / filename
            victim.write_text(mutated, encoding="utf-8")
            ok, verdict = run_gate(work, filename)
            victim.write_text(source, encoding="utf-8")
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


if __name__ == "__main__":
    raise SystemExit(main())
