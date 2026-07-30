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
# Some checks are deliberately absent from this list, each for a stated reason:
# a second guard holds the same fact, the mutated behaviour is provably
# identical, or the difference only shows on a machine CI is not. Writing a
# mutation that can never die would be worse than admitting the gap — it would
# read as coverage. The list is kept here rather than as a number somewhere,
# because a number rots and a reason does not:
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
#   * replay reading `parsed.content` rather than `message["content"]` — with
#     `X1`'s guard in place the two values are equal on every message that
#     reaches replay, so a mutation swapping them cannot die and no black-box
#     test can separate them. The reason to read the checked value anyway is
#     that the guard is what makes them equal: a consumer reaching past its own
#     validator stops being covered the moment the validator changes. Stated
#     here rather than shipped as a mutation that would always survive.
#   * deleting an arm from a gate's own `--self-test` outright. A control
#     cannot detect the removal of one of its own checks; that is true of
#     any positive control and not a property of this one. What *is*
#     reachable is whether each arm still exercises its contract, and
#     `DG4` covers the decoding arm by making its synthetic case emit
#     decodable bytes. The suite covers the deletion — and as of this round
#     the suite *is* one of the oracles a mutated gate is asked, so the
#     `run_gate` limit this paragraph used to disclose no longer holds.
#     See `MUTATION_TARGETS`: a target names its oracles, and any of them
#     may object.
#   * the `env` argument threaded into `dirt()` from the self-test — it matters
#     against a developer's `core.excludesFile`, and CI runs on a machine that
#     has none, so dropping it changes nothing observable *here*. `W1` covers
#     the same fact from the side that is reachable: the hostile HOME the
#     self-test builds for itself.
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
    # Two stage tables now carry these words — the qualification's and the
    # probe's — so each anchor names its table. That the same mutation has to be
    # written twice is the point of having two vocabularies written down.
    ("C6 a lost body after headers called unavailability",
     "STAGE_CAUSE = {\n    \"no-credential\": \"AUTH_FAILED\",\n"
     "    \"before-response\": \"UNAVAILABLE\",",
     "STAGE_CAUSE = {\n    \"no-credential\": \"AUTH_FAILED\",\n"
     "    \"before-response\": \"RESPONSE_CAPTURE_FAILED\","),
    ("C10 a registry file is loaded without vetting its origins",
     "        completions_url(entry[\"api_base\"])",
     "        pass"),

    # -- D: the drifting model kept in evidence --
    ("D1 reported_model overwritten each turn",
     "        receipt[\"reported_model\"] = only.get(\"reported_model\") if only else None",
     "        receipt[\"reported_model\"] = reported"),
    ("D2 per-turn model evidence dropped",
     "        record.update(model_evidence(target[\"model\"], reported))",
     "        pass"),
    ("D3 drift detail names the substituted model instead of digesting it",
     "                for entry in receipt[\"reported_models\"]\n"
     "                if entry.get(\"reported_model\") is None and entry.get(\"reported_model_present\")",
     "                for entry in receipt[\"reported_models\"]\n"
     "                if entry.get(\"reported_model_sha256\") is None"),

    # -- E: the trusted provider registry --
    ("E1 a catalog row's api_base and key_env regain authority",
     "        if claimed.strip().rstrip(\"/\") != entry[field].rstrip(\"/\"):",
     "        if False:"),
    ("E5 a non-string authority claim is ignored instead of refused",
     "        if not isinstance(claimed, str):",
     "        if False:"),
    ("E6 a caller-supplied registry skips normalization",
     "    registry = normalize_registry(registry) if registry is not None else load_registry()\n"
     "    receipt: dict[str, Any] = {",
     "    registry = registry if registry is not None else load_registry()\n"
     "    receipt: dict[str, Any] = {"),
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
     "        verify_against_registry(target, registry)\n"
     "        entry = trusted_entry(registry, target[\"provider\"])",
     "        entry = trusted_entry(registry, target[\"provider\"])"),
    ("E4 the probe skips the registry check",
     "        verify_against_registry(target, registry)\n"
     "        # From the registry, not from the row.",
     "        # From the registry, not from the row."),

    # A durable field must carry the registry's spelling, not the plan's. Taking
    # it from the row one line after the check that compared them makes the plan
    # the source of the field anyway — which is how a rejected host reached
    # `transport_target.endpoint` on a receipt that correctly refused it.
    # `verify_against_registry` compares with `rstrip("/")`, so the two can
    # legitimately differ and the receipt must still say the registry's.
    ("E12 the recorded endpoint is taken from the plan row rather than the registry",
     "    receipt[\"transport_target\"][\"endpoint\"] = entry[\"api_base\"]",
     "    receipt[\"transport_target\"][\"endpoint\"] = target[\"api_base\"]"),

    # -- F: only a verified model identity may pass --
    ("F1 a run whose model was never named still passes qualification",
     "    if facts.model_status != \"verified\":",
     "    if False:"),
    ("F2 a probe whose model was never named still passes",
     "    if facts.model_status == \"missing\":",
     "    if False:"),

    # -- G: the status survives a lost body --
    ("G1 an error status is discarded when its body is lost",
     "                exc.code, None, capture_detail(\"HTTP body capture failure\", read_exc),",
     "                None, None, capture_detail(\"HTTP body capture failure\", read_exc),"),
    ("G2 a success status is discarded when its body is lost",
     "            status, None, capture_detail(\"HTTP body capture failure\", exc),",
     "            None, None, capture_detail(\"HTTP body capture failure\", exc),"),
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
     "        for key in value\n        if key not in ENVELOPE_FIELDS",
     "        for key in value\n        if False"),
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
     "            Decision(\"INTERNAL_ERROR\", \"internal-exception\", LocalDetail(\"internal-exception\")),",
     "            Decision(\"INTERNAL_ERROR\", \"internal-exception\",\n"
     "                     LocalDetail(\"arguments-invalid-json\", (opaque_ref(\"tool-name\", str(exc)),))),"),
    # The same projection for both catch sites, or the second one is a channel
    # with a pedigree: `type(\"BearerSecretValue\", (Exception,), {})` is a class
    # an injected sender can raise, and it reached a receipt verbatim for four
    # rounds because only the transport path had been repaired.
    ("L4 the crash receipt keeps the exception class beside its own projection",
     "            **project_exception(\"internal_failure\", \"internal-error\", exc),",
     "            \"internal_failure_class\": type(exc).__name__,"),

    # -- M: one target's failure is one target's receipt --
    # Both guards for one fact, removed together: the explicit shape check and
    # the `AttributeError` that would otherwise catch `[].get`.
    ("M1 nothing stops a non-object probe payload from raising",
     ["        if not isinstance(payload, dict):\n            raise TypeError(f\"completion was a {type(payload).__name__}, not an object\")\n        reported_model = payload.get(\"model\")",
      "    except (StrictJsonError, json.JSONDecodeError, KeyError, TypeError, IndexError, AttributeError) as exc:"],
     ["        reported_model = payload.get(\"model\")",
      "    except (StrictJsonError, json.JSONDecodeError, KeyError, TypeError, IndexError) as exc:"]),
    ("M3 an unmappable 2xx filed as a refusal",
     "                Decision(\"INVALID_OUTPUT\", \"unmappable-completion\", why),",
     "                Decision(\"PROVIDER_REJECTED\", \"unmappable-completion\", why),"),
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
     "        return validate_send_result(value, response_limit)",
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
     "        parsed = strict_json_loads(raw, \"arguments\")",
     "        parsed = json.loads(raw)"),
    ("P4 a strictly-refused completion no longer classified",
     "    except (StrictJsonError, json.JSONDecodeError, KeyError, TypeError, IndexError, AttributeError) as exc:",
     "    except (json.JSONDecodeError, KeyError, TypeError, IndexError, AttributeError) as exc:"),

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
    ("U1 a lost response body escapes the read entirely",
     "    except (OSError, ValueError, http.client.HTTPException) as exc:",
     "    except (OSError, ValueError) as exc:"),
    ("U2 a lost error body escapes the read entirely",
     "        except (OSError, ValueError, http.client.HTTPException) as read_exc:",
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
     "    lines = status_records(status.stdout)",
     "    lines = []",
     "check_clean_tree.py"),
    ("V2 the clean-tree check looks at one directory again",
     "    return Path(decode_path(top.stdout.strip()))",
     "    return here",
     "check_clean_tree.py"),
    ("V3 the discovery check stops comparing the two runs",
     "    return sorted(module - direct), sorted(direct - module)",
     "    return [], []",
     "check_test_discovery.py"),

    # -- DP: nothing the provider chose is copied into durable evidence --
    ("DP1 the probe copies the provider's whole usage object",
     "        result[\"provider_usage\"] = normalize_provider_usage(\n"
     "            payload[\"usage\"], usage_bounds(len(request_body), PROBE_MAX_TOKENS))",
     "        result[\"provider_usage\"] = payload[\"usage\"]"),
    ("DP2 qualification copies the provider's whole usage object",
     "            record[\"reported_usage\"] = normalize_provider_usage(\n"
     "                payload[\"usage\"], usage_bounds(len(body), QUALIFY_MAX_TOKENS))",
     "            record[\"reported_usage\"] = payload[\"usage\"]"),
    ("DP3 unknown usage fields kept",
     "    for name in USAGE_COUNTERS:\n        count = value.get(name)",
     "    for name in value:\n        count = value.get(name)"),
    ("DP4 a usage counter that is not a count is kept",
     "        if type(count) is int and 0 <= count <= bounds[name]:",
     "        if True:"),
    ("DP5 a boolean counter recorded as a token count",
     "        if type(count) is int and 0 <= count <= bounds[name]:",
     "        if isinstance(count, int) and 0 <= count <= bounds[name]:"),
    ("DP6 a negative counter recorded",
     "        if type(count) is int and 0 <= count <= bounds[name]:",
     "        if type(count) is int and count <= bounds[name]:"),
    ("DP7 the raw request id written to the artifact",
     "    result.update(opaque(\"request_id\", \"request-id\", sent.request_id))",
     "    result[\"request_id\"] = sent.request_id"),
    ("DP8 the raw request id written to the turn record",
     "        record.update(opaque(\"request_id\", \"request-id\", sent.request_id))",
     "        record[\"request_id\"] = sent.request_id"),
    ("DP9 the raw tool call id written to the turn record",
     "                **opaque(\"call_id\", \"tool-call-id\", c[\"id\"]),",
     "                \"call_id\": c[\"id\"],"),
    ("DP10 an undeclared tool name written to the turn record",
     "                \"name\": c[\"name\"] if c[\"name\"] in known else None,",
     "                \"name\": c[\"name\"],"),
    ("DP11 a substituted model kept as the provider spelled it",
     "    if isinstance(reported, str) and reported == requested:",
     "    if isinstance(reported, str):"),
    ("DP12 the undeclared tool names spelled out in the detail",
     "                len(unknown), tuple(opaque_ref(\"tool-name\", name) for name in unknown)))",
     "                len(unknown), tuple(opaque_ref(\"json-value\", n) for n in sorted(unknown))))"),
    ("DP13 the schema validator's text written to the receipt",
     "                record.update(evidence)",
     "                record[\"argument_errors\"] = errors"),
    ("DP14 the cited handle spelled out in the answer errors",
     "    named = opaque_ref(\"handle\", handle)",
     "    named = repr(handle)"),
    ("DP15 the transport's own prose written to the receipt",
     "    if sent.reason is not None:\n        return sent.reason",
     "    if sent.detail:\n        return sent.detail"),
    ("DP16 an unknown transport reason accepted into a receipt",
     "    if result.reason is not None and result.reason not in TRANSPORT_REASONS:",
     "    if False:"),
    ("DP17 evidence digests stop being domain-separated",
     "    return hashlib.sha256(EVIDENCE_DOMAINS[domain] + evidence_bytes(value)).hexdigest()",
     "    return hashlib.sha256(evidence_bytes(value)).hexdigest()"),

    # The discriminator itself is now a typed value, so the mutation is one
    # level in: a role the provider chose reported as if it were one of ours.
    ("DP18 the raw assistant role written into the detail",
     "        return Discriminator(domain, known=value)",
     "        return Discriminator(domain, known=value)  # noqa\n    if isinstance(value, str):\n"
     "        return Discriminator(domain, known=known[0]) if value else Discriminator(domain, known=known[0])"),
    ("DP19 an unknown discriminator reported as a known one",
     "    if isinstance(value, str) and value in known:\n        return Discriminator(domain, known=value)",
     "    if isinstance(value, str):\n        return Discriminator(domain, known=known[0])"),
    ("DP20 a non-string discriminator hashed instead of typed",
     "    return Discriminator(domain, json_type=json_type_name(value))",
     "    return Discriminator(domain, ref=opaque_ref(domain, value))"),
    ("DP21 usage counters lose their upper bound",
     "        if type(count) is int and 0 <= count <= bounds[name]:",
     "        if type(count) is int and 0 <= count:"),
    ("DP22 the usage bound taken from the provider instead of the request",
     "        if type(count) is int and 0 <= count <= bounds[name]:",
     "        if type(count) is int and 0 <= count <= value.get(name, 0):"),
    ("DP23 the completion bound stops following the request",
     "        \"completion_tokens\": max_tokens,",
     "        \"completion_tokens\": 2 ** 64,"),
    ("DP24 the prompt bound stops following the request",
     "        \"prompt_tokens\": request_bytes,",
     "        \"prompt_tokens\": 2 ** 64,"),
    ("DP25 the total may exceed the sum of its allowed parts",
     "        \"total_tokens\": request_bytes + max_tokens,",
     "        \"total_tokens\": 2 ** 64,"),
    ("DP26 any identifier accepted as a transport failure kind",
     "    if result.failure_kind is not None and result.failure_kind not in TRANSPORT_FAILURE_KINDS:",
     "    if result.failure_kind is not None and not result.failure_kind.isidentifier():"),
    ("DP28 a non-string model hashed rather than typed",
     "        \"reported_model_type\": json_type_name(reported),",
     "        **opaque(\"reported_model\", \"model-name\", reported),"),
    ("DP29 the response digest stops being domain-separated",
     "            evidence_digest(\"response-body\", raw) if raw is not None else None)",
     "            sha256_bytes(raw) if raw is not None else None)"),

    # -- TB: the consumer owns the transport boundary --
    ("TB1 the observed byte count loses its upper bound",
     "        if observed > response_limit + 1:",
     "        if False:"),
    ("TB2 the limit+1 allowance becomes unbounded",
     "        if observed > response_limit + 1:",
     "        if observed > response_limit * 2 ** 32:"),
    ("TB3 the completed body is not measured against the limit",
     "    if result.body is not None and len(result.body) > response_limit:",
     "    if False:"),
    ("TB4 the probe validates against the module constant, not its own limit",
     ["    sent = as_send_result(send(url, request_body, timeout), response_limit)",
      "        failure = project_transport_failure(sent, response_limit)\n        result.update(failure)"],
     ["    sent = as_send_result(send(url, request_body, timeout), MAX_RESPONSE_BYTES)",
      "        failure = project_transport_failure(sent, MAX_RESPONSE_BYTES)\n        result.update(failure)"]),
    ("TB5 qualification validates against the module constant, not its own limit",
     ["        sent = as_send_result(send(url, body, timeout), response_limit)",
      "            failure = project_transport_failure(sent, response_limit)"],
     ["        sent = as_send_result(send(url, body, timeout), MAX_RESPONSE_BYTES)",
      "            failure = project_transport_failure(sent, MAX_RESPONSE_BYTES)"]),
    ("TB6 the receipt stops naming the limit it was actually given",
     "            \"max_response_bytes\": response_limit,",
     "            \"max_response_bytes\": MAX_RESPONSE_BYTES,"),
    ("TB7 the failure class is copied instead of hashed",
     "    fields.update(opaque(\"failure_class\", \"failure-class\", sent.failure_class))",
     "    fields[\"failure_class\"] = sent.failure_class"),
    ("TB8 an unknown failure kind accepted",
     "    if result.failure_kind is not None and result.failure_kind not in TRANSPORT_FAILURE_KINDS:",
     "    if False:"),
    ("TB9 the failure class loses its local size bound",
     "        if len(result.failure_class.encode(\"utf-8\", \"surrogatepass\")) > FAILURE_CLASS_MAX_BYTES:",
     "        if False:"),
    ("TB10 the failure class is no longer required to be a string",
     "        if not isinstance(result.failure_class, str):",
     "        if False:"),
    ("TB11 the transport hashes the class itself instead of reporting it",
     "    return {\"failure_kind\": kind, \"failure_class\": type(exc).__name__ if exc is not None else None}",
     "    return {\"failure_kind\": kind, \"failure_class\": (\n"
     "        evidence_digest(\"failure-class\", type(exc).__name__) if exc is not None else None)}"),

    # -- DG: a subprocess may not choose whether a gate returns a verdict --
    # The gate now declares a decoding *policy* instead of owning a decode, so
    # the mutations move with it: one that swaps the policy, one that swaps the
    # verdict, and the boundary's own are in the PB series below.
    ("DG1 the gate declares the wrong decoding policy for a test run",
     "    return decode_output(stdout + stderr)",
     "    return decode_path(stdout + stderr)",
     "check_test_discovery.py"),
    ("DG2 undecodable output is silently replaced",
     "from process_boundary import (\n    ProcessFailure,\n    UndecodableOutput,\n    decode_output,",
     "from process_boundary import (\n    ProcessFailure,\n    UndecodableOutput,\n    decode_path as decode_output,",
     "check_test_discovery.py"),
    ("DG3 unreadable output stops becoming a verdict",
     "    if isinstance(exc, UndecodableOutput):\n"
     "        return \"FAIL a test run produced output that was not valid UTF-8\"",
     "    if False:\n"
     "        return \"FAIL a test run produced output that was not valid UTF-8\"",
     "check_test_discovery.py"),
    ("DG4 the undecodable arm stops producing undecodable output",
     "UNREADABLE = 'import os\\nos.write(1, b\"\\\\xff\")\\n'",
     "UNREADABLE = 'import os\\nos.write(1, b\"ok\")\\n'",
     "check_test_discovery.py"),

    # -- X: everything replay sends back was checked first --
    ("X1 the assistant content type guard removed",
     "    if content is not None and not isinstance(content, str):",
     "    if False:"),

    # -- Y: a provider that breaks HTTP framing is a provider, not a defect here --
    ("Y1 framing failures at open escape the transport",
     "    except http.client.HTTPException as exc:\n        # `BadStatusLine`",
     "    except NotImplementedError as exc:\n        # `BadStatusLine`"),
    ("Y2 a framing failure reported as a retryable transport failure",
     "            None, None, capture_detail(\"HTTP framing failure\", exc), \"response-framing\"",
     "            None, None, capture_detail(\"HTTP framing failure\", exc), \"before-response\""),
    ("Y3 a framing failure classified as unavailability",
     "    \"response-framing\": \"RESPONSE_CAPTURE_FAILED\",\n"
     "    \"after-headers\": \"RESPONSE_CAPTURE_FAILED\",\n}\n# The reason a stage implies",
     "    \"response-framing\": \"UNAVAILABLE\",\n"
     "    \"after-headers\": \"RESPONSE_CAPTURE_FAILED\",\n}\n# The reason a stage implies"),
    ("Y4 the response read narrows back to the one exception already fixed",
     "    except (OSError, ValueError, http.client.HTTPException) as exc:",
     "    except (OSError, ValueError, http.client.IncompleteRead) as exc:"),
    ("Y5 the error-body read narrows back to the one exception already fixed",
     "        except (OSError, ValueError, http.client.HTTPException) as read_exc:",
     "        except (OSError, ValueError, http.client.IncompleteRead) as read_exc:"),
    ("Y6 the malformed status line is written into the receipt",
     "    if isinstance(exc, http.client.HTTPException):\n        return f\"{prefix}: {type(exc).__name__}\"",
     "    if False:\n        return f\"{prefix}: {type(exc).__name__}\""),
    ("Y7 the probe files a framing failure as an unreachable endpoint",
     "PROBE_STAGE_CAUSE = {\n    \"no-credential\": \"AUTH_FAILURE\",\n"
     "    \"response-framing\": \"RESPONSE_CAPTURE_FAILED\",",
     "PROBE_STAGE_CAUSE = {\n    \"no-credential\": \"AUTH_FAILURE\",\n"
     "    \"response-framing\": \"TRANSPORT_FAILURE\","),

    # -- Z: a gate answers for any input, including none --
    ("Z1 the discovery verdict indexes an empty list again",
     "    return found, tail[-1] if tail else \"(no output)\"",
     "    return found, tail[-1] if proc.stdout or proc.stderr else \"(no output)\"",
     "check_test_discovery.py"),

    # -- W: the clean-tree positive control is hermetic and checks its own setup --
    # `W2` and `W3` are two-anchor on purpose: the ambient configuration and the
    # local pin are a belt behind a brace, and removing one leaves the other
    # holding the same fact. `W1` stands alone because `core.excludesFile` has
    # no local pin — and that facet is the dangerous one, since a hidden
    # untracked file leaves the self-test *green* while it silently stops
    # testing anything.
    ("W1 the self-test reads the machine's global git configuration",
     "    env[\"GIT_CONFIG_GLOBAL\"] = str(home / \"absent-global-config\")",
     "    env[\"GIT_CONFIG_GLOBAL\"] = str(home / \".gitconfig\")",
     "check_clean_tree.py"),
    ("W2 the self-test stops pinning commit signing off",
     ["    env[\"GIT_CONFIG_GLOBAL\"] = str(home / \"absent-global-config\")",
      "        must_git(\"config\", \"commit.gpgsign\", \"false\", cwd=root, env=env)\n"],
     ["    env[\"GIT_CONFIG_GLOBAL\"] = str(home / \".gitconfig\")",
      ""],
     "check_clean_tree.py"),
    ("W3 the self-test stops neutralising the ambient hooks path",
     ["    env[\"GIT_CONFIG_GLOBAL\"] = str(home / \"absent-global-config\")",
      "        must_git(\"config\", \"core.hooksPath\", str(empty_hooks), cwd=root, env=env)\n"],
     ["    env[\"GIT_CONFIG_GLOBAL\"] = str(home / \".gitconfig\")",
      ""],
     "check_clean_tree.py"),
    ("W4 a failed setup command stops being an error",
     "        raise GitUnavailable(\n"
     "            f\"self-test setup: `{described(['git', *args])}` exited \"",
     "        del proc\n"
     "        _unused = (\n"
     "            f\"self-test setup: `{described(['git', *args])}` exited \"",
     "check_clean_tree.py"),
    ("W5 the setup failure stops naming the command that failed",
     "            f\"self-test setup: `{described(['git', *args])}` exited \"",
     "            f\"self-test setup: a git command failed: \"",
     "check_clean_tree.py"),

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

    # -- DF: the durable-field inventory ------------------------------------
    #
    # The inventory is the round's central claim, so it gets the round's
    # central positive controls. Each of these makes the table stop enumerating
    # something, and each must make the gate stop being green.

    ("DF1 audit skips a leaf no policy names",
     "        except KeyError as exc:\n"
     "            findings.append(str(exc).strip(\"'\"))\n"
     "            continue",
     "        except KeyError as exc:\n"
     "            del exc\n"
     "            continue",
     "receipt_policy.py"),

    ("DF2 a bounded integer accepts a bool",
     "        if type(value) is not int:\n"
     "            return [f\"{type(value).__name__} is not an integer\"]",
     "        if not isinstance(value, int):\n"
     "            return [f\"{type(value).__name__} is not an integer\"]",
     "receipt_policy.py"),

    ("DF3 a bounded integer loses its ceiling",
     "        if not self.low <= value <= top:\n"
     "            return [f\"integer outside {self.low}..{top}\"]",
     "        if value < self.low:\n"
     "            return [f\"integer outside {self.low}..{top}\"]",
     "receipt_policy.py"),

    ("DF4 a digest field accepts any string",
     "        if not isinstance(value, str) or not re.fullmatch(r\"[0-9a-f]{64}\", value):\n"
     "            return [\"not a sha256 digest\"]",
     "        if not isinstance(value, str):\n"
     "            return [\"not a sha256 digest\"]",
     "receipt_policy.py"),

    ("DF5 prose stops checking its vocabulary",
     "            elif token not in allowed:\n"
     "                found.append(f\"the word {token!r} is not one this module wrote\")",
     "            elif False:\n"
     "                found.append(f\"the word {token!r} is not one this module wrote\")",
     "receipt_policy.py"),

    ("DF6 prose stops checking its alphabet",
     "        if not PROSE_ALPHABET.match(residue):",
     "        if False and not PROSE_ALPHABET.match(residue):",
     "receipt_policy.py"),

    ("DF7 two owners of one field stop being reported",
     "    for path, count in sorted(seen.items()):\n        if count > 1:",
     "    for path, count in sorted(seen.items()):\n        if count > 2:",
     "receipt_policy.py"),

    ("DF8 a digest policy may name an undeclared domain",
     "        if self.domain not in pm.EVIDENCE_DOMAINS:\n"
     "            return [f\"domain {self.domain!r} is not declared in EVIDENCE_DOMAINS\"]",
     "        if False:\n"
     "            return [f\"domain {self.domain!r} is not declared in EVIDENCE_DOMAINS\"]",
     "receipt_policy.py"),

    # The context is what "local" is checked against. Read out of the artifact
    # under audit, every `Local` policy degrades to "this value equals itself".
    ("DF9 the local facts are read out of the artifact being audited",
     "        \"requested_model\": target[\"model\"],",
     "        \"requested_model\": receipt.get(\"requested_model\"),",
     "receipt_policy.py"),

    ("DF10 a local field accepts a value that is not the local one",
     "        return [] if value == expected else [f\"{value!r} is not the local {self.source}\"]",
     "        return []",
     "receipt_policy.py"),

    # -- VD: one owner for every verdict ------------------------------------

    ("VD1 apply_decision stops checking the schema's vocabulary",
     "    if decision.classification not in admissible_classifications(receipt.get(\"schema\", \"\")):",
     "    if False:"),

    ("VD2 apply_decision stops checking the reason vocabulary",
     "    if decision.reason not in DECISION_REASONS:\n"
     "        raise ValueError(f\"unknown decision reason {decision.reason!r}\")",
     "    if decision.reason not in DECISION_REASONS + (\"\",):\n"
     "        raise ValueError(f\"unknown decision reason {decision.reason!r}\")"),

    ("VD3 a missing credential is filed as a transport failure",
     "PROBE_STAGE_CAUSE = {\n    \"no-credential\": \"AUTH_FAILURE\",",
     "PROBE_STAGE_CAUSE = {\n    \"no-credential\": \"TRANSPORT_FAILURE\","),

    ("VD4 the probe reducer puts content above identity",
     "    if facts.model_status == \"drifted\":\n"
     "        return Decision(\n"
     "            \"PROVIDER_SUBSTITUTED\", \"identity-substituted\", LocalDetail(\"probe-substituted\"))",
     "    if facts.output_state == \"matched\" and facts.model_status == \"drifted\":\n"
     "        return Decision(\n"
     "            \"PASS\", \"probe-token-matched\", LocalDetail(\"probe-token-matched\"))"),

    ("VD5 a canary mismatch outranks an unestablished identity",
     "    if facts.model_status != \"verified\":\n"
     "        return Decision(\n"
     "            MODEL_STATUS_VERDICT.get(facts.model_status, \"MODEL_IDENTITY_MISSING\"),",
     "    if facts.model_status != \"verified\" and not facts.canary_errors:\n"
     "        return Decision(\n"
     "            MODEL_STATUS_VERDICT.get(facts.model_status, \"MODEL_IDENTITY_MISSING\"),"),

    ("VD6 the transport reason falls back to the turn-outcome vocabulary",
     "    return STAGE_REASON.get(sent.stage, \"connection-failed\")",
     "    return STAGE_OUTCOME.get(sent.stage, \"transport-failure\")"),

    ("VD7 the recorded timeout is whatever was passed in",
     "    if not math.isfinite(timeout) or not 0 < timeout <= TIMEOUT_MAX_SECS:\n"
     "        raise ValueError(f\"timeout must be in (0, {TIMEOUT_MAX_SECS}]\")",
     "    if False:\n"
     "        raise ValueError(f\"timeout must be in (0, {TIMEOUT_MAX_SECS}]\")"),

    ("VD8 the recorded latency loses its clamp",
     "    return min(max(round((time.time() - started) * 1000), 0), LATENCY_MAX_MS)",
     "    return round((time.time() - started) * 1000)"),

    # -- PB: one owner for every subprocess ---------------------------------
    #
    # Every one of these is a defect that shipped in a gate at some point, or
    # would have if the second gate had been reviewed at the same time as the
    # first. They now live in one file, so one mutation reaches every caller —
    # which is the argument for the file.

    ("PB1 the boundary lets the standard library decode",
     "            list(argv), cwd=cwd, env=env, timeout=timeout,\n"
     "            capture_output=True, text=False,",
     "            list(argv), cwd=cwd, env=env, timeout=timeout,\n"
     "            capture_output=True, text=True,",
     "process_boundary.py"),

    ("PB2 output that is not UTF-8 is silently repaired",
     "    try:\n"
     "        return data.decode(\"utf-8\", \"strict\")\n"
     "    except UnicodeDecodeError:\n"
     "        raise UndecodableOutput from None",
     "    return data.decode(\"utf-8\", \"replace\")",
     "process_boundary.py"),

    ("PB3 a failure message repeats the child's stderr",
     "        return f\"{len(self.stderr)} bytes of stderr\"",
     "        return self.stderr.decode(\"utf-8\", \"replace\")[:400]",
     "process_boundary.py"),

    ("PB4 a command line is reported as a repr of a list",
     "    if isinstance(argv, (list, tuple)):\n"
     "        return \" \".join(str(part) for part in argv)\n"
     "    return str(argv)",
     "    return repr(argv)",
     "process_boundary.py"),

    ("PB5 a stalled child is no longer caught",
     "    except subprocess.TimeoutExpired:\n"
     "        raise ProcessTimeout(f\"`{described(argv)}` exceeded {timeout}s\") from None",
     "    except KeyboardInterrupt:\n"
     "        raise ProcessTimeout(f\"`{described(argv)}` exceeded {timeout}s\") from None",
     "process_boundary.py"),

    ("PB6 a path that is not UTF-8 takes the gate down",
     "    return os.fsdecode(data)",
     "    return data.decode(\"utf-8\", \"strict\")",
     "process_boundary.py"),

    ("PB7 output is printed with nothing rendered safe",
     "    return text.encode(\"utf-8\", \"backslashreplace\").decode(\"ascii\", \"backslashreplace\")",
     "    return text",
     "process_boundary.py"),

    # -- TP: a detail is constructed, not composed ---------------------------
    #
    # The lexical check that came before this could not tell a line this module
    # rendered from a line that merely looks like one. These are that gap, one
    # mutation each: remove the template, widen a slot, let a raw string in.

    ("TP1 the rendered line loses the template it came from",
     "    receipt[\"detail_template\"] = decision.detail.template",
     "    receipt[\"detail_template\"] = None"),

    ("TP2 a turn's line loses the template it came from",
     "    record[\"detail_template\"] = why.template",
     "    record[\"detail_template\"] = \"no-terminal-answer\""),

    ("TP3 a detail may be built from an unregistered template",
     "        spec = DETAIL_TEMPLATES.get(self.template)\n"
     "        if spec is None:\n"
     "            raise ValueError(f\"unregistered detail template {self.template!r}\")",
     "        spec = DETAIL_TEMPLATES.get(self.template, (\"{0}\", (\"count\",)))\n"
     "        if False:\n"
     "            raise ValueError(f\"unregistered detail template {self.template!r}\")"),

    ("TP4 a slot stops checking what it was handed",
     "            problem = slot_problem(slot, value)\n"
     "            if problem is not None:",
     "            problem = slot_problem(slot, value)\n"
     "            if False:"),

    ("TP5 a reference slot accepts a plain string",
     "        return None if isinstance(value, OpaqueRef) else \"is not an opaque reference\"",
     "        return None"),

    ("TP6 a count slot loses its bound",
     "        return (None if type(value) is int and 0 <= value <= DETAIL_MAX_COUNT\n"
     "                else \"is not a bounded count\")",
     "        return None if isinstance(value, int) else \"is not a bounded count\""),

    ("TP7 an enum slot accepts a member of any vocabulary",
     "        return None if value in vocabulary(slot[5:]) else f\"is not a member of {slot[5:]}\"",
     "        return None if isinstance(value, str) else f\"is not a member of {slot[5:]}\""),

    ("TP8 the trusted local value becomes any local value",
     "        return (None if isinstance(value, LocalValue) and value.source == \"key_env\"\n"
     "                else \"is not the trusted key_env\")",
     "        return None if isinstance(value, str) else \"is not the trusted key_env\""),

    ("TP9 a digest may be shortened from anything",
     "        if not re.fullmatch(r\"[0-9a-f]{64}\", digest):\n"
     "            raise ValueError(\"a digest reference is built from a sha256 digest\")",
     "        if False:\n"
     "            raise ValueError(\"a digest reference is built from a sha256 digest\")"),

    ("TP10 the rejected envelope character is spelled out again",
     "            raise NoncanonicalEncoding(\n"
     "                \"character-not-in-the-alphabet\", opaque_ref(\"json-value\", ch))",
     "            raise NoncanonicalEncoding(\n"
     "                \"character-not-in-the-alphabet\", opaque_ref(\"json-value\", ch, max_bytes=0))"),

    ("TP11 the envelope's unknown field is spelled out again",
     "        LocalDetail(\"envelope-unknown-field\", (label, opaque_ref(\"json-value\", key)))",
     "        LocalDetail(\"envelope-unknown-field\", (label, opaque_ref(\"json-value\", key[:0])))"),

    ("TP12 the provenance pass stops rebuilding the line",
     "        if not isinstance(text, str) or not re.fullmatch(template_pattern(template, context), text):",
     "        if False:",
     "receipt_policy.py"),

    ("TP13 the provenance pass admits a line with no template",
     "        if template is None:\n"
     "            if text:",
     "        if template is None:\n"
     "            if False:",
     "receipt_policy.py"),

    ("TP14 a slot pattern widens to anything",
     "    if slot == \"count\":\n        return r\"\\d{1,7}\"",
     "    if slot == \"count\":\n        return r\".*\"",
     "receipt_policy.py"),

    ("TP15 the trusted key_env in a line is no longer checked against the registry",
     "        return re.escape(context[\"key_env\"])",
     "        return r\"[A-Z_]+\"",
     "receipt_policy.py"),

    ("TP16 the canary's lines stop being rebuilt from their templates",
     "            elif not re.fullmatch(template_pattern(name, context), line):",
     "            elif False:",
     "receipt_policy.py"),
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


# What may be asked whether a mutated file still works.
#
# The old shape was a dichotomy: a gate was qualified by its own `--self-test`
# and *only* by it, everything else by the suite and only by it. That was
# written down as a known limit, and a known limit that stays written down for
# five rounds is a design decision. It cost real coverage: a mutation to a gate
# that the suite would have caught was reported as killed by a self-test that
# never looked, and a mutation to `process_boundary.py` — which two gates and
# the suite all depend on — had exactly one oracle by accident of filename.
#
# So a target names its oracles, plural, and is killed when **any** of them
# turns red. The harness reports which one did, because "it died" and "it died
# where I expected" are different facts and only the second is evidence.
SUITE = ("suite", ["-m", "unittest", "test_provider_matrix.py"])
DISCOVERY_GATE = ("discovery-gate", ["check_test_discovery.py", "--self-test"])
CLEAN_TREE_GATE = ("clean-tree-gate", ["check_clean_tree.py", "--self-test"])
POLICY_GATE = ("policy-gate", ["receipt_policy.py", "--self-test"])

MUTATION_TARGETS: dict[str, tuple[tuple[str, list[str]], ...]] = {
    "provider_matrix.py": (SUITE, POLICY_GATE),
    "test_provider_matrix.py": (SUITE,),
    "mutations.py": (SUITE,),
    "receipt_policy.py": (POLICY_GATE, SUITE),
    # Both gates and the suite depend on it, so all three may object. Before
    # this table it had one oracle, chosen by nothing but which `if` its
    # filename fell into.
    "process_boundary.py": (DISCOVERY_GATE, CLEAN_TREE_GATE, SUITE),
    "check_clean_tree.py": (CLEAN_TREE_GATE, SUITE),
    "check_test_discovery.py": (DISCOVERY_GATE, SUITE),
}


def run_oracle(workdir: Path, argv: list[str]) -> tuple[bool, str]:
    env = dict(os.environ, PYTHONPATH=str(CORPUS_TOOLS), PYTHONDONTWRITEBYTECODE="1")
    try:
        proc = subprocess.run(
            [sys.executable, *argv], cwd=workdir, capture_output=True, text=True,
            env=env, timeout=SUITE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        # A mutation that makes an oracle loop is not green, and a harness that
        # blocks on it reports nothing at all. Not-green is the honest reading.
        return False, f"timed out after {SUITE_TIMEOUT}s"
    tail = (proc.stdout + proc.stderr).strip().splitlines()
    return proc.returncode == 0, tail[-1] if tail else "(no output)"


def run_gate(workdir: Path, filename: str) -> tuple[bool, str]:
    """Ask every oracle this target names, stopping at the first red one."""
    oracles = MUTATION_TARGETS.get(filename)
    if oracles is None:
        return True, f"no oracle is declared for {filename}"
    for label, argv in oracles:
        ok, verdict = run_oracle(workdir, argv)
        if not ok:
            return False, f"{label}: {verdict}"
    return True, "every oracle stayed green"


def run_suite(workdir: Path) -> tuple[bool, str]:
    return run_oracle(workdir, list(SUITE[1]))


def main() -> int:
    original = SRC.read_text(encoding="utf-8")
    problems = spec_problems(MUTATIONS)
    if problems:
        print("FAIL the mutation list is not honest about its own size:")
        for line in problems:
            print(f"  {line}")
        return 2
    unnamed = {spec[3] if len(spec) > 3 else DEFAULT_TARGET for spec in MUTATIONS} - set(MUTATION_TARGETS)
    if unnamed:
        print("FAIL a mutation targets a file with no declared oracle:")
        for name in sorted(unnamed):
            print(f"  {name}")
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
