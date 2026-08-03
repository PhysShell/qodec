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
import ast
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from process_boundary import (  # noqa: E402
    ProcessFailure,
    decode_path,
    printable,
    run_bytes,
)
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
#   * `isinstance(claimed, str)` in `verify_against_registry`. A plan reaches it
#     from `strict_json_loads`, so the value is a JSON type, and no JSON
#     non-string renders as `"GROQ_API_KEY"` — `str(claimed)` therefore refuses
#     exactly what the type check refuses, for every input that can arrive. It
#     is kept because it makes the refusal type-correct rather than accidentally
#     correct, and because intake refuses a non-string explicitly for the same
#     reason; the mutation was written, survived, and is withdrawn here rather
#     than propped up with a test that constructs a `__str__` a plan cannot
#     contain. `AU1` covers the comparison that *is* reachable.
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
     "                    reference = DigestRef.of_reference(seen.reference())",
     "                    reference = DigestRef(seen.name[:16].ljust(16, \"0\"))"),

    # -- E: the trusted provider registry --
    ("E1 a catalog row's api_base and key_env regain authority",
     "        if not authority_matches(field, claimed, entry[field]):",
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
    # R20.1 gave the check a second half. Each half is its own observable
    # difference, so each gets its own spec rather than one spec deleting both
    # and reporting a single kill for two contracts.
    ("E9 an implausible key_env accepted",
     "        if (not KEY_ENV_PATTERN.match(entry[\"key_env\"])",
     "        if (False"),

    ("E9b a key_env longer than the bound the certificate adds up",
     "                or len(entry[\"key_env\"].encode(\"utf-8\")) > KEY_ENV_MAX_BYTES):",
     "                or False):"),
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
    # Both follow `is_http_status`, whose range moved from the registry of
    # assigned codes to the three digits the wire can carry.
    ("Q2 bool accepted as a status",
     "    return type(value) is int and HTTP_STATUS_MIN <= value <= HTTP_STATUS_MAX",
     "    return isinstance(value, int)"),
    ("Q3 a status outside the HTTP range accepted",
     "    return type(value) is int and HTTP_STATUS_MIN <= value <= HTTP_STATUS_MAX",
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
     "    if isinstance(identity, TextSubstitution):\n"
     "        return {\"reported_model\": None, **opaque(\"reported_model\", \"model-name\", identity.name)}",
     "    if isinstance(identity, TextSubstitution):\n"
     "        return {\"reported_model\": identity.name, \"reported_model_present\": True}"),
    ("DP12 the undeclared tool names spelled out in the detail",
     "                len(unknown), shown_refs(\"undeclared-tools\", \"tool-name\", unknown)))",
     "                len(unknown), shown_refs(\"undeclared-tools\", \"json-value\", unknown)))"),
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
     "        \"reported_model_type\": identity.json_type,",
     "        **opaque(\"reported_model\", \"model-name\", identity.json_type),"),
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
    # Both streams, because "the output of a test run" is both: unittest names
    # the tests it ran on stderr and prints its verdict there too.
    ("DG1 the gate reads only one of the child's two streams",
     "    return decode_output(stdout + stderr)",
     "    return decode_output(stdout)",
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
     "    except (OSError, http.client.HTTPException) as exc:\n        # `BadStatusLine`",
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
     "    if isinstance(exc, (http.client.HTTPException, OSError)):\n"
     "        return f\"{prefix}: {type(exc).__name__}\"\n    return str(exc)",
     "    if False:\n        return f\"{prefix}: {type(exc).__name__}\"\n    return str(exc)"),
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
    # `del proc` was the first spelling, and it was `DF9` in a different coat:
    # the mutant read `proc.returncode` two lines later and died of
    # `UnboundLocalError` before the control reached the property it names.
    # Neutralising the branch is what "a failed setup command stops being an
    # error" actually means. The mirrored form — `== 0` — is no better: it would
    # raise on every *successful* setup command and produce a kill just as
    # accidental, only pointing the other way.
    ("W4 a failed setup command stops being an error",
     "    proc = git(*args, cwd=cwd, env=env)\n    if proc.returncode != 0:",
     "    proc = git(*args, cwd=cwd, env=env)\n    if False:",
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
     "        if count > 1:\n            problems.append(",
     "        if count > 2:\n            problems.append(",
     "receipt_policy.py"),

    ("DF8 a digest policy may name an undeclared domain",
     "        if self.domain not in pm.EVIDENCE_DOMAINS:\n"
     "            return [f\"domain {self.domain!r} is not declared in EVIDENCE_DOMAINS\"]",
     "        if False:\n"
     "            return [f\"domain {self.domain!r} is not declared in EVIDENCE_DOMAINS\"]",
     "receipt_policy.py"),

    # The context is what "local" is checked against. Read out of the artifact
    # under audit, every `Local` policy degrades to "this value equals itself".
    #
    # Mutated inside `audit`, not inside `context_for`. The first version of
    # this spec put `receipt.get(...)` into `context_for`, which has no such
    # name — so every oracle died of `NameError` before a single policy compared
    # anything, and the harness counted an invalid program as evidence for the
    # contract it names. `EXPECTED_KILL` now requires this one to be killed by
    # the test that forges a receipt field. The harness does not refuse a kill
    # by inspecting its exception class — enumerating exception names was the
    # first repair and the wrong shape — it refuses a *suite* run that never
    # reported how many tests it discovered, or reported a different number
    # from the baseline. A mutant that cannot be imported never gets that far,
    # whatever it dies of.
    ("DF9 the local facts are taken from the artifact being audited",
     "    findings: list[str] = []\n    for path, value in flatten(receipt):",
     "    context = {**context, \"requested_model\": receipt.get(\"requested_model\"),\n"
     "               \"provider\": receipt.get(\"provider\"),\n"
     "               \"target_id\": receipt.get(\"target_id\")}\n"
     "    findings: list[str] = []\n    for path, value in flatten(receipt):",
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
     "        return r\"(?!)\" if supplied is None else re.escape(supplied)",
     "        return r\"(?!)\" if supplied is None else r\"[A-Z_]+\"",
     "receipt_policy.py"),

    ("TP16 the canary's lines stop being rebuilt from their templates",
     "            elif text is None or not re.fullmatch(template_pattern(registered, context), text):",
     "            elif False:",
     "receipt_policy.py"),

    # -- NP: a container is a path, and a key is durable -------------------
    #
    # A reviewer produced the counterexample to this round's own theorem:
    # `{"provider_said": {"sk-live-secret": {}}}` yielded no leaves, so the
    # closed-world audit answered `[]` for an artifact carrying a
    # provider-chosen key. These are that hole, and the projection of the
    # refusal that follows from it.

    ("NP1 an empty container disappears from the inventory",
     "        if prefix:\n            yield prefix, (EMPTY_OBJECT if not value else OBJECT_NODE)",
     "        if prefix and value:\n            yield prefix, OBJECT_NODE",
     "receipt_policy.py"),

    ("NP2 an unknown path is reported with the provider's own key in it",
     "        raise KeyError(f\"no policy names the durable field {projected_path(path, table)}\")",
     "        raise KeyError(f\"no policy names the durable field {path!r}\")",
     "receipt_policy.py"),

    ("NP3 an array node stops being a path of its own",
     "        yield prefix, (EMPTY_ARRAY if not value else ARRAY_NODE)",
     "        _unused = (EMPTY_ARRAY if not value else ARRAY_NODE)",
     "receipt_policy.py"),

    ("NP4 a container is admitted wherever a scalar belongs",
     "        if not isinstance(value, Node):\n"
     "            return [f\"{type(value).__name__} is not a container\"]",
     "        if not isinstance(value, Node):\n            return []",
     "receipt_policy.py"),

    ("NP5 an object is admitted where an array belongs",
     "        if value.kind != self.kind:\n"
     "            return [f\"an {value.kind} where an {self.kind} belongs\"]",
     "        if False:\n"
     "            return [f\"an {value.kind} where an {self.kind} belongs\"]",
     "receipt_policy.py"),

    # -- CV: the table is covered by runs, not by classifications ----------

    ("CV1 the coverage gate stops asking for the paths a run must produce",
     "        missing=sorted(render_path(path) for path in required - reached),",
     "        missing=[],",
     "receipt_policy.py"),

    # Follows the filter, which moved into `policies_for` when the coverage
    # API's guard was given one site. A spec whose anchor stays where the code
    # used to be is not a weaker proof — it is no proof, and the harness says
    # so out loud rather than counting it as a kill.
    ("CV2 coverage is asked over the union of both receipt kinds",
     "        policy for policy in (POLICIES if policies is None else policies)\n"
     "        if kind in policy.schemas\n"
     "    ]",
     "        policy for policy in (POLICIES if policies is None else policies)\n"
     "    ]",
     "receipt_policy.py"),

    ("CV3 every policy is excused from coverage by default",
     "    coverage_required: bool = True",
     "    coverage_required: bool = False",
     "receipt_policy.py"),

    ("CV4 coverage stops looking for a declaration that is simply false",
     "        wrong_schema=sorted(",
     "        wrong_schema=[] or sorted(\n            [] if True else",
     "receipt_policy.py"),

    ("CV5 a coverage opt-out needs no stated reason",
     "        if not policy.coverage_required and not policy.why:",
     "        if False:",
     "receipt_policy.py"),

    # -- the structural path model -----------------------------------------

    # Matching by notation rather than by structure is the whole defect in one
    # line: `"turns[].detail"` as a literal key renders exactly as the path
    # `(Key("turns"), Each(), Key("detail"))` does.
    ("NP6 a path is a string again, so a key can impersonate a structure",
     "    matches = [policy for policy in table if policy.path == path]",
     "    matches = [policy for policy in table if render_path(policy.path) == render_path(path)]",
     "receipt_policy.py"),

    ("NP7 the projection asks whether a word is known anywhere",
     "        if not lost and isinstance(step, Key) and step in node:",
     "        if isinstance(step, Key) and any(\n"
     "                step in level for level in [node] + [{s: {} for p in POLICIES for s in p.path}]):",
     "receipt_policy.py"),

    ("NP8 a non-string key is laundered through str()",
     "            step = Key(key) if isinstance(key, str) else BadKey(pm.json_type_name(key))",
     "            step = Key(key) if isinstance(key, str) else Key(str(key))",
     "receipt_policy.py"),

    # -- MH: a kill is evidence only if the mutant ran ----------------------

    ("MH1 a suite that never reported a test count is accepted",
     "        if self.test_count is None:\n"
     "            return f\"{self.label} never reported how many tests it ran\"",
     "        if False:\n"
     "            return f\"{self.label} never reported how many tests it ran\"",
     "mutations.py"),

    # Anchored with the line below it: this file quotes its own source in the
    # spec literals, so a one-line anchor matches twice and the harness reports
    # SKIPPED rather than pretending.
    ("MH2 a suite that discovered a different number of tests is accepted",
     "        if self.test_count != baseline_tests:\n"
     "            return (f\"{self.label} discovered {self.test_count} tests, \"",
     "        if False:\n"
     "            return (f\"{self.label} discovered {self.test_count} tests, \"",
     "mutations.py"),

    ("MH3 a target may name no suite oracle to anchor coherence on",
     "        if not any(oracle.kind == SUITE_ORACLE for oracle in oracles):\n"
     "            problems.append(f\"{filename} names no suite oracle",
     "        if False:\n"
     "            problems.append(f\"{filename} names no suite oracle",
     "mutations.py"),

    ("MH4 an expected kill may arrive from an oracle that stayed green",
     "        if not any(expected in result.output for result in red):\n"
     "            return \"MISATTRIBUTED\", f\"killed, but not by {expected}\"",
     "        if not any(expected in result.output for result in results):\n"
     "            return \"MISATTRIBUTED\", f\"killed, but not by {expected}\"",
     "mutations.py"),

    # -- TT: the transport is total over what a peer can do to a socket ----

    ("TT1 a reset while the status line is read escapes as an internal error",
     "    except (OSError, http.client.HTTPException) as exc:",
     "    except http.client.HTTPException as exc:"),

    ("TT2 the broad framing catch is hoisted above the narrow URLError one",
     "    except TimeoutError as exc:\n"
     "        return SendResult(None, None, \"timeout\", \"before-response\",",
     "    except (OSError, http.client.HTTPException) as exc:\n"
     "        return SendResult(\n"
     "            None, None, capture_detail(\"HTTP framing failure\", exc), \"response-framing\",\n"
     "            reason=\"http-framing-failure\", **failure_evidence(\"http-framing-error\", exc),\n"
     "        )\n"
     "    except TimeoutError as exc:\n"
     "        return SendResult(None, None, \"timeout\", \"before-response\","),

    ("TT3 an OSError framing failure repeats the message it was raised with",
     "    if isinstance(exc, (http.client.HTTPException, OSError)):",
     "    if isinstance(exc, (http.client.HTTPException, InterruptedError)):"),

    # -- MI: identity is one sum type, and every reader projects it ---------

    ("MI1 a non-string model is called missing again",
     "    if reported is None:\n        return MissingModel()",
     "    if reported is None or not isinstance(reported, (str, bytes)):\n"
     "        return MissingModel()"),

    ("MI2 the terminal answer assumes every substitution carries a digest",
     "                if isinstance(seen, TextSubstitution):\n"
     "                    reference = DigestRef.of_reference(seen.reference())",
     "                if isinstance(seen, (TextSubstitution, NonTextModel)):\n"
     "                    reference = DigestRef.of_reference(\n"
     "                        opaque_ref(\"model-name\", getattr(seen, \"name\", \"\")))"),

    ("MI3 a non-text drift is rendered with the text-only template",
     "    if types:\n        return LocalDetail(\"identity-substituted-nontext\", (len(types), few_types))",
     "    if False:\n        return LocalDetail(\"identity-substituted-nontext\", (len(types), few_types))"),

    ("MI4 a mixed drift reports only its digests",
     "    if digests and types:",
     "    if False:"),

    ("MI5 model_evidence stops agreeing with the identity it projects",
     "    if isinstance(identity, MissingModel):\n"
     "        return {\"reported_model\": None, \"reported_model_present\": False}",
     "    if isinstance(identity, MissingModel):\n"
     "        return {\"reported_model\": None, \"reported_model_present\": True}"),

    ("MI6 the status stops being a projection of the identity",
     "    return status_of_identity(model_identity(requested, reported))",
     "    return \"missing\" if not isinstance(reported, str) or not reported else (\n"
     "        \"verified\" if reported == requested else \"drifted\")"),

    ("MI7 two turns naming the same other model become two findings",
     "                    if reference not in digests:\n                        digests.append(reference)",
     "                    if True:\n                        digests.append(reference)"),

    # -- RK: the receipt-kind vocabulary is closed -------------------------

    ("RK1 an unknown receipt kind is swallowed by the coverage proof",
     "        for kind in policy.schemas:\n"
     "            if not isinstance(kind, ReceiptKind):",
     "        for kind in policy.schemas:\n            if False:",
     "receipt_policy.py"),

    ("RK2 a policy applying to no receipt kind stops being reported",
     "        if not policy.schemas:\n"
     "            problems.append(f\"{policy.named()}: applies to no receipt kind\")",
     "        if False:\n"
     "            problems.append(f\"{policy.named()}: applies to no receipt kind\")",
     "receipt_policy.py"),

    # -- FG: a launcher may not leave the inspected grammar -----------------

    ("FG1 a launcher may leave the grammar unremarked",
     "        uses.extend(self.escapes_the_grammar(tree, modules))",
     "        pass",
     "test_provider_matrix.py"),

    ("FG2 the alias rule widens to any assignment target",
     "            if (isinstance(parent, ast.Assign) and parent.value is node\n"
     "                    and all(isinstance(goal, ast.Name) for goal in parent.targets)):",
     "            if isinstance(parent, ast.Assign) and parent.value is node:",
     "test_provider_matrix.py"),

    # -- RM: a peer's metadata is content, not a broken internal contract --

    ("RM1 an oversized request id is refused instead of projected",
     "        if not isinstance(result.request_id, str):\n"
     "            raise ValueError(f\"request_id must be a string, got {type(result.request_id).__name__}\")",
     "        if not isinstance(result.request_id, str):\n"
     "            raise ValueError(f\"request_id must be a string, got {type(result.request_id).__name__}\")\n"
     "        if len(result.request_id.encode(\"utf-8\", \"surrogatepass\")) > EVIDENCE_MAX_BYTES[\"request-id\"]:\n"
     "            raise ValueError(\"request_id is longer than the local bound\")"),

    ("RM2 a producer handing over the wrong type stops being refused",
     "        if not isinstance(result.request_id, str):\n"
     "            raise ValueError(f\"request_id must be a string, got {type(result.request_id).__name__}\")",
     "        if False:\n"
     "            raise ValueError(f\"request_id must be a string, got {type(result.request_id).__name__}\")"),

    # -- UC: each counter carries the bound that produced it ----------------

    ("UC1 the usage ceilings come from the response limit again",
     "        \"prompt_ceiling\": pm.MAX_REQUEST_BYTES,",
     "        \"prompt_ceiling\": response_limit,",
     "receipt_policy.py"),

    ("UC2 the three counters share one slack ceiling",
     "        \"completion_tokens\": \"completion_ceiling\",",
     "        \"completion_tokens\": \"usage_ceiling\",",
     "receipt_policy.py"),

    ("UC3 the completion ceiling stops following the generation asked for",
     "        \"completion_ceiling\": (\n"
     "            pm.PROBE_MAX_TOKENS if kind is PROBE else pm.QUALIFY_MAX_TOKENS),",
     "        \"completion_ceiling\": pm.QUALIFY_MAX_TOKENS,",
     "receipt_policy.py"),

    # -- CK: the coverage API has a door too --------------------------------

    ("CK1 a plain string reaches the coverage queries again",
     "    if not isinstance(value, ReceiptKind):\n        raise TypeError(",
     "    if False:\n        raise TypeError(",
     "receipt_policy.py"),

    # The guard was first written at all four public queries, where three of the
    # four were undistinguishable from their own absence — the queries call one
    # another. It now has one site, and bypassing it is what each query can be
    # caught doing.

    ("CK2 declared_paths selects without going through the checked door",
     "    return frozenset(policy.path for policy in policies_for(kind, policies))",
     "    return frozenset(\n"
     "        policy.path for policy in (POLICIES if policies is None else policies)\n"
     "        if kind in policy.schemas)",
     "receipt_policy.py"),

    ("CK3 applicable_paths selects without going through the checked door",
     "    return frozenset(\n"
     "        policy.path for policy in policies_for(kind, policies)\n"
     "        if policy.coverage_required\n"
     "    )",
     "    return frozenset(\n"
     "        policy.path for policy in (POLICIES if policies is None else policies)\n"
     "        if kind in policy.schemas and policy.coverage_required)",
     "receipt_policy.py"),

    # -- HG: the real verdict is as isolated as its control -----------------

    ("HG1 the real clean-tree verdict runs with the ambient environment",
     "            lines = dirt(repo_root(env=env), env=env)",
     "            lines = dirt(repo_root())",
     "check_clean_tree.py"),

    ("HG2 repo_root stops accepting the isolation it is given",
     "    top = git(\"rev-parse\", \"--show-toplevel\", cwd=here, env=env)",
     "    top = git(\"rev-parse\", \"--show-toplevel\", cwd=here)",
     "check_clean_tree.py"),

    # -- LV: a child gets EOF, not the deadline -----------------------------

    ("LV1 a child inherits the terminal again",
     "            stdin=subprocess.DEVNULL,",
     "            stdin=None,",
     "process_boundary.py"),

    # -- VT: the mutation table's validator is itself checked ---------------

    ("VT1 zip truncates a lopsided multi-anchor spec in silence",
     "            if len(old) != len(new):\n"
     "                problems.append(",
     "            if False:\n"
     "                problems.append(",
     "mutations.py"),

    ("VT2 a half-list spec stops being refused",
     "        if isinstance(old, list) != isinstance(new, list):\n"
     "            problems.append(f\"{name}: one half of a multi-anchor edit",
     "        if False:\n"
     "            problems.append(f\"{name}: one half of a multi-anchor edit",
     "mutations.py"),

    ("VT3 an orphaned expectation stops being reported",
     "    for orphan in sorted(set(expectations or {}) - declared):\n"
     "        problems.append(",
     "    for orphan in sorted(set() - declared):\n"
     "        problems.append(",
     "mutations.py"),

    # -- FN: a file name for every id, not for the ids somebody thought of ----

    ("FN1 the escape set shrinks back to the characters somebody listed",
     "        chr(byte) if bytes([byte]) in FILENAME_ALPHABET else f\"%{byte:02X}\"",
     "        chr(byte) if byte not in (0x2F, 0x5C) else f\"%{byte:02X}\""),

    ("FN2 the stem is unbounded again",
     "    return f\"{stem[:RECEIPT_STEM_MAX_CHARS]}-{digest}.json\"",
     "    return f\"{stem}-{digest}.json\""),

    ("FN3 truncation is left to collide",
     "    digest = hashlib.sha256(RECEIPT_FILENAME_DOMAIN + raw).hexdigest()\n"
     "    return f\"{stem[:RECEIPT_STEM_MAX_CHARS]}-{digest}.json\"",
     "    return f\"{stem[:RECEIPT_STEM_MAX_CHARS]}.json\""),

    # -- AU: one normalisation for three kinds of string ---------------------

    ("AU1 the URL rule is applied to every authority field again",
     "    if rule == \"url\":\n"
     "        return claimed.strip().rstrip(\"/\") == trusted.rstrip(\"/\")\n"
     "    return claimed == trusted",
     "    return claimed.strip().rstrip(\"/\") == trusted.rstrip(\"/\")"),

    ("AU2 an unnamed authority field quietly inherits a rule",
     "    rule = AUTHORITY_COMPARISON[field]",
     "    rule = AUTHORITY_COMPARISON.get(field, \"url\")"),

    # -- EW: the write is inside the boundary that promises it ---------------

    ("EW1 a failed write leaves the boundary again",
     "    try:\n"
     "        write_json(out_dir / receipt_filename(target_id), receipt)\n"
     "    except OSError as exc:\n"
     "        return f\"receipt {index + 1} of {total} could not be written: {type(exc).__name__}\"\n"
     "    return None",
     "    write_json(out_dir / receipt_filename(target_id), receipt)\n"
     "    return None"),

    ("EW2 an incomplete matrix is reported as a complete one",
     "    if problems:\n"
     "        print(f\"provider-matrix: {len(problems)} receipt(s) were not written; \"",
     "    if False:\n"
     "        print(f\"provider-matrix: {len(problems)} receipt(s) were not written; \""),

    # -- PB(ounds): the producer applies what the auditor bounds --------------

    ("PBD1 a response may carry more tool calls than the producer admits",
     "    if len(raw) > MAX_TOOL_CALLS:",
     "    if False:"),

    ("PBD2 the cardinality bound is read as an ordinal again",
     "    if len(raw) > MAX_TOOL_CALLS:",
     "    if len(raw) > MAX_CALL_ORDINAL + 2:"),

    ("PBD3 the ordinal ceiling stops following the producer's bound",
     "MAX_CALL_ORDINAL = MAX_TOOL_CALLS - 1",
     "MAX_CALL_ORDINAL = MAX_TOOL_CALLS"),

    ("PBD4 the error evidence is unbounded again",
     "    kept = errors[:MAX_ARGUMENT_ERRORS]",
     "    kept = errors"),

    ("PBD5 truncation stops being reported",
     "        f\"{prefix}_truncated\": len(errors) > MAX_ARGUMENT_ERRORS,",
     "        f\"{prefix}_truncated\": False,"),

    ("PBD6 the digest describes more than the count does",
     "        f\"{prefix}_sha256\": evidence_digest(\"argument-errors\", \"\\n\".join(kept)),",
     "        f\"{prefix}_sha256\": evidence_digest(\"argument-errors\", \"\\n\".join(errors)),"),

    # A literal `1024` here was the first attempt, and it survived: it equals
    # `MAX_ARGUMENT_ERRORS` today, so the edit changed nothing to observe. The
    # observable contract is that the two numbers *agree*, so the mutation that
    # tests it has to make them disagree. A stale literal that agrees today and
    # diverges tomorrow is caught by the test, which compares against the
    # producer's constant rather than against 1024.
    ("PBD7 the auditor's error ceiling stops agreeing with the producer's bound",
     "        \"error_ceiling\": pm.MAX_ARGUMENT_ERRORS,",
     "        \"error_ceiling\": 4096,",
     "receipt_policy.py"),

    ("PBD8 the policy declares its own ordinal ceiling again",
     "        \"max_call_ordinal\": pm.MAX_CALL_ORDINAL,",
     "        \"max_call_ordinal\": 1024,",
     "receipt_policy.py"),

    # -- HR: the listener reads the request it was sent ----------------------

    ("HR1 the listener answers before the body has arrived",
     "    while len(body) < wanted:",
     "    while False:",
     "test_provider_matrix.py"),

    ("HR2 a short read of the headers is taken for the whole request",
     "    while b\"\\r\\n\\r\\n\" not in buffered:",
     "    while False:",
     "test_provider_matrix.py"),

    ("HR3 a peer that stops mid-body is a short read rather than a failure",
     "            raise TruncatedRequest(\n"
     "                f\"the peer closed after {len(body)} of {wanted} declared bytes\")",
     "            break",
     "test_provider_matrix.py"),

    ("HR4 an unusable Content-Length is taken on trust",
     "            if wanted < 0 or wanted > MAX_TEST_REQUEST_BYTES:",
     "            if False:",
     "test_provider_matrix.py"),

    # -- BC: the bounded-field closure ---------------------------------------

    ("BC1 a bounded field may again be enforced by nobody",
     "    problems = [\n"
     "        f\"{render_path(path)}: bounded by the table and enforced by nobody\"\n"
     "        for path in sorted(bounded - set(table), key=render_path)\n"
     "    ]",
     "    problems = []",
     "receipt_policy.py"),

    ("BC2 an enforcement entry may name a field with no bound",
     "    problems.extend(\n"
     "        f\"{render_path(path)}: an enforcement entry for a field with no bound\"\n"
     "        for path in sorted(set(table) - bounded, key=render_path)\n"
     "    )",
     "    problems.extend([])",
     "receipt_policy.py"),

    ("BC3 a strategy may be declared without an argument",
     "        if not strategy.why.strip()",
     "        if False",
     "receipt_policy.py"),

    ("BC4 Prose stops counting as a stated quantity",
     "    return isinstance(kind, (BoundedInt, BoundedNumber, Prose))",
     "    return isinstance(kind, (BoundedInt, BoundedNumber))",
     "receipt_policy.py"),

    # -- CN: the canary diagnostics are bounded evidence ----------------------

    ("CN1 the canary findings are unbounded again",
     "    kept = errors[:MAX_CANARY_ERRORS]",
     "    kept = errors"),

    ("CN2 truncation of the canary findings stops being reported",
     "        \"canary_answer_errors_truncated\": len(errors) > MAX_CANARY_ERRORS,",
     "        \"canary_answer_errors_truncated\": False,"),

    ("CN3 the count and the kept lines describe different things",
     "        \"canary_answer_errors_count\": len(kept),",
     "        \"canary_answer_errors_count\": len(errors),"),

    # Aimed at the truncated branch, which is the only one where the two
    # numbers differ: on the other, `kept` *is* the total, so the substitution
    # is equivalent and would survive — the same lesson `PBD7` taught a round
    # earlier, applied before the run rather than after it.
    ("CN4 the truncated detail reports the provider's count rather than the kept one",
     "            why = LocalDetail(\"canary-mismatch-truncated\", (kept,))",
     "            why = LocalDetail(\"canary-mismatch-truncated\", (len(facts.canary_errors),))"),

    # -- RQ: one request-size boundary, and it is reached before the key ------

    ("RQ1 the probe stops checking the size of what it is about to send",
     "        request_body = bounded_request(canonical_bytes({",
     "        request_body = (canonical_bytes({"),

    ("RQ2 the qualification loop stops checking it",
     "            body = bounded_request(\n"
     "                canonical_bytes(canonical_request(surface, target[\"model\"], messages)))",
     "            body = (\n"
     "                canonical_bytes(canonical_request(surface, target[\"model\"], messages)))"),

    ("RQ3 an oversized body is admitted rather than refused",
     "    if len(body) > MAX_REQUEST_BYTES:",
     "    if False:"),

    ("RQ4 the probe stops recording the request it sent",
     "        result[\"request_bytes\"] = len(request_body)",
     "        result[\"request_bytes\"] = 0"),

    ("RQ5 a three-digit status nobody assigned is refused again",
     "    return type(value) is int and HTTP_STATUS_MIN <= value <= HTTP_STATUS_MAX",
     "    return type(value) is int and HTTP_STATUS_MIN <= value <= 599"),

    # -- DB: the certificate's own inputs are enforced where they are built ---
    #
    # `slot_max_bytes` adds `DISCRIMINATOR_MAX_BYTES` into every template that
    # carries a discriminator. R20.1 shipped the number and the constructor that
    # applies it, and anchored neither: the certificate was arithmetic over a
    # bound no proof asked about.

    ("DB1 a discriminator's word is no longer bounded where it is built",
     "        if self.known is not None and len(repr(self.known).encode(\"utf-8\")) > DISCRIMINATOR_MAX_BYTES:",
     "        if False:"),

    # -- CW: the corpus walk reaches nested places, not top-level names -------
    #
    # Every one of these leaves the auditor untouched and narrows the *corpus*.
    # A mutation that survives here would mean the coverage report is decorative
    # — which is what it was two heads ago, when it counted member names and a
    # tool call's `ordinal` was covered by a claim about a turn's.

    ("CW1 the corpus walk stops at the first element of an array",
     "    elif isinstance(node, list):\n"
     "        for element in node:\n"
     "            found |= fixture_paths(element, prefix + (EACH,))",
     "    elif isinstance(node, list) and node:\n"
     "        found |= fixture_paths(node[0], prefix + (EACH,))",
     "receipt_policy.py"),

    ("CW2 the corpus walk stops descending into objects",
     "        for key, value in node.items():\n"
     "            if isinstance(key, str):\n"
     "                found |= fixture_paths(value, prefix + (Key(key),))",
     "        for key, value in node.items():\n"
     "            if isinstance(key, str):\n"
     "                found.add(prefix + (Key(key),))",
     "receipt_policy.py"),

    ("CW3 the tally stops recording which places were reached",
     "        tally.paths.add(path)",
     "        pass",
     "receipt_policy.py"),

    ("CW4 a required place may go without a hostile value",
     "    unwitnessed = sorted(set(required) - tally.paths, key=render_path)",
     "    unwitnessed = []",
     "receipt_policy.py"),

    ("CW5 a required place need not be one any policy reads",
     "    fictional = sorted(set(required) - declared, key=render_path)",
     "    fictional = []",
     "receipt_policy.py"),

    # NP6 was written against a prefix expansion in `declared_places` and
    # survived the round-twenty run — because that expansion produced no path
    # the table did not already hold, so deleting it changed nothing. The
    # expansion was a tautology wearing the clothes of a check, and it was
    # hiding the property that made it a tautology: the table names every
    # container on every declared path. The spec is retargeted onto that
    # property, which a mutation *can* break.

    ("CW6 a leaf may sit under a container no policy names",
     "        for stop in range(1, len(path)):\n"
     "            if path[:stop] not in named:",
     "        for stop in range(1, 1):\n"
     "            if path[:stop] not in named:",
     "receipt_policy.py"),

    # Two more were written for this closure and are not shipped, because both
    # would survive and I know why. Deleting the gate's *call* to
    # `unnamed_containers` is invisible: the shipped table has no unnamed
    # container, so the arm is silent either way — which is true of every gate
    # arm checking a property that currently holds, and is why `BC1`/`BC2`
    # anchor detectors rather than call sites. And restoring the prefix
    # expansion in `declared_places` is provably an identity on a closed table,
    # so it cannot be observed at all. A mutation known to survive proves
    # nothing and inflates the denominator.

    ("CW7 only the first occurrence of an array is addressable, and it is the wrong one",
     "        for index, element in enumerate(node):\n"
     "            if not rest:\n"
     "                return node, index\n"
     "            found = locate(element, rest)\n"
     "            if found is not None:\n"
     "                return found\n"
     "        return None",
     "        if not node:\n"
     "            return None\n"
     "        return (node, 0) if not rest else locate(node[0], rest)",
     "receipt_policy.py"),

    ("CW8 a canary template is looked up without being read as a string",
     "            registered = read_str(name)\n"
     "            if registered is None or registered not in pm.DETAIL_TEMPLATES:",
     "            registered = name\n"
     "            if registered not in pm.DETAIL_TEMPLATES:",
     "receipt_policy.py"),

    # -- RD: the README's claims about this code are asked of this code --------
    #
    # Four were written against the *test* first and withdrawn: a test asserting
    # "the README matches the code" cannot fail while it matches, so deleting it
    # is invisible. The comparison is a function over supplied text instead, and
    # these aim at its arms, which the gate's seven controls anchor.

    ("RD1 a missing anchor reads as an empty block rather than as a finding",
     "    if needle not in text:\n        return None",
     "    if needle not in text:\n        return \"\"",
     "check_readme.py"),

    ("RD2 the README may list an outcome this code cannot emit",
     "    for name in sorted(stated - emitted):\n"
     "        problems.append(f\"{where}: the README lists {name}, which this code cannot emit\")",
     "    for name in sorted(set()):\n"
     "        problems.append(f\"{where}: the README lists {name}, which this code cannot emit\")",
     "check_readme.py"),

    ("RD3 the README may omit an outcome this code emits",
     "    for name in sorted(emitted - stated):",
     "    for name in sorted(set()):",
     "check_readme.py"),

    ("RD4 the stated remainder stops being compared to the asserted one",
     "        problems.extend(compare(\"unreached remainder\", stated, set(UNREACHED_BY_THE_TABLE)))",
     "        problems.extend([])",
     "check_readme.py"),

    ("RD5 the prose reader depends on where the line breaks fall",
     "    return \" \".join(text.split())",
     "    return text",
     "check_readme.py"),

    ("RD7 the policy-kind table stops being compared to the kinds that exist",
     "        problems.extend(compare(\n"
     "            \"policy kinds\", kinds,\n"
     "            {kind.__name__ for kind in receipt_policy.Kind.__subclasses__()}))",
     "        problems.extend([])",
     "check_readme.py"),

    ("RD8 a table row that names nothing stops ending the scan",
     "        if not line.startswith(\"|\"):\n            break",
     "        if not line.startswith(\"|\"):\n            continue",
     "check_readme.py"),

    ("RD6 a literal NUL in the README stops being a finding",
     "    if \"\\x00\" in text:",
     "    if False:",
     "check_readme.py"),

    # -- GE: the git environment is dropped wholesale, not by enumeration ------
    #
    # `HG1`/`HG2` prove the shipped verdict *accepts* isolation. They say
    # nothing about how wide it is, and the two witnesses that existed poisoned
    # one variable each — so five of the variables that redirect git were never
    # set at all, and the boundary was demonstrated for the ones somebody
    # thought of. Same shape as an escape set of three characters.

    ("GE1 the isolation enumerates the git variables it drops",
     "    env = {key: value for key, value in os.environ.items() if not key.startswith(\"GIT_\")}",
     "    env = {key: value for key, value in os.environ.items()\n"
     "           if key not in (\"GIT_DIR\", \"GIT_WORK_TREE\")}",
     "check_clean_tree.py"),

    ("GE2 the isolation stops replacing HOME",
     "    env[\"HOME\"] = str(home)",
     "    env[\"HOME\"] = os.environ.get(\"HOME\", str(home))",
     "check_clean_tree.py"),

    ("GE3 the machine's global configuration is readable again",
     "    env[\"GIT_CONFIG_GLOBAL\"] = str(home / \"absent-global-config\")",
     "    env.pop(\"GIT_CONFIG_GLOBAL\", None)",
     "check_clean_tree.py"),

    # -- EM: nothing is written until everything about the writing is decided -

    ("EM1 a target id may again be ambiguous about the pair it names",
     "    if TARGET_ID_SEPARATOR in provider:\n"
     "        raise ValueError(\n"
     "            f\"provider {provider!r} contains {TARGET_ID_SEPARATOR!r}, which would make \"\n"
     "            \"its target ids ambiguous\")",
     "    pass"),

    ("EM2 the registry stops refusing a provider whose ids would collide",
     "        if TARGET_ID_SEPARATOR in name:",
     "        if False:"),

    ("EM3 a target id need not follow from the pair beside it",
     "        if claimed_id != derived:",
     "        if False:"),

    ("EM4 two selected targets may share one id",
     "        if claimed_id in ids:\n"
     "            problems.append(f\"{where}: target_id {claimed_id!r} repeats selected[{ids[claimed_id]}]\")",
     "        if False:\n"
     "            problems.append(f\"{where}: target_id {claimed_id!r} repeats selected[{ids[claimed_id]}]\")"),

    ("EM5 two selected targets may share one provider/model pair",
     "        if pair in pairs:\n"
     "            problems.append(f\"{where}: provider/model {pair!r} repeats selected[{pairs[pair]}]\")",
     "        if False:\n"
     "            problems.append(f\"{where}: provider/model {pair!r} repeats selected[{pairs[pair]}]\")"),

    ("EM6 the probe writes its first receipts before the plan is checked",
     "            refuse_emission(plan[\"selected\"])\n"
     "            args.out_dir.mkdir(parents=True, exist_ok=True)\n"
     "            selected = plan[\"selected\"]\n"
     "            problems = []\n"
     "            for index, target in enumerate(selected):\n"
     "                receipt = guarded_receipt(\n"
     "                    PROBE_SCHEMA, target,",
     "            args.out_dir.mkdir(parents=True, exist_ok=True)\n"
     "            selected = plan[\"selected\"]\n"
     "            problems = []\n"
     "            for index, target in enumerate(selected):\n"
     "                receipt = guarded_receipt(\n"
     "                    PROBE_SCHEMA, target,"),

    ("EM7 the qualification writes its first receipts before the plan is checked",
     "            refuse_emission(plan[\"selected\"])\n"
     "            args.out_dir.mkdir(parents=True, exist_ok=True)\n"
     "            selected = plan[\"selected\"]\n"
     "            problems = []\n"
     "            for index, target in enumerate(selected):\n"
     "                receipt = guarded_receipt(QUALIFY_SCHEMA, target,",
     "            args.out_dir.mkdir(parents=True, exist_ok=True)\n"
     "            selected = plan[\"selected\"]\n"
     "            problems = []\n"
     "            for index, target in enumerate(selected):\n"
     "                receipt = guarded_receipt(QUALIFY_SCHEMA, target,"),

    ("EM8 the preflight reports the first problem and stops",
     "    problems = emission_problems(selected)\n"
     "    if problems:",
     "    problems = emission_problems(selected)[:0]\n"
     "    if problems:"),

    ("MH5 the expected killer is no longer required at all",
     "    if expected is not None:\n"
     "        # In the failing oracle's own output",
     "    if False:\n"
     "        # In the failing oracle's own output",
     "mutations.py"),
]


def target_problems(targets: dict) -> list[str]:
    """Refuse a target table that cannot support an attributed kill.

    Coherence is asked of the suite — see `OracleResult.incoherent` — so a
    target that names no suite oracle has no anchor, and every kill against it
    would be taken on trust. A function rather than three lines inside `main`
    because a check the suite cannot reach is a check no mutation can kill.
    """
    problems = []
    for filename, oracles in sorted(targets.items()):
        if not any(oracle.kind == SUITE_ORACLE for oracle in oracles):
            problems.append(f"{filename} names no suite oracle to anchor coherence on")
    return problems


def spec_fingerprint(spec) -> str:
    """The machine identity of a mutation operation.

    Target path, anchors, replacements — and deliberately not the display name.
    A rename must leave this unchanged, or a baseline taken before the rename
    cannot be compared with a run taken after it, and the attribution evidence
    dies of its own housekeeping.
    """
    old, new = spec[1], spec[2]
    target = spec[3] if len(spec) > 3 else DEFAULT_TARGET
    edits = list(zip(old, new)) if isinstance(old, list) else [(old, new)]
    payload = json.dumps([target, edits], ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def spec_problems(specs: list, expectations: dict | None = None) -> list[str]:
    """Refuse a mutation list that flatters itself.

    `E7` and `N2` carried different names, the same anchor and the same
    replacement. "96 mutations killed" was therefore 95 mutations killed and one
    counted twice, and one of the two names claimed coverage it did not add —
    the same self-flattery the anchor check exists to prevent, one level up.

    Two identities, and this function once checked only the first of them.

    A specification is referred to by its **id** — the leading token of its
    name — in the harness output, in `EXPECTED_KILL`, in commit messages and in
    review. Full names were required to be unique and ids were not, so eight
    specifications ended up sharing four... no: eight specifications shared the
    ids of eight others, and 317 rows carried 309 distinct ids. Every one of
    those pairs reads as one specification anywhere an id is the reference,
    which is everywhere a human looks. It survived a full green run because the
    only uniqueness anybody asked for was of a string nobody quotes.

    And a specification *is* a mutation operation — a file, an anchor, a
    replacement. Two rows describing the same operation are one contract counted
    twice, which `by_edit` already refused; the fingerprint below states the
    same thing as an identity rather than as a pairwise comparison, so an
    attribution manifest can be keyed by it across a rename.
    """
    problems = []
    by_name: dict[str, int] = {}
    by_id: dict[str, list[str]] = {}
    by_fingerprint: dict[str, list[str]] = {}
    by_edit: dict[tuple, list[str]] = {}
    for spec in specs:
        name, old, new = spec[0], spec[1], spec[2]
        target = spec[3] if len(spec) > 3 else DEFAULT_TARGET
        by_name[name] = by_name.get(name, 0) + 1
        by_id.setdefault(name.split()[0], []).append(name)
        by_fingerprint.setdefault(spec_fingerprint(spec), []).append(name)
        if isinstance(old, list) != isinstance(new, list):
            problems.append(f"{name}: one half of a multi-anchor edit is a list and the other is not")
            continue
        if isinstance(old, list):
            # `zip` truncates in silence, so a spec removing three guards and
            # supplying two replacements would apply two of them, report a kill,
            # and leave the third guard in place — the harness counting a
            # contract it never broke.
            if len(old) != len(new):
                problems.append(
                    f"{name}: {len(old)} anchors and {len(new)} replacements; "
                    "`zip` would discard the difference without saying so")
                continue
        edits = tuple(zip(old, new)) if isinstance(old, list) else ((old, new),)
        by_edit.setdefault((target, edits), []).append(name)
    for name, count in by_name.items():
        if count > 1:
            problems.append(f"the name {name!r} is used {count} times")
    for spec_id, names in sorted(by_id.items()):
        if len(names) > 1:
            problems.append(f"the id {spec_id!r} names {len(names)} different "
                            f"specifications: {', '.join(sorted(names))}")
    for names in sorted(by_fingerprint.values()):
        if len(names) > 1:
            problems.append("one mutation operation under several names: "
                            + ", ".join(sorted(names)))
    for names in by_edit.values():
        if len(names) > 1:
            problems.append(f"identical anchor and replacement: {', '.join(names)}")
    # An expectation keyed to a name nothing carries stops being asked, without
    # anything going red. Renaming a mutation is exactly how that happens, and
    # the attribution it was carrying disappears with it.
    #
    # Supplied rather than reached for, because this function is also called on
    # small hand-built lists in the suite, and against one of those every real
    # expectation would look orphaned. `main` passes the shipped table.
    declared = {spec[0] for spec in specs}
    for orphan in sorted(set(expectations or {}) - declared):
        problems.append(f"EXPECTED_KILL names {orphan!r}, which no mutation declares")
    return problems


# What may be asked whether a mutated file still works.
#
# The old shape was a dichotomy: a gate was qualified by its own `--self-test`
# and *only* by it, everything else by the suite and only by it. That was
# written down as a known limit, and a known limit that stays written down for
# five rounds is a design decision. `MUTATION_TARGETS` maps each mutable file to
# the oracles that may object to it, **every** one of them is asked, and the
# harness reports which ones did.
SUITE_ORACLE = "suite"
GATE_ORACLE = "gate"


@dataclass(frozen=True)
class Oracle:
    label: str
    argv: tuple[str, ...]
    kind: str


SUITE = Oracle("suite", ("-m", "unittest", "test_provider_matrix.py"), SUITE_ORACLE)
DISCOVERY_GATE = Oracle(
    "discovery-gate", ("check_test_discovery.py", "--self-test"), GATE_ORACLE)
CLEAN_TREE_GATE = Oracle(
    "clean-tree-gate", ("check_clean_tree.py", "--self-test"), GATE_ORACLE)
POLICY_GATE = Oracle("policy-gate", ("receipt_policy.py", "--self-test"), GATE_ORACLE)
README_GATE = Oracle("readme-gate", ("check_readme.py", "--self-test"), GATE_ORACLE)

MUTATION_TARGETS: dict[str, tuple[Oracle, ...]] = {
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
    "check_readme.py": (README_GATE, SUITE),
}

RAN_TESTS = re.compile(r"^Ran (\d+) tests?", re.M)

@dataclass(frozen=True)
class OracleResult:
    """One oracle's answer, with enough structure to tell *how* it answered.

    The previous version returned a boolean and a tail line, and inferred an
    invalid mutant from a list of exception names. That list was the wrong
    shape: `NameError` was on it because a mutation had died of one, and
    tomorrow's `RuntimeError` would have been the sixth neighbouring defect
    discovered one at a time — the exact habit this round exists to retire.
    Coherence is asked structurally instead. A suite run that does not report
    how many tests it discovered did not get as far as running any.
    """

    label: str
    kind: str
    passed: bool
    output: str
    test_count: int | None

    def incoherent(self, baseline_tests: int) -> str | None:
        """Did this oracle run far enough for its answer to mean anything?

        Asked of the **suite** only, which is why every target names one. A gate
        is the wrong place for this rule: several gate mutations exist precisely
        to make a gate die of a traceback instead of printing a report, so
        requiring a verdict line from it would refuse the kill that proves the
        contract. The suite is the anchor because it discovers and runs the
        whole file — a mutant that cannot be imported never gets that far.
        """
        if self.kind != SUITE_ORACLE:
            return None
        if self.test_count is None:
            return f"{self.label} never reported how many tests it ran"
        if self.test_count != baseline_tests:
            return (f"{self.label} discovered {self.test_count} tests, "
                    f"not the {baseline_tests} it discovers unmutated")
        return None


def discovered(output: str) -> int | None:
    found = RAN_TESTS.search(output)
    return int(found.group(1)) if found else None


# A mutated program is an arbitrary program, so its output is arbitrary bytes.
# Through the one boundary that starts processes, decoded the way arbitrary
# bytes are decoded, and rendered safe before anything is printed — the harness
# itself used to be the last direct `subprocess` caller outside the boundary,
# which made "one module starts processes" true only if you did not count this
# one.
def run_oracle(workdir: Path, oracle: Oracle) -> OracleResult:
    env = dict(os.environ, PYTHONPATH=str(CORPUS_TOOLS), PYTHONDONTWRITEBYTECODE="1")
    try:
        proc = run_bytes(
            [sys.executable, *oracle.argv], cwd=workdir, env=env, timeout=SUITE_TIMEOUT)
    except ProcessFailure as exc:
        # A mutation that makes an oracle loop is not green, and a harness that
        # blocks on it reports nothing at all. Not-green is the honest reading.
        return OracleResult(oracle.label, oracle.kind, False, str(exc), None)
    output = printable(decode_path(proc.stdout + proc.stderr))
    return OracleResult(
        oracle.label, oracle.kind, proc.returncode == 0, output, discovered(output))


def run_gate(workdir: Path, filename: str) -> list[OracleResult]:
    """Ask **every** oracle this target names, and keep each answer separate.

    Stopping at the first red one was cheaper and quietly weaker: for a file
    whose oracles are ordered `(policy gate, suite)`, a mutation that reddens
    the first was never shown to the second. Concatenating their outputs
    afterwards was weaker again — an expected test id could then be matched
    against a run that did not fail at all.
    """
    return [run_oracle(workdir, oracle) for oracle in MUTATION_TARGETS.get(filename, ())]


def run_suite(workdir: Path) -> OracleResult:
    return run_oracle(workdir, SUITE)


def verdict_for(name: str, results: list[OracleResult], baseline_tests: int) -> tuple[str, str]:
    """`(state, why)` for one mutant. The whole attribution rule, in one place.

    `DF9` referred to a name that no longer existed in the function it mutated,
    so every oracle died before a single policy compared anything and the
    harness counted it as the contract holding. One corpse was a passer-by, and
    "210/210 killed" was arithmetically true and evidentially false.
    """
    if not results:
        return "INVALID", "no oracle is declared for this target"
    for result in results:
        problem = result.incoherent(baseline_tests)
        if problem is not None:
            return "INVALID", f"{problem}; the mutant never ran as a program"
    red = [result for result in results if not result.passed]
    if not red:
        return "SURVIVED", "every oracle stayed green"
    expected = EXPECTED_KILL.get(name)
    if expected is not None:
        # In the failing oracle's own output, not in a concatenation of all of
        # them: otherwise a test id can arrive from a run that passed.
        if not any(expected in result.output for result in red):
            return "MISATTRIBUTED", f"killed, but not by {expected}"
    return "killed", "; ".join(f"{result.label}: {last_line(result.output)}" for result in red)


def last_line(output: str) -> str:
    lines = output.strip().splitlines()
    return lines[-1] if lines else "(no output)"


# Where a mutation's kill must be *attributed*, not merely counted. The value is
# a substring the killing oracle's output has to contain — a test id for the
# contract the mutation is named after. Not every mutation needs one; the ones
# that carry a provenance or ownership claim do, because those are exactly the
# claims a spurious kill would silently support.
EXPECTED_KILL = {
    "DF9 the local facts are taken from the artifact being audited":
        "test_a_receipt_that_disagrees_with_the_plan_stops_the_gate",
    "DF10 a local field accepts a value that is not the local one":
        "test_a_receipt_that_disagrees_with_the_plan_stops_the_gate",
    "DF1 audit skips a leaf no policy names":
        "test_an_unnamed_leaf_stops_the_gate",
    "NP1 an empty container disappears from the inventory":
        "test_an_empty_container_is_a_path_and_not_a_silence",
    "NP2 an unknown path is reported with the provider's own key in it":
        "test_the_refusal_names_the_shape_and_digests_the_key",
    "NP6 a path is a string again, so a key can impersonate a structure":
        "test_a_key_cannot_impersonate_a_structural_path",
    "NP7 the projection asks whether a word is known anywhere":
        "test_a_known_word_under_an_unknown_prefix_is_still_projected",
    # The positive control, not the assertion that shares its subject: a
    # coverage gate that reports nothing keeps `..._is_produced_by_a_real_run`
    # green by construction, so naming that test would have been naming the one
    # place this mutation cannot be caught. The expectation is what found that.
    "CV1 the coverage gate stops asking for the paths a run must produce":
        "test_the_coverage_gate_would_notice_a_policy_nothing_produces",
    "CV4 coverage stops looking for a declaration that is simply false":
        "test_the_coverage_gate_looks_in_both_directions",
    "TP12 the provenance pass stops rebuilding the line":
        "test_a_line_made_of_local_words_but_never_rendered_is_refused",
    "W4 a failed setup command stops being an error":
        "test_a_failed_seed_commit_is_reported_as_a_failed_setup",
    "RM1 an oversized request id is refused instead of projected":
        "test_the_probe_keeps_its_classification_and_projects_the_header",
    "RM2 a producer handing over the wrong type stops being refused":
        "test_a_producer_handing_over_the_wrong_type_is_still_refused",
    "UC1 the usage ceilings come from the response limit again":
        "test_no_counter_is_bounded_by_the_response_limit",
    "CK1 a plain string reaches the coverage queries again":
        "test_a_plain_string_is_refused_by_every_query",
    "LV1 a child inherits the terminal again":
        "test_a_child_reading_stdin_is_not_left_waiting",
    "VT1 zip truncates a lopsided multi-anchor spec in silence":
        "test_a_multi_anchor_spec_with_unequal_halves_is_refused",
    "VT3 an orphaned expectation stops being reported":
        "test_an_orphaned_expectation_is_refused",
    # The write boundary is an ownership claim — `guarded_receipt` says one
    # target's failure must not cost the others — so its kill is attributed.
    "EW1 a failed write leaves the boundary again":
        "test_a_write_failure_costs_one_target_and_not_the_run",
    "FN1 the escape set shrinks back to the characters somebody listed":
        "test_a_hostile_model_id_still_yields_a_usable_file_name",
    "TT1 a reset while the status line is read escapes as an internal error":
        "test_the_probe_classifies_a_reset_rather_than_blaming_itself",
    "TT2 the broad framing catch is hoisted above the narrow URLError one":
        "test_the_broad_catch_sits_below_the_narrow_one",
    "MI1 a non-string model is called missing again":
        "test_a_non_string_model_reaching_a_terminal_answer_is_a_substitution",
    # The accumulation site, not the three-readers test that shares its subject:
    # `model_evidence` and `model_status_of` are unchanged by this mutation, so
    # naming their test would have named a place it cannot be caught.
    "MI2 the terminal answer assumes every substitution carries a digest":
        "test_a_non_string_model_reaching_a_terminal_answer_is_a_substitution",
    "MI5 model_evidence stops agreeing with the identity it projects":
        "test_the_three_readers_of_identity_agree",
    "RK1 an unknown receipt kind is swallowed by the coverage proof":
        "test_a_receipt_kind_the_table_does_not_know_stops_the_gate",
    "FG1 a launcher may leave the grammar unremarked":
        "test_the_gate_would_notice_every_class_of_new_caller",
    "FG2 the alias rule widens to any assignment target":
        "test_the_gate_would_notice_every_class_of_new_caller",
    "U4 the lenient reader loses its depth pre-scan":
        "test_the_lenient_reader_stops_at_the_depth_the_module_declares",
}


def main() -> int:
    original = SRC.read_text(encoding="utf-8")
    problems = spec_problems(MUTATIONS, EXPECTED_KILL)
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
    unanchored = target_problems(MUTATION_TARGETS)
    if unanchored:
        for line in unanchored:
            print(f"FAIL {line}")
        return 2
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "provider-matrix"
        shutil.copytree(HERE, work, ignore=shutil.ignore_patterns("__pycache__"))

        first = run_suite(work)
        print(f"baseline: {'GREEN' if first.passed else 'RED'} ({last_line(first.output)})")
        if not first.passed:
            print("baseline is red; nothing below means anything")
            return 2
        baseline_tests = first.test_count
        if baseline_tests is None:
            print("baseline did not report how many tests it ran; "
                  "a mutant that breaks discovery could not be told from one that fails")
            return 2
        print(f"baseline: {baseline_tests} tests discovered")

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
            try:
                ast.parse(mutated)
            except SyntaxError:
                # Not a mutation of the contract, a mutation of the language.
                print(f"  INVALID  {name}: the mutant is not a valid program")
                failures.append(name)
                continue
            victim = work / filename
            victim.write_text(mutated, encoding="utf-8")
            results = run_gate(work, filename)
            victim.write_text(source, encoding="utf-8")
            state, why = verdict_for(name, results, baseline_tests)
            if state == "killed":
                print(f"  killed   {name}  ({why})")
            elif state == "SURVIVED":
                print(f"  SURVIVED {name}  <-- no oracle noticed ({why})")
                failures.append(name)
            else:
                print(f"  {state} {name}: {why}")
                failures.append(name)

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
