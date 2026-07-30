import argparse
import hashlib
import http.client
import io
import sys
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import mutations
import process_boundary
import provider_matrix as pm
import receipt_policy


def registry(providers=None) -> dict:
    """A stand-in trusted registry.

    Deliberately not the committed one for the discovery tests: those need
    several providers, and adding fictional entries to the real registry to keep
    a test happy is how a registry stops being a trust boundary.
    """
    return {
        "schema": pm.REGISTRY_SCHEMA,
        "providers": providers or {
            "groq": {"api_base": "https://example/v1", "api_style": "openai-chat", "key_env": "GROQ_API_KEY"},
            "openrouter": {"api_base": "https://example/v1", "api_style": "openai-chat", "key_env": "OPENROUTER_API_KEY"},
            "p": {"api_base": "https://x/v1", "api_style": "openai-chat", "key_env": "K"},
        },
    }


def probe_row(row: dict, model: str = "m") -> dict:
    return {
        "target_id": f"p--{model}", "provider": "p", "model": model,
        "api_style": "openai-chat", "api_base": "https://x/v1", "key_env": "K",
        **row,
    }


class ProviderMatrixTests(unittest.TestCase):
    def source(self, root: Path) -> Path:
        path = root / "source.json"
        path.write_text(json.dumps([
            {"provider": "Groq", "model": "m1", "api_base": "https://example/v1", "key_env": "GROQ_API_KEY", "free_tier": True, "card_required": False, "training_use": "unknown"},
            {"provider": "OpenRouter", "model": "m2", "api_base": "https://example/v1", "key_env": "OPENROUTER_API_KEY", "free_tier": "yes", "card_required": "no", "training_use": "no"},
        ]), encoding="utf-8")
        return path

    def test_import_is_deterministic_and_sorted(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            first = pm.import_catalog(self.source(root), "2026-07-28T00:00:00Z", registry())
            second = pm.import_catalog(self.source(root), "2026-07-28T00:00:00Z", registry())
            self.assertEqual(pm.canonical_bytes(first), pm.canonical_bytes(second))
            self.assertEqual([x["provider"] for x in first["targets"]], ["groq", "openrouter"])
            # The catalog records which registry its origins came from, so it
            # cannot be replayed later against a different one invisibly.
            self.assertEqual(first["registry_sha256"], pm.registry_digest(pm.normalize_registry(registry())))

    def test_unknown_policy_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            catalog = pm.import_catalog(self.source(Path(td)), "2026-07-28T00:00:00Z", registry())
            args = argparse.Namespace(free_only=True, no_card=True, no_training=True)
            plan = pm.build_plan(catalog, args)
            self.assertEqual([x["target_id"] for x in plan["selected"]], ["openrouter--m2"])
            self.assertEqual(plan["rejected"][0]["reasons"], ["training_use=unknown"])

    def test_duplicate_provider_model_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source.json"
            row = {"provider": "p", "model": "m", "api_base": "https://x/v1", "key_env": "K"}
            source.write_text(json.dumps([row, row]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                pm.import_catalog(source, "2026-07-28T00:00:00Z", registry())

    def test_missing_key_is_auth_failure(self):
        with patch.dict("os.environ", {}, clear=True):
            result = pm.probe_target(probe_row({"key_env": "K"}), 1, None, registry())
        self.assertEqual(result["classification"], "AUTH_FAILURE")

    def test_model_substitution_is_not_pass(self):
        body = json.dumps({"model": "other", "choices": [{"message": {"content": "QODEC_PROBE_OK"}}]}).encode()
        result = pm.probe_target(probe_row({}), 1, scripted([(200, body, "", "completed")]), registry())
        self.assertEqual(result["classification"], "PROVIDER_SUBSTITUTED")

    def test_a_probe_with_no_reported_model_does_not_pass(self):
        """The exact text plus no `model` field used to be a PASS.

        `if reported_model and reported_model != target["model"]` skipped its
        first branch when the field was absent, so a response whose origin was
        never established satisfied the gate that decides which targets the
        adapter is allowed to use.
        """
        body = json.dumps({"choices": [{"message": {"content": "QODEC_PROBE_OK"}}]}).encode()
        result = pm.probe_target(probe_row({}), 1, scripted([(200, body, "", "completed")]), registry())
        self.assertNotEqual(result["classification"], "PASS")
        self.assertEqual(result["classification"], "MODEL_IDENTITY_MISSING")
        self.assertEqual(result["model_status"], "missing")

    def test_exact_probe_passes(self):
        body = json.dumps({"model": "m", "choices": [{"message": {"content": "QODEC_PROBE_OK"}}], "usage": {"prompt_tokens": 9}}).encode()
        result = pm.probe_target(probe_row({}), 1, scripted([(200, body, "", "completed")]), registry())
        self.assertEqual(result["classification"], "PASS")
        self.assertEqual(result["model_status"], "verified")
        self.assertEqual(result["provider_usage"]["prompt_tokens"], 9)
        self.assertEqual(result["endpoint"], "https://x/v1/chat/completions")

    def test_the_probe_and_the_canary_share_one_transport(self):
        """Same endpoint rule, same body bound, same stage vocabulary.

        Two transports would mean two chances to send the credential somewhere
        the other one refuses to.
        """
        # A plan pointing somewhere the registry does not is refused per target.
        result = pm.probe_target(
            probe_row({"api_base": "https://elsewhere/v1"}), 1,
            scripted([(200, b"{}", "", "completed")]), registry(),
        )
        self.assertEqual(result["classification"], "ENDPOINT_REJECTED")
        # And a body that never finished arriving is not "the provider was down".
        result = pm.probe_target(
            probe_row({}), 1, scripted([(429, None, "body too large", "after-headers", 4096, "req-9")]), registry(),
        )
        self.assertEqual(result["classification"], "RESPONSE_CAPTURE_FAILED")
        # The status the provider already sent is not thrown away with the body.
        self.assertEqual(result["http_status"], 429)
        self.assertEqual(result["body_bytes_observed"], 4096)
        # The raw header never crosses; evidence about it does.
        self.assertTrue(result["request_id_present"])
        self.assertNotIn("req-9", json.dumps(result))
        self.assertEqual(result["request_id_sha256"],
                         pm.evidence_digest("request-id", "req-9"))


# ---------------------------------------------------------------------------
# Tool-calling qualification
# ---------------------------------------------------------------------------


def surface() -> dict:
    """The frozen C1 surface, read from the committed artifact.

    Not a hand-written stand-in: the point of the canary is that it sends the
    real schemas, so a test built on invented ones would qualify a request that
    is never sent.
    """
    return pm.load_surface(Path(__file__).resolve().parent / "c1-panel-surface.json")


def target(model: str = "openai/gpt-oss-120b") -> dict:
    return {
        "target_id": f"groq--{model}",
        "provider": "groq",
        "model": model,
        "api_style": "openai-chat",
        "api_base": "https://api.groq.com/openai/v1",
        "key_env": "GROQ_API_KEY",
    }


def completion(calls, model="openai/gpt-oss-120b", usage=None):
    """An OpenAI-chat completion carrying the given tool calls."""
    body = {
        "id": "chatcmpl-test",
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": None, "tool_calls": calls}}],
    }
    if usage is not None:
        body["usage"] = usage
    return json.dumps(body).encode()


def call(name, arguments, call_id="call_0"):
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments}}


INTERSECT_ARGS = json.dumps({"index": "line", "sections": ["attempt_1", "attempt_2", "attempt_3"]})
MATERIALIZE_ARGS = json.dumps({
    "handle": pm.CANNED_HANDLE,
    "record_ids": [{"store": pm.CANNED_HANDLE, "section": "attempt_1", "ordinal": 0}],
})
ANSWER_ARGS = json.dumps({
    "handle": pm.CANNED_HANDLE,
    "answer": {"encoding": "base64url-nopad", "data": "YWxwaGE"},
    "cited": [{"store": pm.CANNED_HANDLE, "section": "attempt_1", "ordinal": 0}],
})
# Schema-perfect and wrong: "beta" is not the line in every section.
WRONG_ANSWER_ARGS = json.dumps({
    "handle": pm.CANNED_HANDLE,
    "answer": {"encoding": "base64url-nopad", "data": "YmV0YQ"},
    "cited": [{"store": pm.CANNED_HANDLE, "section": "attempt_1", "ordinal": 0}],
})

# The shortest script that is actually a qualification: one operation, the
# results handed back, then the terminal answer. Every case that only needs a
# terminal answer to be *reached* is written on top of this rather than on a
# single-turn shortcut, because a single-turn shortcut is not the arm.
def OPERATION_THEN(reply):
    return [(200, completion([call("qodec_intersect", INTERSECT_ARGS, "call_op")]), ""), reply]


ANSWER_REPLY = (200, completion([call("qodec_answer", ANSWER_ARGS, "call_ans")]), "")


def call_with_object_arguments(name, call_id="call_obj"):
    """Arguments as a JSON object — a coherent other dialect, not a malformed one."""
    return {"id": call_id, "type": "function",
            "function": {"name": name, "arguments": {"index": "line"}}}


def scripted(replies):
    """A stand-in `send`: one scripted reply per turn, and it records requests."""
    seen = []

    def send(url, body, timeout):
        seen.append((url, body))
        if len(seen) > len(replies):
            return None, None, "stand-in ran out of replies"
        return replies[len(seen) - 1]

    send.seen = seen  # type: ignore[attr-defined]
    return send


class QualificationTests(unittest.TestCase):
    def run_qualify(self, replies, model="openai/gpt-oss-120b", max_turns=6):
        send = scripted(replies)
        receipt = pm.qualify_target(target(model), surface(), 30.0, max_turns, send)
        return receipt, send

    # -- the happy path, which every negative case below is measured against --

    def test_operation_then_answer_passes(self):
        receipt, send = self.run_qualify([
            (200, completion([call("qodec_intersect", INTERSECT_ARGS)]), ""),
            (200, completion([call("qodec_answer", ANSWER_ARGS, "call_1")], usage={"prompt_tokens": 11, "completion_tokens": 4}), ""),
        ])
        self.assertEqual(receipt["classification"], "PASS")
        self.assertEqual(receipt["model_status"], "verified")
        self.assertEqual(receipt["turn_count"], 2)
        self.assertTrue(receipt["tool_result_roundtrip"])
        self.assertEqual(receipt["turns"][0]["tool_names"], ["qodec_intersect"])
        self.assertEqual(receipt["turns"][1]["outcome"], "terminal-answer")
        self.assertTrue(receipt["turns"][1]["canary_answer_matches"])
        self.assertEqual(receipt["turns"][1]["reported_usage"]["prompt_tokens"], 11)

    def test_the_request_carries_the_exact_c1_surface(self):
        """Four tools, the real schemas, and forcing — or it qualifies nothing."""
        receipt, send = self.run_qualify(OPERATION_THEN(ANSWER_REPLY))
        self.assertEqual(receipt["classification"], "PASS")
        _url, body = send.seen[0]
        sent = json.loads(body)
        self.assertEqual(sent["tool_choice"], "required")
        names = [t["function"]["name"] for t in sent["tools"]]
        self.assertEqual(names, ["qodec_lookup", "qodec_intersect", "qodec_materialize", "qodec_answer"])
        # The schemas are the frozen ones, not a paraphrase.
        frozen = surface()
        self.assertEqual(sent["tools"][0]["function"]["parameters"], frozen["operations"][0]["input_schema"])
        self.assertEqual(sent["tools"][3]["function"]["parameters"], frozen["terminal_answer"]["schema"])

    def test_tool_results_are_keyed_to_the_calls_that_asked_for_them(self):
        receipt, send = self.run_qualify([
            (200, completion([call("qodec_intersect", INTERSECT_ARGS, "call_abc")]), ""),
            (200, completion([call("qodec_answer", ANSWER_ARGS, "call_xyz")]), ""),
        ])
        self.assertEqual(receipt["classification"], "PASS")
        second = json.loads(send.seen[1][1])
        roles = [m["role"] for m in second["messages"]]
        self.assertEqual(roles, ["system", "user", "assistant", "tool"])
        self.assertEqual(second["messages"][2]["tool_calls"][0]["id"], "call_abc")
        self.assertEqual(second["messages"][3]["tool_call_id"], "call_abc")
        # And the tools and forcing are re-sent unchanged.
        self.assertEqual(second["tool_choice"], "required")
        self.assertEqual(len(second["tools"]), 4)

    # -- every classification, reachable without a network --

    def test_a_rejected_tool_choice_is_not_reported_as_unavailability(self):
        body = json.dumps({"error": {"message": "tool_choice is not supported", "param": "tool_choice"}}).encode()
        receipt, _ = self.run_qualify([(400, body, "")])
        self.assertEqual(receipt["classification"], "TOOL_CHOICE_UNSUPPORTED")
        self.assertEqual(receipt["detail"], "HTTP 400: tools-or-tool-choice-named-in-a-400")

    def test_a_later_rejection_is_about_the_tool_results(self):
        """Same status, different turn, different thing to fix."""
        body = json.dumps({"error": {"message": "invalid message at index 3"}}).encode()
        receipt, _ = self.run_qualify([
            (200, completion([call("qodec_intersect", INTERSECT_ARGS)]), ""),
            (400, body, ""),
        ])
        self.assertEqual(receipt["classification"], "TOOL_RESULT_REJECTED")

    def test_a_first_turn_rejection_is_not_about_tool_results(self):
        body = json.dumps({"error": {"message": "invalid request"}}).encode()
        receipt, _ = self.run_qualify([(400, body, "")])
        self.assertEqual(receipt["classification"], "PROVIDER_REJECTED")

    def test_status_codes_map_to_distinct_causes(self):
        for status, expected in ((401, "AUTH_FAILED"), (404, "MODEL_MISSING"), (429, "RATE_LIMITED"), (503, "UNAVAILABLE")):
            receipt, _ = self.run_qualify([(status, b"{}", "")])
            self.assertEqual(receipt["classification"], expected, f"status {status}")

    def test_a_transport_failure_is_unavailable(self):
        receipt, _ = self.run_qualify([(None, None, "connection refused")])
        self.assertEqual(receipt["classification"], "UNAVAILABLE")
        # A local reason code, not the transport's prose: an SSL failure's
        # message carries fields the peer chose, and this string is committed.
        # From `TRANSPORT_REASONS`, which is the vocabulary the field is
        # declared over — the old fallback answered in the turn-outcome
        # vocabulary instead, so one field held members of either enum.
        self.assertEqual(receipt["detail"], "connection-failed")
        self.assertIn(receipt["turns"][0]["transport_reason"], pm.TRANSPORT_REASONS)
        self.assertNotIn("connection refused", json.dumps(receipt))

    def test_a_substituted_model_does_not_pass(self):
        receipt, _ = self.run_qualify(OPERATION_THEN(
            (200, completion([call("qodec_answer", ANSWER_ARGS, "call_ans")], model="some-other-model"), ""),
        ))
        self.assertEqual(receipt["classification"], "PROVIDER_SUBSTITUTED")
        self.assertEqual(receipt["model_status"], "drifted")
        self.assertNotIn("some-other-model", receipt["detail"])
        self.assertIn(pm.evidence_digest("model-name", "some-other-model")[:16], receipt["detail"])

    def test_the_drifting_model_survives_a_later_correct_turn(self):
        """`drifted → verified` must not fold into "reported the model we asked for".

        The status folds to the worst turn, so the run is `drifted` either way.
        What a single overwritten `reported_model` loses is *which* model served
        the first turn — the only thing that makes the drift actionable, and the
        exact case where the last write is the innocent one.
        """
        receipt, _ = self.run_qualify([
            (200, completion([call("qodec_intersect", INTERSECT_ARGS, "call_op")], model="sneaky-substitute"), ""),
            (200, completion([call("qodec_answer", ANSWER_ARGS, "call_ans")]), ""),
        ])
        self.assertEqual(receipt["model_status"], "drifted")
        self.assertEqual(receipt["classification"], "PROVIDER_SUBSTITUTED")
        # Two distinct entries survive the fold — the substituted one as a
        # digest, since the provider chose that string and could have chosen
        # the credential.
        self.assertEqual(len(receipt["reported_models"]), 2)
        self.assertIsNone(receipt["turns"][0]["reported_model"])
        self.assertEqual(receipt["turns"][0]["reported_model_sha256"],
                         pm.evidence_digest("model-name", "sneaky-substitute"))
        self.assertEqual(receipt["turns"][1]["reported_model"], "openai/gpt-oss-120b")
        # No single consistent value exists, so none is claimed.
        self.assertIsNone(receipt["reported_model"])
        # And the detail identifies the model that actually drifted, without
        # repeating what the provider sent.
        self.assertNotIn("sneaky-substitute", receipt["detail"])
        self.assertIn(pm.evidence_digest("model-name", "sneaky-substitute")[:16], receipt["detail"])
        self.assertNotIn("provider reported openai/gpt-oss-120b", receipt["detail"])

    def test_a_consistent_reported_model_is_still_offered_once(self):
        receipt, _ = self.run_qualify(OPERATION_THEN(ANSWER_REPLY))
        self.assertEqual(receipt["reported_models"],
                         [{"reported_model": "openai/gpt-oss-120b", "reported_model_present": True}])
        self.assertEqual(receipt["reported_model"], "openai/gpt-oss-120b")

    def test_an_unnamed_model_is_missing_and_does_not_pass(self):
        """`missing` is not a milder `drifted`; both fail, only `verified` passes.

        The receipt used to record `model_status: missing` and classify the run
        `PASS` anyway, because only `drifted` overrode the verdict. A target
        whose identity was never established could then satisfy the "PASS on
        both probes" gate that decides what the adapter may be pointed at.
        """
        answer = json.dumps({"id": "x", "choices": [{"message": {
            "role": "assistant", "tool_calls": [call("qodec_answer", ANSWER_ARGS, "call_ans")],
        }}]}).encode()
        receipt, _ = self.run_qualify([
            (200, json.dumps({"id": "x", "choices": [{"message": {
                "role": "assistant", "tool_calls": [call("qodec_intersect", INTERSECT_ARGS, "call_op")],
            }}]}).encode(), ""),
            (200, answer, ""),
        ])
        self.assertEqual(receipt["model_status"], "missing")
        self.assertNotEqual(receipt["classification"], "PASS")
        self.assertEqual(receipt["classification"], "MODEL_IDENTITY_MISSING")
        self.assertIn("unestablished", receipt["detail"])
        self.assertIsNone(receipt["turns"][1]["reported_model"])
        # The protocol itself held — that is why the cause is about identity.
        self.assertEqual(receipt["turns"][1]["outcome"], "terminal-answer")
        self.assertTrue(receipt["tool_result_roundtrip"])

    def test_one_named_turn_is_enough_to_establish_identity(self):
        """`missing` folds worst-turn, so a single unnamed turn still fails."""
        unnamed = json.dumps({"id": "x", "choices": [{"message": {
            "role": "assistant", "tool_calls": [call("qodec_intersect", INTERSECT_ARGS, "call_op")],
        }}]}).encode()
        receipt, _ = self.run_qualify([(200, unnamed, ""), ANSWER_REPLY])
        self.assertEqual(receipt["model_status"], "missing")
        self.assertEqual(receipt["classification"], "MODEL_IDENTITY_MISSING")
        self.assertEqual(receipt["reported_models"], [
            {"reported_model": None, "reported_model_present": False},
            {"reported_model": "openai/gpt-oss-120b", "reported_model_present": True},
        ])

    def test_unparseable_arguments_are_malformed_not_a_protocol_violation(self):
        receipt, _ = self.run_qualify([(200, completion([call("qodec_answer", "{not json")]), "")])
        self.assertEqual(receipt["classification"], "MALFORMED_TOOL_ARGUMENTS")

    def test_missing_required_arguments_are_malformed(self):
        receipt, _ = self.run_qualify([(200, completion([call("qodec_answer", json.dumps({"answer": {}}))]), "")])
        self.assertEqual(receipt["classification"], "MALFORMED_TOOL_ARGUMENTS")
        # Which rule failed, not which field: `jsonschema_mini` interpolates
        # the instance, so its text cannot reach a committed receipt.
        self.assertIn("required", receipt["turns"][0]["argument_errors_kinds"])

    def test_two_answers_are_a_protocol_violation(self):
        receipt, _ = self.run_qualify([(200, completion([
            call("qodec_answer", ANSWER_ARGS, "a1"),
            call("qodec_answer", ANSWER_ARGS, "a2"),
        ]), "")])
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")

    def test_an_answer_beside_an_operation_is_a_protocol_violation(self):
        receipt, _ = self.run_qualify([(200, completion([
            call("qodec_intersect", INTERSECT_ARGS, "o1"),
            call("qodec_answer", ANSWER_ARGS, "a1"),
        ]), "")])
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")

    def test_an_undeclared_tool_is_a_protocol_violation(self):
        receipt, _ = self.run_qualify([(200, completion([call("get_weather", "{}")]), "")])
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")

    def test_prose_instead_of_a_tool_call_is_no_terminal_answer(self):
        body = json.dumps({"id": "x", "model": "openai/gpt-oss-120b",
                           "choices": [{"message": {"role": "assistant", "content": "The answer is alpha."}}]}).encode()
        receipt, _ = self.run_qualify([(200, body, "")])
        self.assertEqual(receipt["classification"], "NO_TERMINAL_ANSWER")

    def test_an_endless_operation_loop_exhausts_the_budget(self):
        replies = [(200, completion([call("qodec_intersect", INTERSECT_ARGS, f"c{n}")]), "") for n in range(3)]
        receipt, _ = self.run_qualify(replies, max_turns=3)
        self.assertEqual(receipt["classification"], "NO_TERMINAL_ANSWER")
        self.assertEqual(receipt["turn_count"], 3)

    def test_every_classification_is_declared(self):
        """The receipt may only carry a cause the schema knows about."""
        self.assertIn("PASS", pm.CLASSIFICATIONS)
        reached = set()
        for replies, expected in (
            (OPERATION_THEN(ANSWER_REPLY), "PASS"),
            ([(401, b"{}", "")], "AUTH_FAILED"),
            ([(404, b"{}", "")], "MODEL_MISSING"),
            ([(429, b"{}", "")], "RATE_LIMITED"),
            ([(503, b"{}", "")], "UNAVAILABLE"),
            ([(302, b"", "")], "REDIRECT_NOT_FOLLOWED"),
            ([(502, None, "body too large", "after-headers")], "RESPONSE_CAPTURE_FAILED"),
            ([(None, None, "missing env GROQ_API_KEY", "no-credential")], "AUTH_FAILED"),
            ([(400, b'{"error":{"message":"nope"}}', "")], "PROVIDER_REJECTED"),
            ([(400, b'{"error":{"param":"tools","message":"x"}}', "")], "TOOL_CHOICE_UNSUPPORTED"),
            (OPERATION_THEN((400, b'{"error":{"message":"invalid message at index 3"}}', "")),
             "TOOL_RESULT_REJECTED"),
            ([(200, completion([call("qodec_answer", "{bad")]), "")], "MALFORMED_TOOL_ARGUMENTS"),
            ([(200, completion([call("get_weather", "{}")]), "")], "PROTOCOL_VIOLATION"),
            (OPERATION_THEN((200, completion([call("qodec_answer", ANSWER_ARGS, "call_ans")], model="other"), "")),
             "PROVIDER_SUBSTITUTED"),
            (OPERATION_THEN((200, completion([call("qodec_answer", WRONG_ANSWER_ARGS, "call_ans")]), "")),
             "CANARY_ANSWER_MISMATCH"),
            ([(200, completion([call("qodec_answer", json.loads(ANSWER_ARGS))]), "")], "DIALECT_MISMATCH"),
            (OPERATION_THEN((200, json.dumps({"id": "x", "choices": [{"message": {
                "role": "assistant", "tool_calls": [call("qodec_answer", ANSWER_ARGS, "call_ans")],
            }}]}).encode(), "")), "MODEL_IDENTITY_MISSING"),
            ([(200, b"[]", "")], "INVALID_OUTPUT"),
        ):
            receipt, _ = self.run_qualify(replies)
            self.assertEqual(receipt["classification"], expected)
            reached.add(expected)
        reached.add(pm.qualify_target(
            dict(target(), api_base="http://plaintext/v1"), surface(), 30.0, 6, scripted([]),
        )["classification"])
        self.assertIn("ENDPOINT_REJECTED", reached)
        self.assertTrue(reached.issubset(set(pm.CLASSIFICATIONS)))
        # The two left out have their own tests: NO_TERMINAL_ANSWER in the
        # budget-exhaustion case above, INTERNAL_ERROR in MatrixIsolationTests.
        self.assertEqual(
            set(pm.CLASSIFICATIONS) - reached,
            {"NO_TERMINAL_ANSWER", "INTERNAL_ERROR"},
        )

    def test_a_model_id_with_a_slash_stays_one_receipt_file(self):
        """`openai/gpt-oss-120b` must not become a directory."""
        name = pm.receipt_filename("groq--openai/gpt-oss-120b")
        self.assertEqual(name, "groq--openai%2Fgpt-oss-120b.json")
        self.assertNotIn("/", name)
        # And two targets differing only in slash placement stay distinct.
        self.assertNotEqual(
            pm.receipt_filename("a--b/c"),
            pm.receipt_filename("a--b%2Fc"),
        )

    def test_the_receipt_never_carries_the_credential(self):
        receipt, _ = self.run_qualify(OPERATION_THEN(ANSWER_REPLY))
        blob = json.dumps(receipt)
        self.assertNotIn("Authorization", blob)
        self.assertNotIn("GROQ_API_KEY", json.dumps(receipt["transport_target"]))
        self.assertNotIn("api_key", blob)


class RoundtripTests(unittest.TestCase):
    """Qualification is the loop, not one forced tool call."""

    def run_qualify(self, replies, max_turns=6):
        send = scripted(replies)
        return pm.qualify_target(target(), surface(), 30.0, max_turns, send), send

    def test_an_immediate_terminal_answer_does_not_qualify(self):
        """The defect this guard exists for.

        A target that answers on the first response has run no operation and has
        never been shown a `role: tool` message. Calling that PASS would qualify
        every target that can emit one forced call — which is the RAW arm, not
        the forced-query arm.
        """
        receipt, send = self.run_qualify([ANSWER_REPLY])
        self.assertNotEqual(receipt["classification"], "PASS")
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")
        self.assertIn("roundtrip", receipt["detail"])
        self.assertFalse(receipt["tool_result_roundtrip"])
        self.assertEqual(len(send.seen), 1)

    def test_the_roundtrip_is_the_providers_acceptance_not_our_send(self):
        """Handing results back is not the roundtrip; the next 200 is.

        A provider that rejects the request carrying `role: tool` messages has
        answered the question the roundtrip asks, and the answer is no.
        """
        receipt, _ = self.run_qualify(OPERATION_THEN((400, b'{"error":{"message":"bad tool message"}}', "")))
        self.assertEqual(receipt["classification"], "TOOL_RESULT_REJECTED")
        self.assertFalse(receipt["tool_result_roundtrip"])
        self.assertTrue(receipt["turns"][1]["carried_tool_results"])

    def test_a_completed_roundtrip_admits_the_terminal_answer(self):
        receipt, _ = self.run_qualify(OPERATION_THEN(ANSWER_REPLY))
        self.assertEqual(receipt["classification"], "PASS")
        self.assertTrue(receipt["tool_result_roundtrip"])
        self.assertFalse(receipt["turns"][0]["tool_result_roundtrip"])
        self.assertTrue(receipt["turns"][1]["tool_result_roundtrip"])

    def test_the_roundtrip_survives_more_than_one_operation_turn(self):
        receipt, _ = self.run_qualify([
            (200, completion([call("qodec_intersect", INTERSECT_ARGS, "c0")]), ""),
            (200, completion([call("qodec_materialize", MATERIALIZE_ARGS, "c1")]), ""),
            ANSWER_REPLY,
        ])
        self.assertEqual(receipt["classification"], "PASS")
        self.assertEqual(receipt["turn_count"], 3)


class ArgumentSchemaTests(unittest.TestCase):
    """Required-key presence is not validation."""

    def run_qualify(self, replies, max_turns=6):
        return pm.qualify_target(target(), surface(), 30.0, max_turns, scripted(replies))

    def malformed(self, name, arguments):
        receipt = self.run_qualify([(200, completion([call(name, json.dumps(arguments))]), "")])
        self.assertEqual(receipt["classification"], "MALFORMED_TOOL_ARGUMENTS")
        return receipt

    def test_a_wrong_type_is_not_valid_merely_because_the_key_is_present(self):
        receipt = self.malformed("qodec_intersect", {"index": 123, "sections": ["attempt_1"]})
        self.assertIn("type", receipt["turns"][0]["argument_errors_kinds"])

    def test_a_forbidden_extra_field_is_rejected(self):
        receipt = self.malformed("qodec_intersect", {
            "index": "line", "sections": ["attempt_1"], "unexpected_field": True,
        })
        self.assertIn("additional-property", receipt["turns"][0]["argument_errors_kinds"])

    def test_an_array_field_given_a_string_is_rejected(self):
        self.malformed("qodec_intersect", {"index": "line", "sections": "not-an-array"})

    def test_an_empty_array_below_min_items_is_rejected(self):
        self.malformed("qodec_intersect", {"index": "line", "sections": []})

    def test_a_wrong_encoding_enum_is_rejected(self):
        """The byte envelope reached through a local `$ref`."""
        receipt = self.malformed("qodec_lookup", {
            "index": "line", "key": {"encoding": "hex", "data": "61"},
        })
        self.assertIn("enum", receipt["turns"][0]["argument_errors_kinds"])

    def test_a_handle_that_is_not_a_sha256_is_rejected(self):
        receipt = self.malformed("qodec_materialize", {
            "handle": "sha256:not-a-digest",
            "record_ids": [{"store": pm.CANNED_HANDLE, "section": "attempt_1", "ordinal": 0}],
        })
        self.assertIn("pattern", receipt["turns"][0]["argument_errors_kinds"])

    def test_a_nested_citation_error_is_rejected(self):
        self.malformed("qodec_answer", {
            "handle": pm.CANNED_HANDLE,
            "answer": {"encoding": "base64url-nopad", "data": "YWxwaGE"},
            "cited": [{"store": pm.CANNED_HANDLE, "section": "attempt_1", "ordinal": -1}],
        })

    def test_the_valid_arguments_really_are_valid(self):
        """A negative suite that also rejects the happy path proves nothing."""
        self.assertEqual(pm.validate_arguments(surface(), "qodec_answer", json.loads(ANSWER_ARGS)), [])
        self.assertEqual(pm.validate_arguments(surface(), "qodec_intersect", json.loads(INTERSECT_ARGS)), [])


class CanaryAnswerTests(unittest.TestCase):
    """A schema-valid answer to the wrong question is its own outcome."""

    def run_qualify(self, answer_args):
        replies = OPERATION_THEN((200, completion([call("qodec_answer", json.dumps(answer_args), "call_ans")]), ""))
        return pm.qualify_target(target(), surface(), 30.0, 6, scripted(replies))

    def test_wrong_answer_bytes_are_a_mismatch_not_a_protocol_violation(self):
        receipt = self.run_qualify({
            "handle": pm.CANNED_HANDLE,
            "answer": {"encoding": "base64url-nopad", "data": "YmV0YQ"},  # "beta"
            "cited": [{"store": pm.CANNED_HANDLE, "section": "attempt_1", "ordinal": 0}],
        })
        self.assertEqual(receipt["classification"], "CANARY_ANSWER_MISMATCH")
        # The wrong answer is named by digest: those bytes are the provider's.
        self.assertNotIn("beta", receipt["detail"])
        self.assertIn(pm.evidence_digest("answer-bytes", b"beta")[:16], receipt["detail"])
        self.assertIn("not in any result this run returned", receipt["detail"])
        self.assertFalse(receipt["turns"][1]["canary_answer_matches"])
        # The protocol still held, and the receipt says so.
        self.assertEqual(receipt["turns"][1]["outcome"], "terminal-answer")
        self.assertTrue(receipt["turns"][1]["arguments_valid"])

    def test_an_invented_handle_is_a_mismatch(self):
        receipt = self.run_qualify({
            "handle": "sha256:" + "1" * 64,
            "answer": {"encoding": "base64url-nopad", "data": "YWxwaGE"},
            "cited": [{"store": pm.CANNED_HANDLE, "section": "attempt_1", "ordinal": 0}],
        })
        self.assertEqual(receipt["classification"], "CANARY_ANSWER_MISMATCH")
        self.assertIn("never returned", receipt["detail"])

    def test_a_citation_outside_the_support_is_a_mismatch(self):
        receipt = self.run_qualify({
            "handle": pm.CANNED_HANDLE,
            "answer": {"encoding": "base64url-nopad", "data": "YWxwaGE"},
            "cited": [{"store": pm.CANNED_HANDLE, "section": "attempt_9", "ordinal": 0}],
        })
        self.assertEqual(receipt["classification"], "CANARY_ANSWER_MISMATCH")
        self.assertIn("support", receipt["detail"])

    def test_the_expected_answer_matches(self):
        observed = pm.Observed()
        observed.record(pm.CANNED_RESULT)
        self.assertEqual(pm.canary_answer_errors(json.loads(ANSWER_ARGS), observed), [])


class TransportHardeningTests(unittest.TestCase):
    """The catalog is untrusted, and it names the URL the key is sent to."""

    def test_only_https_is_accepted(self):
        for base in ("http://api.example/v1", "ftp://api.example/v1", "//api.example/v1", "/v1"):
            with self.assertRaises(pm.EndpointRejected, msg=base):
                pm.completions_url(base)

    def test_userinfo_is_refused(self):
        with self.assertRaisesRegex(pm.EndpointRejected, "userinfo"):
            pm.completions_url("https://stealer:pw@api.example/v1")

    def test_a_query_or_fragment_is_refused(self):
        with self.assertRaisesRegex(pm.EndpointRejected, "query"):
            pm.completions_url("https://api.example/v1?callback=https://elsewhere")
        with self.assertRaisesRegex(pm.EndpointRejected, "fragment"):
            pm.completions_url("https://api.example/v1#x")

    def test_a_host_is_required(self):
        with self.assertRaisesRegex(pm.EndpointRejected, "host"):
            pm.completions_url("https:///v1")

    def test_the_path_is_appended_exactly_once(self):
        self.assertEqual(
            pm.completions_url("https://api.groq.com/openai/v1"),
            "https://api.groq.com/openai/v1/chat/completions",
        )
        self.assertEqual(
            pm.completions_url("https://api.groq.com/openai/v1/chat/completions"),
            "https://api.groq.com/openai/v1/chat/completions",
        )

    def test_a_hand_edited_plan_is_still_refused_at_send_time(self):
        """Intake is the first gate, not the only one."""
        receipt = pm.qualify_target(
            dict(target(), api_base="https://user:pw@api.example/v1"),
            surface(), 30.0, 6, scripted([]),
        )
        self.assertEqual(receipt["classification"], "ENDPOINT_REJECTED")
        self.assertEqual(receipt["turns"], [])


class TrustedRegistryTests(unittest.TestCase):
    """https and a valid certificate do not make a stranger into Groq."""

    def import_row(self, row, reg=None):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source.json"
            source.write_text(json.dumps([row]), encoding="utf-8")
            return pm.import_catalog(source, "2026-07-28T00:00:00Z", reg or registry())

    def test_a_valid_https_exfiltration_host_is_refused(self):
        """The defect this registry exists for.

        Every URL rule passes this row: it is https, it names a host, it carries
        no userinfo, no query, no fragment, and it will not be redirected
        anywhere. TLS then guarantees the credential arrives at `steal.example`
        confidentially and intact. A certificate proves who answered, never that
        they are the provider the row claims.
        """
        with self.assertRaisesRegex(pm.EndpointRejected, "trusted registry"):
            self.import_row({
                "provider": "groq", "model": "openai/gpt-oss-120b",
                "api_base": "https://steal.example/v1", "key_env": "GROQ_API_KEY",
            })

    def test_an_arbitrary_key_env_is_refused(self):
        """A row does not get to choose which secret is read out of the process."""
        with self.assertRaisesRegex(pm.EndpointRejected, "key_env"):
            self.import_row({
                "provider": "groq", "model": "m",
                "api_base": "https://example/v1", "key_env": "ANTHROPIC_API_KEY",
            })

    def test_a_provider_outside_the_registry_never_reaches_a_plan(self):
        with self.assertRaisesRegex(pm.EndpointRejected, "not in the trusted registry"):
            self.import_row({"provider": "unheard-of", "model": "m"})

    def test_a_row_that_omits_origin_and_key_is_fine(self):
        """Discovery supplies provider, model and metadata. Nothing more."""
        catalog = self.import_row({
            "provider": "groq", "model": "m", "free_tier": "yes",
            "source_url": "https://www.modelhubby.com/providers/",
        })
        target_row = catalog["targets"][0]
        self.assertEqual(target_row["api_base"], "https://example/v1")
        self.assertEqual(target_row["key_env"], "GROQ_API_KEY")
        self.assertEqual(target_row["api_style"], "openai-chat")

    def test_a_hand_edited_plan_cannot_repoint_a_provider(self):
        """The catalog is not the only file that exists after review."""
        edited = dict(target(), api_base="https://steal.example/v1")
        receipt = pm.qualify_target(edited, surface(), 30.0, 6, scripted([]))
        self.assertEqual(receipt["classification"], "ENDPOINT_REJECTED")
        # The reason, not the rejected text. `str(exc)` used to be copied into
        # `detail`, so the receipt's content was whatever the plan happened to
        # say — an open vocabulary in a durable field, which is the same defect
        # as a copied provider string with a friendlier provenance story.
        self.assertEqual(receipt["decision_reason"], "endpoint-rejected")
        self.assertEqual(receipt["detail"], "endpoint rejected: authority-mismatch")
        self.assertNotIn("steal.example", json.dumps(receipt))
        self.assertEqual(receipt["turns"], [])

    def test_a_hand_edited_plan_cannot_repoint_the_key(self):
        edited = dict(target(), key_env="ANTHROPIC_API_KEY")
        receipt = pm.qualify_target(edited, surface(), 30.0, 6, scripted([]))
        self.assertEqual(receipt["classification"], "ENDPOINT_REJECTED")
        self.assertEqual(receipt["detail"], "endpoint rejected: authority-mismatch")
        self.assertNotIn("ANTHROPIC_API_KEY", json.dumps(receipt))

    def test_the_committed_registry_is_loadable_and_bound_to_this_target(self):
        """The tests above use a stand-in; this one pins the real file."""
        real = pm.load_registry()
        self.assertEqual(real["schema"], pm.REGISTRY_SCHEMA)
        groq = real["providers"]["groq"]
        self.assertEqual(groq["api_base"], "https://api.groq.com/openai/v1")
        self.assertEqual(groq["key_env"], "GROQ_API_KEY")
        self.assertEqual(groq["api_style"], "openai-chat")

    def test_a_registry_entry_must_itself_survive_the_url_rules(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "registry.json"
            path.write_text(json.dumps({
                "schema": pm.REGISTRY_SCHEMA,
                "providers": {"p": {"api_base": "http://x/v1", "api_style": "openai-chat", "key_env": "K"}},
            }), encoding="utf-8")
            with self.assertRaisesRegex(pm.EndpointRejected, "https"):
                pm.load_registry(path)

    def test_the_url_rules_still_apply_to_a_registry_built_in_memory(self):
        """`load_registry` is the usual door, not the only one.

        Callers may pass a registry dict directly — the tests here do — so the
        URL rules stay on the path that builds the request as well as on the one
        that loads the file. Otherwise a registry that never went through
        `load_registry` would hand the transport an origin nobody vetted.
        """
        plain = registry({"p": {"api_base": "http://x/v1", "api_style": "openai-chat", "key_env": "K"}})
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source.json"
            source.write_text(json.dumps([{"provider": "p", "model": "m"}]), encoding="utf-8")
            with self.assertRaisesRegex(pm.EndpointRejected, "https"):
                pm.import_catalog(source, "2026-07-28T00:00:00Z", plain)

        planned = {
            "target_id": "p--m", "provider": "p", "model": "m",
            "api_style": "openai-chat", "api_base": "http://x/v1", "key_env": "K",
        }
        with self.assertRaisesRegex(pm.EndpointRejected, "https"):
            pm.qualify_target(planned, surface(), 30.0, 6, scripted([]), plain)


class StrictOpenAiDialectTests(unittest.TestCase):
    """The canary must not accept a response the adapter will reject.

    `api_style: openai-chat` is what is being qualified, and `OpenAiChatCompletions`
    is what will consume the PASS. Accepting a looser shape here is the same
    defect as paraphrasing the schemas, moved to the response side.
    """

    def run_qualify(self, message_body):
        body = json.dumps({"id": "x", "model": "openai/gpt-oss-120b",
                           "choices": [{"message": message_body}]}).encode()
        return pm.qualify_target(target(), surface(), 30.0, 6, scripted([(200, body, "")]))

    def test_object_arguments_are_a_dialect_mismatch_not_a_courtesy(self):
        """Anthropic sends an object. That is a different adapter, not a nicety.

        The canary used to accept both and call it politeness toward dialects.
        It qualified a response `OpenAiChatCompletions` would refuse to
        deserialize.
        """
        receipt = self.run_qualify({
            "role": "assistant",
            "tool_calls": [call("qodec_answer", json.loads(ANSWER_ARGS))],
        })
        self.assertEqual(receipt["classification"], "DIALECT_MISMATCH")
        self.assertIn("JSON string", receipt["detail"])
        self.assertNotEqual(receipt["classification"], "PASS")

    def test_a_non_function_tool_call_type_is_rejected(self):
        entry = call("qodec_answer", ANSWER_ARGS)
        entry["type"] = "custom"
        receipt = self.run_qualify({"role": "assistant", "tool_calls": [entry]})
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")
        self.assertIn("'function'", receipt["detail"])

    def test_a_missing_tool_call_type_is_rejected(self):
        entry = call("qodec_answer", ANSWER_ARGS)
        del entry["type"]
        receipt = self.run_qualify({"role": "assistant", "tool_calls": [entry]})
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")

    def test_duplicate_tool_call_ids_are_rejected(self):
        """Results are returned keyed by id; two calls sharing one make it a guess."""
        receipt = self.run_qualify({"role": "assistant", "tool_calls": [
            call("qodec_lookup", json.dumps({"index": "line", "key": {"encoding": "base64url-nopad", "data": "YQ"}}), "same"),
            call("qodec_intersect", INTERSECT_ARGS, "same"),
        ]})
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")
        self.assertIn("more than once", receipt["detail"])

    def test_an_empty_tool_call_id_is_rejected(self):
        receipt = self.run_qualify({"role": "assistant", "tool_calls": [call("qodec_answer", ANSWER_ARGS, "")]})
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")

    def test_tool_calls_under_the_wrong_role_are_rejected(self):
        receipt = self.run_qualify({"role": "tool", "tool_calls": [call("qodec_answer", ANSWER_ARGS)]})
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")
        self.assertIn("assistant", receipt["detail"])

    def test_tool_calls_that_are_not_an_array_are_rejected(self):
        receipt = self.run_qualify({"role": "assistant", "tool_calls": {"0": call("qodec_answer", ANSWER_ARGS)}})
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")

    def test_non_string_non_object_arguments_are_rejected(self):
        entry = call("qodec_answer", ANSWER_ARGS)
        entry["function"]["arguments"] = 42
        receipt = self.run_qualify({"role": "assistant", "tool_calls": [entry]})
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")

    def test_the_replay_echoes_the_providers_own_tool_calls(self):
        """Verbatim means the provider's array, not one rebuilt from our view.

        A rebuilt array drops fields the parser does not model and re-encodes
        the arguments, so a provider that only accepts its own emission back
        would fail for a reason this canary invented.
        """
        emitted = call("qodec_intersect", INTERSECT_ARGS, "call_op")
        emitted["index"] = 0          # a field the parser does not model
        body = json.dumps({"id": "x", "model": "openai/gpt-oss-120b", "choices": [{"message": {
            "role": "assistant", "content": None, "tool_calls": [emitted],
        }}]}).encode()
        send = scripted([(200, body, ""), ANSWER_REPLY])
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, send)
        self.assertEqual(receipt["classification"], "PASS")
        replayed = json.loads(send.seen[1][1])["messages"][2]["tool_calls"]
        self.assertEqual(replayed, [emitted])
        self.assertEqual(replayed[0]["index"], 0)
        self.assertEqual(replayed[0]["function"]["arguments"], INTERSECT_ARGS)

    def test_redirects_are_disabled_in_the_opener(self):
        """Not "we classify 3xx" — the handler must not be able to follow one."""
        handlers = [type(h).__name__ for h in pm._OPENER.handlers]
        self.assertIn("_NoRedirects", handlers)
        self.assertNotIn("HTTPRedirectHandler", handlers)
        self.assertIsNone(
            pm._NoRedirects().redirect_request(None, None, 302, "Found", {}, "https://elsewhere/")
        )

    def test_the_response_body_is_bounded(self):
        stream = io.BytesIO(b"x" * 100)
        self.assertEqual(pm.read_bounded(stream, 100), b"x" * 100)
        with self.assertRaisesRegex(ValueError, "exceeded"):
            pm.read_bounded(io.BytesIO(b"x" * 101), 100)

    def test_the_bound_is_on_the_read_not_on_the_complaint_afterwards(self):
        """A hostile endpoint streams; checking the length after `read()` is too late.

        Reading it all and *then* raising still lets a 4 GB response through
        memory first, which is the failure the bound exists to prevent. So the
        contract is on what gets asked for.
        """

        class CountingStream:
            def __init__(self):
                self.requested = None

            def read(self, size=-1):
                self.requested = size
                return b"x" * (2048 if size in (-1, None) else min(size, 2048))

        stream = CountingStream()
        with self.assertRaisesRegex(ValueError, "exceeded"):
            pm.read_bounded(stream, 100)
        self.assertEqual(stream.requested, 101)
        self.assertNotIn(stream.requested, (-1, None))

    def test_a_body_read_failure_after_headers_is_not_unavailability(self):
        """The generation exists and will be billed; a retry pays twice."""
        receipt = pm.qualify_target(
            target(), surface(), 30.0, 6,
            scripted([(200, None, "response body exceeded 4194304 bytes", "after-headers")]),
        )
        self.assertEqual(receipt["classification"], "RESPONSE_CAPTURE_FAILED")
        self.assertNotEqual(receipt["classification"], "UNAVAILABLE")
        self.assertEqual(receipt["turns"][0]["outcome"], "response-capture-failure")

    def test_a_failure_before_headers_stays_retryable(self):
        receipt = pm.qualify_target(
            target(), surface(), 30.0, 6,
            scripted([(None, None, "connection refused", "before-response")]),
        )
        self.assertEqual(receipt["classification"], "UNAVAILABLE")

    def test_a_missing_credential_is_an_auth_failure_not_an_outage(self):
        spec = target()
        with patch.dict("os.environ", {}, clear=True):
            receipt = pm.qualify_target(
                spec, surface(), 30.0, 6, pm.key_bound_sender(spec["key_env"]),
            )
        self.assertEqual(receipt["classification"], "AUTH_FAILED")
        # The env var name comes from the trusted registry by way of the
        # target, so it is a local value and may be named. The transport's
        # own message is not consulted for it.
        self.assertIn(spec["key_env"], receipt["detail"])
        self.assertEqual(receipt["turns"][0]["transport_reason"], "credential-missing")
        self.assertEqual(receipt["turns"][0]["key_env"], spec["key_env"])

    def test_a_refused_redirect_is_recorded_not_followed(self):
        """The real `send_json`, not the stand-in.

        Everything above injects `send`, which is exactly what makes the failure
        paths reachable — and exactly what would leave the one function that
        touches the network untested.
        """
        err = urllib.error.HTTPError(
            "https://api.example/v1/chat/completions", 302, "Found", {}, io.BytesIO(b"moved"),
        )
        with patch.object(pm._OPENER, "open", side_effect=err):
            sent = pm.send_json("https://api.example/v1/chat/completions", b"{}", "k", 1)
        self.assertEqual((sent.status, sent.body, sent.stage), (302, b"moved", "completed"))
        self.assertEqual(pm.classify_qualify_http(302, b"moved", False)[0], "REDIRECT_NOT_FOLLOWED")

    def test_an_oversize_error_body_keeps_the_status_it_already_had(self):
        """`status is None` must mean "no headers", nothing else.

        Losing the body is not a reason to also forget that the provider said
        401 — that is the most useful fact in the exchange, and filing it as a
        nameless capture failure discards it.
        """
        err = urllib.error.HTTPError(
            "https://api.example/v1", 401, "nope", {"x-request-id": "req-77"}, io.BytesIO(b"z" * 300),
        )
        with patch.object(pm._OPENER, "open", side_effect=err):
            sent = pm.send_json("https://api.example/v1", b"{}", "k", 1, limit=100)
        self.assertEqual(sent.stage, "after-headers")
        self.assertEqual(sent.status, 401)
        self.assertIsNone(sent.body)
        self.assertEqual(sent.body_bytes_observed, 101)
        self.assertEqual(sent.request_id, "req-77")
        self.assertIn("exceeded", sent.detail)

    def test_a_lost_body_on_a_success_keeps_its_status_too(self):
        class Response:
            status = 200
            headers = {"x-groq-request-id": "req-42"}

            def read(self, size=-1):
                return b"z" * 300

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with patch.object(pm._OPENER, "open", side_effect=lambda *a, **k: Response()):
            sent = pm.send_json("https://api.example/v1", b"{}", "k", 1, limit=100)
        self.assertEqual((sent.stage, sent.status), ("after-headers", 200))
        self.assertEqual(sent.request_id, "req-42")

    def test_a_status_of_none_means_no_headers_ever_arrived(self):
        with patch.object(pm._OPENER, "open", side_effect=urllib.error.URLError("refused")):
            sent = pm.send_json("https://api.example/v1", b"{}", "k", 1)
        self.assertIsNone(sent.status)
        self.assertEqual(sent.stage, "before-response")

    def test_the_receipt_keeps_the_status_when_the_body_is_lost(self):
        receipt = pm.qualify_target(
            target(), surface(), 30.0, 6,
            scripted([(401, None, "response body exceeded", "after-headers", 4194305, "req-3")]),
        )
        self.assertEqual(receipt["classification"], "RESPONSE_CAPTURE_FAILED")
        self.assertIn("HTTP 401", receipt["detail"])
        turn = receipt["turns"][0]
        self.assertEqual(turn["http_status"], 401)
        self.assertEqual(turn["body_bytes_observed"], 4194305)
        self.assertTrue(turn["request_id_present"])
        self.assertEqual(turn["request_id_sha256"],
                         pm.evidence_digest("request-id", "req-3"))

    def test_a_connect_failure_stops_before_the_response(self):
        with patch.object(pm._OPENER, "open", side_effect=urllib.error.URLError("refused")):
            sent = pm.send_json("https://api.example/v1", b"{}", "k", 1)
        self.assertEqual(sent.stage, "before-response")
        with patch.object(pm._OPENER, "open", side_effect=TimeoutError()):
            sent = pm.send_json("https://api.example/v1", b"{}", "k", 1)
        self.assertEqual((sent.stage, sent.detail), ("before-response", "timeout"))

    def test_a_successful_send_carries_the_credential_and_nothing_else(self):
        class Response:
            status = 200

            def read(self, size=-1):
                return b'{"ok":true}'

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        seen = {}

        def opened(request, timeout=None):
            seen["headers"] = dict(request.header_items())
            seen["method"] = request.get_method()
            return Response()

        with patch.object(pm._OPENER, "open", side_effect=opened):
            sent = pm.send_json("https://api.example/v1", b"{}", "sk-live", 1)
        self.assertEqual((sent.status, sent.body, sent.stage), (200, b'{"ok":true}', "completed"))
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["headers"]["Authorization"], "Bearer sk-live")
        self.assertEqual(seen["headers"]["Content-type"], "application/json")

    def test_the_sender_closes_over_the_env_name_not_the_key(self):
        """The credential is read at call time and never captured.

        A sender built while the key was in scope would hold it for the life of
        the run, where anything that reprs a closure can find it.
        """
        with patch.dict("os.environ", {"SOME_KEY": "sk-super-secret"}, clear=True):
            send = pm.key_bound_sender("SOME_KEY")
        captured = [cell.cell_contents for cell in send.__closure__ or ()]
        # The contract is what is *absent*. Asserting an exact list makes the
        # test fail whenever the sender gains a parameter, which says nothing
        # about the credential.
        self.assertNotIn("sk-super-secret", captured)
        self.assertIn("SOME_KEY", captured)


class ByteEnvelopeOracleTests(unittest.TestCase):
    """One strict oracle, agreeing with `canon.rs` on a negative corpus.

    `base64.urlsafe_b64decode` accepted `YWxwaGE=` and ignored non-zero trailing
    bits, so a padded or nonsense-tailed spelling of `alpha` passed the canary
    and would be refused by `KeyBytes::from_envelope`. A regex banning `=` fixes
    one character and leaves the semantics; this is the procedure instead.
    """

    def envelope(self, **fields):
        base = {"encoding": "base64url-nopad", "data": "YWxwaGE"}
        base.update(fields)
        return base

    def errors(self, **fields):
        return pm.envelope_errors(self.envelope(**fields), "answer")[0]

    def test_the_canonical_envelope_is_accepted(self):
        errors, decoded = pm.envelope_errors(self.envelope(), "answer")
        self.assertEqual(errors, [])
        self.assertEqual(decoded, b"alpha")

    def test_padding_is_rejected(self):
        self.assertTrue(any("padding" in e for e in self.errors(data="YWxwaGE=")))

    def test_the_standard_alphabet_is_rejected(self):
        # `+` and `/` are the standard alphabet, not base64url.
        self.assertTrue(any("rejects" in e for e in self.errors(data="++++")))
        self.assertTrue(any("rejects" in e for e in self.errors(data="a/b")))
        self.assertTrue(any("rejects" in e for e in self.errors(data="YWxw aGE")))

    def test_an_invalid_length_is_rejected(self):
        # One leftover character cannot encode any whole byte.
        self.assertTrue(any("dangling" in e for e in self.errors(data="YWxwaGEx3")))

    def test_non_zero_trailing_bits_are_rejected(self):
        # "YWxwaGF" and "YWxwaGE" differ only in bits that decode to nothing.
        self.assertEqual(pm.b64url_nopad_decode("YWxwaGE"), b"alpha")
        self.assertTrue(any("trailing bits" in e for e in self.errors(data="YWxwaGF")))

    def test_a_disagreeing_display_utf8_is_rejected(self):
        self.assertTrue(any("disagrees" in e for e in self.errors(display_utf8="beta")))

    def test_an_agreeing_display_utf8_is_accepted(self):
        self.assertEqual(self.errors(display_utf8="alpha"), [])

    def test_a_non_string_display_utf8_is_rejected(self):
        self.assertTrue(any("must be a string" in e for e in self.errors(display_utf8=7)))

    def test_an_unknown_envelope_field_is_rejected(self):
        self.assertTrue(any("unknown field" in e for e in self.errors(extra=1)))

    def test_a_wrong_encoding_is_rejected(self):
        self.assertTrue(any("encoding must be" in e for e in self.errors(encoding="hex")))

    def test_the_round_trip_is_canonical(self):
        for raw in (b"", b"a", b"ab", b"abc", b"alpha", bytes(range(256))):
            self.assertEqual(pm.b64url_nopad_decode(pm.b64url_nopad_encode(raw)), raw)

    def test_the_oracle_reaches_tool_arguments_not_just_the_answer(self):
        """`qodec_lookup.key` is an envelope too, found structurally."""
        args = {"index": "line", "key": {"encoding": "base64url-nopad", "data": "YQ=="}}
        self.assertTrue(pm.validate_arguments(surface(), "qodec_lookup", args))

    def test_a_padded_terminal_answer_does_not_pass(self):
        padded = json.dumps({
            "handle": pm.CANNED_HANDLE,
            "answer": {"encoding": "base64url-nopad", "data": "YWxwaGE=", "display_utf8": "lies"},
            "cited": [{"store": pm.CANNED_HANDLE, "section": "attempt_1", "ordinal": 0}],
        })
        receipt = pm.qualify_target(
            target(), surface(), 30.0, 6,
            scripted(OPERATION_THEN((200, completion([call("qodec_answer", padded, "call_ans")]), ""))),
        )
        self.assertNotEqual(receipt["classification"], "PASS")
        self.assertEqual(receipt["classification"], "MALFORMED_TOOL_ARGUMENTS")


class ObservedResultTests(unittest.TestCase):
    """The answer is graded against this run, never against a constant."""

    def test_a_materialize_only_run_cannot_produce_a_handle_to_cite(self):
        """The defect: `qodec_materialize` returns records and no handle.

        Grading against `CANNED_HANDLE` let a script that ran only materialize
        cite a handle nothing had returned, and pass. That rewards guessing a
        module constant, which is not a property of the protocol.
        """
        receipt = pm.qualify_target(
            target(), surface(), 30.0, 6, scripted([
                (200, completion([call("qodec_materialize", MATERIALIZE_ARGS, "call_m")]), ""),
                (200, completion([call("qodec_answer", ANSWER_ARGS, "call_ans")]), ""),
            ]),
        )
        self.assertNotEqual(receipt["classification"], "PASS")
        self.assertEqual(receipt["classification"], "CANARY_ANSWER_MISMATCH")
        self.assertIn("no operation in this run returned a handle", receipt["detail"])

    def test_an_operation_that_returns_a_handle_makes_the_answer_citable(self):
        receipt = pm.qualify_target(
            target(), surface(), 30.0, 6, scripted(OPERATION_THEN(ANSWER_REPLY)),
        )
        self.assertEqual(receipt["classification"], "PASS")

    def test_the_observable_set_grows_only_from_returned_results(self):
        observed = pm.Observed()
        self.assertEqual((observed.handles, observed.support, observed.bytes), (set(), set(), set()))
        observed.record(pm.canned_result_for("qodec_materialize"))
        self.assertEqual(observed.handles, set())          # records carry no handle
        self.assertIn(b"alpha", observed.bytes)
        observed.record(pm.canned_result_for("qodec_intersect"))
        self.assertEqual(observed.handles, {pm.CANNED_HANDLE})
        self.assertEqual(len(observed.support), 3)


class TransportStateTests(unittest.TestCase):
    """`SendResult` is a state machine, not an inference from one field."""

    def test_the_legacy_tuple_table_is_exhaustive(self):
        self.assertEqual(pm.infer_stage(None, None), "before-response")
        self.assertEqual(pm.infer_stage(503, None), "after-headers")
        self.assertEqual(pm.infer_stage(200, b'{"ok":1}'), "completed")
        with self.assertRaisesRegex(ValueError, "without a status"):
            pm.infer_stage(None, b"body")

    def test_an_empty_body_is_received_not_lost(self):
        """`b""` is a complete empty body; `None` is a body that never arrived.

        Collapsing the two would file a 200 with an empty payload — received,
        billed, and simply unparseable — as a capture failure.
        """
        self.assertEqual(pm.infer_stage(200, b""), "completed")
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted([(200, b"", "")]))
        self.assertEqual(receipt["classification"], "INVALID_OUTPUT")

    def test_a_status_without_a_body_is_never_promoted_to_completed(self):
        """The defect: `(503, None, "body lost")` was inferred as `completed`.

        Qualification then called a billed after-headers loss a retryable
        `UNAVAILABLE`, which is an invitation to pay for the same generation
        twice.
        """
        receipt = pm.qualify_target(
            target(), surface(), 30.0, 6, scripted([(503, None, "body lost")]),
        )
        self.assertNotEqual(receipt["classification"], "UNAVAILABLE")
        self.assertEqual(receipt["classification"], "RESPONSE_CAPTURE_FAILED")
        self.assertIn("HTTP 503", receipt["detail"])


class SecretContainmentTests(unittest.TestCase):
    """A sentinel that must not appear in anything this tool leaves behind."""

    SENTINEL = "sk-QODEC-SENTINEL-b3f9c1d7e2a4-DO-NOT-LEAK"

    def outputs_for(self, replies, key=None):
        """Run one qualification and collect every channel it can write to."""
        import contextlib
        import io as _io

        out, err = _io.StringIO(), _io.StringIO()
        env = {"GROQ_API_KEY": key if key is not None else self.SENTINEL}
        with patch.dict("os.environ", env, clear=True):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted(replies))
                except Exception as exc:  # noqa: BLE001 — the text is the point
                    receipt = {"raised": f"{type(exc).__name__}: {exc}"}
        return json.dumps(receipt) + out.getvalue() + err.getvalue()

    def assert_clean(self, blob, label):
        self.assertNotIn(self.SENTINEL, blob, f"credential reached {label}")
        self.assertNotIn("Bearer", blob, f"an Authorization header reached {label}")

    def test_a_provider_that_echoes_the_key_does_not_get_it_into_the_receipt(self):
        """Provider error bodies are untrusted text bound for a committed file.

        A gateway echoing the rejected `Authorization` value into
        `error.message` used to have that text copied verbatim into `detail`
        and written to disk.
        """
        body = json.dumps({"error": {
            "message": f"rejected credential Bearer {self.SENTINEL}",
            "param": "authorization",
        }}).encode()
        self.assert_clean(self.outputs_for([(401, body, "")]), "the receipt")

    def test_every_qualification_failure_path_is_clean(self):
        for name, replies in (
            ("transport", [(None, None, "connection refused")]),
            ("capture", [(500, None, "body lost", "after-headers", 9, "req-1")]),
            ("redirect", [(302, b"moved", "")]),
            ("rate limit", [(429, b'{"error":{"message":"slow down"}}', "")]),
            ("bad json", [(200, b"[]", "")]),
            ("dialect", [(200, completion([call("qodec_answer", json.loads(ANSWER_ARGS))]), "")]),
        ):
            self.assert_clean(self.outputs_for(replies), name)

    def test_a_malformed_credential_never_reaches_a_message(self):
        """`http.client` raises `ValueError: Invalid header value b'Bearer ...'`.

        `send_json` did not catch it and `main` prints `ValueError` to stderr,
        so a key with a stray newline would be preserved in CI logs forever.
        """
        result = pm.send_json("https://api.example/v1", b"{}", self.SENTINEL + "\n", 1)
        self.assertEqual(result.stage, "no-credential")
        self.assert_clean(json.dumps(result.detail), "the send result")
        self.assertFalse(pm.credential_is_header_safe(self.SENTINEL + "\n"))
        self.assertTrue(pm.credential_is_header_safe(self.SENTINEL))

    def test_the_receipt_records_facts_rather_than_provider_prose(self):
        receipt = pm.qualify_target(
            target(), surface(), 30.0, 6,
            scripted([(400, json.dumps({"error": {"message": "tool_choice unsupported"}}).encode(), "")]),
        )
        self.assertEqual(receipt["detail"], "HTTP 400: tools-or-tool-choice-named-in-a-400")
        self.assertIn(receipt["turns"][0]["detail"], pm.QUALIFY_REASONS)
        turn = receipt["turns"][0]
        # What is kept: status, digest, byte count. Not the provider's words.
        self.assertEqual(turn["http_status"], 400)
        self.assertTrue(turn["response_sha256"])
        self.assertNotIn("unsupported", json.dumps(receipt))


def occurrences(value, needle, path="$"):
    """Every place `needle` appears anywhere inside `value`, as paths.

    Recursive on purpose. Two rounds of review found the credential in a field
    nobody had thought to check — `usage`, then `request_id` — because the
    containment tests looked in a list of *known* places. A list of known places
    ages faster than milk on a radiator: the next field is always the one that
    is not on it.
    """
    found = []
    if isinstance(value, dict):
        for key, sub in value.items():
            if needle in str(key):
                found.append(f"{path}.<key {key!r}>")
            found.extend(occurrences(sub, needle, f"{path}.{key}"))
    elif isinstance(value, (list, tuple)):
        for index, sub in enumerate(value):
            found.extend(occurrences(sub, needle, f"{path}[{index}]"))
    elif isinstance(value, str):
        if needle in value:
            found.append(path)
    elif isinstance(value, (bytes, bytearray)):
        if needle.encode() in bytes(value):
            found.append(path)
    return found


def completion_with_role(role, calls, model="openai/gpt-oss-120b"):
    """A completion whose assistant `role` is whatever the caller says."""
    return json.dumps({
        "id": "chatcmpl-test", "model": model,
        "choices": [{"index": 0, "message": {
            "role": role, "content": None, "tool_calls": calls}}],
    }).encode()


def call_with_type(kind, name="qodec_intersect", arguments=INTERSECT_ARGS, call_id="call_0"):
    return {"id": call_id, "type": kind,
            "function": {"name": name, "arguments": arguments}}


class DurableProjectionTests(unittest.TestCase):
    """Nothing the provider chose is copied into durable evidence.

    Two rounds found this as two bugs — `usage` copied whole, `request_id` taken
    verbatim from a provider-controlled header — and either could have been
    closed with an `if`. The `if` is the wrong repair: the next review finds the
    tool call id, then the substituted model name, then whatever a creative
    gateway puts in the next field, one per round, forever. The provider has
    already seen the bearer token; every string it returns is a way to hand it
    back.
    """

    SENTINEL = "sk-QODEC-SENTINEL-b3f9c1d7e2a4-DO-NOT-LEAK"

    @property
    def ENCODED(self):
        """The same secret as a non-negative integer.

        A sweep that looks only for text is a sweep a provider can walk
        past by encoding: `int.from_bytes(secret.encode(), "big")` is a
        perfectly well-typed token count.
        """
        return int.from_bytes(self.SENTINEL.encode(), "big")

    def assert_absent(self, artifact, label):
        """The recursive assertion, not a list of fields to remember."""
        blob = json.dumps(artifact, default=repr)
        for shape, needle in (("text", self.SENTINEL), ("integer", str(self.ENCODED))):
            where = occurrences(artifact, needle)
            self.assertEqual(
                where, [], f"the credential reached {label} as {shape} at {where}")
            self.assertNotIn(needle, blob, f"{label} ({shape})")

    # -- usage --

    BOUNDS = {"prompt_tokens": 10_000, "completion_tokens": 1024, "total_tokens": 11_024}

    def test_only_known_non_negative_integer_counters_survive(self):
        self.assertEqual(
            pm.normalize_provider_usage({
                "prompt_tokens": 12, "completion_tokens": 0, "total_tokens": 12,
                "echo": f"Bearer {self.SENTINEL}",
                "prompt_tokens_details": {"cached": 3},
                "queue_time": 0.03,
                # An allowlist, not a type filter: a plausible integer under
                # an unknown name is still a field the provider invented.
                "queue_position": 3,
                "reasoning_tokens": 7,
            }, self.BOUNDS),
            {"prompt_tokens": 12, "completion_tokens": 0, "total_tokens": 12},
        )

    def test_a_counter_that_is_not_a_count_is_dropped(self):
        for label, usage in (
            ("string", {"prompt_tokens": "12"}),
            # `True` is an `int` in Python and would land in a receipt as 1.
            ("bool", {"prompt_tokens": True}),
            ("float", {"prompt_tokens": 12.0}),
            ("negative", {"prompt_tokens": -1}),
            ("null", {"prompt_tokens": None}),
            ("object", {"prompt_tokens": {"value": 12}}),
        ):
            self.assertEqual(pm.normalize_provider_usage(usage, self.BOUNDS), {}, label)

    def test_a_usage_that_is_not_an_object_yields_nothing(self):
        for value in ("12", 12, None, [1, 2], True):
            self.assertEqual(pm.normalize_provider_usage(value, self.BOUNDS), {})

    def test_usage_never_reaches_a_verdict(self):
        """Descriptive telemetry. A poisoned `usage` changes nothing but itself."""
        poisoned = {"prompt_tokens": 12, "echo": f"Bearer {self.SENTINEL}"}
        body = json.dumps({
            "id": "chatcmpl", "model": "openai/gpt-oss-120b", "usage": poisoned,
            "choices": [{"message": {"role": "assistant", "content": None,
                                     "tool_calls": [call("qodec_intersect", INTERSECT_ARGS, "op")]}}],
        }).encode()
        receipt = pm.qualify_target(target(), surface(), 30.0, 6,
                                    scripted([(200, body, ""), ANSWER_REPLY]))
        self.assertEqual(receipt["classification"], "PASS")
        self.assertEqual(receipt["turns"][0]["reported_usage"], {"prompt_tokens": 12})
        self.assert_absent(receipt, "a PASS receipt")

    # -- request id --

    def test_a_reflected_request_id_never_reaches_an_artifact(self):
        body = completion([call("qodec_answer", ANSWER_ARGS, "call_ans")])
        for label, replies in (
            ("qualification", OPERATION_THEN(
                (200, body, "", "completed", len(body), self.SENTINEL))),
            ("capture failure", [(500, None, "lost", "after-headers", 9, self.SENTINEL)]),
        ):
            receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted(replies))
            self.assert_absent(receipt, f"the {label} receipt")

    def test_the_request_id_crosses_as_evidence_and_stays_comparable(self):
        sent = [(500, None, "lost", "after-headers", 9, "req-42")]
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted(sent))
        turn = receipt["turns"][0]
        self.assertTrue(turn["request_id_present"])
        self.assertEqual(turn["request_id_bytes"], len("req-42"))
        self.assertEqual(turn["request_id_sha256"], pm.evidence_digest("request-id", "req-42"))
        self.assertNotIn("req-42", json.dumps(receipt))

    def test_an_absent_request_id_says_so_rather_than_hashing_nothing(self):
        receipt = pm.qualify_target(target(), surface(), 30.0, 6,
                                    scripted([(500, None, "lost", "after-headers", 9, None)]))
        turn = receipt["turns"][0]
        self.assertEqual(turn["request_id_present"], False)
        self.assertNotIn("request_id_sha256", turn)

    def test_digests_are_domain_separated(self):
        """The same string in two fields must not produce the same hash.

        Otherwise a receipt reveals that the provider reflected its request id
        into a tool call id — small, and free to close.
        """
        digests = {
            pm.evidence_digest(domain, "identical") for domain in pm.EVIDENCE_DOMAINS
        }
        self.assertEqual(len(digests), len(pm.EVIDENCE_DOMAINS))
        self.assertNotEqual(
            pm.evidence_digest("request-id", "x"), hashlib.sha256(b"x").hexdigest())

    # -- every other field the provider fills in --

    def poisoned_receipt(self, replies):
        return pm.qualify_target(target(), surface(), 30.0, 6, scripted(replies))

    def test_no_reflected_field_reaches_a_qualification_receipt(self):
        poisoned_usage = {"prompt_tokens": 1, "echo": f"Bearer {self.SENTINEL}"}
        answer = completion([call("qodec_answer", ANSWER_ARGS, "call_ans")])
        scenarios = {
            "PASS": OPERATION_THEN((200, answer, "")),
            "provider rejection": [(400, json.dumps(
                {"error": {"message": f"rejected Bearer {self.SENTINEL}"}}).encode(), "")],
            "response-capture failure": [
                (500, None, f"lost {self.SENTINEL}", "after-headers", 9, self.SENTINEL)],
            "model substitution": OPERATION_THEN((200, completion(
                [call("qodec_answer", ANSWER_ARGS, "call_ans")], model=self.SENTINEL), "")),
            "unknown tool": [(200, completion(
                [call(f"tool_{self.SENTINEL}", "{}", "call_x")]), "")],
            "call-id reflection": [(200, completion(
                [call("qodec_intersect", INTERSECT_ARGS, self.SENTINEL)]), "")],
            "duplicate call-id reflection": [(200, completion([
                call("qodec_intersect", INTERSECT_ARGS, self.SENTINEL),
                call("qodec_lookup", INTERSECT_ARGS, self.SENTINEL),
            ]), "")],
            "model-name reflection": [(200, completion(
                [call("qodec_intersect", INTERSECT_ARGS, "op")], model=self.SENTINEL), "")],
            "usage unknown field": [(200, json.dumps({
                "model": "openai/gpt-oss-120b", "usage": poisoned_usage,
                "choices": [{"message": {"role": "assistant", "content": None,
                                         "tool_calls": [call("qodec_intersect", INTERSECT_ARGS, "op")]}}],
            }).encode(), "")],
            "malformed arguments": [(200, completion(
                [call("qodec_intersect", json.dumps({"index": self.SENTINEL, "sections": []}), "op")]), "")],
            "cited handle reflection": OPERATION_THEN((200, completion([call(
                "qodec_answer",
                json.dumps({"handle": self.SENTINEL,
                            "answer": {"encoding": "base64url-nopad", "data": "YWxwaGE"},
                            "cited": [{"store": self.SENTINEL, "section": "attempt_1", "ordinal": 0}]}),
                "call_ans")]), "")),
            "assistant content reflection": [(200, completion_with_content(
                self.SENTINEL, [call("qodec_intersect", INTERSECT_ARGS, "op")]), "")],
            # The discriminators. A sweep that covered content, ids, names,
            # models and usage but not these was a field list wearing a
            # recursive walk's clothes.
            "role reflection": [(200, completion_with_role(
                self.SENTINEL, [call("qodec_intersect", INTERSECT_ARGS, "op")]), "")],
            "role reflection as an object": [(200, completion_with_role(
                {"echo": self.SENTINEL}, [call("qodec_intersect", INTERSECT_ARGS, "op")]), "")],
            "tool call type reflection": [(200, completion(
                [call_with_type(self.SENTINEL)]), "")],
            "tool call type reflection as an array": [(200, completion(
                [call_with_type([self.SENTINEL])]), "")],
            # A secret does not have to arrive as a string. This one is a
            # well-typed non-negative integer, and a sweep for the sentinel text
            # would walk straight past it.
            "usage as a number": [(200, json.dumps({
                "model": "openai/gpt-oss-120b",
                "usage": {"prompt_tokens": int.from_bytes(self.SENTINEL.encode(), "big")},
                "choices": [{"message": {"role": "assistant", "content": None,
                                         "tool_calls": [call("qodec_intersect", INTERSECT_ARGS, "op")]}}],
            }).encode(), "")],
        }
        for label, replies in scenarios.items():
            with self.subTest(scenario=label):
                self.assert_absent(self.poisoned_receipt(replies), label)

    def test_no_reflected_field_reaches_a_probe_result(self):
        poisoned_usage = {"prompt_tokens": 1, "echo": f"Bearer {self.SENTINEL}"}
        ok = {"model": "m", "choices": [{"message": {"content": "QODEC_PROBE_OK"}}]}
        scenarios = {
            "PASS with poisoned usage": [(200, json.dumps(
                dict(ok, usage=poisoned_usage)).encode(), "")],
            "request-id reflection": [(200, json.dumps(ok).encode(), "",
                                       "completed", len(json.dumps(ok)), self.SENTINEL)],
            "model-name reflection": [(200, json.dumps(
                dict(ok, model=self.SENTINEL)).encode(), "")],
            "capture failure": [(500, None, "lost", "after-headers", 9, self.SENTINEL)],
        }
        for label, replies in scenarios.items():
            with self.subTest(scenario=label):
                result = pm.probe_target(probe_row({}), 1, scripted(replies), registry())
                self.assert_absent(result, label)

    def test_a_counter_above_its_local_bound_is_dropped(self):
        """"Bounded numeric scalar" with no upper bound is an open channel.

        The bound comes from the request this module sent — bytes for the
        prompt, `max_tokens` for the completion — so nothing in the response
        decides how large a number the response may write down.
        """
        bounds = pm.usage_bounds(request_bytes=500, max_tokens=16)
        self.assertEqual(
            pm.normalize_provider_usage({
                "prompt_tokens": self.ENCODED,
                "completion_tokens": 17,
                "total_tokens": 512,
            }, bounds),
            {"total_tokens": 512},
        )
        # One past the ceiling is one too many, for each of the three.
        self.assertEqual(pm.normalize_provider_usage(
            {"prompt_tokens": 501, "completion_tokens": 17, "total_tokens": 517}, bounds),
            {})
        self.assertEqual(pm.normalize_provider_usage(
            {"prompt_tokens": 500, "completion_tokens": 16, "total_tokens": 516}, bounds),
            {"prompt_tokens": 500, "completion_tokens": 16, "total_tokens": 516})

    def test_a_numerically_encoded_secret_never_reaches_a_receipt(self):
        body = json.dumps({
            "model": "openai/gpt-oss-120b",
            "usage": {"prompt_tokens": self.ENCODED, "completion_tokens": self.ENCODED},
            "choices": [{"message": {"role": "assistant", "content": None,
                                     "tool_calls": [call("qodec_intersect", INTERSECT_ARGS, "op")]}}],
        }).encode()
        receipt = pm.qualify_target(target(), surface(), 30.0, 6,
                                    scripted([(200, body, ""), ANSWER_REPLY]))
        self.assertEqual(receipt["classification"], "PASS")
        self.assertEqual(receipt["turns"][0]["reported_usage"], {})
        self.assert_absent(receipt, "a receipt whose usage was a number")

    def test_a_reflected_discriminator_is_still_a_protocol_violation(self):
        """Containment must not be bought by losing the verdict."""
        cases = {
            "role as text": completion_with_role(
                self.SENTINEL, [call("qodec_intersect", INTERSECT_ARGS, "op")]),
            "role as an object": completion_with_role(
                {"echo": self.SENTINEL}, [call("qodec_intersect", INTERSECT_ARGS, "op")]),
            "type as text": completion([call_with_type(self.SENTINEL)]),
            "type as an array": completion([call_with_type([self.SENTINEL])]),
        }
        for label, body in cases.items():
            with self.subTest(case=label):
                receipt = self.poisoned_receipt([(200, body, "")])
                self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION", label)
                self.assert_absent(receipt, label)

    def test_a_discriminator_that_is_one_of_ours_is_named_outright(self):
        """A matched enum member is a value we already had, so it is not hidden."""
        self.assertEqual(pm.discriminator("message-role", "user", pm.MESSAGE_ROLES), "'user'")
        self.assertEqual(
            pm.discriminator("message-role", "bot", pm.MESSAGE_ROLES),
            pm.opaque_ref("message-role", "bot"))
        self.assertEqual(
            pm.discriminator("tool-call-type", {"a": 1}, pm.TOOL_CALL_TYPES),
            "<tool-call-type object>")

    def test_a_non_string_model_crosses_as_a_type_and_not_as_a_hash(self):
        """Unrecognised structures do not cross — not even as a digest of one."""
        evidence = pm.model_evidence("m", {"echo": self.SENTINEL})
        self.assertEqual(evidence, {
            "reported_model": None,
            "reported_model_present": True,
            "reported_model_type": "object",
        })
        self.assertEqual(pm.model_evidence("m", None),
                         {"reported_model": None, "reported_model_present": False})

    def test_the_response_digest_is_domain_separated_and_measured(self):
        body = completion([call("qodec_intersect", INTERSECT_ARGS, "op")])
        receipt = pm.qualify_target(target(), surface(), 30.0, 6,
                                    scripted([(200, body, ""), ANSWER_REPLY]))
        turn = receipt["turns"][0]
        self.assertEqual(turn["response_sha256"], pm.evidence_digest("response-body", body))
        self.assertEqual(turn["response_bytes"], len(body))
        self.assertNotEqual(turn["response_sha256"], hashlib.sha256(body).hexdigest())

    # -- the consumer owns the boundary --

    def test_an_unbounded_observed_count_never_reaches_a_receipt(self):
        """The channel `usage` closed, one field over.

        `after-headers` has no body, so nothing local contradicts the number —
        which is exactly what made it an opening. The transport's own limit is
        the only fact that bounds it.
        """
        limit = 4096
        for label, run in (
            ("qualification", lambda replies: pm.qualify_target(
                target(), surface(), 30.0, 6, scripted(replies), response_limit=limit)),
            ("probe", lambda replies: pm.probe_target(
                probe_row({}), 1, scripted(replies), registry(), response_limit=limit)),
        ):
            # `limit + 2` as well as the encoded secret: a path that validated
            # against the module constant rather than against its own limit
            # would still refuse a number the size of a credential, and pass
            # this one. The small number is what catches that.
            for name, observed in (("encoded secret", self.ENCODED), ("just over", limit + 2)):
                with self.subTest(path=label, count=name):
                    artifact = pm.guarded_receipt(
                        pm.QUALIFY_SCHEMA, {"target_id": "t", "provider": "p", "model": "m"},
                        lambda: run([(500, None, "lost", "after-headers", observed, None)]))
                    self.assert_absent(artifact, f"the {label} artifact")
                    self.assertEqual(artifact["classification"], "INTERNAL_ERROR")

    def test_the_limit_plus_one_sentinel_is_admitted_and_nothing_beyond_it(self):
        """`read_bounded` reads `limit + 1` on purpose, to prove overflow.

        One past the limit is therefore the largest count this transport
        contract can produce; two past it is not a measurement.
        """
        limit = 4096
        ok = pm.SendResult(500, None, "lost", "after-headers", limit + 1, None)
        self.assertEqual(pm.validate_send_result(ok, limit), ok)
        with self.assertRaisesRegex(ValueError, "exceeds the local response limit"):
            pm.validate_send_result(
                pm.SendResult(500, None, "lost", "after-headers", limit + 2, None), limit)

    def test_the_refusal_never_repeats_the_number_it_refused(self):
        limit = 4096
        with self.assertRaises(ValueError) as caught:
            pm.validate_send_result(
                pm.SendResult(500, None, "lost", "after-headers", self.ENCODED, None), limit)
        self.assertNotIn(str(self.ENCODED), str(caught.exception))

    def test_a_completed_body_is_bounded_and_must_agree_with_its_count(self):
        limit = 16
        with self.assertRaisesRegex(ValueError, "longer than the local response limit"):
            pm.validate_send_result(
                pm.SendResult(200, b"x" * 17, "", "completed", 17, None), limit)
        with self.assertRaisesRegex(ValueError, "disagrees"):
            pm.validate_send_result(
                pm.SendResult(200, b"xx", "", "completed", 9, None), limit)

    def test_the_limit_is_one_number_from_the_caller_to_the_receipt(self):
        limit = 8192
        receipt = pm.qualify_target(
            target(), surface(), 30.0, 6, scripted(OPERATION_THEN(ANSWER_REPLY)),
            response_limit=limit)
        self.assertEqual(receipt["transport_target"]["max_response_bytes"], limit)

    # -- the digest is computed here, never submitted --

    def test_a_pre_projected_digest_cannot_be_submitted(self):
        """Three times now: a shape check is not a statement about origin.

        `isidentifier()`, then 64 hex characters. A 64-hex credential satisfies
        a 64-hex check, so the field is gone and the consumer projects.
        """
        self.assertNotIn("failure_class_sha256", pm.SendResult._fields)
        self.assertIn("failure_class", pm.SendResult._fields)

    def test_a_hex_credential_offered_as_a_class_becomes_a_digest_of_itself(self):
        hex_secret = "c0ffee" + "0" * 58
        self.assertEqual(len(hex_secret), 64)
        sent = pm.SendResult(None, None, "x", "before-response",
                             reason="connection-failed", failure_kind="url-error",
                             failure_class=hex_secret)
        projected = pm.project_transport_failure(sent, pm.MAX_RESPONSE_BYTES)
        self.assertEqual(projected["failure_class_sha256"],
                         pm.evidence_digest("failure-class", hex_secret))
        self.assertNotIn(hex_secret, json.dumps(projected))

    def test_both_paths_project_a_failure_class_the_same_way(self):
        replies = [(None, None, "refused", "before-response")]
        sent = pm.SendResult(None, None, "refused", "before-response",
                             reason="connection-failed", failure_kind="url-error",
                             failure_class="ConnectionRefusedError")
        digest = pm.evidence_digest("failure-class", "ConnectionRefusedError")
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted([sent]))
        result = pm.probe_target(probe_row({}), 1, scripted([sent]), registry())
        self.assertEqual(receipt["turns"][0]["failure_class_sha256"], digest)
        self.assertEqual(result["failure_class_sha256"], digest)
        self.assertTrue(receipt["turns"][0]["failure_class_present"])
        del replies

    def test_two_framing_classes_stay_distinguishable(self):
        self.assertNotEqual(pm.evidence_digest("failure-class", "BadStatusLine"),
                            pm.evidence_digest("failure-class", "LineTooLong"))

    def test_a_failure_class_is_locally_bounded(self):
        with self.assertRaisesRegex(ValueError, "longer than the local bound"):
            pm.validate_send_result(pm.SendResult(
                None, None, "x", "before-response",
                failure_class="C" * (pm.FAILURE_CLASS_MAX_BYTES + 1)))
        with self.assertRaisesRegex(ValueError, "must be a string"):
            pm.validate_send_result(pm.SendResult(
                None, None, "x", "before-response", failure_class=["C"]))

    def test_a_raw_failure_class_never_reaches_a_detail(self):
        sent = pm.SendResult(None, None, "refused", "before-response",
                             reason="connection-failed", failure_kind="url-error",
                             failure_class=f"Cls{self.SENTINEL}")
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted([sent]))
        self.assert_absent(receipt, "a receipt whose failure class was poisoned")
        self.assertNotIn(self.SENTINEL, receipt["detail"])

    def test_a_reflected_model_still_fails_the_identity_check(self):
        """Projection must not buy containment by losing the finding."""
        receipt = self.poisoned_receipt(OPERATION_THEN((200, completion(
            [call("qodec_answer", ANSWER_ARGS, "call_ans")], model=self.SENTINEL), "")))
        self.assertEqual(receipt["classification"], "PROVIDER_SUBSTITUTED")
        self.assertEqual(receipt["model_status"], "drifted")
        self.assertIn(pm.evidence_digest("model-name", self.SENTINEL)[:16], receipt["detail"])

    def test_a_reflected_tool_name_is_still_an_undeclared_tool(self):
        receipt = self.poisoned_receipt([(200, completion(
            [call(f"tool_{self.SENTINEL}", "{}", "call_x")]), "")])
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")
        self.assertIn("never declared", receipt["detail"])

    def test_a_cited_handle_is_named_by_digest_and_never_spelled_out(self):
        """Schema-valid and unobserved: the one shape that reaches the grader.

        A handle carrying the sentinel cannot get this far — it fails the
        `sha256:` pattern first — so the sentinel sweep cannot cover this path.
        The contract is asserted directly instead of assumed.
        """
        invented = "sha256:" + "b" * 64
        errors = pm.canary_answer_errors(
            {"handle": invented,
             "answer": {"encoding": "base64url-nopad", "data": "YWxwaGE"},
             "cited": []},
            pm.Observed(),
        )
        joined = " ".join(errors)
        self.assertNotIn(invented, joined)
        self.assertIn(pm.evidence_digest("handle", invented)[:16], joined)

    def test_an_unknown_transport_reason_is_refused(self):
        """The vocabulary is closed, or it is not a vocabulary.

        A reason nobody declared would reach a receipt as free text wearing an
        enum's clothes — which is the whole failure mode this round exists for.
        """
        with self.assertRaisesRegex(ValueError, "unknown transport reason"):
            pm.validate_send_result(
                pm.SendResult(None, None, "x", "before-response", reason="made-up"))
        for reason in pm.TRANSPORT_REASONS:
            ok = pm.SendResult(None, None, "x", "before-response", reason=reason)
            self.assertEqual(pm.validate_send_result(ok), ok)

    def test_a_failure_kind_is_an_enum_not_an_identifier(self):
        """`"BearerSecretValue"` is a valid Python identifier.

        The earlier field admitted any of them and called that provenance.
        Syntax is not origin: `SendResult` is constructible by an injected
        sender, so the vocabulary has to be closed rather than well-formed.
        """
        with self.assertRaisesRegex(ValueError, "unknown transport failure kind"):
            pm.validate_send_result(pm.SendResult(
                None, None, "x", "before-response", failure_kind="BearerSecretValue"))
        # A pre-projected digest can no longer be submitted at all: the field
        # is gone, and the consumer computes the digest at the boundary.
        self.assertNotIn("failure_class_sha256", pm.SendResult._fields)
        with self.assertRaisesRegex(ValueError, "longer than the local bound"):
            pm.validate_send_result(pm.SendResult(
                None, None, "x", "before-response",
                failure_class="C" * (pm.FAILURE_CLASS_MAX_BYTES + 1)))
        for kind in pm.TRANSPORT_FAILURE_KINDS:
            ok = pm.SendResult(None, None, "x", "before-response", failure_kind=kind)
            self.assertEqual(pm.validate_send_result(ok), ok)

    def test_call_ids_cross_as_ordinals_and_digests(self):
        receipt = self.poisoned_receipt([(200, completion(
            [call("qodec_intersect", INTERSECT_ARGS, "call_op")]), "")])
        entry = receipt["turns"][0]["tool_calls"][0]
        self.assertEqual(entry["ordinal"], 0)
        self.assertEqual(entry["name"], "qodec_intersect")
        self.assertEqual(entry["call_id_sha256"], pm.evidence_digest("tool-call-id", "call_op"))
        self.assertNotIn("call_op", json.dumps(receipt))

    def test_replay_still_uses_the_real_call_id_the_provider_sent(self):
        """Containment is about the artifact, not about the wire."""
        send = scripted([(200, completion(
            [call("qodec_intersect", INTERSECT_ARGS, "call_op")]), ""), ANSWER_REPLY])
        pm.qualify_target(target(), surface(), 30.0, 6, send)
        replayed = json.loads(send.seen[1][1])
        results = [m for m in replayed["messages"] if m.get("role") == "tool"]
        self.assertEqual([m["tool_call_id"] for m in results], ["call_op"])


class MatrixIsolationTests(unittest.TestCase):
    """One malformed target must not cost every later target its receipt."""

    def test_a_crash_becomes_a_receipt_and_names_no_secret(self):
        def explode():
            raise ValueError("Invalid header value b'Bearer sk-SECRET'")

        receipt = pm.guarded_receipt(pm.PROBE_SCHEMA, {"target_id": "p--m", "provider": "p", "model": "m"}, explode)
        self.assertEqual(receipt["classification"], "INTERNAL_ERROR")
        self.assertEqual(receipt["detail"], "provider-matrix raised an internal exception")
        self.assertNotIn("SECRET", json.dumps(receipt))

    def test_an_internal_crash_uses_the_same_exception_projection_as_transport(self):
        """One projection for exception classes, not one per call site.

        `guarded_receipt` used to write `type(exc).__name__` into `detail`
        verbatim while the transport path digested it. Two policies for one
        kind of value is how the next class name reaches a durable artifact
        unbounded.
        """
        def explode():
            raise ValueError("Invalid header value b'Bearer sk-SECRET'")

        receipt = pm.guarded_receipt(pm.PROBE_SCHEMA, {"target_id": "p--m", "provider": "p", "model": "m"}, explode)
        self.assertEqual(receipt["internal_failure_kind"], "internal-error")
        self.assertTrue(receipt["internal_failure_class_present"])
        self.assertEqual(receipt["internal_failure_class_sha256"],
                         pm.evidence_digest("failure-class", "ValueError"))
        self.assertFalse(receipt["internal_failure_class_oversize"])
        self.assertNotIn("ValueError", json.dumps(receipt))

    def test_three_targets_three_receipts_independent_classifications(self):
        """A non-object 2xx used to raise `AttributeError` and end the run."""
        import subprocess
        import sys as _sys

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reg = root / "registry.json"
            reg.write_text(json.dumps({"schema": pm.REGISTRY_SCHEMA, "providers": {
                "p": {"api_base": "https://x/v1", "api_style": "openai-chat", "key_env": "K"},
            }}), encoding="utf-8")
            source = root / "source.json"
            source.write_text(json.dumps([
                {"provider": "p", "model": "bad-json", "free_tier": "yes"},
                {"provider": "p", "model": "good", "free_tier": "yes"},
                {"provider": "p", "model": "http-fail", "free_tier": "yes"},
            ]), encoding="utf-8")

            here = Path(__file__).resolve().parent
            catalog, plan, out = root / "catalog.json", root / "plan.json", root / "probes"
            run = lambda *a: subprocess.run(  # noqa: E731
                [_sys.executable, str(here / "provider_matrix.py"), *a],
                capture_output=True, text=True,
            )
            self.assertEqual(run("import", "--source", str(source), "--observed-at",
                                 "2026-07-29T00:00:00Z", "--out", str(catalog),
                                 "--registry", str(reg)).returncode, 0)
            self.assertEqual(run("plan", "--catalog", str(catalog), "--out", str(plan),
                                 "--free-only").returncode, 0)

            # Three targets, three fates, one process.
            replies = {
                "p--bad-json": (200, b"[]", "", "completed"),
                "p--good": (200, json.dumps({"model": "good", "choices": [
                    {"message": {"content": "QODEC_PROBE_OK"}}]}).encode(), "", "completed"),
                "p--http-fail": (503, b"{}", "", "completed"),
            }
            plan_obj = pm.read_json(plan)
            out.mkdir()
            for tgt in plan_obj["selected"]:
                receipt = pm.guarded_receipt(pm.PROBE_SCHEMA, tgt, lambda t=tgt: pm.probe_target(
                    t, 1, scripted([replies[t["target_id"]]]), pm.load_registry(reg)))
                pm.write_json(out / pm.receipt_filename(tgt["target_id"]), receipt)

            written = sorted(p.name for p in out.glob("*.json"))
            self.assertEqual(len(written), 3, written)
            got = {pm.read_json(p)["target_id"]: pm.read_json(p)["classification"]
                   for p in out.glob("*.json")}
            self.assertEqual(got, {
                "p--bad-json": "INVALID_OUTPUT",
                "p--good": "PASS",
                "p--http-fail": "PROVIDER_5XX",
            })

    def test_a_non_object_2xx_no_longer_raises(self):
        for body in (b"[]", b"null", b"5", b'"text"'):
            result = pm.probe_target(probe_row({}), 1, scripted([(200, body, "", "completed")]), registry())
            self.assertEqual(result["classification"], "INVALID_OUTPUT", body)


class RegistryValidationTests(unittest.TestCase):
    """A caller-supplied dict takes the same path as the committed file."""

    def normalized(self, providers):
        return pm.normalize_registry({"schema": pm.REGISTRY_SCHEMA, "providers": providers})

    def test_a_non_string_authority_claim_is_refused(self):
        for bad in ({"host": "steal.example"}, ["OTHER_KEY"], 42, None, True):
            with self.assertRaises(pm.EndpointRejected, msg=repr(bad)):
                pm.normalize_target({"provider": "p", "model": "m", "api_base": bad}, registry())

    def test_an_absent_authority_field_is_allowed(self):
        row = pm.normalize_target({"provider": "p", "model": "m"}, registry())
        self.assertEqual(row["api_base"], "https://x/v1")

    def test_an_exactly_matching_authority_field_is_allowed(self):
        row = pm.normalize_target(
            {"provider": "p", "model": "m", "api_base": "https://x/v1", "key_env": "K"}, registry())
        self.assertEqual(row["key_env"], "K")

    def test_unknown_registry_fields_are_refused(self):
        with self.assertRaisesRegex(ValueError, "unknown registry fields"):
            pm.normalize_registry({"schema": pm.REGISTRY_SCHEMA, "providers": {}, "extra": 1})
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            self.normalized({"p": {"api_base": "https://x/v1", "api_style": "openai-chat",
                                   "key_env": "K", "note": "hi"}})

    def test_an_implausible_key_env_is_refused(self):
        with self.assertRaisesRegex(ValueError, "key_env"):
            self.normalized({"p": {"api_base": "https://x/v1", "api_style": "openai-chat",
                                   "key_env": "rm -rf /"}})

    def test_a_non_lowercase_provider_name_is_refused(self):
        with self.assertRaisesRegex(ValueError, "lowercase"):
            self.normalized({"Groq": {"api_base": "https://x/v1", "api_style": "openai-chat", "key_env": "K"}})

    def test_a_duplicate_provider_key_in_the_file_is_refused(self):
        """`json.loads` keeps the last of two identical keys, silently."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "registry.json"
            path.write_text(
                '{"schema": "%s", "providers": {'
                '"p": {"api_base": "https://a/v1", "api_style": "openai-chat", "key_env": "K"},'
                '"p": {"api_base": "https://steal.example/v1", "api_style": "openai-chat", "key_env": "K"}}}'
                % pm.REGISTRY_SCHEMA, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate key"):
                pm.load_registry(path)

    def test_normalization_returns_a_fresh_object(self):
        """Nothing downstream holds a reference somebody else can still mutate."""
        raw = registry()
        norm = pm.normalize_registry(raw)
        raw["providers"]["p"]["api_base"] = "https://steal.example/v1"
        self.assertEqual(norm["providers"]["p"]["api_base"], "https://x/v1")

    def test_the_committed_registry_normalizes_to_itself(self):
        loaded = pm.load_registry()
        self.assertEqual(pm.normalize_registry(loaded), loaded)


class DuplicateJsonKeyTests(unittest.TestCase):
    """`json.loads` resolves a repeated key by document order, silently.

    That silence is a tamper channel. A row naming `api_base` twice arrives at
    `bind_to_registry` as one agreeing value, so "every authority value that is
    present is checked" holds only because the check never sees the hostile one.
    Detection is possible while parsing text and nowhere after: by the time JSON
    is a dict, Python has already discarded the losing value.
    """

    def source(self, body: str) -> Path:
        path = Path(self._td.name) / "source.json"
        path.write_text(body, encoding="utf-8")
        return path

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)

    def test_python_really_does_keep_the_last_one(self):
        """The premise, stated as a test so it cannot quietly stop being true."""
        self.assertEqual(json.loads('{"a": 1, "a": 2}'), {"a": 2})

    def test_a_duplicated_api_base_in_a_source_row_is_refused(self):
        body = ('[{"provider":"groq","model":"m",'
                '"api_base":"https://steal.example/v1",'
                '"api_base":"https://api.groq.com/openai/v1"}]')
        with self.assertRaisesRegex(pm.DuplicateJsonKey, "api_base"):
            pm.import_catalog(self.source(body), "2026-07-29T00:00:00Z")

    def test_a_duplicated_key_env_in_a_source_row_is_refused(self):
        body = ('[{"provider":"groq","model":"m",'
                '"key_env":"ANTHROPIC_API_KEY","key_env":"GROQ_API_KEY"}]')
        with self.assertRaisesRegex(pm.DuplicateJsonKey, "key_env"):
            pm.import_catalog(self.source(body), "2026-07-29T00:00:00Z")

    def test_a_duplicated_provider_or_model_is_refused(self):
        for field in ("provider", "model"):
            body = '[{"provider":"groq","model":"m","%s":"shadow"}]' % field
            with self.assertRaises(pm.DuplicateJsonKey, msg=field):
                pm.import_catalog(self.source(body), "2026-07-29T00:00:00Z")

    def test_a_duplicated_authority_field_in_a_plan_is_refused(self):
        path = Path(self._td.name) / "plan.json"
        path.write_text(
            '{"schema": "%s", "identity": {}, "plan_sha256": "x", "rejected": [],'
            ' "selected": [{"target_id":"groq--m","provider":"groq","model":"m",'
            '"api_style":"openai-chat","key_env":"GROQ_API_KEY",'
            '"api_base":"https://steal.example/v1",'
            '"api_base":"https://api.groq.com/openai/v1"}]}' % pm.PLAN_SCHEMA,
            encoding="utf-8")
        with self.assertRaisesRegex(pm.DuplicateJsonKey, "api_base"):
            pm.read_json(path)

    def test_the_surface_and_the_registry_share_the_one_loader(self):
        for name, loader in (("surface", pm.load_surface), ("registry", pm.load_registry)):
            path = Path(self._td.name) / f"{name}.json"
            path.write_text('{"schema": "x", "schema": "y"}', encoding="utf-8")
            with self.assertRaises(pm.DuplicateJsonKey, msg=name):
                loader(path)

    def test_only_the_http_error_body_stays_lenient(self):
        """The line is *decides* versus *describes*, not ours versus theirs.

        An error body is read to pick a local reason code; it never becomes a
        tool call and cannot earn a PASS, so refusing to read a sloppy one would
        turn the provider's untidiness into our transport failure. A successful
        completion is the opposite: its `model` settles identity.
        """
        sloppy_error = b'{"error": {"message": "no", "message": "really no"}}'
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted([(429, sloppy_error, "")]))
        self.assertEqual(receipt["classification"], "RATE_LIMITED")


class ExplicitSendStageTests(unittest.TestCase):
    """A stage supplied by hand is a claim, not a credential."""

    def test_every_stage_declares_its_shape(self):
        self.assertEqual(set(pm.SEND_STAGE_SHAPES), {
            "before-response", "no-credential", "response-framing",
            "after-headers", "completed",
        })

    def test_every_failing_stage_has_a_cause_and_an_outcome(self):
        """A stage nobody classified falls through to a default that is a guess.

        `STAGE_CAUSE.get(stage, "UNAVAILABLE")` is the fallback, and
        `UNAVAILABLE` asserts the request may never have been served — the one
        thing a new failure stage is least likely to mean.
        """
        failing = set(pm.SEND_STAGE_SHAPES) - {"completed"}
        self.assertEqual(failing - set(pm.STAGE_CAUSE), set())
        self.assertEqual(failing - set(pm.STAGE_OUTCOME), set())
        for cause in pm.STAGE_CAUSE.values():
            self.assertIn(cause, pm.CLASSIFICATIONS)

    def test_a_consistent_result_survives_every_input_form(self):
        for value in (
            pm.SendResult(200, b"{}", "", "completed"),
            (200, b"{}", "", "completed"),
            (200, b"{}"),
            (None, None, "refused"),
            (503, None, "lost"),
        ):
            self.assertIsInstance(pm.as_send_result(value), pm.SendResult)

    def test_an_explicit_stage_cannot_promote_a_lost_body(self):
        """The defect: only legacy tuples had their stage inferred and checked.

        `(503, None, "lost", "completed")` walked past the inference entirely
        and was treated as a successful exchange — the same promotion the table
        exists to prevent, arriving through the front door.
        """
        with self.assertRaisesRegex(ValueError, "completed"):
            pm.as_send_result((503, None, "lost", "completed"))

    def test_an_explicit_after_headers_still_needs_a_status(self):
        """`status is None` means no headers arrived. It cannot mean anything else."""
        with self.assertRaisesRegex(ValueError, "after-headers"):
            pm.as_send_result(pm.SendResult(None, None, "x", "after-headers"))
        with self.assertRaisesRegex(ValueError, "after-headers"):
            pm.as_send_result((None, None, "x", "after-headers"))

    def test_a_before_response_result_cannot_carry_a_status_or_a_body(self):
        for bad in ((200, None, "x", "before-response"), (None, b"{}", "x", "before-response")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                pm.as_send_result(bad)

    def test_a_completed_result_cannot_lack_a_body(self):
        with self.assertRaises(ValueError):
            pm.as_send_result(pm.SendResult(200, None, "", "completed"))

    def test_an_unknown_stage_is_refused(self):
        with self.assertRaisesRegex(ValueError, "unknown send stage"):
            pm.as_send_result((200, b"{}", "", "probably-fine"))

    def test_the_real_transport_only_produces_valid_results(self):
        """`send_json`'s own outputs must satisfy the table, not just the tests."""
        err = urllib.error.HTTPError(
            "https://api.example/v1", 500, "boom", {}, io.BytesIO(b"z" * 300))
        with patch.object(pm._OPENER, "open", side_effect=err):
            lost = pm.send_json("https://api.example/v1", b"{}", "k", 1, limit=100)
        self.assertEqual(pm.validate_send_result(lost), lost)

        with patch.object(pm._OPENER, "open", side_effect=urllib.error.URLError("refused")):
            refused = pm.send_json("https://api.example/v1", b"{}", "k", 1)
        self.assertEqual(pm.validate_send_result(refused), refused)

        no_key = pm.send_json("https://api.example/v1", b"{}", "bad\nkey", 1)
        self.assertEqual(pm.validate_send_result(no_key), no_key)


class DecidingResponsesAreStrictTests(unittest.TestCase):
    """A successful completion decides identity; its arguments are the tool call.

    `strict_json_loads` first covered only documents we author or plan with, on
    the reasoning that a provider response is "just evidence". That was wrong:
    `model` settles whether a target may PASS, and `function.arguments` is the
    call being qualified. A field stated twice makes both ambiguous, and Python
    resolves the ambiguity by document order.
    """

    def qualify(self, body: bytes):
        return pm.qualify_target(target(), surface(), 30.0, 6, scripted([(200, body, "")]))

    def test_a_completion_naming_the_model_twice_is_invalid_output(self):
        """`{"model": "wrong", "model": "requested"}` used to report `verified`."""
        body = ('{"model":"wrong-model","model":"openai/gpt-oss-120b","choices":'
                '[{"message":{"role":"assistant","tool_calls":[]}}]}').encode()
        receipt = self.qualify(body)
        self.assertEqual(receipt["classification"], "INVALID_OUTPUT")
        self.assertNotEqual(receipt["model_status"], "verified")

    def test_a_completion_naming_choices_twice_is_invalid_output(self):
        body = ('{"model":"openai/gpt-oss-120b","choices":[],"choices":'
                '[{"message":{"role":"assistant","tool_calls":[]}}]}').encode()
        self.assertEqual(self.qualify(body)["classification"], "INVALID_OUTPUT")

    def test_a_message_naming_tool_calls_twice_is_invalid_output(self):
        inner = json.dumps(call("qodec_intersect", INTERSECT_ARGS, "c1"))
        body = ('{"model":"openai/gpt-oss-120b","choices":[{"message":{"role":"assistant",'
                '"tool_calls":[],"tool_calls":[%s]}}]}' % inner).encode()
        self.assertEqual(self.qualify(body)["classification"], "INVALID_OUTPUT")

    def test_a_probe_completion_naming_the_model_twice_is_invalid_output(self):
        body = ('{"model":"wrong-model","model":"m","choices":'
                '[{"message":{"content":"QODEC_PROBE_OK"}}]}').encode()
        result = pm.probe_target(probe_row({}), 1, scripted([(200, body, "", "completed")]), registry())
        self.assertNotEqual(result["classification"], "PASS")
        self.assertEqual(result["classification"], "INVALID_OUTPUT")

    def test_arguments_naming_a_field_twice_are_malformed(self):
        for arguments in (
            '{"handle":"invented","handle":"sha256:%s",'
            '"answer":{"encoding":"base64url-nopad","data":"YWxwaGE"},"cited":[]}' % ("0" * 64),
            '{"handle":"sha256:%s",'
            '"answer":{"encoding":"base64url-nopad","data":"invalid","data":"YWxwaGE"},'
            '"cited":[]}' % ("0" * 64),
        ):
            receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted(
                OPERATION_THEN((200, completion([call("qodec_answer", arguments, "call_ans")]), ""))))
            self.assertEqual(receipt["classification"], "MALFORMED_TOOL_ARGUMENTS", arguments)
            self.assertIn("twice", receipt["detail"])

    def test_the_ambiguous_answer_never_reaches_grading(self):
        """Both spellings would otherwise be graded on the surviving one."""
        arguments = ('{"handle":"invented","handle":"sha256:%s","answer":'
                     '{"encoding":"base64url-nopad","data":"YWxwaGE"},"cited":'
                     '[{"store":"sha256:%s","section":"attempt_1","ordinal":0}]}' % ("0" * 64, "0" * 64))
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted(
            OPERATION_THEN((200, completion([call("qodec_answer", arguments, "call_ans")]), ""))))
        self.assertNotEqual(receipt["classification"], "PASS")
        self.assertNotEqual(receipt["classification"], "CANARY_ANSWER_MISMATCH")
        self.assertEqual(receipt["classification"], "MALFORMED_TOOL_ARGUMENTS")


class SendResultTypeTests(unittest.TestCase):
    """The table says `status=int, body=bytes`. That is what gets checked."""

    def test_a_string_status_is_refused(self):
        with self.assertRaisesRegex(ValueError, "100..599"):
            pm.as_send_result(("503", None, "lost", "after-headers"))

    def test_a_bool_status_is_refused(self):
        """`bool` subclasses `int`, and `True == 1`, with great confidence."""
        self.assertIsInstance(True, int)
        with self.assertRaisesRegex(ValueError, "100..599"):
            pm.as_send_result((True, b"{}", "", "completed"))

    def test_a_status_outside_the_http_range_is_refused(self):
        for status in (0, 99, 600, 1000, -200):
            with self.assertRaises(ValueError, msg=status):
                pm.as_send_result((status, b"{}", "", "completed"))

    def test_a_non_bytes_body_is_refused(self):
        for body in ("not bytes", bytearray(b"{}"), memoryview(b"{}"), ["{}"]):
            with self.assertRaises(ValueError, msg=repr(body)):
                pm.as_send_result((200, body, "", "completed"))

    def test_a_negative_or_non_int_observed_count_is_refused(self):
        for observed in (-1, -4096, "9", 1.5, True):
            with self.assertRaises(ValueError, msg=repr(observed)):
                pm.as_send_result((200, b"{}", "", "completed", observed))
        # On `after-headers` there is no body to compare a count against, so the
        # range check is the only thing standing between a receipt and a
        # negative number of bytes.
        for observed in (-1, -4096, "9", 1.5, True):
            with self.assertRaises(ValueError, msg=f"after-headers {observed!r}"):
                pm.as_send_result((503, None, "lost", "after-headers", observed))
        self.assertEqual(pm.as_send_result((503, None, "lost", "after-headers", 0)).body_bytes_observed, 0)

    def test_a_non_string_request_id_is_refused(self):
        with self.assertRaisesRegex(ValueError, "request_id"):
            pm.as_send_result((200, b"{}", "", "completed", 2, 12345))

    def test_the_valid_shapes_are_still_accepted(self):
        for good in (
            (200, b"{}", "", "completed", 2, "req-1"),
            (503, None, "lost", "after-headers", 4096, None),
            (None, None, "refused", "before-response"),
            (None, None, "missing env K", "no-credential"),
            (100, b"", "", "completed", 0, "req-2"),
            (599, b"x", "", "completed"),
        ):
            self.assertIsInstance(pm.as_send_result(good), pm.SendResult, repr(good))

    def test_the_real_transport_still_satisfies_the_types(self):
        class Response:
            status = 200
            headers = {"x-request-id": "req-7"}

            def read(self, size=-1):
                return b'{"ok":1}'

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with patch.object(pm._OPENER, "open", side_effect=lambda *a, **k: Response()):
            sent = pm.send_json("https://api.example/v1", b"{}", "k", 1)
        self.assertEqual(pm.validate_send_result(sent), sent)
        self.assertIs(type(sent.status), int)
        self.assertIs(type(sent.body), bytes)


class JsonEncodingTests(unittest.TestCase):
    """`json.loads` sniffs encodings. The consumer of a PASS does not.

    Passing bytes straight to `json.loads` accepts UTF-16, UTF-32 and a UTF-8
    BOM. `serde_json::from_slice` — what the adapter will use — accepts none of
    them, so sniffing here would qualify a body the mapper refuses: the same
    liberality as before, moved from structure to encoding. And
    `UnicodeDecodeError` was in no except tuple, so a broken 2xx surfaced as
    `INTERNAL_ERROR` — blaming the matrix for what the provider sent.
    """

    BODY = '{"model":"openai/gpt-oss-120b","choices":[{"message":{"role":"assistant","tool_calls":[]}}]}'

    def qualify(self, raw: bytes):
        return pm.qualify_target(target(), surface(), 30.0, 6, scripted([(200, raw, "")]))

    def test_the_policy_is_the_consumers_measured_behaviour(self):
        """Pinned so a change here has to be a decision, not a drift.

        Measured against `serde_json::from_slice`, which the crate uses for
        every provider body: utf-8 Ok, utf-8+BOM Err, utf-16 Err, broken Err.
        """
        self.assertEqual(pm.strict_json_loads(b'{"a":1}', "x"), {"a": 1})
        for raw in (b"\xef\xbb\xbf" + b'{"a":1}',
                    '{"a":1}'.encode("utf-16"),
                    '{"a":1}'.encode("utf-32"),
                    b'{"a":"\xff\xfe"}'):
            with self.assertRaises(pm.InvalidJsonEncoding, msg=repr(raw[:8])):
                pm.strict_json_loads(raw, "x")

    def test_a_utf8_completion_still_passes_through(self):
        receipt = self.qualify(self.BODY.encode("utf-8"))
        self.assertEqual(receipt["classification"], "NO_TERMINAL_ANSWER")
        self.assertEqual(receipt["model_status"], "verified")

    def test_a_broken_utf8_completion_is_invalid_output_not_internal_error(self):
        """The provider sent it. That is not a defect in the matrix."""
        receipt = self.qualify(b'{"model":"m","choices":"\xff\xfe"}')
        self.assertEqual(receipt["classification"], "INVALID_OUTPUT")
        self.assertNotEqual(receipt["classification"], "INTERNAL_ERROR")

    def test_utf16_and_utf32_completions_are_invalid_output(self):
        for encoding in ("utf-16", "utf-32", "utf-16-le", "utf-16-be"):
            receipt = self.qualify(self.BODY.encode(encoding))
            self.assertEqual(receipt["classification"], "INVALID_OUTPUT", encoding)

    def test_a_bom_prefixed_completion_is_invalid_output(self):
        receipt = self.qualify(b"\xef\xbb\xbf" + self.BODY.encode("utf-8"))
        self.assertEqual(receipt["classification"], "INVALID_OUTPUT")

    def test_the_probe_applies_the_same_rule(self):
        good = b'{"model":"m","choices":[{"message":{"content":"QODEC_PROBE_OK"}}]}'
        self.assertEqual(
            pm.probe_target(probe_row({}), 1, scripted([(200, good, "", "completed")]), registry())["classification"],
            "PASS")
        for raw in (b"\xef\xbb\xbf" + good, good.decode().encode("utf-16"), b'{"model":"\xff\xfe"}'):
            result = pm.probe_target(probe_row({}), 1, scripted([(200, raw, "", "completed")]), registry())
            self.assertEqual(result["classification"], "INVALID_OUTPUT", repr(raw[:8]))

    def test_badly_encoded_tool_arguments_are_malformed_not_a_crash(self):
        """`function.arguments` reaches the loader as a `str`, already decoded.

        The strings a JSON parser produces are always valid Unicode, so the
        encoding branch cannot fire here — but a lone surrogate can still be
        spelled with `\\ud800`, and that must not escape as an encoding crash.
        """
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted(
            OPERATION_THEN((200, completion([call("qodec_answer", '"\\ud800"', "call_ans")]), ""))))
        self.assertEqual(receipt["classification"], "MALFORMED_TOOL_ARGUMENTS")

    def test_the_http_error_body_is_still_read_whatever_its_encoding(self):
        """It picks a reason code and can never earn a PASS."""
        for raw in ('{"error":{"message":"тише"}}'.encode("utf-16"), b'{"error":\xff\xfe}'):
            receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted([(429, raw, "")]))
            self.assertEqual(receipt["classification"], "RATE_LIMITED", repr(raw[:8]))


class JsonAdmissionParityTests(unittest.TestCase):
    """`json.loads` is not a JSON parser; it is a parser for a superset.

    It admits `NaN`, `Infinity`, `-Infinity`, turns `1e400` into `inf`, and
    accepts an unpaired `\\ud800`. `serde_json::from_slice::<Value>` — which the
    adapter runs over the *whole* body before reading a field — refuses all of
    them. So `{"model": "m", "choices": [...], "unread": NaN}` yields a model
    and tool calls here, and nothing at all there: a PASS for a target the
    consumer cannot talk to.

    The corpus carries a frozen `consumer_admits` per case, measured by running
    real `serde_json`. `check_json_admission.py` re-measures it in CI so the
    frozen value cannot rot; these tests use it so parity is still checked when
    no Rust toolchain is present.
    """

    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parent / "json-admission-corpus.json"
        cls.cases = json.loads(path.read_text(encoding="utf-8"))["cases"]

    def admits(self, raw: bytes) -> bool:
        try:
            pm.strict_json_loads(raw, "case")
        except (pm.StrictJsonError, json.JSONDecodeError):
            return False
        return True

    def test_the_gate_admits_nothing_the_consumer_refuses(self):
        """One-directional, and that is the whole contract.

        Stricter is a choice — duplicate keys are admitted by `serde_json` and
        refused here because a repeated key is a tamper channel. More liberal is
        a false PASS.
        """
        liberal = [c["name"] for c in self.cases
                   if self.admits(bytes.fromhex(c["hex"])) and not c["consumer_admits"]]
        self.assertEqual(liberal, [], f"the gate admits what the consumer refuses: {liberal}")

    def test_the_only_deliberate_strictness_is_duplicate_keys(self):
        stricter = [c["name"] for c in self.cases
                    if c["consumer_admits"] and not self.admits(bytes.fromhex(c["hex"]))]
        self.assertEqual(stricter, ["duplicate-keys"])

    def test_the_corpus_covers_the_cases_that_matter(self):
        """A vacuous parity proof is not one."""
        names = {c["name"] for c in self.cases}
        self.assertLessEqual({
            "nan", "infinity", "negative-infinity", "nan-in-an-unread-field",
            "float-overflow", "negative-float-overflow",
            "lone-leading-surrogate", "lone-trailing-surrogate",
            "lone-surrogate-in-a-key", "lone-surrogate-nested",
            "valid-surrogate-pair", "u64-max", "u64-max-plus-one",
            "i64-min", "i64-min-minus-one", "integer-far-past-u64",
            "duplicate-keys", "utf8-bom", "utf16le-with-bom", "broken-utf8",
        }, names)
        self.assertTrue(any(c["consumer_admits"] for c in self.cases))
        self.assertTrue(any(not c["consumer_admits"] for c in self.cases))

    def test_a_completion_carrying_nan_in_an_unread_field_does_not_pass(self):
        """The concrete false PASS. Nothing here reads `unread`."""
        body = b'{"model":"openai/gpt-oss-120b","choices":[{"message":{"role":"assistant","tool_calls":[]}}],"unread":NaN}'
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted([(200, body, "")]))
        self.assertEqual(receipt["classification"], "INVALID_OUTPUT")
        self.assertNotEqual(receipt["model_status"], "verified")

    def test_a_lone_surrogate_in_a_tool_call_id_does_not_pass(self):
        """A field the canary treats as an ordinary non-empty string.

        Rust `String` cannot hold it, so `serde_json` refuses the body outright
        — long before anything asks whether the id is non-empty.
        """
        body = ('{"model":"openai/gpt-oss-120b","choices":[{"message":{"role":"assistant",'
                '"tool_calls":[{"id":"\\ud800","type":"function","function":'
                '{"name":"qodec_intersect","arguments":%s}}]}}]}' % json.dumps(INTERSECT_ARGS)).encode()
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted([(200, body, "")]))
        self.assertEqual(receipt["classification"], "INVALID_OUTPUT")

    def test_big_integers_are_admitted_by_both(self):
        """Measured, not assumed: `serde_json` falls back to `f64` rather than refusing.

        An earlier plan called for rejecting integers past `u64::MAX`. The
        oracle says otherwise, so the gate does not invent a rule the consumer
        does not have — being stricter is only free when it is deliberate.
        """
        for name in ("u64-max-plus-one", "i64-min-minus-one", "integer-far-past-u64"):
            case = next(c for c in self.cases if c["name"] == name)
            self.assertTrue(case["consumer_admits"], name)
            self.assertTrue(self.admits(bytes.fromhex(case["hex"])), name)

    def test_non_finite_numbers_in_tool_arguments_are_malformed(self):
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted(
            OPERATION_THEN((200, completion([call("qodec_answer", '{"handle":NaN}', "call_ans")]), ""))))
        self.assertEqual(receipt["classification"], "MALFORMED_TOOL_ARGUMENTS")
        self.assertIn("not acceptable JSON", receipt["detail"])

    def test_the_http_error_body_may_still_carry_anything(self):
        receipt = pm.qualify_target(target(), surface(), 30.0, 6,
                                    scripted([(429, b'{"error":{"message":NaN}}', "")]))
        self.assertEqual(receipt["classification"], "RATE_LIMITED")


class JsonRecursionDepthTests(unittest.TestCase):
    """Parity over a finite corpus is a sample, not a proof — depth was missing.

    `serde_json`'s deserializer starts with a remaining depth of 128 and returns
    `RecursionLimitExceeded` when it runs out; the oracle puts the boundary at
    127 admitted, 128 refused. Python's decoder admits far more and then raises
    `RecursionError`, which is not a `ValueError` and so would escape every
    except tuple and be filed as `INTERNAL_ERROR` — blaming the matrix for a
    body the provider sent.
    """

    def nested(self, kind: str, depth: int) -> str:
        if kind == "array":
            return "[" * depth + "]" * depth
        return '{"a":' * depth + "1" + "}" * depth

    def test_the_boundary_is_the_measured_one(self):
        for kind in ("array", "object"):
            pm.strict_json_loads(self.nested(kind, pm.MAX_JSON_DEPTH), "case")
            with self.assertRaises(pm.UnadmittedJsonValue, msg=kind):
                pm.strict_json_loads(self.nested(kind, pm.MAX_JSON_DEPTH + 1), "case")

    def test_depth_is_measured_before_parsing(self):
        """Otherwise Python's own decoder overflows before we can decide."""
        for depth in (1_000, 5_000, 20_000):
            with self.assertRaises(pm.UnadmittedJsonValue, msg=depth):
                pm.strict_json_loads(self.nested("array", depth), "case")

    def test_the_surrogate_walk_does_not_recurse(self):
        """A check that itself overflows has swapped one crash for another."""
        deep: Any = "x"
        for _ in range(20_000):
            deep = [deep]
        pm._refuse_lone_surrogates(deep)

    def test_brackets_inside_strings_do_not_nest(self):
        self.assertEqual(pm.json_nesting_depth('{"a":"[[[[["}'), 1)
        self.assertEqual(pm.json_nesting_depth(r'{"a":"\""}'), 1)
        self.assertEqual(pm.json_nesting_depth('[[["]]]"]]]'), 3)
        self.assertEqual(pm.json_nesting_depth('{"a":[1,{"b":2}]}'), 3)

    def test_a_deep_value_in_an_unread_field_does_not_pass(self):
        """The concrete false PASS. Nothing here reads `unread`."""
        body = (b'{"model":"openai/gpt-oss-120b","choices":[{"message":{"role":"assistant",'
                b'"tool_calls":[]}}],"unread":' + b"[" * 128 + b"]" * 128 + b"}")
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted([(200, body, "")]))
        self.assertEqual(receipt["classification"], "INVALID_OUTPUT")
        self.assertNotEqual(receipt["model_status"], "verified")

    def test_a_shallow_value_in_an_unread_field_still_passes_through(self):
        body = (b'{"model":"openai/gpt-oss-120b","choices":[{"message":{"role":"assistant",'
                b'"tool_calls":[]}}],"unread":' + b"[" * 120 + b"]" * 120 + b"}")
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted([(200, body, "")]))
        self.assertEqual(receipt["classification"], "NO_TERMINAL_ANSWER")
        self.assertEqual(receipt["model_status"], "verified")

    def test_deep_tool_arguments_are_malformed(self):
        arguments = "[" * 128 + "]" * 128
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted(
            OPERATION_THEN((200, completion([call("qodec_answer", arguments, "call_ans")]), ""))))
        self.assertEqual(receipt["classification"], "MALFORMED_TOOL_ARGUMENTS")
        self.assertIn("UnadmittedJsonValue", receipt["detail"])
        self.assertNotIn("nested", receipt["detail"])

    def test_the_probe_applies_the_depth_rule_too(self):
        body = (b'{"model":"m","choices":[{"message":{"content":"QODEC_PROBE_OK"}}],"unread":'
                + b"[" * 128 + b"]" * 128 + b"}")
        result = pm.probe_target(probe_row({}), 1, scripted([(200, body, "", "completed")]), registry())
        self.assertEqual(result["classification"], "INVALID_OUTPUT")


class JsonIntegerRangeTests(unittest.TestCase):
    """`parse_int` was left standard while `parse_float` was replaced.

    `serde_json` keeps an integer while it fits `u64`/`i64`, falls back to
    `f64` past that, and refuses only when the fallback overflows. Python hands
    every integer literal to `int()`, which is unbounded — so a 400-digit number
    parsed here and sank the whole body there.
    """

    def qualify(self, raw: bytes):
        return pm.qualify_target(target(), surface(), 30.0, 6, scripted([(200, raw, "")]))

    def test_moderately_out_of_range_integers_are_still_admitted(self):
        """Measured. A rule banning "anything past u64" would be an invention."""
        for literal in ("18446744073709551616", "-9223372036854775809",
                        "10000000000000000000000000000000"):
            self.assertEqual(pm.strict_json_loads('{"a":%s}' % literal, "case"),
                             {"a": int(literal)}, literal)

    def test_the_boundary_is_the_fallback_not_the_digit_count(self):
        """308 nines pass; 1 with 308 zeros is longer and also passes; 309 nines do not."""
        pm.strict_json_loads('{"a":%s}' % ("9" * 308), "case")
        pm.strict_json_loads('{"a":1%s}' % ("0" * 308), "case")
        with self.assertRaises(pm.UnadmittedJsonValue):
            pm.strict_json_loads('{"a":%s}' % ("9" * 309), "case")
        with self.assertRaises(pm.UnadmittedJsonValue):
            pm.strict_json_loads('{"a":1%s}' % ("0" * 309), "case")

    def test_the_negative_side_is_refused_too(self):
        with self.assertRaises(pm.UnadmittedJsonValue):
            pm.strict_json_loads('{"a":-%s}' % ("9" * 309), "case")

    def test_a_literal_past_pythons_int_limit_does_not_escape(self):
        """`int()` refuses past `sys.get_int_max_str_digits()` with a bare `ValueError`.

        Not a `JSONDecodeError`, so it would escape every except tuple and be
        filed as `INTERNAL_ERROR`. The float check runs first for that reason.
        """
        self.assertLess(sys.get_int_max_str_digits(), 5000)
        with self.assertRaises(pm.UnadmittedJsonValue):
            pm.strict_json_loads('{"a":%s}' % ("9" * 5000), "case")

    def test_a_huge_integer_in_an_unread_field_does_not_pass(self):
        body = (b'{"model":"openai/gpt-oss-120b","choices":[{"message":{"role":"assistant",'
                b'"tool_calls":[]}}],"unread":' + b"9" * 400 + b"}")
        receipt = self.qualify(body)
        self.assertEqual(receipt["classification"], "INVALID_OUTPUT")
        self.assertNotEqual(receipt["model_status"], "verified")

    def test_a_large_finite_integer_in_an_unread_field_still_passes_through(self):
        body = (b'{"model":"openai/gpt-oss-120b","choices":[{"message":{"role":"assistant",'
                b'"tool_calls":[]}}],"unread":' + b"9" * 100 + b"}")
        receipt = self.qualify(body)
        self.assertEqual(receipt["classification"], "NO_TERMINAL_ANSWER")
        self.assertEqual(receipt["model_status"], "verified")

    def test_a_huge_integer_in_tool_arguments_is_malformed(self):
        arguments = '{"handle":%s}' % ("9" * 400)
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted(
            OPERATION_THEN((200, completion([call("qodec_answer", arguments, "call_ans")]), ""))))
        self.assertEqual(receipt["classification"], "MALFORMED_TOOL_ARGUMENTS")
        self.assertIn("not acceptable JSON", receipt["detail"])

    def test_the_probe_applies_the_integer_rule_too(self):
        body = (b'{"model":"m","choices":[{"message":{"content":"QODEC_PROBE_OK"}}],"unread":'
                + b"9" * 400 + b"}")
        result = pm.probe_target(probe_row({}), 1, scripted([(200, body, "", "completed")]), registry())
        self.assertEqual(result["classification"], "INVALID_OUTPUT")


class ProviderControlledFailureTests(unittest.TestCase):
    """Every path over untrusted bytes must end in a local classification.

    `INTERNAL_ERROR` means *this tool* is broken. Using it for anything the
    provider chose to send blames the matrix for the wire, and the exceptions
    that get there are the ones nobody thought to catch because they are not
    `ValueError`.
    """

    def truncating_response(self):
        class Truncated:
            status = 200
            headers = {"x-request-id": "req-truncated"}

            def read(self, size=-1):
                # The genuine article, not a stand-in: `IncompleteRead` derives
                # from `HTTPException`, which is the whole point.
                raise http.client.IncompleteRead(b"partial body", 500)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        return Truncated()

    def test_a_truncated_body_is_an_after_headers_loss(self):
        with patch.object(pm._OPENER, "open", side_effect=lambda *a, **k: self.truncating_response()):
            sent = pm.send_json("https://api.example/v1", b"{}", "k", 1)
        self.assertEqual(sent.stage, "after-headers")
        self.assertEqual(sent.status, 200)
        self.assertIsNone(sent.body, "a truncated body is not a body")
        self.assertEqual(sent.body_bytes_observed, len(b"partial body"))
        self.assertEqual(sent.request_id, "req-truncated")
        self.assertEqual(pm.validate_send_result(sent), sent)

    def test_a_truncated_error_body_keeps_its_status(self):
        err = urllib.error.HTTPError("https://api.example/v1", 429, "slow", {}, io.BytesIO(b""))
        err.read = lambda *a: (_ for _ in ()).throw(http.client.IncompleteRead(b"half", 99))
        with patch.object(pm._OPENER, "open", side_effect=err):
            sent = pm.send_json("https://api.example/v1", b"{}", "k", 1)
        self.assertEqual((sent.stage, sent.status), ("after-headers", 429))
        self.assertEqual(sent.body_bytes_observed, 4)

    def test_a_truncated_body_classifies_rather_than_crashing(self):
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted(
            [(200, None, "IncompleteRead(12 bytes read)", "after-headers", 12, "req-x")]))
        self.assertEqual(receipt["classification"], "RESPONSE_CAPTURE_FAILED")
        self.assertNotEqual(receipt["classification"], "INTERNAL_ERROR")
        self.assertEqual(receipt["turns"][0]["http_status"], 200)

    # -- the lenient error-body reader is total --

    def test_the_lenient_reader_never_raises(self):
        """Contract: any bytes in, a bool out. It is the one lenient parse."""
        for name, body in (
            ("huge integer", b'{"error":{"message":"x"},"pad":' + b"9" * 5000 + b"}"),
            ("deep nesting", b'{"error":' + b"[" * 400 + b"]" * 400 + b"}"),
            ("very deep nesting", b"[" * 40_000 + b"]" * 40_000),
            ("broken utf-8", b'{"error":"\xff\xfe"}'),
            ("not json", b"<html>502</html>"),
            ("empty", b""),
            ("bare scalar", b"5"),
            ("nan", b'{"error":{"message":NaN}}'),
        ):
            self.assertIsInstance(pm.provider_named_the_tools(body), bool, name)

    def test_a_huge_integer_in_an_error_body_still_classifies(self):
        """`int()` past the digit limit raises a bare `ValueError`, not a decode error."""
        body = b'{"error":{"message":"tool_choice unsupported"},"pad":' + b"9" * 5000 + b"}"
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted([(400, body, "")]))
        self.assertNotEqual(receipt["classification"], "INTERNAL_ERROR")
        self.assertEqual(receipt["classification"], "PROVIDER_REJECTED")

    def test_a_deeply_nested_error_body_still_classifies(self):
        """`json.loads` recurses; `RecursionError` is not a `ValueError`."""
        body = b'{"error":' + b"[" * 400 + b"]" * 400 + b"}"
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted([(429, body, "")]))
        self.assertNotEqual(receipt["classification"], "INTERNAL_ERROR")
        self.assertEqual(receipt["classification"], "RATE_LIMITED")

    def test_a_lenient_read_still_recognises_a_normal_dialect_rejection(self):
        """Totality must not be bought by refusing to read anything."""
        body = b'{"error":{"param":"tool_choice","message":"unsupported"}}'
        self.assertTrue(pm.provider_named_the_tools(body))


def completion_with_content(content, calls, model="openai/gpt-oss-120b"):
    """A completion whose assistant `content` is whatever the caller says.

    `ABSENT` leaves the field out entirely, which is a third case: openai-chat
    admits a message with no content at all, and "absent" is not the same input
    as "null" even though both must end as `None`.
    """
    message = {"role": "assistant", "tool_calls": calls}
    if content is not ABSENT:
        message["content"] = content
    return json.dumps({
        "id": "chatcmpl-test",
        "model": model,
        "choices": [{"index": 0, "message": message}],
    }).encode()


ABSENT = object()


class AssistantContentContractTests(unittest.TestCase):
    """Everything replay sends back has to be something the parser checked.

    `parse_tool_calls` called itself the strict openai-chat contract while
    reading only `role` and `tool_calls`; replay then reached past it into the
    original dict for `content`. So the check and the consumer were two
    programs over the same bytes, and the comment claiming "strictness above is
    what makes echoing safe" was true of every field except the one being
    echoed.
    """

    def assistant_of(self, request_body):
        """The replayed assistant message out of a request this canary sent."""
        sent = json.loads(request_body)
        return next(m for m in sent["messages"] if m.get("role") == "assistant")

    def test_a_non_string_content_is_a_protocol_violation(self):
        body = completion_with_content(123, [call("qodec_intersect", INTERSECT_ARGS, "call_op")])
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted([(200, body, "")]))
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")
        self.assertIn("assistant content was int", receipt["detail"])

    def test_every_non_string_content_shape_is_refused(self):
        for label, content in (
            ("number", 123), ("float", 1.5), ("bool", True),
            ("object", {"type": "text"}), ("array", [{"type": "text", "text": "x"}]),
        ):
            body = completion_with_content(content, [call("qodec_intersect", INTERSECT_ARGS, "c")])
            receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted([(200, body, "")]))
            self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION", label)

    def test_nothing_runs_before_the_content_is_checked(self):
        """No operation, no roundtrip, no replay — the verdict lands first."""
        body = completion_with_content(123, [call("qodec_intersect", INTERSECT_ARGS, "call_op")])
        send = scripted([(200, body, "")])
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, send)
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")
        self.assertFalse(receipt["tool_result_roundtrip"])
        self.assertEqual(len(send.seen), 1, "a second request means the message was replayed")
        self.assertNotIn("tool_names", receipt["turns"][0])

    def test_a_numeric_content_anywhere_in_the_run_prevents_pass(self):
        """The full arm, with the defect on the second turn rather than the first."""
        answer = completion_with_content(456, [call("qodec_answer", ANSWER_ARGS, "call_ans")])
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted(
            OPERATION_THEN((200, answer, ""))))
        self.assertNotEqual(receipt["classification"], "PASS")
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")

    def test_null_content_is_admitted(self):
        receipt, _ = QualificationTests().run_qualify(OPERATION_THEN(ANSWER_REPLY))
        self.assertEqual(receipt["classification"], "PASS")

    def test_string_content_is_admitted_and_echoed_verbatim(self):
        body = completion_with_content(
            "let me look that up", [call("qodec_intersect", INTERSECT_ARGS, "call_op")])
        send = scripted([(200, body, ""), ANSWER_REPLY])
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, send)
        self.assertEqual(receipt["classification"], "PASS")
        self.assertEqual(self.assistant_of(send.seen[1][1])["content"], "let me look that up")

    def test_an_absent_content_is_replayed_as_null(self):
        body = completion_with_content(ABSENT, [call("qodec_intersect", INTERSECT_ARGS, "call_op")])
        send = scripted([(200, body, ""), ANSWER_REPLY])
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, send)
        self.assertEqual(receipt["classification"], "PASS")
        self.assertIsNone(self.assistant_of(send.seen[1][1])["content"])

    def test_every_admitted_content_shape_survives_the_replay_unchanged(self):
        """All three admitted shapes, from the wire to the next request.

        Deliberately *not* claiming to prove that replay reads `parsed.content`
        rather than `message["content"]`: once the guard is in place those two
        values are equal on every message that reaches replay, so no black-box
        test can tell them apart. The reason to read the checked one anyway is
        that the guard is what makes them equal, and a consumer that reaches
        past its own validator stops being covered the moment the validator
        changes. `mutations.py` records this as deliberately unmutated with the
        same reasoning, rather than shipping a mutation that cannot die.
        """
        for label, content, expected in (
            ("absent", ABSENT, None), ("null", None, None), ("string", "thinking", "thinking"),
        ):
            body = completion_with_content(content, [call("qodec_intersect", INTERSECT_ARGS, "op")])
            send = scripted([(200, body, ""), ANSWER_REPLY])
            receipt = pm.qualify_target(target(), surface(), 30.0, 6, send)
            self.assertEqual(receipt["classification"], "PASS", label)
            replayed = self.assistant_of(send.seen[1][1])
            self.assertIn("content", replayed, label)
            self.assertEqual(replayed["content"], expected, label)

    def test_the_parser_returns_the_content_it_checked(self):
        parsed = pm.parse_tool_calls(
            {"role": "assistant", "content": "hi", "tool_calls": [call("qodec_intersect", "{}")]})
        self.assertIsNone(parsed.problem)
        self.assertEqual(parsed.content, "hi")
        absent = pm.parse_tool_calls(
            {"role": "assistant", "tool_calls": [call("qodec_intersect", "{}")]})
        self.assertIsNone(absent.content)


class HttpFramingFailureTests(unittest.TestCase):
    """A provider that breaks HTTP framing is a provider, not a bug in this tool.

    `IncompleteRead` was fixed by name last round, which left every other
    `http.client.HTTPException` exactly where it was: `BadStatusLine` and
    `LineTooLong` are neither `OSError` nor `ValueError`, and urllib re-raises
    them rather than wrapping them in `URLError`.
    """

    SENTINEL = "X-QODEC-HOSTILE-STATUS-LINE"

    def sent_with_open_raising(self, exc):
        with patch.object(pm._OPENER, "open", side_effect=exc):
            return pm.send_json("https://api.example/v1", b"{}", "k", 1)

    def test_a_malformed_status_line_is_a_framing_failure(self):
        sent = self.sent_with_open_raising(http.client.BadStatusLine(self.SENTINEL))
        self.assertEqual(sent.stage, "response-framing")
        self.assertIsNone(sent.status)
        self.assertIsNone(sent.body)
        self.assertEqual(pm.validate_send_result(sent), sent)

    def test_an_overlong_status_line_is_a_framing_failure(self):
        sent = self.sent_with_open_raising(http.client.LineTooLong("status line"))
        self.assertEqual(sent.stage, "response-framing")
        self.assertEqual(sent.detail, "HTTP framing failure: LineTooLong")

    def test_a_framing_failure_is_not_reported_as_unavailable(self):
        """`before-response` claims the request may never have been served.

        A malformed status line proves the opposite half: the request went out
        and something answered. Nothing here can say the provider did not
        generate, so calling it retryable invites paying for it twice.
        """
        self.assertEqual(pm.STAGE_CAUSE["response-framing"], "RESPONSE_CAPTURE_FAILED")
        self.assertNotEqual(pm.STAGE_CAUSE["response-framing"], pm.STAGE_CAUSE["before-response"])
        self.assertEqual(pm.STAGE_OUTCOME["response-framing"], "response-capture-failure")

    def test_the_hostile_status_line_is_never_written_down(self):
        with patch.object(pm._OPENER, "open", side_effect=http.client.BadStatusLine(self.SENTINEL)):
            receipt = pm.qualify_target(target(), surface(), 30.0, 6, lambda url, body, timeout:
                                        pm.send_json(url, body, "k", timeout))
        self.assertEqual(receipt["classification"], "RESPONSE_CAPTURE_FAILED")
        self.assertNotIn(self.SENTINEL, json.dumps(receipt))
        # The kind is named; the concrete class crosses as a digest anyone can
        # recompute for a class they suspect.
        self.assertIn("http-framing-error", receipt["detail"])
        self.assertEqual(receipt["turns"][0]["failure_class_sha256"],
                         pm.evidence_digest("failure-class", "BadStatusLine"))

    def test_qualification_classifies_a_framing_failure_rather_than_crashing(self):
        with patch.object(pm._OPENER, "open", side_effect=http.client.LineTooLong("header line")):
            receipt = pm.qualify_target(target(), surface(), 30.0, 6, lambda url, body, timeout:
                                        pm.send_json(url, body, "k", timeout))
        self.assertNotEqual(receipt["classification"], "INTERNAL_ERROR")
        self.assertEqual(receipt["classification"], "RESPONSE_CAPTURE_FAILED")
        self.assertEqual(receipt["turns"][0]["outcome"], "response-capture-failure")

    def test_the_probe_shares_the_verdict_because_it_shares_the_transport(self):
        with patch.object(pm._OPENER, "open", side_effect=http.client.BadStatusLine(self.SENTINEL)):
            result = pm.probe_target(probe_row({}), 1, lambda url, body, timeout:
                                     pm.send_json(url, body, "k", timeout), registry())
        self.assertEqual(result["classification"], "RESPONSE_CAPTURE_FAILED")
        self.assertNotIn(self.SENTINEL, json.dumps(result))

    def test_a_body_read_that_breaks_framing_keeps_the_status(self):
        class Broken:
            status = 200
            headers = {"x-request-id": "req-framing"}

            def read(self, size=-1):
                raise http.client.LineTooLong("chunk size")

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with patch.object(pm._OPENER, "open", side_effect=lambda *a, **k: Broken()):
            sent = pm.send_json("https://api.example/v1", b"{}", "k", 1)
        self.assertEqual((sent.stage, sent.status), ("after-headers", 200))
        self.assertEqual(sent.request_id, "req-framing")
        self.assertEqual(sent.detail, "HTTP body capture failure: LineTooLong")

    def test_an_error_body_read_that_breaks_framing_keeps_its_status(self):
        err = urllib.error.HTTPError("https://api.example/v1", 502, "bad", {}, io.BytesIO(b""))
        err.read = lambda *a: (_ for _ in ()).throw(http.client.HTTPException("framing gave up"))
        with patch.object(pm._OPENER, "open", side_effect=err):
            sent = pm.send_json("https://api.example/v1", b"{}", "k", 1)
        self.assertEqual((sent.stage, sent.status), ("after-headers", 502))
        self.assertEqual(sent.detail, "HTTP body capture failure: HTTPException")

    def test_a_truncated_read_still_reports_its_partial_length(self):
        """Broadening the catch must not lose what `IncompleteRead` knows."""
        class Truncated:
            status = 200
            headers: dict[str, str] = {}

            def read(self, size=-1):
                raise http.client.IncompleteRead(b"seven!!", 40)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with patch.object(pm._OPENER, "open", side_effect=lambda *a, **k: Truncated()):
            sent = pm.send_json("https://api.example/v1", b"{}", "k", 1)
        self.assertEqual(sent.body_bytes_observed, 7)

    def test_a_bounded_read_still_reports_its_own_message(self):
        """`capture_detail` replaces the message only for HTTP framing errors."""
        self.assertEqual(
            pm.capture_detail("HTTP body capture failure", pm.BodyTooLarge(9, 8)),
            "response body exceeded 8 bytes (stopped after 9)",
        )


class SendResultCrossFieldTests(unittest.TestCase):
    """A receipt must not be able to hold an impossible transport state."""

    def test_a_stage_that_received_nothing_carries_no_response_metadata(self):
        """The defect: no headers arrived, yet 123 bytes and a request id.

        Both impossibilities were then persisted, because the table checked
        `status`/`body` and merely type-checked the other two fields.
        """
        for stage in ("before-response", "no-credential"):
            with self.assertRaisesRegex(ValueError, "observed body bytes", msg=stage):
                pm.as_send_result((None, None, "x", stage, 123, None))
            with self.assertRaisesRegex(ValueError, "request id", msg=stage):
                pm.as_send_result((None, None, "x", stage, None, "req-1"))

    def test_an_after_headers_loss_may_carry_both(self):
        sent = pm.as_send_result((503, None, "lost", "after-headers", 4096, "req-2"))
        self.assertEqual((sent.body_bytes_observed, sent.request_id), (4096, "req-2"))

    def test_a_completed_count_must_match_the_body(self):
        """A number nobody can check is a number everybody believes."""
        pm.as_send_result((200, b"{}", "", "completed", 2, None))
        for wrong in (0, 1, 3, 99):
            with self.assertRaises(ValueError, msg=wrong):
                pm.as_send_result((200, b"{}", "", "completed", wrong, None))

    def test_the_real_transport_reports_a_count_that_matches(self):
        class Response:
            status = 200
            headers = {}

            def read(self, size=-1):
                return b'{"ok":1}'

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with patch.object(pm._OPENER, "open", side_effect=lambda *a, **k: Response()):
            sent = pm.send_json("https://api.example/v1", b"{}", "k", 1)
        self.assertEqual(sent.body_bytes_observed, len(sent.body))


class GatesCanFailTests(unittest.TestCase):
    """Every CI gate needs a positive control, or green means nothing."""

    def helper(self, name: str):
        import importlib.util
        path = Path(__file__).resolve().parent / name
        spec = importlib.util.spec_from_file_location(name[:-3], path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_the_clean_tree_check_detects_all_three_kinds_of_dirt(self):
        self.assertEqual(self.helper("check_clean_tree.py").self_test(), 0)

    def test_the_discovery_check_detects_a_mid_file_entrypoint(self):
        self.assertEqual(self.helper("check_test_discovery.py").self_test(), 0)

    # `check_test_discovery.main()` is deliberately *not* called from here: it
    # runs this suite twice as subprocesses, and this suite would then run it
    # again, forever. Its positive control is the synthetic case above; the real
    # comparison is a CI step, which is where a gate over the whole file belongs.

    def stalled(self, module_name: str, cmd: list[str]):
        """The gate module, with every subprocess call stalling past its timeout.

        Both gates already passed `timeout=`; what neither had was anyone to
        catch what it throws. A gate that dies of `TimeoutExpired` reports
        nothing at all — the CI log shows a traceback, which reads as a broken
        check rather than as the honest answer, "I could not tell".
        """
        import contextlib
        import io as _io
        import subprocess

        gate = self.helper(module_name)
        stall = subprocess.TimeoutExpired(cmd=cmd, timeout=gate.TIMEOUT)
        out = _io.StringIO()
        return gate, stall, out, contextlib.redirect_stdout(out)

    def test_the_clean_tree_check_reports_a_stalled_git(self):
        import subprocess

        gate, stall, out, capture = self.stalled("check_clean_tree.py", ["git", "status"])
        with patch.object(subprocess, "run", side_effect=stall):
            with self.assertRaises(gate.GitUnavailable):
                gate.git("status", cwd=Path(__file__).resolve().parent)
            with capture:
                self.assertEqual(gate.main([]), 1)
        self.assertIn("FAIL", out.getvalue())
        self.assertIn(f"exceeded {gate.TIMEOUT}s", out.getvalue())

    def test_a_stalled_git_does_not_read_as_a_clean_tree(self):
        """The failure mode worth naming: no dirt listed is not the same answer
        as no dirt found, and only the exit code can keep them apart."""
        import subprocess

        gate, stall, out, capture = self.stalled("check_clean_tree.py", ["git", "status"])
        with patch.object(subprocess, "run", side_effect=stall), capture:
            self.assertEqual(gate.main([]), 1)
        self.assertNotIn("byte-clean", out.getvalue())

    def test_the_clean_tree_self_test_reports_a_stall_rather_than_raising(self):
        """The positive control is the one place that must not die silently."""
        import subprocess

        gate, stall, out, capture = self.stalled("check_clean_tree.py", ["git", "init"])
        with patch.object(subprocess, "run", side_effect=stall), capture:
            self.assertEqual(gate.main(["--self-test"]), 1)
        self.assertIn("FAIL", out.getvalue())

    def test_the_clean_tree_check_reports_a_missing_git(self):
        import subprocess

        gate = self.helper("check_clean_tree.py")
        import contextlib
        import io as _io

        out = _io.StringIO()
        missing = FileNotFoundError(2, "No such file or directory: 'git'")
        with patch.object(subprocess, "run", side_effect=missing):
            with contextlib.redirect_stdout(out):
                self.assertEqual(gate.main([]), 1)
        self.assertIn("could not run", out.getvalue())

    def test_the_discovery_self_test_reports_a_stall_rather_than_raising(self):
        """`self_test()` used to be dispatched above the handler, so the two
        synthetic runs it drives could stall straight through it."""
        import subprocess

        gate, stall, out, capture = self.stalled(
            "check_test_discovery.py", [sys.executable, "synthetic_case.py", "-v"]
        )
        with patch.object(subprocess, "run", side_effect=stall):
            with patch.object(sys, "argv", ["check_test_discovery.py", "--self-test"]):
                with capture:
                    self.assertEqual(gate.main(), 1)
        self.assertIn("FAIL", out.getvalue())
        self.assertIn(f"exceeded {gate.TIMEOUT}s", out.getvalue())

    def only_output(self, stdout: str | bytes, stderr: str | bytes = b""):
        """A `subprocess.run` that produces exactly these bytes and exits 0.

        Bytes, because the gate now reads bytes: the decision "is this output
        readable" belongs to the gate rather than to the standard library's
        locale-driven decode, which raised out of a place no handler covered.
        """
        import subprocess

        def encoded(value):
            return value.encode("utf-8") if isinstance(value, str) else value

        def fake(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, encoded(stdout), encoded(stderr))

        return patch.object(subprocess, "run", side_effect=fake)

    def test_whitespace_only_output_is_a_verdict_not_a_traceback(self):
        """The guard tested the raw streams; the index ran on the stripped split.

        A run that printed one newline was truthy, split to `[]`, and `[-1]`
        raised — out of the gate whose entire job is to print a report.
        """
        gate = self.helper("check_test_discovery.py")
        for stdout, stderr in (("\n", ""), ("", " \n\t"), ("", ""), ("   ", "\n\n")):
            with self.only_output(stdout, stderr):
                found, verdict = gate.ids_from(["-m", "unittest", "whatever"])
            self.assertEqual(found, set(), repr((stdout, stderr)))
            self.assertEqual(verdict, "(no output)", repr((stdout, stderr)))

    def test_a_run_that_says_nothing_is_reported_as_finding_no_tests(self):
        import contextlib
        import io as _io

        gate = self.helper("check_test_discovery.py")
        out = _io.StringIO()
        with self.only_output("\n"):
            with patch.object(sys, "argv", ["check_test_discovery.py"]):
                with contextlib.redirect_stdout(out):
                    self.assertEqual(gate.main(), 1)
        self.assertIn("FAIL one of the runs reported no tests at all", out.getvalue())
        self.assertIn("(no output)", out.getvalue())

    def test_undecodable_output_is_a_typed_failure_not_a_traceback(self):
        """`text=True` decoded inside the library, and raised there too.

        `UnicodeDecodeError` is a `ValueError`, so neither the `TimeoutExpired`
        nor the `OSError` handler covered it and the gate died instead of
        reporting. The decode is now this gate's own, and its failure has a
        type of its own.
        """
        gate = self.helper("check_test_discovery.py")
        with self.assertRaises(process_boundary.UndecodableOutput):
            gate.decode_test_output(b"\xff", b"")
        with self.only_output(b"ok\xff\xfe", b""):
            with self.assertRaises(process_boundary.UndecodableOutput):
                gate.ids_from(["-m", "unittest", "whatever"])

    def test_undecodable_output_is_reported_as_a_fail(self):
        import contextlib
        import io as _io

        gate = self.helper("check_test_discovery.py")
        out = _io.StringIO()
        with self.only_output(b"\xff"):
            with patch.object(sys, "argv", ["check_test_discovery.py"]):
                with contextlib.redirect_stdout(out):
                    self.assertEqual(gate.main(), 1)
        self.assertIn("not valid UTF-8", out.getvalue())

    def test_the_report_never_repeats_the_bytes_that_caused_it(self):
        """`UnicodeDecodeError`'s message quotes the offending bytes."""
        import contextlib
        import io as _io

        gate = self.helper("check_test_discovery.py")
        out = _io.StringIO()
        with self.only_output(b"QODEC-BYTES-\xff-MARKER"):
            with patch.object(sys, "argv", ["check_test_discovery.py"]):
                with contextlib.redirect_stdout(out):
                    gate.main()
        printed = out.getvalue()
        self.assertNotIn("QODEC-BYTES", printed)
        self.assertNotIn("UnicodeDecodeError", printed)
        self.assertNotIn("0xff", printed)

    def test_the_self_test_proves_the_decoding_contract(self):
        """The control must exercise the rule, not merely coexist with it.

        A mutated gate is qualified by its own `--self-test`, so a decoding
        rule the control never runs could not be killed by any mutation. Make
        the decode lenient and the control has to notice.
        """
        gate = self.helper("check_test_discovery.py")
        import contextlib
        import io as _io

        out = _io.StringIO()
        with patch.object(gate, "decode_test_output",
                          lambda o, e: (o + e).decode("utf-8", "replace")):
            with contextlib.redirect_stdout(out):
                self.assertEqual(gate.self_test(), 1)
        self.assertIn("unreadable", out.getvalue())

    # -- the clean-tree self-test is hermetic, and says so when it is not --

    def test_the_isolated_environment_admits_nothing_from_the_machine(self):
        gate = self.helper("check_clean_tree.py")
        hostile = {
            "GIT_DIR": "/somebody/elses/.git",
            "GIT_INDEX_FILE": "/tmp/theirs",
            "GIT_AUTHOR_NAME": "not us",
            "HOME": "/home/whoever",
        }
        with patch.dict("os.environ", hostile, clear=False):
            env = gate.isolated_env(Path("/tmp/self-test-home"))
        self.assertEqual(sorted(key for key in env if key.startswith("GIT_")),
                         ["GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM",
                          "GIT_CONFIG_SYSTEM", "GIT_TERMINAL_PROMPT"])
        self.assertNotIn("GIT_DIR", env)
        self.assertNotIn("GIT_INDEX_FILE", env)
        self.assertNotIn("GIT_AUTHOR_NAME", env)
        self.assertEqual(env["HOME"], "/tmp/self-test-home")
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")

    def test_the_hostile_home_would_actually_break_a_commit(self):
        """The positive control needs its own positive control.

        A hostile HOME nobody verifies is a hostile HOME that might be empty,
        and then the isolation it exists to prove is proving nothing.
        """
        gate = self.helper("check_clean_tree.py")
        with tempfile.TemporaryDirectory() as tmp:
            home = gate.hostile_home(Path(tmp))
            config = (home / ".gitconfig").read_text(encoding="utf-8")
        self.assertIn("gpgsign = true", config)
        self.assertIn("hooksPath", config)
        self.assertIn("excludesFile", config)

    def failing_git(self, subcommand: str):
        """Real git, except the one subcommand that must be seen to fail."""
        import subprocess

        original = subprocess.run

        def fake(args, **kwargs):
            if isinstance(args, list) and len(args) > 1 and args[1] == subcommand:
                return subprocess.CompletedProcess(args, 128, "", f"fatal: {subcommand} refused\n")
            return original(args, **kwargs)

        return patch.object(subprocess, "run", side_effect=fake)

    def assert_setup_failure_named(self, subcommand: str):
        import contextlib
        import io as _io

        gate = self.helper("check_clean_tree.py")
        out = _io.StringIO()
        with self.failing_git(subcommand):
            with contextlib.redirect_stdout(out):
                self.assertEqual(gate.main(["--self-test"]), 1)
        printed = out.getvalue()
        self.assertIn("self-test setup", printed)
        self.assertIn(f"`git {subcommand}", printed)
        self.assertNotIn("freshly committed tree was reported dirty", printed)
        return printed

    def test_a_failed_seed_commit_is_reported_as_a_failed_setup(self):
        """It used to surface as `a freshly committed tree was reported dirty`.

        The gate diagnosing its own broken preparation as a defect in the
        property it was checking — the most misleading thing a control can do.
        """
        self.assertIn("exited 128", self.assert_setup_failure_named("commit"))

    def test_a_failed_init_or_clean_is_a_report_and_not_a_traceback(self):
        for subcommand in ("init", "clean"):
            with self.subTest(subcommand=subcommand):
                self.assert_setup_failure_named(subcommand)

    def test_a_stalled_command_is_reported_as_a_command_line(self):
        gate = self.helper("check_test_discovery.py")
        self.assertEqual(gate.described(["python3", "-m", "unittest", "x"]),
                         "python3 -m unittest x")
        self.assertEqual(gate.described("python3 x.py"), "python3 x.py")

    def test_the_mutation_list_declares_no_duplicate_specs(self):
        """`E7` and `N2` had different names and identical edits.

        "96 mutations killed" was 95 killed and one counted twice.
        """
        self.assertEqual(mutations.spec_problems(mutations.MUTATIONS), [])

    def test_the_uniqueness_guard_notices_a_duplicate(self):
        same_edit = [("A", "x", "y"), ("B", "x", "y")]
        self.assertTrue(any("identical anchor" in p for p in mutations.spec_problems(same_edit)))
        same_name = [("A", "x", "y"), ("A", "p", "q")]
        self.assertTrue(any("used 2 times" in p for p in mutations.spec_problems(same_name)))

    def test_a_spec_targeting_another_file_is_distinct(self):
        """The same edit in two files is two mutations, not a duplicate."""
        across = [("A", "x", "y"), ("B", "x", "y", "other.py")]
        self.assertEqual(mutations.spec_problems(across), [])


class DurableFieldInventoryTests(unittest.TestCase):
    """Every leaf of every receipt this vertical can produce, against one table.

    Five rounds found five copied provider values, one per round, each in a
    field the previous round had not looked at. The repairs were correct and the
    method was not: checking the sites a reviewer visited leaves exactly as many
    holes as there are sites nobody visited.

    So the receipts are *generated* here — one per classification, driven
    through the real `probe_target` and `qualify_target` — and every leaf of
    every one of them is matched against `receipt_policy.POLICIES`. An unnamed
    field is a finding. That is what makes this an inventory rather than a
    fifth spot check.
    """

    LIMIT = 4096

    def registry_entry(self):
        """The committed registry, because that is what `qualify_target` loads.

        Checking a receipt against a stand-in registry would prove the receipt
        agrees with the test's idea of the truth rather than with the file the
        credential is actually bound to.
        """
        return pm.load_registry()["providers"]["groq"]

    def probe_entry(self):
        return receipt_policy.pm.normalize_registry(registry())["providers"]["p"]

    def declared_tools(self):
        return {op["name"] for op in surface()["operations"]}

    def qualification_receipts(self):
        """One run per reachable classification, named by what it exercises."""
        bad_json = (200, b"[]", "")
        wrong_role = (200, completion_with_role("user", [call("qodec_answer", ANSWER_ARGS)]), "")
        undeclared = (200, completion([call("qodec_nope", "{}", "call_x")]), "")
        unparseable = (200, completion([call("qodec_intersect", "{not json", "call_y")]), "")
        schema_bad = (200, completion([call("qodec_intersect", json.dumps({"index": 5}), "call_z")]), "")
        two_answers = (200, completion([
            call("qodec_answer", ANSWER_ARGS, "call_a1"),
            call("qodec_answer", ANSWER_ARGS, "call_a2"),
        ]), "")
        answer_and_op = (200, completion([
            call("qodec_answer", ANSWER_ARGS, "call_a"),
            call("qodec_intersect", INTERSECT_ARGS, "call_o"),
        ]), "")
        wrong_answer = (200, completion([call("qodec_answer", WRONG_ANSWER_ARGS, "call_w")]), "")
        substituted = (200, completion(
            [call("qodec_answer", ANSWER_ARGS, "call_s")], model="somebody-elses-model"), "")
        no_model = (200, json.dumps({"choices": [{"message": {
            "role": "assistant", "content": None,
            "tool_calls": [call("qodec_answer", ANSWER_ARGS, "call_n")]}}]}).encode(), "")
        operations = (200, completion(
            [call("qodec_intersect", INTERSECT_ARGS, "call_op")], usage={"prompt_tokens": 11}), "")

        scenarios = {
            "endpoint-rejected": ([], dict(target(), api_base="https://steal.example/v1")),
            "credential-missing": ([(None, None, "no key", "no-credential")], None),
            "transport-failure": ([(None, None, "down", "before-response")], None),
            "capture-failure": ([(500, None, "lost", "after-headers", 12, "req-1")], None),
            "framing-failure": ([(None, None, "framing", "response-framing")], None),
            "provider-rejected": ([(400, b"{}", "")], None),
            "tool-choice-unsupported": (
                [(400, json.dumps({"error": {"message": "tool_choice unsupported"}}).encode(), "")], None),
            "rate-limited": ([(429, b"{}", "")], None),
            "auth-rejected": ([(401, b"{}", "")], None),
            "model-missing": ([(404, b"{}", "")], None),
            "redirect": ([(302, b"{}", "")], None),
            "server-error": ([(500, b"{}", "")], None),
            # A 400 in answer to a request that carried `role: tool` messages is
            # about the result shape, not about the tools.
            "tool-result-rejected": (
                [(200, completion([call("qodec_intersect", INTERSECT_ARGS, "call_op")]), ""),
                 (400, b"{}", "")], None),
            "dialect-mismatch": (
                [(200, completion([call_with_object_arguments("qodec_intersect")]), "")], None),
            "invalid-output": ([bad_json], None),
            "dialect-violation": ([wrong_role], None),
            "no-tool-call": ([(200, completion([]), "")], None),
            "undeclared-tool": ([undeclared], None),
            "unparseable-arguments": ([unparseable], None),
            "schema-violation": ([schema_bad], None),
            "two-answers": (OPERATION_THEN(two_answers), None),
            "answer-with-operation": (OPERATION_THEN(answer_and_op), None),
            "answer-before-roundtrip": ([ANSWER_REPLY], None),
            "canary-mismatch": (OPERATION_THEN(wrong_answer), None),
            "identity-substituted": (OPERATION_THEN(substituted), None),
            "identity-unestablished": (OPERATION_THEN(no_model), None),
            "no-terminal-answer": ([operations, operations], None),
            "pass": (OPERATION_THEN(ANSWER_REPLY), None),
        }
        for name, (replies, edited) in scenarios.items():
            yield name, pm.qualify_target(
                edited or target(), surface(), 30.0, 2 if name == "no-terminal-answer" else 6,
                scripted(replies), response_limit=self.LIMIT)

    def probe_receipts(self):
        ok = json.dumps({"model": "m", "choices": [{"message": {"content": "QODEC_PROBE_OK"}}],
                         "usage": {"prompt_tokens": 9}}).encode()
        drifted = json.dumps({"model": "other", "choices": [{"message": {"content": "QODEC_PROBE_OK"}}]}).encode()
        silent = json.dumps({"choices": [{"message": {"content": "QODEC_PROBE_OK"}}]}).encode()
        wrong = json.dumps({"model": "m", "choices": [{"message": {"content": "no"}}]}).encode()
        scenarios = {
            "pass": ([(200, ok, "", "completed")], None),
            "substituted": ([(200, drifted, "", "completed")], None),
            "identity-missing": ([(200, silent, "", "completed")], None),
            "token-mismatch": ([(200, wrong, "", "completed")], None),
            "unmappable": ([(200, b"[]", "", "completed")], None),
            "http-failure": ([(418, b"{}", "", "completed")], None),
            "provider-5xx": ([(503, b"{}", "", "completed")], None),
            "auth-failure": ([(401, b"{}", "", "completed")], None),
            "model-not-found": ([(404, b"{}", "", "completed")], None),
            "rate-limited": ([(429, b"{}", "", "completed")], None),
            "redirect": ([(302, b"{}", "", "completed")], None),
            "timeout": ([pm.SendResult(None, None, "timeout", "before-response", None, None,
                                       "timeout", "timeout-error", "TimeoutError")], None),
            "credential-missing": ([pm.SendResult(None, None, "no key", "no-credential", None, None,
                                                  "credential-missing", None, None)], None),
            "capture-failure": ([(500, None, "lost", "after-headers", 12, "req-2")], None),
            "transport-failure": ([(None, None, "down", "before-response")], None),
            "endpoint-rejected": ([], probe_row({"api_base": "https://elsewhere/v1"})),
        }
        for name, (replies, edited) in scenarios.items():
            yield name, pm.probe_target(
                edited or probe_row({}), 1, scripted(replies), registry(),
                response_limit=self.LIMIT)

    def audit(self, receipt, target_row, entry, schema=None, max_turns=6):
        context = receipt_policy.context_for(
            schema or pm.QUALIFY_SCHEMA, target_row, entry, response_limit=self.LIMIT,
            max_turns=max_turns, declared_tools=self.declared_tools(),
        )
        return receipt_policy.audit(receipt, context)

    def test_the_policy_table_is_internally_consistent(self):
        self.assertEqual(receipt_policy.policy_problems(receipt_policy.POLICIES), [])

    def test_every_leaf_of_every_qualification_receipt_has_exactly_one_policy(self):
        for name, receipt in self.qualification_receipts():
            with self.subTest(scenario=name):
                self.assertEqual(self.audit(receipt, target(), self.registry_entry()), [])

    def test_every_leaf_of_every_probe_receipt_has_exactly_one_policy(self):
        for name, receipt in self.probe_receipts():
            with self.subTest(scenario=name):
                self.assertEqual(
                    self.audit(receipt, probe_row({}), self.probe_entry(), pm.PROBE_SCHEMA), [])

    def test_a_guarded_crash_receipt_is_inventoried_too(self):
        """The path that exists because the others can fail is not exempt."""
        def explode():
            raise ValueError("Bearer sk-SECRET")

        for schema in (pm.PROBE_SCHEMA, pm.QUALIFY_SCHEMA):
            with self.subTest(schema=schema):
                receipt = pm.guarded_receipt(schema, target(), explode)
                self.assertEqual(self.audit(receipt, target(), self.registry_entry(), schema), [])

    def test_the_scenarios_reach_every_classification_the_module_declares(self):
        """An inventory over three receipts would prove almost nothing.

        Any classification the scenarios never produce is a shape of receipt
        this table has never been checked against, so the coverage is asserted
        rather than assumed.
        """
        reached = {receipt["classification"] for _, receipt in self.qualification_receipts()}
        reached |= {receipt["classification"] for _, receipt in self.probe_receipts()}
        # `INTERNAL_ERROR` comes from `guarded_receipt`, checked above.
        declared = (set(pm.CLASSIFICATIONS) | set(pm.PROBE_CLASSIFICATIONS)) - {"INTERNAL_ERROR"}
        self.assertEqual(declared - reached, set())

    # -- the positive controls, on receipts this module really produced --

    def specimen(self):
        receipt = pm.qualify_target(target(), surface(), 30.0, 6,
                                    scripted(OPERATION_THEN(ANSWER_REPLY)), response_limit=self.LIMIT)
        self.assertEqual(receipt["classification"], "PASS")
        return receipt

    def assert_refused(self, receipt, phrase):
        findings = self.audit(receipt, target(), self.registry_entry())
        self.assertTrue(any(phrase in f for f in findings),
                        f"expected a finding containing {phrase!r}, got {findings}")

    def test_an_unnamed_leaf_stops_the_gate(self):
        receipt = self.specimen()
        receipt["provider_said"] = "anything at all"
        self.assert_refused(receipt, "no policy names")

    def test_an_unbounded_integer_stops_the_gate(self):
        receipt = self.specimen()
        receipt["turns"][0]["body_bytes_observed"] = int.from_bytes(b"sk-secret", "big")
        self.assert_refused(receipt, "outside 0..")

    def test_a_digest_field_holding_something_else_stops_the_gate(self):
        receipt = self.specimen()
        receipt["turns"][0]["tool_calls"][0]["call_id_sha256"] = "call_op"
        self.assert_refused(receipt, "not a sha256 digest")

    def test_provider_prose_in_a_detail_stops_the_gate(self):
        receipt = self.specimen()
        receipt["detail"] = "the upstream said: sk-live-9f2c and then hung up"
        self.assert_refused(receipt, "is not one this module wrote")

    def test_a_doubly_owned_field_stops_the_gate(self):
        doubled = receipt_policy.POLICIES + [
            receipt_policy.DurableFieldPolicy("detail", receipt_policy.Flag())]
        problems = receipt_policy.policy_problems(doubled)
        self.assertTrue(any("exactly one may" in p for p in problems), problems)
        with self.assertRaisesRegex(KeyError, "2 policies name"):
            receipt_policy.exactly_one_policy_for("detail", doubled)

    def test_a_digest_policy_without_a_declared_domain_stops_the_gate(self):
        """A digest nobody can recompute is a field nobody can audit."""
        problems = receipt_policy.policy_problems(
            [receipt_policy.DurableFieldPolicy("x", receipt_policy.Digest("invented"))])
        self.assertTrue(any("not declared in EVIDENCE_DOMAINS" in p for p in problems), problems)

    def test_the_policy_modules_own_self_test_passes(self):
        self.assertEqual(receipt_policy.self_test(), 0)

    def test_a_reference_is_prose_and_a_bare_secret_is_not(self):
        """The one rule that lets a detail line mention foreign material at all."""
        prose = receipt_policy.Prose(4096)
        context = {"local_words": set()}
        named = pm.opaque_ref("tool-name", "qodec_intersect")
        self.assertEqual(prose.problems(f"{named} arguments were dict, not a string", context), [])
        self.assertTrue(prose.problems("qodec_intersect_v2_beta arguments were bad", context))
        self.assertTrue(prose.problems("<made-up sha256:0000000000000000 4B> is fine", context))

    def test_a_line_whose_words_are_local_but_whose_bytes_are_not(self):
        """The alphabet check, which the vocabulary check cannot stand in for.

        Every word below is one this module wrote. What is not this module's is
        the punctuation between them — an em dash, a NUL, a control byte — and a
        detail line assembled somewhere else is far more likely to differ in its
        bytes than in its nouns.
        """
        prose = receipt_policy.Prose(4096)
        context = {"local_words": set()}
        for hostile in ("the response named no model \u2014 unestablished",
                        "the response named no model\x00 unestablished",
                        "the response named no model\x1b[31m unestablished"):
            with self.subTest(line=repr(hostile)):
                found = prose.problems(hostile, context)
                self.assertTrue(any("outside the local alphabet" in f for f in found), found)

    def test_a_receipt_that_disagrees_with_the_plan_stops_the_gate(self):
        """`Local` means "equal to a fact from outside the artifact".

        Audited against a context read out of the receipt itself, every `Local`
        policy degrades to "this value equals itself" and the whole table becomes
        a shape check. So the fields are moved *away* from their local facts
        here, one at a time, and each must be refused.
        """
        for field, forged in (("requested_model", "somebody-elses-model"),
                              ("provider", "not-groq"),
                              ("target_id", "groq--something-else"),
                              ("schema", pm.PROBE_SCHEMA)):
            with self.subTest(field=field):
                receipt = self.specimen()
                receipt[field] = forged
                self.assert_refused(receipt, "is not the local")

    def test_a_transport_target_pointing_elsewhere_stops_the_gate(self):
        receipt = self.specimen()
        receipt["transport_target"]["endpoint"] = "https://steal.example/v1"
        self.assert_refused(receipt, "is not the local api_base")

    def test_the_recorded_endpoint_is_the_registrys_spelling_not_the_plans(self):
        """`verify_against_registry` compares with `rstrip("/")`.

        So a plan row may legitimately differ from the registry and still be
        accepted — and the receipt must then say what the registry says. A field
        filled from the row after the check that compared them makes the plan
        the source of a durable value one line past the gate that settled it.
        """
        entry = self.registry_entry()
        row = dict(target(), api_base=entry["api_base"] + "/")
        receipt = pm.qualify_target(row, surface(), 30.0, 6,
                                    scripted(OPERATION_THEN(ANSWER_REPLY)), response_limit=self.LIMIT)
        self.assertEqual(receipt["classification"], "PASS")
        self.assertEqual(receipt["transport_target"]["endpoint"], entry["api_base"])
        self.assertEqual(self.audit(receipt, row, entry), [])


class DecisionOwnershipTests(unittest.TestCase):
    """`classification` has exactly one writer, and an AST gate says so.

    Eighteen `receipt.update(classification=...)` calls is eighteen chances for
    one of them to pair a verdict with a stale detail, and three rounds running
    that is what a reviewer found. Counting them is not the fix; making the
    count one is.
    """

    OWNED_FIELDS = ("classification", "decision_reason")
    WRITER = "apply_decision"

    def module(self):
        import ast
        source = (Path(__file__).resolve().parent / "provider_matrix.py").read_text(encoding="utf-8")
        return ast.parse(source)

    def enclosing_functions(self, tree):
        import ast
        owner = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    owner.setdefault(child, node.name)
        return owner

    def write_sites(self):
        """Every place the source could put a value into an owned field."""
        import ast
        tree = self.module()
        owner = self.enclosing_functions(tree)
        sites = []
        for node in ast.walk(tree):
            # `receipt["classification"] = ...`
            if isinstance(node, (ast.Assign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for goal in targets:
                    if (isinstance(goal, ast.Subscript)
                            and isinstance(goal.slice, ast.Constant)
                            and goal.slice.value in self.OWNED_FIELDS):
                        sites.append((goal.slice.value, owner.get(node, "<module>"), node.lineno))
            # `receipt.update(classification=...)`
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg in self.OWNED_FIELDS:
                        sites.append((keyword.arg, owner.get(node, "<module>"), node.lineno))
            # `{"classification": ...}` in a literal
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if (isinstance(key, ast.Constant) and key.value in self.OWNED_FIELDS):
                        seed = (isinstance(value, ast.Name)
                                and value.id in ("PENDING_CLASSIFICATION",)) or (
                                    isinstance(value, ast.Constant) and value.value is None)
                        if not seed:
                            sites.append((key.value, owner.get(node, "<module>"), node.lineno))
        return sites

    def test_only_one_function_writes_a_verdict(self):
        offenders = [site for site in self.write_sites() if site[1] != self.WRITER]
        self.assertEqual(offenders, [], f"{len(offenders)} write sites outside {self.WRITER}()")

    def test_the_gate_would_notice_a_second_writer(self):
        """A gate that has never seen a violation is a gate nobody has tested."""
        import ast
        tree = ast.parse('def elsewhere(r):\n    r["classification"] = "PASS"\n')
        owner = self.enclosing_functions(tree)
        found = [n for n in ast.walk(tree)
                 if isinstance(n, ast.Assign)
                 and isinstance(n.targets[0], ast.Subscript)
                 and n.targets[0].slice.value in self.OWNED_FIELDS]
        self.assertEqual([owner[node] for node in found], ["elsewhere"])

    def test_the_seed_is_never_the_verdict_of_a_returned_receipt(self):
        """`PENDING_CLASSIFICATION` is a placeholder, and the suite says so."""
        inventory = DurableFieldInventoryTests()
        for name, receipt in inventory.qualification_receipts():
            with self.subTest(scenario=name):
                self.assertNotEqual(receipt["decision_reason"], None)
                self.assertIn(receipt["decision_reason"], pm.DECISION_REASONS)

    def test_a_verdict_from_the_other_schemas_vocabulary_is_refused(self):
        """A probe cannot be handed a qualification verdict, or the reverse."""
        with self.assertRaisesRegex(ValueError, "is not a classification of"):
            pm.apply_decision({"schema": pm.PROBE_SCHEMA},
                              pm.Decision("TOOL_CHOICE_UNSUPPORTED", "transport-failed", "x"))
        with self.assertRaisesRegex(ValueError, "is not a classification of"):
            pm.apply_decision({"schema": pm.QUALIFY_SCHEMA},
                              pm.Decision("PROVIDER_5XX", "transport-failed", "x"))
        with self.assertRaisesRegex(ValueError, "no classification vocabulary"):
            pm.apply_decision({"schema": "invented"}, pm.Decision("PASS", "transport-failed", "x"))

    def test_an_unenumerated_reason_is_refused(self):
        # The empty string among them on purpose: "not in the tuple" is the
        # check, and a vocabulary widened by one convenient member is the
        # commonest way that check stops being one.
        for reason in ("felt-right", "", None, "PASS"):
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, "unknown decision reason"):
                pm.apply_decision({"schema": pm.PROBE_SCHEMA}, pm.Decision("PASS", reason, "x"))

    # -- the reducers, tested as functions rather than through the loop --

    def test_the_transport_reducer_reads_the_reason_not_the_prose(self):
        """The probe used to switch on `sent.detail`, which a sender fills in."""
        facts = pm.TransportFacts(pm.PROBE_SCHEMA, "before-response", "timeout", None, None, "K")
        self.assertEqual(pm.reduce_transport(facts).classification, "TIMEOUT")
        other = pm.TransportFacts(pm.PROBE_SCHEMA, "before-response", "connection-failed", None, None, "K")
        self.assertEqual(pm.reduce_transport(other).classification, "TRANSPORT_FAILURE")

    def test_both_stage_tables_are_total_over_the_send_stages(self):
        """A stage with no entry falls through to a default nobody chose."""
        failing = set(pm.SEND_STAGE_SHAPES) - {"completed"}
        for stage in sorted(failing):
            with self.subTest(stage=stage):
                for schema in (pm.PROBE_SCHEMA, pm.QUALIFY_SCHEMA):
                    facts = pm.TransportFacts(schema, stage, "connection-failed", None, None, "K")
                    decision = pm.reduce_transport(facts)
                    self.assertIn(decision.classification, pm.SCHEMA_CLASSIFICATIONS[schema])
                self.assertIn(stage, pm.STAGE_OUTCOME)

    def test_identity_outranks_the_canary_and_the_protocol(self):
        drifted = pm.AnswerFacts("drifted", ("wrong bytes",), ("abcdef0123456789",))
        self.assertEqual(pm.reduce_qualification(drifted).classification, "PROVIDER_SUBSTITUTED")
        missing = pm.AnswerFacts("missing", (), ())
        self.assertEqual(pm.reduce_qualification(missing).classification, "MODEL_IDENTITY_MISSING")
        # And with a wrong answer as well: an unestablished identity is not
        # downgraded by a second failure arriving beside it. Both fail, and the
        # one a reader must act on first is "we do not know what produced this".
        both = pm.AnswerFacts("missing", ("wrong bytes",), ())
        self.assertEqual(pm.reduce_qualification(both).classification, "MODEL_IDENTITY_MISSING")
        drifted_and_wrong = pm.AnswerFacts("drifted", ("wrong bytes",), ("abcdef0123456789",))
        self.assertEqual(pm.reduce_qualification(drifted_and_wrong).classification,
                         "PROVIDER_SUBSTITUTED")
        wrong = pm.AnswerFacts("verified", ("wrong bytes",), ())
        self.assertEqual(pm.reduce_qualification(wrong).classification, "CANARY_ANSWER_MISMATCH")
        good = pm.AnswerFacts("verified", (), ())
        self.assertEqual(pm.reduce_qualification(good).classification, "PASS")

    def test_the_probe_reducer_refuses_a_state_it_does_not_know(self):
        with self.assertRaisesRegex(ValueError, "unknown probe output state"):
            pm.reduce_probe(pm.ProbeFacts("verified", "probably-fine"))

    def test_every_durable_number_that_comes_from_a_clock_or_a_flag_is_bounded(self):
        with patch.object(pm.time, "time", side_effect=[0.0]):
            self.assertEqual(pm.latency_ms_since(1e18), 0)
        with patch.object(pm.time, "time", side_effect=[1e18]):
            self.assertEqual(pm.latency_ms_since(0.0), pm.LATENCY_MAX_MS)
        for bad in (0, -1, pm.TIMEOUT_MAX_SECS + 1, float("inf"), float("nan"), True, "30"):
            with self.subTest(timeout=bad), self.assertRaises(ValueError):
                pm.bounded_timeout(bad)
        for bad in (0, -1, pm.MAX_TURNS_BOUND + 1, True, 3.0):
            with self.subTest(turns=bad), self.assertRaises(ValueError):
                pm.bounded_turns(bad)


class ProcessBoundaryOwnershipTests(unittest.TestCase):
    """One module starts processes, and an AST gate enforces it.

    Two gates learned the same lesson a round apart, because `subprocess.run`
    was called in two places and only one of them was reviewed. The second was
    found by a reviewer wearing the same clothes as the first. That is a boundary
    with no owner, and an owner is what this checks.
    """

    # The test suite is exempt, stated rather than silently skipped: it runs the
    # CLI end to end and patches `subprocess.run` to prove the gates report
    # rather than raise. It writes no receipts and ships to nobody.
    EXEMPT = {"process_boundary.py", "test_provider_matrix.py"}

    def modules(self):
        here = Path(__file__).resolve().parent
        return sorted(path for path in here.glob("*.py") if path.name not in self.EXEMPT)

    def subprocess_uses(self, path):
        import ast
        tree = ast.parse(path.read_text(encoding="utf-8"))
        uses = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                uses.extend(f"import {a.name}" for a in node.names if a.name.startswith("subprocess"))
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("subprocess"):
                uses.append(f"from {node.module} import ...")
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                    and node.value.id == "subprocess"):
                uses.append(f"subprocess.{node.attr} at line {node.lineno}")
        return uses

    def test_no_module_but_the_boundary_starts_a_process(self):
        offenders = {}
        for path in self.modules():
            if path.name == "mutations.py":
                # The harness copies the tree and runs oracles in it, which is
                # starting processes for a living. It is checked separately
                # below: what matters there is that every oracle is enumerated.
                continue
            uses = self.subprocess_uses(path)
            if uses:
                offenders[path.name] = uses
        self.assertEqual(offenders, {})

    def test_the_gate_would_notice_a_new_caller(self):
        with tempfile.TemporaryDirectory() as td:
            offender = Path(td) / "sneaky.py"
            offender.write_text("import subprocess\nsubprocess.run(['ls'])\n", encoding="utf-8")
            self.assertTrue(self.subprocess_uses(offender))

    def test_the_boundary_returns_bytes_and_decodes_by_declared_policy(self):
        self.assertEqual(process_boundary.decode_output(b"ok"), "ok")
        with self.assertRaises(process_boundary.UndecodableOutput):
            process_boundary.decode_output(b"\xff")
        # A path is arbitrary bytes by design, so it round-trips instead.
        self.assertEqual(process_boundary.decode_path(b"a\xffb").encode(
            "utf-8", "surrogateescape"), b"a\xffb")
        # And what is printed carries nothing raw: a surrogate written straight
        # to a terminal raises `UnicodeEncodeError` out of `print`, which is the
        # gate dying while reporting rather than reporting.
        rendered = process_boundary.printable(process_boundary.decode_path(b"a\xffb"))
        self.assertEqual(rendered, "a\\udcffb")
        self.assertEqual(rendered.encode("ascii"), b"a\\udcffb")
        self.assertEqual(process_boundary.printable("plain"), "plain")

    def test_a_failure_never_repeats_the_bytes_that_caused_it(self):
        """`UnicodeDecodeError`'s message contains them; this one carries none."""
        try:
            process_boundary.decode_output(b"secret-\xff")
        except process_boundary.UndecodableOutput as exc:
            self.assertEqual(str(exc), "")
        else:  # pragma: no cover
            self.fail("undecodable output was accepted")

    def test_every_mutation_target_names_its_oracles(self):
        """A file the harness can mutate but cannot ask about is unqualifiable."""
        named = {spec[3] if len(spec) > 3 else mutations.DEFAULT_TARGET
                 for spec in mutations.MUTATIONS}
        self.assertEqual(named - set(mutations.MUTATION_TARGETS), set())
        for name, oracles in mutations.MUTATION_TARGETS.items():
            with self.subTest(target=name):
                self.assertTrue(oracles, f"{name} has no oracle")
                self.assertTrue((Path(__file__).resolve().parent / name).exists())


if __name__ == "__main__":
    unittest.main()
