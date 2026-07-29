import argparse
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import provider_matrix as pm


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
            first = pm.import_catalog(self.source(root), "2026-07-28T00:00:00Z")
            second = pm.import_catalog(self.source(root), "2026-07-28T00:00:00Z")
            self.assertEqual(pm.canonical_bytes(first), pm.canonical_bytes(second))
            self.assertEqual([x["provider"] for x in first["targets"]], ["groq", "openrouter"])

    def test_unknown_policy_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            catalog = pm.import_catalog(self.source(Path(td)), "2026-07-28T00:00:00Z")
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
                pm.import_catalog(source, "2026-07-28T00:00:00Z")

    def test_missing_key_is_auth_failure(self):
        target = {"target_id": "p--m", "provider": "p", "model": "m", "api_base": "https://x/v1", "key_env": "ABSENT"}
        with patch.dict("os.environ", {}, clear=True):
            result = pm.probe_target(target, 1)
        self.assertEqual(result["classification"], "AUTH_FAILURE")

    def test_model_substitution_is_not_pass(self):
        target = {"target_id": "p--m", "provider": "p", "model": "m", "api_base": "https://x/v1", "key_env": "K"}
        body = json.dumps({"model": "other", "choices": [{"message": {"content": "QODEC_PROBE_OK"}}]}).encode()
        result = pm.probe_target(target, 1, scripted([(200, body, "", "completed")]))
        self.assertEqual(result["classification"], "PROVIDER_SUBSTITUTED")

    def test_exact_probe_passes(self):
        target = {"target_id": "p--m", "provider": "p", "model": "m", "api_base": "https://x/v1", "key_env": "K"}
        body = json.dumps({"model": "m", "choices": [{"message": {"content": "QODEC_PROBE_OK"}}], "usage": {"prompt_tokens": 9}}).encode()
        result = pm.probe_target(target, 1, scripted([(200, body, "", "completed")]))
        self.assertEqual(result["classification"], "PASS")
        self.assertEqual(result["provider_usage"]["prompt_tokens"], 9)
        self.assertEqual(result["endpoint"], "https://x/v1/chat/completions")

    def test_the_probe_and_the_canary_share_one_transport(self):
        """Same endpoint rule, same body bound, same stage vocabulary.

        Two transports would mean two chances to send the credential somewhere
        the other one refuses to.
        """
        target = {"target_id": "p--m", "provider": "p", "model": "m", "api_base": "http://x/v1", "key_env": "K"}
        result = pm.probe_target(target, 1, scripted([(200, b"{}", "", "completed")]))
        self.assertEqual(result["classification"], "ENDPOINT_REJECTED")
        # And a body that never finished arriving is not "the provider was down".
        target["api_base"] = "https://x/v1"
        result = pm.probe_target(target, 1, scripted([(None, None, "body too large", "after-headers")]))
        self.assertEqual(result["classification"], "RESPONSE_CAPTURE_FAILED")


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
        self.assertIn("tool_choice", receipt["detail"])

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
        self.assertEqual(receipt["detail"], "connection refused")

    def test_a_substituted_model_does_not_pass(self):
        receipt, _ = self.run_qualify(OPERATION_THEN(
            (200, completion([call("qodec_answer", ANSWER_ARGS, "call_ans")], model="some-other-model"), ""),
        ))
        self.assertEqual(receipt["classification"], "PROVIDER_SUBSTITUTED")
        self.assertEqual(receipt["model_status"], "drifted")
        self.assertIn("some-other-model", receipt["detail"])

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
        self.assertEqual(receipt["reported_models"], ["sneaky-substitute", "openai/gpt-oss-120b"])
        self.assertEqual(receipt["turns"][0]["reported_model"], "sneaky-substitute")
        self.assertEqual(receipt["turns"][1]["reported_model"], "openai/gpt-oss-120b")
        # No single consistent value exists, so none is claimed.
        self.assertIsNone(receipt["reported_model"])
        # And the detail names the model that actually drifted.
        self.assertIn("sneaky-substitute", receipt["detail"])
        self.assertNotIn("provider reported openai/gpt-oss-120b", receipt["detail"])

    def test_a_consistent_reported_model_is_still_offered_once(self):
        receipt, _ = self.run_qualify(OPERATION_THEN(ANSWER_REPLY))
        self.assertEqual(receipt["reported_models"], ["openai/gpt-oss-120b"])
        self.assertEqual(receipt["reported_model"], "openai/gpt-oss-120b")

    def test_an_unnamed_model_is_missing_not_verified(self):
        answer = json.dumps({"id": "x", "choices": [{"message": {"tool_calls": [call("qodec_answer", ANSWER_ARGS, "call_ans")]}}]}).encode()
        receipt, _ = self.run_qualify(OPERATION_THEN((200, answer, "")))
        self.assertEqual(receipt["model_status"], "missing")
        self.assertIsNone(receipt["turns"][1]["reported_model"])

    def test_unparseable_arguments_are_malformed_not_a_protocol_violation(self):
        receipt, _ = self.run_qualify([(200, completion([call("qodec_answer", "{not json")]), "")])
        self.assertEqual(receipt["classification"], "MALFORMED_TOOL_ARGUMENTS")

    def test_missing_required_arguments_are_malformed(self):
        receipt, _ = self.run_qualify([(200, completion([call("qodec_answer", json.dumps({"answer": {}}))]), "")])
        self.assertEqual(receipt["classification"], "MALFORMED_TOOL_ARGUMENTS")
        self.assertIn("handle", receipt["detail"])

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
            ([(None, None, "body too large", "after-headers")], "RESPONSE_CAPTURE_FAILED"),
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
        ):
            receipt, _ = self.run_qualify(replies)
            self.assertEqual(receipt["classification"], expected)
            reached.add(expected)
        reached.add(pm.qualify_target(
            dict(target(), api_base="http://plaintext/v1"), surface(), 30.0, 6, scripted([]),
        )["classification"])
        self.assertIn("ENDPOINT_REJECTED", reached)
        self.assertTrue(reached.issubset(set(pm.CLASSIFICATIONS)))
        # NO_TERMINAL_ANSWER is covered by the budget-exhaustion test above.
        self.assertEqual(
            set(pm.CLASSIFICATIONS) - reached,
            {"NO_TERMINAL_ANSWER"},
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
        self.assertTrue(any("expected type" in e for e in receipt["turns"][0]["argument_errors"]))

    def test_a_forbidden_extra_field_is_rejected(self):
        receipt = self.malformed("qodec_intersect", {
            "index": "line", "sections": ["attempt_1"], "unexpected_field": True,
        })
        self.assertTrue(any("additional property" in e for e in receipt["turns"][0]["argument_errors"]))

    def test_an_array_field_given_a_string_is_rejected(self):
        self.malformed("qodec_intersect", {"index": "line", "sections": "not-an-array"})

    def test_an_empty_array_below_min_items_is_rejected(self):
        self.malformed("qodec_intersect", {"index": "line", "sections": []})

    def test_a_wrong_encoding_enum_is_rejected(self):
        """The byte envelope reached through a local `$ref`."""
        receipt = self.malformed("qodec_lookup", {
            "index": "line", "key": {"encoding": "hex", "data": "61"},
        })
        self.assertTrue(any("enum" in e for e in receipt["turns"][0]["argument_errors"]))

    def test_a_handle_that_is_not_a_sha256_is_rejected(self):
        receipt = self.malformed("qodec_materialize", {
            "handle": "sha256:not-a-digest",
            "record_ids": [{"store": pm.CANNED_HANDLE, "section": "attempt_1", "ordinal": 0}],
        })
        self.assertTrue(any("pattern" in e for e in receipt["turns"][0]["argument_errors"]))

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
        self.assertIn("beta", receipt["detail"])
        self.assertIn("alpha", receipt["detail"])
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
        self.assertEqual(pm.canary_answer_errors(json.loads(ANSWER_ARGS)), [])


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

    def test_a_hostile_catalog_row_never_becomes_a_target(self):
        """Fail closed at intake, so a bad row cannot reach a plan at all."""
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source.json"
            source.write_text(json.dumps([{
                "provider": "p", "model": "m",
                "api_base": "http://exfiltrate.example/v1", "key_env": "K",
            }]), encoding="utf-8")
            with self.assertRaisesRegex(pm.EndpointRejected, "https"):
                pm.import_catalog(source, "2026-07-28T00:00:00Z")

    def test_a_hand_edited_plan_is_still_refused_at_send_time(self):
        """Intake is the first gate, not the only one."""
        receipt = pm.qualify_target(
            dict(target(), api_base="https://user:pw@api.example/v1"),
            surface(), 30.0, 6, scripted([]),
        )
        self.assertEqual(receipt["classification"], "ENDPOINT_REJECTED")
        self.assertEqual(receipt["turns"], [])

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
            scripted([(None, None, "response body exceeded 4194304 bytes", "after-headers")]),
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
        receipt = pm.qualify_target(
            target(), surface(), 30.0, 6, pm.key_bound_sender("DEFINITELY_ABSENT_KEY"),
        )
        self.assertEqual(receipt["classification"], "AUTH_FAILED")
        self.assertIn("DEFINITELY_ABSENT_KEY", receipt["detail"])

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

    def test_an_oversize_error_body_stops_after_headers(self):
        err = urllib.error.HTTPError(
            "https://api.example/v1", 500, "boom", {}, io.BytesIO(b"z" * 300),
        )
        with patch.object(pm._OPENER, "open", side_effect=err):
            sent = pm.send_json("https://api.example/v1", b"{}", "k", 1, limit=100)
        self.assertEqual(sent.stage, "after-headers")
        self.assertIsNone(sent.status)
        self.assertIn("exceeded", sent.detail)

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
        self.assertEqual(captured, ["SOME_KEY"])


if __name__ == "__main__":
    unittest.main()
