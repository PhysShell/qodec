import argparse
import json
import tempfile
import unittest
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
        response = unittest.mock.MagicMock()
        response.status = 200
        response.read.return_value = json.dumps({"model": "other", "choices": [{"message": {"content": "QODEC_PROBE_OK"}}]}).encode()
        response.__enter__.return_value = response
        with patch.dict("os.environ", {"K": "secret"}, clear=True), patch("urllib.request.urlopen", return_value=response):
            result = pm.probe_target(target, 1)
        self.assertEqual(result["classification"], "PROVIDER_SUBSTITUTED")

    def test_exact_probe_passes(self):
        target = {"target_id": "p--m", "provider": "p", "model": "m", "api_base": "https://x/v1", "key_env": "K"}
        response = unittest.mock.MagicMock()
        response.status = 200
        response.read.return_value = json.dumps({"model": "m", "choices": [{"message": {"content": "QODEC_PROBE_OK"}}], "usage": {"prompt_tokens": 9}}).encode()
        response.__enter__.return_value = response
        with patch.dict("os.environ", {"K": "secret"}, clear=True), patch("urllib.request.urlopen", return_value=response):
            result = pm.probe_target(target, 1)
        self.assertEqual(result["classification"], "PASS")
        self.assertEqual(result["provider_usage"]["prompt_tokens"], 9)


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
ANSWER_ARGS = json.dumps({
    "handle": pm.CANNED_HANDLE,
    "answer": {"encoding": "base64url-nopad", "data": "YWxwaGE"},
    "cited": [{"store": pm.CANNED_HANDLE, "section": "attempt_1", "ordinal": 0}],
})


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
        self.assertEqual(receipt["turns"][0]["tool_names"], ["qodec_intersect"])
        self.assertEqual(receipt["turns"][1]["outcome"], "terminal-answer")
        self.assertEqual(receipt["turns"][1]["reported_usage"]["prompt_tokens"], 11)

    def test_the_request_carries_the_exact_c1_surface(self):
        """Four tools, the real schemas, and forcing — or it qualifies nothing."""
        receipt, send = self.run_qualify([
            (200, completion([call("qodec_answer", ANSWER_ARGS)]), ""),
        ])
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
        receipt, _ = self.run_qualify([
            (200, completion([call("qodec_answer", ANSWER_ARGS)], model="some-other-model"), ""),
        ])
        self.assertEqual(receipt["classification"], "PROVIDER_SUBSTITUTED")
        self.assertEqual(receipt["model_status"], "drifted")
        self.assertEqual(receipt["reported_model"], "some-other-model")

    def test_an_unnamed_model_is_missing_not_verified(self):
        body = json.dumps({"id": "x", "choices": [{"message": {"tool_calls": [call("qodec_answer", ANSWER_ARGS)]}}]}).encode()
        receipt, _ = self.run_qualify([(200, body, "")])
        self.assertEqual(receipt["model_status"], "missing")

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
            ([(200, completion([call("qodec_answer", ANSWER_ARGS)]), "")], "PASS"),
            ([(401, b"{}", "")], "AUTH_FAILED"),
            ([(404, b"{}", "")], "MODEL_MISSING"),
            ([(429, b"{}", "")], "RATE_LIMITED"),
            ([(503, b"{}", "")], "UNAVAILABLE"),
            ([(400, b'{"error":{"message":"nope"}}', "")], "PROVIDER_REJECTED"),
            ([(400, b'{"error":{"param":"tools","message":"x"}}', "")], "TOOL_CHOICE_UNSUPPORTED"),
            ([(200, completion([call("qodec_answer", "{bad")]), "")], "MALFORMED_TOOL_ARGUMENTS"),
            ([(200, completion([call("get_weather", "{}")]), "")], "PROTOCOL_VIOLATION"),
            ([(200, completion([call("qodec_answer", ANSWER_ARGS)], model="other"), "")], "PROVIDER_SUBSTITUTED"),
        ):
            receipt, _ = self.run_qualify(replies)
            self.assertEqual(receipt["classification"], expected)
            reached.add(expected)
        self.assertTrue(reached.issubset(set(pm.CLASSIFICATIONS)))

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
        receipt, _ = self.run_qualify([(200, completion([call("qodec_answer", ANSWER_ARGS)]), "")])
        blob = json.dumps(receipt)
        self.assertNotIn("Authorization", blob)
        self.assertNotIn("GROQ_API_KEY", json.dumps(receipt["transport_target"]))
        self.assertNotIn("api_key", blob)


if __name__ == "__main__":
    unittest.main()
