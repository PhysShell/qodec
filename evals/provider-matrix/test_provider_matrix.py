import argparse
import builtins
import contextlib
import re
import hashlib
import http.client
import io
import sys
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import mutations
import process_boundary
import provider_matrix as pm
import receipt_policy


MAX_TEST_REQUEST_BYTES = 8 * 1024 * 1024


class TruncatedRequest(RuntimeError):
    """A client stopped before the request it announced was complete."""


def read_http_request(conn, chunk: int = 65536) -> bytes:
    """Read one whole HTTP request from a socket, headers and declared body.

    A single `conn.recv(65536)` returns whatever has arrived, not the request.
    The qualification bodies carry the entire tool surface and run to several
    kilobytes, so a split between headers and body is ordinary; answering and
    closing with unread bytes still queued makes some platforms send RST, and
    the client then reports a transport failure instead of the 200 the test
    asserts. That is a test which is green because of how the kernel happened
    to segment a stream today.

    Fail-closed on every way this can go wrong — a peer that stops early, a
    `Content-Length` that is not a number, and a length past a local bound —
    because a listener that guesses is the same defect one layer down.
    """
    buffered = b""
    while b"\r\n\r\n" not in buffered:
        piece = conn.recv(chunk)
        if not piece:
            raise TruncatedRequest("the peer closed before the headers ended")
        buffered += piece
    head, _, body = buffered.partition(b"\r\n\r\n")
    wanted = 0
    for line in head.split(b"\r\n"):
        name, sep, value = line.partition(b":")
        if sep and name.strip().lower() == b"content-length":
            try:
                wanted = int(value.strip())
            except ValueError:
                raise TruncatedRequest("Content-Length is not a number") from None
            if wanted < 0 or wanted > MAX_TEST_REQUEST_BYTES:
                raise TruncatedRequest(f"Content-Length {wanted} is outside the local bound")
    while len(body) < wanted:
        piece = conn.recv(chunk)
        if not piece:
            raise TruncatedRequest(
                f"the peer closed after {len(body)} of {wanted} declared bytes")
        body += piece
    return head + b"\r\n\r\n" + body


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
        self.assertTrue(name.startswith("groq--openai%2Fgpt-oss-120b-"), name)
        self.assertNotIn("/", name)
        # And two targets differing only in slash placement stay distinct.
        self.assertNotEqual(
            pm.receipt_filename("a--b/c"),
            pm.receipt_filename("a--b%2Fc"),
        )

    def test_a_hostile_model_id_still_yields_a_usable_file_name(self):
        """The discovery source picks the model, so it picks part of the path.

        A NUL raises `ValueError` from `open()` and three hundred characters
        raise `OSError`, both from outside every receipt boundary — so one row
        in an untrusted catalog used to end the run and deny every later target
        its evidence. The escape set is now the complement of a declared
        alphabet, which is total by construction rather than by enumeration.
        """
        for model in ("a\x00b", "a" * 400, "..", "\n", " ", "sk-live/../../etc/passwd",
                      "\udcff", "%2F", ""):
            with self.subTest(model=model):
                name = pm.receipt_filename(f"groq--{model}")
                self.assertLessEqual(len(name.encode("utf-8")), 255, name)
                self.assertNotIn("\x00", name)
                self.assertEqual(name, Path(name).name, "must stay a single component")
                self.assertTrue(re.fullmatch(r"[A-Za-z0-9._%-]+", name), name)
                with tempfile.TemporaryDirectory() as td:
                    # The real proof: the filesystem takes it.
                    pm.write_json(Path(td) / name, {"ok": True})
                    self.assertEqual(len(list(Path(td).iterdir())), 1)

    def test_two_hostile_ids_that_truncate_alike_stay_distinct(self):
        """Bounding the stem is what makes a digest necessary, not optional."""
        self.assertNotEqual(
            pm.receipt_filename("groq--" + "m" * 400 + "one"),
            pm.receipt_filename("groq--" + "m" * 400 + "two"),
        )

    def test_a_write_failure_costs_one_target_and_not_the_run(self):
        """`guarded_receipt` promises this and used to stop one step short.

        The write sat outside it, so a name the filesystem refuses — or a full
        disk — ended the loop rather than being recorded against the target it
        belongs to.
        """
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "receipts"
            out.mkdir()
            blocked = out / "sub"
            blocked.write_text("not a directory", encoding="utf-8")
            # `out/sub` is a file, so writing beneath it raises NotADirectoryError.
            problem = pm.emit_receipt(blocked, 2, 5, "groq--m", {"ok": True})
        self.assertIsNotNone(problem)
        self.assertIn("3 of 5", problem)
        # A class name, not a message: an `OSError` renders the path it failed
        # on, and the path carries the model id. The contract is the shape.
        named = problem.rsplit(": ", 1)[1]
        self.assertTrue(issubclass(getattr(builtins, named), OSError), named)
        # The line describes the failure without quoting the path, which carries
        # a model name the discovery source chose.
        self.assertNotIn("groq--m", problem)

    def test_a_run_with_an_unwritable_receipt_reports_incomplete(self):
        out = io.StringIO()
        with contextlib.redirect_stderr(out):
            code = pm.report_write_problems(["receipt 1 of 2 could not be written: OSError"])
        self.assertEqual(code, 2)
        self.assertIn("the matrix is incomplete", out.getvalue())
        self.assertEqual(pm.report_write_problems([]), 0)

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
        # The findings live in the turn, where they are bounded. The top-level
        # detail carries a count, because the provider chooses how many there
        # are and that multiplicity must cross the boundary once.
        found = " ".join(receipt["turns"][1]["canary_answer_errors"])
        # The wrong answer is named by digest: those bytes are the provider's.
        self.assertNotIn("beta", found)
        self.assertIn(pm.evidence_digest("answer-bytes", b"beta")[:16], found)
        self.assertIn("not in any result this run returned", found)
        self.assertIn("canary check(s)", receipt["detail"])
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
        self.assertIn("never returned", " ".join(receipt["turns"][1]["canary_answer_errors"]))

    def test_a_citation_outside_the_support_is_a_mismatch(self):
        receipt = self.run_qualify({
            "handle": pm.CANNED_HANDLE,
            "answer": {"encoding": "base64url-nopad", "data": "YWxwaGE"},
            "cited": [{"store": pm.CANNED_HANDLE, "section": "attempt_9", "ordinal": 0}],
        })
        self.assertEqual(receipt["classification"], "CANARY_ANSWER_MISMATCH")
        self.assertIn("support", " ".join(receipt["turns"][1]["canary_answer_errors"]))

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

    def test_a_trailing_slash_is_a_url_property_and_not_a_name_property(self):
        """One normalisation was applied to three different kinds of string.

        `claimed.strip().rstrip("/")` is right for a URL, where a trailing slash
        is not part of the identity. `key_env` is the *name of an environment
        variable*: `GROQ_API_KEY/` is a different name, and the run that follows
        reads the name the plan supplied. So the check altered its input, found
        agreement, and admitted a row that then pointed at a variable the
        registry never named.
        """
        for field, value in (("key_env", "GROQ_API_KEY/"),
                             ("key_env", " GROQ_API_KEY"),
                             ("api_style", "openai-chat/")):
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(pm.EndpointRejected, "trusted registry"):
                    self.import_row({"provider": "groq", "model": "m", field: value})

    def test_a_trailing_slash_on_the_origin_is_still_tolerated(self):
        """The other half. Refusing this would be inventing a rule, not keeping one."""
        catalog = self.import_row({
            "provider": "groq", "model": "m",
            "api_base": registry()["providers"]["groq"]["api_base"] + "/",
        })
        self.assertEqual(catalog["targets"][0]["api_base"],
                         registry()["providers"]["groq"]["api_base"])

    def test_every_authority_field_states_how_it_is_compared(self):
        """An unnamed field must stop the program, not inherit a rule."""
        self.assertEqual(set(pm.AUTHORITY_COMPARISON), set(pm.AUTHORITY_FIELDS))
        with self.assertRaises(KeyError):
            pm.authority_matches("invented", "a", "a")

    def test_an_edited_plan_cannot_launder_a_key_name_either(self):
        """Intake is the first gate; the plan on disk is re-checked at use."""
        target = dict(self.import_row({"provider": "groq", "model": "m"})["targets"][0])
        target["key_env"] = target["key_env"] + "/"
        with self.assertRaisesRegex(pm.EndpointRejected, "does not match"):
            pm.verify_against_registry(target, registry())

    def test_a_plan_whose_authority_field_is_not_a_string_is_refused(self):
        """The outcome, which is what this can honestly claim.

        It does *not* prove the `isinstance` guard: a plan arrives from
        `strict_json_loads`, so no JSON non-string renders as `GROQ_API_KEY`,
        and the previous `str(claimed)` comparison refused all of these too.
        The mutation for that guard was written, survived, and is withdrawn in
        `mutations.py` with its reason rather than propped up here by a
        `__str__` a plan cannot contain.
        """
        target = dict(self.import_row({"provider": "groq", "model": "m"})["targets"][0])
        for hostile in (None, {"host": "steal.example"}, 7, True):
            with self.subTest(value=repr(hostile)):
                with self.assertRaisesRegex(pm.EndpointRejected, "does not match"):
                    pm.verify_against_registry({**target, "key_env": hostile}, registry())

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
        # Rendered here, because the oracle now returns typed lines. The text
        # is the same text; what changed is that it can only be built from a
        # registered template and typed arguments.
        return [why.render() for why in
                pm.envelope_errors(self.envelope(**fields), pm.EnvelopeLabel(known="answer"))[0]]

    def test_the_canonical_envelope_is_accepted(self):
        errors, decoded = pm.envelope_errors(self.envelope(), pm.EnvelopeLabel(known="answer"))
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
        self.assertTrue(any("dangling-character" in e for e in self.errors(data="YWxwaGEx3")))

    def test_non_zero_trailing_bits_are_rejected(self):
        # "YWxwaGF" and "YWxwaGE" differ only in bits that decode to nothing.
        self.assertEqual(pm.b64url_nopad_decode("YWxwaGE"), b"alpha")
        self.assertTrue(any("non-zero-trailing-bits" in e for e in self.errors(data="YWxwaGF")))

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
        self.assertIn("no operation in this run returned a handle",
                      " ".join(receipt["turns"][-1]["canary_answer_errors"]))

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
        self.assertEqual(
            pm.discriminator("message-role", "user", pm.MESSAGE_ROLES).render(), "'user'")
        self.assertEqual(
            pm.discriminator("message-role", "bot", pm.MESSAGE_ROLES).render(),
            pm.opaque_ref("message-role", "bot").render())
        self.assertEqual(
            pm.discriminator("tool-call-type", {"a": 1}, pm.TOOL_CALL_TYPES).render(),
            "<tool-call-type object>")
        # And the rendered form is the *only* way out: the discriminator is a
        # typed value, so a template slot cannot be filled with a string that
        # merely looks like one.
        self.assertIsInstance(
            pm.discriminator("message-role", "bot", pm.MESSAGE_ROLES), pm.Discriminator)

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
        joined = " ".join(why.render() for why in errors)
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
        for status in (0, 99, 1000, -200):
            with self.assertRaises(ValueError, msg=status):
                pm.as_send_result((status, b"{}", "", "completed"))

    def test_a_three_digit_status_nobody_assigned_is_an_observation(self):
        """Refusing it raised out of the transport and became `INTERNAL_ERROR`.

        `http.client` parses any three-digit status line, so `HTTP/1.1 600 Nope`
        reaches this module — and the matrix was blamed for a status somebody
        else wrote. An unassigned code is still something that happened; what it
        is not is a success, and `classify_http` files it as `HTTP_FAILURE`.
        """
        for status in (600, 799, pm.HTTP_STATUS_MAX):
            with self.subTest(status=status):
                self.assertEqual(
                    pm.as_send_result((status, b"{}", "", "completed")).status, status)
                self.assertEqual(pm.classify_http(status), "HTTP_FAILURE")

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

    def nested_rejection(self, depth: int) -> bytes:
        """A 400 body that names `tool_choice`, wrapped `depth` levels deep.

        Valid JSON at any depth, and readable by `json.loads` at the depths used
        here — which is the point. The old regression relied on a 40,000-level
        body raising `RecursionError`, and CPython 3.14 parses that happily, so
        removing the depth pre-scan stopped changing the answer and `U4`
        survived. The mutation had been dying of a platform accident rather than
        of the contract it names.

        `MAX_JSON_DEPTH` is a *declared* boundary, so the specimen stands on it:
        one level past it must not be read, one level inside it must.
        """
        # `error` stays at the top level, where the reader looks for it; the
        # depth is in a sibling it never reads. Burying the error object itself
        # would prove only that the reader does not dig, which is not the
        # contract under test.
        return (b'{"error":{"param":"tool_choice","message":"unsupported"},"pad":'
                + b"[" * depth + b"]" * depth + b"}")

    def test_the_lenient_reader_stops_at_the_depth_the_module_declares(self):
        """The contract, not the interpreter's stack.

        One level past `MAX_JSON_DEPTH` the body is not interpreted, so the
        provider's own word about the tools is never seen and the rejection is
        the ordinary one. One level inside it, the same body is read and the
        cause is the specific one. The two classifications differ, which is what
        makes the pre-scan's removal detectable on any Python.
        """
        # The surrounding object is one level of its own, so `MAX_JSON_DEPTH`
        # brackets put the body exactly one past the boundary.
        too_deep = self.nested_rejection(pm.MAX_JSON_DEPTH)
        self.assertEqual(pm.json_nesting_depth(too_deep.decode()), pm.MAX_JSON_DEPTH + 1)
        self.assertFalse(pm.provider_named_the_tools(too_deep))
        admitted = self.nested_rejection(pm.MAX_JSON_DEPTH - 1)
        self.assertEqual(pm.json_nesting_depth(admitted.decode()), pm.MAX_JSON_DEPTH)
        self.assertTrue(pm.provider_named_the_tools(admitted))

        deep = pm.qualify_target(target(), surface(), 30.0, 6, scripted([(400, too_deep, "")]))
        self.assertEqual(deep["classification"], "PROVIDER_REJECTED")
        shallow = pm.qualify_target(target(), surface(), 30.0, 6, scripted([(400, admitted, "")]))
        self.assertEqual(shallow["classification"], "TOOL_CHOICE_UNSUPPORTED")

    def test_the_depth_specimen_does_not_depend_on_a_recursion_error(self):
        """If the interpreter can read it, the *gate* is what refused it."""
        import json as _json

        too_deep = self.nested_rejection(pm.MAX_JSON_DEPTH)
        try:
            _json.loads(too_deep)
        except RecursionError:  # pragma: no cover — depends on the interpreter
            self.fail("the specimen must be readable, or it tests the stack again")
        self.assertGreater(pm.json_nesting_depth(too_deep.decode()), pm.MAX_JSON_DEPTH)

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
        # Every counter, so the bounded-integer policies for all three are
        # exercised by something the loop really produced rather than by a unit
        # test of `normalize_provider_usage` standing in for the wiring.
        counted = (200, completion(
            [call("qodec_intersect", INTERSECT_ARGS, "call_c")],
            usage={"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}), "")
        # A `model` that is an object: it crosses as its JSON type and nothing
        # else, which is the only way `reported_model_type` is ever written.
        typed_model = (200, json.dumps({
            "model": {"name": "not-a-string"},
            "choices": [{"message": {
                "role": "assistant", "content": None,
                "tool_calls": [call("qodec_intersect", INTERSECT_ARGS, "call_t")]}}]}).encode(), "")
        # A transport failure that names its class, so the failure-class
        # projection in a turn record is produced rather than assumed.
        classed = pm.SendResult(None, None, "boom", "before-response", None, None,
                                "connection-failed", "url-error", "URLError")
        # Arguments that violate more rules than the producer will record, so
        # `argument_errors_truncated` is written by the real loop rather than
        # declared reachable and never reached. One error per wrongly typed
        # array item, and the whole body is about three kilobytes — which is
        # what made the unbounded count a defect rather than a curiosity: the
        # response is unremarkable and the count was not.
        flooded = (200, completion([call(
            "qodec_intersect",
            json.dumps({"index": "i", "sections": [0] * (pm.MAX_ARGUMENT_ERRORS + 1)}),
            "call_flood")]), "")

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
            "schema-violations-truncated": ([flooded], None),
            "two-answers": (OPERATION_THEN(two_answers), None),
            "answer-with-operation": (OPERATION_THEN(answer_and_op), None),
            "answer-before-roundtrip": ([ANSWER_REPLY], None),
            "canary-mismatch": (OPERATION_THEN(wrong_answer), None),
            "identity-substituted": (OPERATION_THEN(substituted), None),
            "identity-unestablished": (OPERATION_THEN(no_model), None),
            "no-terminal-answer": ([operations, operations], None),
            "usage-counters": ([counted, counted], None),
            "object-model": ([typed_model, typed_model], None),
            "classed-transport-failure": ([classed], None),
            "pass": (OPERATION_THEN(ANSWER_REPLY), None),
        }
        for name, (replies, edited) in scenarios.items():
            yield name, pm.qualify_target(
                edited or target(), surface(), 30.0, 2 if name == "no-terminal-answer" else 6,
                scripted(replies), response_limit=self.LIMIT)

    def probe_receipts(self):
        ok = json.dumps({"model": "m", "choices": [{"message": {"content": "QODEC_PROBE_OK"}}],
                         "usage": {"prompt_tokens": 9}}).encode()
        counted = json.dumps({"model": "m", "choices": [{"message": {"content": "QODEC_PROBE_OK"}}],
                              "usage": {"prompt_tokens": 9, "completion_tokens": 5,
                                        "total_tokens": 14}}).encode()
        typed_model = json.dumps({"model": {"name": "not-a-string"},
                                  "choices": [{"message": {"content": "QODEC_PROBE_OK"}}]}).encode()
        drifted = json.dumps({"model": "other", "choices": [{"message": {"content": "QODEC_PROBE_OK"}}]}).encode()
        silent = json.dumps({"choices": [{"message": {"content": "QODEC_PROBE_OK"}}]}).encode()
        wrong = json.dumps({"model": "m", "choices": [{"message": {"content": "no"}}]}).encode()
        scenarios = {
            "pass": ([(200, ok, "", "completed")], None),
            "usage-counters": ([(200, counted, "", "completed")], None),
            "object-model": ([(200, typed_model, "", "completed")], None),
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

    def reached(self, generator, schema):
        """Every path the real pipeline produced, for one receipt kind."""
        def explode():
            raise ValueError("Bearer sk-SECRET")

        paths = set()
        for _, receipt in generator():
            paths |= receipt_policy.reached_paths(receipt)
        paths |= receipt_policy.reached_paths(
            pm.guarded_receipt(schema, target(), explode))
        return paths

    def test_every_applicable_policy_is_produced_by_a_real_run(self):
        """Coverage of the *table*, not of the classification vocabulary.

        Asserting that the scenarios reach every classification is a claim about
        verdicts, and the table is a claim about places. Twelve of a hundred and
        nine policies turned out never to be produced by any generated receipt —
        `reported_model_type`, the per-turn failure-class projection, two of the
        three usage counters — so weakening any of the twelve left every gate
        green. A reviewer found the first of them; this finds the rest, and the
        next one, without anybody having to look.

        Asked per receipt kind on purpose: a qualification-only path satisfied
        by a qualification scenario says nothing about the probe, and a union
        would hide exactly that.
        """
        for kind, generator, schema in (
            (receipt_policy.QUALIFICATION, self.qualification_receipts, pm.QUALIFY_SCHEMA),
            (receipt_policy.PROBE, self.probe_receipts, pm.PROBE_SCHEMA),
        ):
            with self.subTest(receipt=kind):
                gaps = receipt_policy.coverage_gaps(kind, self.reached(generator, schema))
                self.assertEqual(gaps, [], f"{len(gaps)} {kind} policies no run produces")

    def test_the_coverage_gate_would_notice_a_policy_nothing_produces(self):
        """A gate that has never reported a gap is a gate nobody has tested."""
        invented = receipt_policy.POLICIES + [
            receipt_policy.DurableFieldPolicy(
                receipt_policy.P("nobody_writes_this"), receipt_policy.Flag(),
                (receipt_policy.PROBE,))]
        gaps = receipt_policy.coverage_gaps(
            receipt_policy.PROBE, self.reached(self.probe_receipts, pm.PROBE_SCHEMA), invented)
        self.assertEqual(gaps, ["no run produces nobody_writes_this"])

    def test_the_coverage_gate_looks_in_both_directions(self):
        """Subtracting one way cannot see a declaration that is simply false.

        Mark a shared policy probe-only and qualification keeps writing the
        field; `required - reached` stays empty because nothing is *missing*.
        What is wrong is the declaration, and only `reached - declared` sees it.
        """
        mislabelled = [
            receipt_policy.DurableFieldPolicy(
                policy.path, policy.kind, (receipt_policy.PROBE,), policy.nullable,
                policy.coverage_required, policy.why)
            if policy.path == receipt_policy.P("schema") else policy
            for policy in receipt_policy.POLICIES
        ]
        reached = self.reached(self.qualification_receipts, pm.QUALIFY_SCHEMA)
        report = receipt_policy.coverage(receipt_policy.QUALIFICATION, reached, mislabelled)
        self.assertEqual(report.missing, [])
        self.assertEqual(report.wrong_schema, ["schema"])

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

    def test_an_empty_container_is_a_path_and_not_a_silence(self):
        """The counterexample to the round's own theorem, closed.

        `flatten` used to yield nothing for `{}` and `[]` on the grounds that an
        empty container has no leaves. That removed the path from the check
        without removing it from the file — and a provider-chosen **key** with an
        empty object under it passed the closed-world audit reporting nothing at
        all. A JSON key is as durable as a JSON value.
        """
        for hostile in ({}, [], {"sk-live-secret": {}}, [[]]):
            with self.subTest(value=repr(hostile)):
                receipt = self.specimen()
                receipt["provider_said"] = hostile
                self.assert_refused(receipt, "no policy names")

    def test_a_key_cannot_impersonate_a_structural_path(self):
        """`"turns[].detail"` as a literal top-level key is not `turns[].detail`.

        While a path was a dotted string those two were the same value, so a
        provider-chosen key could satisfy the policy written for a different
        place entirely — and escaping `.` and `[]` would have been the third
        patch on a representation problem. A path is now a tuple of steps, and
        the string exists only when a finding is printed.
        """
        for hostile in ("turns[].detail", "turns.detail", "detail.name",
                        "a.b", "x[]", "", "provider_said[]"):
            with self.subTest(key=hostile):
                receipt = self.specimen()
                receipt[hostile] = "timeout"
                self.assert_refused(receipt, "no policy names")

    def test_a_key_that_is_not_a_string_is_a_finding_and_not_a_crash(self):
        """A receipt is built in Python before it is serialised.

        `str(key)` would launder an integer into a component that looks exactly
        like a declared one, so a non-string key becomes a step no policy can
        name — and its rendering carries the key's type, never its value.
        """
        receipt = self.specimen()
        receipt[7] = "x"
        findings = self.audit(receipt, target(), self.registry_entry())
        self.assertTrue(any("non-string key: number" in f for f in findings), findings)
        self.assertFalse(any("7" in f.split("non-string")[0] for f in findings))

    def test_a_known_word_under_an_unknown_prefix_is_still_projected(self):
        """A name declared in another branch is not a name declared *here*.

        `provider_said.detail.name.ordinal` printed three provider-chosen keys
        verbatim, because each of them is a real component somewhere else in the
        tree. The walk is prefix-sensitive now: once a step is unrecognised,
        every step below it is foreign too.
        """
        receipt = self.specimen()
        receipt["provider_said"] = {"detail": {"name": {"ordinal": "sk-live-secret"}}}
        findings = self.audit(receipt, target(), self.registry_entry())
        joined = " ".join(findings)
        for word in ("provider_said", "detail", "name", "ordinal"):
            with self.subTest(component=word):
                self.assertIn(pm.opaque_ref("json-value", word).render(), joined)
        self.assertNotIn("sk-live-secret", joined)

    def test_the_refusal_names_the_shape_and_digests_the_key(self):
        """The gate must not print into CI what it is refusing to write to disk."""
        secret = "sk-live-not-a-real-key"
        receipt = self.specimen()
        receipt["provider_said"] = {secret: {}}
        findings = self.audit(receipt, target(), self.registry_entry())
        joined = " ".join(findings)
        self.assertNotIn(secret, joined)
        self.assertIn(pm.opaque_ref("json-value", secret).render(), joined)
        # The components the table does declare stay readable: a finding nobody
        # can read is a finding nobody acts on.
        self.assertEqual(
            receipt_policy.projected_path(
                receipt_policy.P("turns", receipt_policy.EACH, "detail"),
                receipt_policy.POLICIES),
            "turns[].detail")

    def test_every_container_in_a_real_receipt_is_named(self):
        """The table describes the artifact's shape, not only its scalars."""
        receipt = self.specimen()
        nodes = [path for path, value in receipt_policy.flatten(receipt)
                 if isinstance(value, receipt_policy.Node)]
        self.assertIn(receipt_policy.P("turns"), nodes)
        self.assertIn(receipt_policy.P("turns", receipt_policy.EACH), nodes)
        self.assertIn(receipt_policy.P("transport_target"), nodes)
        for path in nodes:
            with self.subTest(node=receipt_policy.render_path(path)):
                policy = receipt_policy.exactly_one_policy_for(path)
                self.assertIsInstance(policy.kind, receipt_policy.Shape)

    def test_a_container_where_a_scalar_belongs_stops_the_gate(self):
        receipt = self.specimen()
        receipt["turn_count"] = {}
        self.assert_refused(receipt, "is not an integer")
        other = self.specimen()
        other["turns"] = {}
        self.assert_refused(other, "an object where an array belongs")
        # And the reverse: a scalar where a container belongs. A `Shape` policy
        # that shrugs at a non-container is a policy that stops describing the
        # artifact's shape the moment the shape is wrong.
        scalar = self.specimen()
        scalar["transport_target"] = "https://api.groq.com/openai/v1"
        self.assert_refused(scalar, "is not a container")
        listed = self.specimen()
        listed["turns"] = 5
        self.assert_refused(listed, "is not a container")

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
            receipt_policy.DurableFieldPolicy(receipt_policy.P("detail"), receipt_policy.Flag())]
        problems = receipt_policy.policy_problems(doubled)
        self.assertTrue(any("exactly one may" in p for p in problems), problems)
        with self.assertRaisesRegex(KeyError, "2 policies name"):
            receipt_policy.exactly_one_policy_for(receipt_policy.P("detail"), doubled)

    def test_a_digest_policy_without_a_declared_domain_stops_the_gate(self):
        """A digest nobody can recompute is a field nobody can audit."""
        problems = receipt_policy.policy_problems(
            [receipt_policy.DurableFieldPolicy(
                receipt_policy.P("x"), receipt_policy.Digest("invented"))])
        self.assertTrue(any("not declared in EVIDENCE_DOMAINS" in p for p in problems), problems)

    def test_a_receipt_kind_the_table_does_not_know_stops_the_gate(self):
        """`schemas=("proeb",)` put a policy in neither universe.

        One transposition, and both directions of the coverage proof went green
        by the policy vanishing from each of them: demanded of no kind, declared
        for no kind. The vocabulary is a closed type now, and membership is
        checked at runtime — an annotation stands beside a program and offers
        moral support while it does as it pleases.
        """
        for bad in (("proeb",), ("probe", "qualifcation"), ("PROBE",), (None,), (1,)):
            with self.subTest(schemas=bad):
                problems = receipt_policy.policy_problems(
                    [receipt_policy.DurableFieldPolicy(
                        receipt_policy.P("x"), receipt_policy.Flag(), bad)])
                self.assertTrue(any("is not a receipt kind" in p for p in problems), problems)
        empty = receipt_policy.policy_problems(
            [receipt_policy.DurableFieldPolicy(
                receipt_policy.P("x"), receipt_policy.Flag(), ())])
        self.assertTrue(any("applies to no receipt kind" in p for p in empty), empty)
        # And every kind in the shipped table is a member of the closed type.
        for policy in receipt_policy.POLICIES:
            for kind in policy.schemas:
                self.assertIsInstance(kind, receipt_policy.ReceiptKind, policy.named())

    def test_a_coverage_opt_out_without_a_reason_stops_the_gate(self):
        """An escape hatch from the closed world has to be argued for in writing."""
        excused = [receipt_policy.DurableFieldPolicy(
            receipt_policy.P("x"), receipt_policy.Flag(), coverage_required=False)]
        self.assertTrue(any("without a stated reason" in p
                            for p in receipt_policy.policy_problems(excused)))
        argued = [receipt_policy.DurableFieldPolicy(
            receipt_policy.P("x"), receipt_policy.Flag(), coverage_required=False,
            why="companion-only, written by nothing")]
        self.assertEqual(receipt_policy.policy_problems(argued), [])
        # And every opt-out in the shipped table carries one.
        for policy in receipt_policy.POLICIES:
            if not policy.coverage_required:
                self.assertTrue(policy.why, policy.named())

    def test_the_policy_modules_own_self_test_passes(self):
        self.assertEqual(receipt_policy.self_test(), 0)

    def test_a_reference_is_prose_and_a_bare_secret_is_not(self):
        """The one rule that lets a detail line mention foreign material at all."""
        prose = receipt_policy.Prose(4096)
        context = {"local_words": set()}
        named = pm.opaque_ref("tool-name", "qodec_intersect").render()
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
        wrong = (pm.LocalDetail("handle-never-returned", (pm.opaque_ref("handle", "h"),)),)
        digests = (pm.DigestRef.of("ab" * 32),)
        drifted = pm.AnswerFacts("drifted", wrong, digests)
        self.assertEqual(pm.reduce_qualification(drifted).classification, "PROVIDER_SUBSTITUTED")
        missing = pm.AnswerFacts("missing", (), ())
        self.assertEqual(pm.reduce_qualification(missing).classification, "MODEL_IDENTITY_MISSING")
        # And with a wrong answer as well: an unestablished identity is not
        # downgraded by a second failure arriving beside it. Both fail, and the
        # one a reader must act on first is "we do not know what produced this".
        both = pm.AnswerFacts("missing", wrong, ())
        self.assertEqual(pm.reduce_qualification(both).classification, "MODEL_IDENTITY_MISSING")
        drifted_and_wrong = pm.AnswerFacts("drifted", wrong, digests)
        self.assertEqual(pm.reduce_qualification(drifted_and_wrong).classification,
                         "PROVIDER_SUBSTITUTED")
        mismatched = pm.AnswerFacts("verified", wrong, ())
        self.assertEqual(pm.reduce_qualification(mismatched).classification, "CANARY_ANSWER_MISMATCH")
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

    # Exact relative paths, not bare filenames. `path.name` would give a nested
    # `helpers/test_provider_matrix.py` the same diplomatic immunity as the real
    # one, which is a strange thing for an ownership gate to hand out.
    #
    # The test suite is exempt, stated rather than silently skipped: it runs the
    # CLI end to end and patches `subprocess.run` to prove the gates report
    # rather than raise. It writes no receipts and ships to nobody.
    EXEMPT = {Path("process_boundary.py"), Path("test_provider_matrix.py")}

    # The standard library's direct process-launch surface. The first version of
    # this gate matched only the word `subprocess`, which made the test an
    # assertion about a module name while its own name and docstring claimed
    # something else: `os.system`, `os.popen` and
    # `asyncio.create_subprocess_exec` all start processes and all stayed green.
    #
    # A theorem quietly renamed after a counterexample is worth less than the
    # counterexample, so the surface is widened rather than the claim narrowed.
    # What a static check *cannot* cover is stated in `mutations.py` with the
    # other deliberately unmutated gaps: `importlib.import_module("subprocess")`
    # and a computed `getattr` are not reachable from the AST, and closing them
    # needs a runtime audit hook rather than a wider pattern.
    LAUNCHERS = {
        # every attribute, because the module exists to start processes
        "subprocess": None,
        "os": frozenset({
            "system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp",
            "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp",
            "execvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv",
            "spawnve", "spawnvp", "spawnvpe",
        }),
        "asyncio": frozenset({"create_subprocess_exec", "create_subprocess_shell"}),
        "multiprocessing": frozenset({"Process", "Pool", "get_context", "spawn"}),
        "pty": frozenset({"spawn", "fork"}),
    }

    def modules(self, root=None):
        """Every module in the vertical, nested ones included.

        `glob("*.py")` saw only the top level, so a future
        `helpers/runner.py` could call `subprocess.run` with this gate green —
        the ownership claim would have been true of one directory and asserted
        of a package.

        `root` is a parameter so the test that proves the enumeration reaches a
        nested module can build one somewhere else. The first version wrote a
        `nested_probe_dir` into the directory under test and removed it in a
        `finally`: harmless alone, and not harmless at all beside the mutation
        harness, which copies this tree while the suite may be running. A copy
        taken mid-test carried a nested `import subprocess` and turned the
        ownership gate red in a run that had nothing to do with it — a test that
        can make an unrelated gate fail is a test whose failures get blamed on
        the gate.
        """
        here = Path(root) if root is not None else Path(__file__).resolve().parent
        return sorted(
            path for path in here.rglob("*.py")
            if "__pycache__" not in path.parts
            and path.relative_to(here) not in self.EXEMPT
        )

    def launches(self, module: str, attr: str) -> bool:
        allowed = self.LAUNCHERS.get(module, ())
        return module in self.LAUNCHERS and (allowed is None or attr in allowed)

    def launcher_names(self, tree):
        """Local names that refer to a launcher module, to a fixed point.

        `import os as other` was resolved and `launcher = os` was not, so the
        alias the gate caught was the one a reader would notice anyway. Plain
        assignment chains are reachable statically, so they are followed:
        `again = launcher = os` binds all three.
        """
        import ast
        names = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in self.LAUNCHERS:
                        names[alias.asname or alias.name] = root
        changed = True
        while changed:
            changed = False
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Name):
                    continue
                source = names.get(node.value.id)
                if source is None:
                    continue
                for goal in node.targets:
                    if isinstance(goal, ast.Name) and names.get(goal.id) != source:
                        names[goal.id] = source
                        changed = True
        return names

    def escapes_the_grammar(self, tree, modules):
        """Every place a launcher leaves the shapes this gate can read.

        The first version resolved `import x as y` and then `a = b`, and a
        reviewer immediately produced three more spellings: tuple unpacking, a
        walrus, a parameter default. Adding an `if` for each would have been the
        next round's finding — `for launcher in [os]`, `run(os)`, `return os`,
        `box = [os]`, `yield subprocess` — because the list of ways to move a
        value in Python is not a list anybody finishes.

        So the gate states what is *allowed* instead. Outside the boundary a
        launcher may only be imported, aliased by plain `name = name`, and
        inspected directly as an attribute. Every other movement is a finding on
        its own — not because the value is proven to reach a launch, but because
        it has left the grammar in which that could be proven, and a gate that
        tries to follow it becomes a points-to analysis and stops being a gate.
        """
        import ast
        parents = {child: node
                   for node in ast.walk(tree)
                   for child in ast.iter_child_nodes(node)}
        out = []
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)):
                continue
            if node.id not in modules:
                continue
            parent = parents.get(node)
            # Inspected directly: `os.fsdecode`, `subprocess.run`. Whether the
            # attribute is a launch is the other rule's business.
            if isinstance(parent, ast.Attribute):
                continue
            # The alias rule, and only in its plain form: every target a bare
            # name, so `a, b = os, asyncio` is not it.
            if (isinstance(parent, ast.Assign) and parent.value is node
                    and all(isinstance(goal, ast.Name) for goal in parent.targets)):
                continue
            out.append(
                f"a launcher leaves the inspected grammar at line {node.lineno}")
        return out

    def subprocess_uses(self, path):
        """Every direct standard-library process launch in one module."""
        import ast
        tree = ast.parse(path.read_text(encoding="utf-8"))
        uses = []
        modules = self.launcher_names(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == "subprocess":
                        uses.append(f"import {alias.name} at line {node.lineno}")
            if isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                for alias in node.names:
                    if self.launches(root, alias.name):
                        uses.append(f"from {node.module} import {alias.name} at line {node.lineno}")
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                module = modules.get(node.value.id, node.value.id)
                if self.launches(module, node.attr):
                    uses.append(f"{module}.{node.attr} at line {node.lineno}")
        uses.extend(self.escapes_the_grammar(tree, modules))
        return uses

    def test_no_module_but_the_boundary_starts_a_process(self):
        offenders = {str(path.name): self.subprocess_uses(path) for path in self.modules()}
        self.assertEqual({name: uses for name, uses in offenders.items() if uses}, {})

    def test_the_enumeration_reaches_a_nested_module(self):
        """`glob` saw one directory while the claim was about the vertical."""
        here = Path(__file__).resolve().parent
        found = self.modules()
        self.assertIn(here / "receipt_policy.py", found)
        self.assertNotIn(here / "process_boundary.py", found)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "process_boundary.py").write_text("import subprocess\n", encoding="utf-8")
            nested = root / "helpers"
            nested.mkdir()
            (nested / "runner.py").write_text("import subprocess\n", encoding="utf-8")
            self.assertIn(nested / "runner.py", self.modules(root))
            # The exemption is a relative path, so the real one is exempt...
            self.assertNotIn(root / "process_boundary.py", self.modules(root))
            # ...and a nested file wearing its name is not.
            (nested / "process_boundary.py").write_text("import os\n", encoding="utf-8")
            self.assertIn(nested / "process_boundary.py", self.modules(root))

    def test_the_gate_would_notice_every_class_of_new_caller(self):
        specimens = {
            "subprocess.run": "import subprocess\nsubprocess.run(['ls'])\n",
            "an aliased subprocess": "import subprocess as sp\nsp.run(['ls'])\n",
            "a named import": "from subprocess import run\nrun(['ls'])\n",
            "os.system": "import os\nos.system('ls')\n",
            "os.popen": "import os\nos.popen('ls')\n",
            "os.execv": "import os\nos.execv('/bin/ls', ['ls'])\n",
            "an aliased os": "import os as oh\noh.spawnv(0, '/bin/ls', ['ls'])\n",
            "from os import system": "from os import system\nsystem('ls')\n",
            "from os import system as helper":
                "from os import system as helper\nhelper('ls')\n",
            "asyncio": "import asyncio\nasyncio.create_subprocess_exec('ls')\n",
            "multiprocessing": "import multiprocessing\nmultiprocessing.Process()\n",
            "pty.spawn": "import pty\npty.spawn('ls')\n",
            # assignment aliases, one hop and two
            "a rebound module": "import os\nlauncher = os\nlauncher.system('ls')\n",
            "a twice-rebound module":
                "import os\nlauncher = os\nagain = launcher\nagain.system('ls')\n",
            # left the inspected grammar: a finding in itself, because a gate
            # that follows the value from here is a points-to analysis
            "stored on an attribute": "import os\nholder.launcher = os\n",
            "stored in a mapping": "import subprocess\nmapping['x'] = subprocess\n",
            "tuple unpacking": "import os\nimport asyncio\na, b = os, asyncio\n",
            "a parameter default": "import os\ndef run(launcher=os):\n    pass\n",
            "a walrus": "import os\n(launcher := os).getcwd()\n",
            "a for target": "import os\nfor launcher in [os]:\n    pass\n",
            "a call argument": "import subprocess\nhelper(subprocess)\n",
            "a return": "import os\ndef give():\n    return os\n",
            "a yield": "import subprocess\ndef give():\n    yield subprocess\n",
            "a container literal": "import os\nbox = [os]\n",
            "a globals write": "import os\nglobals()['x'] = os\n",
            "a launcher callable stored": "import os\nholder.launcher = os.system\n",
        }
        with tempfile.TemporaryDirectory() as td:
            for name, source in specimens.items():
                with self.subTest(specimen=name):
                    offender = Path(td) / "sneaky.py"
                    offender.write_text(source, encoding="utf-8")
                    self.assertTrue(self.subprocess_uses(offender), name)

    def test_an_innocent_use_of_a_launcher_module_is_not_flagged(self):
        """`os.fsdecode` and `os.environ` are not process creation.

        A gate that refuses every use of `os` would be turned off within a week,
        and a gate that gets turned off protects nothing.
        """
        with tempfile.TemporaryDirectory() as td:
            innocent = Path(td) / "fine.py"
            innocent.write_text(
                "import os\nfrom pathlib import Path\n"
                "x = os.fsdecode(b'a')\ny = os.environ.get('HOME')\n"
                "p = Path('x')\nq = p\nq.name\n",
                encoding="utf-8")
            self.assertEqual(self.subprocess_uses(innocent), [])

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

    def test_a_kill_counts_only_when_the_mutant_ran_as_a_program(self):
        """The remains of the `DF9` class, as a rule rather than a name list.

        Enumerating `NameError` and its friends would have been the sixth
        neighbouring defect found one at a time. A suite run that never says how
        many tests it discovered did not get as far as running any, whatever
        exception it died of.
        """
        def suite(passed, output, count):
            return mutations.OracleResult("suite", mutations.SUITE_ORACLE, passed, output, count)

        # import-time AttributeError, import-time TypeError, a red process with
        # no count at all: three spellings of the same incoherence.
        for output in ("AttributeError: module has no attribute 'x'",
                       "TypeError: unsupported operand",
                       "Traceback (most recent call last):\n  RuntimeError: nope"):
            with self.subTest(output=output.splitlines()[0]):
                self.assertIn("never reported", suite(False, output, None).incoherent(330))
        self.assertIn("discovered 12 tests", suite(False, "Ran 12 tests\nFAILED", 12).incoherent(330))
        self.assertIsNone(suite(False, "Ran 330 tests\nFAILED", 330).incoherent(330))

        # A gate is deliberately *not* held to this rule. Several gate
        # mutations exist to make a gate die of a traceback instead of printing
        # a report, so demanding a verdict line from it would refuse the very
        # kill that proves the contract. The suite is the anchor instead, which
        # is why every target names one.
        def gate(passed, output):
            return mutations.OracleResult("policy-gate", mutations.GATE_ORACLE, passed, output, None)

        self.assertIsNone(gate(False, "Traceback (most recent call last):").incoherent(330))

    def test_every_target_names_the_oracle_coherence_is_asked_of(self):
        """No suite oracle means no anchor, and every kill taken on trust."""
        self.assertEqual(mutations.target_problems(mutations.MUTATION_TARGETS), [])
        unanchored = {"x.py": (mutations.POLICY_GATE,)}
        self.assertEqual(mutations.target_problems(unanchored),
                         ["x.py names no suite oracle to anchor coherence on"])

    def test_an_expected_kill_must_come_from_the_oracle_that_failed(self):
        """Otherwise the test id can arrive from a run that passed."""
        name = "DF1 audit skips a leaf no policy names"
        expected = mutations.EXPECTED_KILL[name]
        red = mutations.OracleResult(
            "suite", mutations.SUITE_ORACLE, False, "Ran 330 tests\nFAILED (failures=1)", 330)
        green_with_the_name = mutations.OracleResult(
            "policy-gate", mutations.GATE_ORACLE, True, f"OK ... {expected} ...", None)
        state, why = mutations.verdict_for(name, [red, green_with_the_name], 330)
        self.assertEqual(state, "MISATTRIBUTED", why)

        red_with_the_name = mutations.OracleResult(
            "suite", mutations.SUITE_ORACLE, False,
            f"Ran 330 tests\nFAIL: {expected}\nFAILED (failures=1)", 330)
        state, _ = mutations.verdict_for(name, [red_with_the_name], 330)
        self.assertEqual(state, "killed")

    def test_a_mutant_that_no_oracle_noticed_is_a_survivor(self):
        green = mutations.OracleResult(
            "suite", mutations.SUITE_ORACLE, True, "Ran 330 tests\nOK", 330)
        state, _ = mutations.verdict_for("anything", [green], 330)
        self.assertEqual(state, "SURVIVED")
        state, why = mutations.verdict_for("anything", [], 330)
        self.assertEqual(state, "INVALID", why)

    def test_every_mutation_target_names_its_oracles(self):
        """A file the harness can mutate but cannot ask about is unqualifiable."""
        named = {spec[3] if len(spec) > 3 else mutations.DEFAULT_TARGET
                 for spec in mutations.MUTATIONS}
        self.assertEqual(named - set(mutations.MUTATION_TARGETS), set())
        for name, oracles in mutations.MUTATION_TARGETS.items():
            with self.subTest(target=name):
                self.assertTrue(oracles, f"{name} has no oracle")
                self.assertTrue((Path(__file__).resolve().parent / name).exists())
                for oracle in oracles:
                    self.assertIn(oracle.kind, (mutations.SUITE_ORACLE, mutations.GATE_ORACLE))


class DetailProvenanceTests(unittest.TestCase):
    """A detail line is constructed, not composed — and the gate says so.

    The first version of the durable-field inventory checked a finished string
    against a local vocabulary and a local alphabet. That answers "could this
    module have written this line", which is not the question. `"timeout"`, `"the
    completion carried the probe token"` and sixteen hex characters are all
    things a provider can send verbatim and all pass a lexical check.

    This vertical has withdrawn that argument twice — `isidentifier()` for a
    failure class, then sixty-four hex characters for a digest. These are the
    gates that stop it needing a third withdrawal: a line can only exist as a
    registered template plus typed arguments, and the receipt records which
    template, so the inventory rebuilds the pattern instead of inspecting prose.
    """

    def tree(self, name="provider_matrix.py"):
        import ast
        return ast.parse((Path(__file__).resolve().parent / name).read_text(encoding="utf-8"))

    def owners(self, tree):
        import ast
        owner = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    owner.setdefault(child, node.name)
        return owner

    def calls_to(self, tree, name):
        import ast
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name:
                yield node

    def test_no_decision_carries_a_string_it_composed_itself(self):
        """The gate for the whole idea: `detail` is never text at this layer."""
        import ast
        tree = self.tree()
        offenders = []
        for node in self.calls_to(tree, "Decision"):
            supplied = list(node.args[2:3]) + [k.value for k in node.keywords if k.arg == "detail"]
            for value in supplied:
                if isinstance(value, (ast.Constant, ast.JoinedStr, ast.BinOp)):
                    offenders.append(node.lineno)
        self.assertEqual(offenders, [])

    def test_every_local_detail_names_a_registered_template(self):
        import ast
        offenders = []
        for node in self.calls_to(self.tree(), "LocalDetail"):
            first = node.args[0] if node.args else None
            if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
                offenders.append(("not a literal", node.lineno))
            elif first.value not in pm.DETAIL_TEMPLATES:
                offenders.append((first.value, node.lineno))
        self.assertEqual(offenders, [])

    def test_every_registered_template_is_actually_built_somewhere(self):
        """A table that outgrows its callers rots into a list of excuses."""
        import ast
        built = {node.args[0].value for node in self.calls_to(self.tree(), "LocalDetail")
                 if node.args and isinstance(node.args[0], ast.Constant)}
        self.assertEqual(set(pm.DETAIL_TEMPLATES) - built, set())

    def test_only_one_constructor_shortens_a_digest(self):
        """`entry["reported_model_sha256"][:16]` at a second site is a second rule."""
        import ast
        tree = self.tree()
        owner = self.owners(tree)
        offenders = []
        for node in ast.walk(tree):
            if (isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice)
                    and isinstance(node.slice.upper, ast.Constant)
                    and node.slice.upper.value == 16):
                if owner.get(node) not in ("of", "opaque_ref"):
                    offenders.append((owner.get(node, "<module>"), node.lineno))
        self.assertEqual(offenders, [])

    def docstrings(self, tree):
        """Prose that *describes* the grammar is not the grammar."""
        import ast
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                first = node.body[0] if node.body else None
                if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                        and isinstance(first.value.value, str)):
                    found.add(id(first.value))
        return found

    def test_only_one_place_spells_a_reference(self):
        """A hand-written `f"<handle sha256:{x} 4B>"` wears the wrapper that closes it."""
        import ast
        tree = self.tree()
        owner = self.owners(tree)
        prose = self.docstrings(tree)
        offenders = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and "sha256:" in node.value:
                if id(node) in prose or owner.get(node) == "render":
                    continue
                # `CANNED_HANDLE` is a handle *this module* invents for the
                # canary, not a reference to anything the provider sent.
                if node.value == "sha256:":
                    continue
                offenders.append((owner.get(node, "<module>"), node.lineno))
        self.assertEqual(offenders, [])

    def test_only_two_functions_write_a_line_into_an_artifact(self):
        import ast
        tree = self.tree()
        owner = self.owners(tree)
        offenders = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for goal in node.targets:
                    if (isinstance(goal, ast.Subscript) and isinstance(goal.slice, ast.Constant)
                            and goal.slice.value in ("detail", "detail_template")
                            and owner.get(node) not in ("apply_decision", "record_detail")):
                        offenders.append((owner.get(node, "<module>"), node.lineno))
        self.assertEqual(offenders, [])

    def test_the_gates_would_notice_their_own_violations(self):
        """Six gates that have never refused anything are six decorations."""
        import ast
        specimens = {
            "literal detail": 'Decision("PASS", "probe-token-matched", "looks local to me")',
            "f-string detail": 'Decision("PASS", "probe-token-matched", f"{x} looks local")',
            "unregistered template": 'LocalDetail("invented-line", ())',
            "hand-shortened digest": 'x = entry["reported_model_sha256"][:16]',
            "hand-spelled reference": 'y = f"<handle sha256:{d} 4B>"',
        }
        for name, source in specimens.items():
            with self.subTest(specimen=name):
                tree = ast.parse(source)
                found = any(
                    (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                     and n.func.id in ("Decision", "LocalDetail"))
                    or (isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Slice))
                    or (isinstance(n, ast.Constant) and isinstance(n.value, str)
                        and "sha256:" in n.value)
                    for n in ast.walk(tree))
                self.assertTrue(found, name)

    # -- the construction rules themselves --

    def test_a_line_cannot_be_built_from_the_wrong_kind_of_value(self):
        """Validation is in `__post_init__`: an inadmissible line never exists."""
        cases = {
            "a raw string where a reference belongs": ("duplicate-call-id", ("call_op",)),
            "a raw string where a count belongs": ("multiple-answers", ("two",)),
            "a number past the prose bound": ("multiple-answers", (10_000_000,)),
            "a status that is not one": ("http", (1000, pm.LocalDetail("qualified"))),
            "a reason from another vocabulary": ("transport", ("internal-error",)),
            "a digest tuple of strings": ("identity-substituted", (1, ("ab" * 8,))),
            "the wrong number of arguments": ("multiple-answers", ()),
        }
        for name, (template, args) in cases.items():
            with self.subTest(case=name), self.assertRaises(ValueError):
                pm.LocalDetail(template, args)

    def test_an_unregistered_template_cannot_be_built(self):
        with self.assertRaisesRegex(ValueError, "unregistered detail template"):
            pm.LocalDetail("something-reasonable-sounding")

    def test_a_reference_is_the_only_way_a_provider_value_enters_a_line(self):
        secret = "sk-live-not-a-real-key"
        line = pm.LocalDetail("duplicate-call-id", (pm.opaque_ref("tool-call-id", secret),))
        rendered = line.render()
        self.assertNotIn(secret, rendered)
        self.assertIn(pm.evidence_digest("tool-call-id", secret)[:16], rendered)

    def test_a_local_value_carries_which_local_source_it_came_from(self):
        with self.assertRaisesRegex(ValueError, "not a declared local source"):
            pm.LocalValue("whatever", "x")
        with self.assertRaises(ValueError):
            pm.LocalDetail("transport-key", ("credential-missing", "GROQ_API_KEY"))
        ok = pm.LocalDetail("transport-key", ("credential-missing", pm.LocalValue("key_env", "K")))
        self.assertEqual(ok.render(), "credential-missing: K")

    def test_a_digest_reference_is_built_from_a_digest(self):
        with self.assertRaises(ValueError):
            pm.DigestRef.of("not a digest")
        with self.assertRaises(ValueError):
            pm.DigestRef.of("ab" * 8)
        self.assertEqual(pm.DigestRef.of("ab" * 32).render(), "ab" * 8)

    # -- the provenance pass, on receipts this module really produced --

    def inventory(self):
        return DurableFieldInventoryTests()

    def test_a_line_made_of_local_words_but_never_rendered_is_refused(self):
        """The exact case the lexical check cannot see.

        Every word below is one this module wrote, in an order it never writes.
        `Prose` is content; the template pattern is not.
        """
        probe = self.inventory()
        receipt = probe.specimen()
        receipt["detail"] = "the protocol held and the identity was verified, not an object"
        findings = probe.audit(receipt, target(), probe.registry_entry())
        self.assertTrue(any("does not match what template" in f for f in findings), findings)

    def test_a_copied_provider_string_that_is_a_local_enum_member_is_still_refused(self):
        """`"timeout"` is a word this module writes — in one template only."""
        probe = self.inventory()
        receipt = probe.specimen()
        receipt["detail"] = "timeout"
        findings = probe.audit(receipt, target(), probe.registry_entry())
        self.assertTrue(any("does not match what template" in f for f in findings), findings)

    def test_sixteen_hex_characters_are_not_admitted_wherever_they_appear(self):
        """`BARE_DIGEST` erases them for `Prose`; the template pattern does not."""
        probe = self.inventory()
        receipt = probe.specimen()
        receipt["detail"] = "0123456789abcdef"
        findings = probe.audit(receipt, target(), probe.registry_entry())
        self.assertTrue(any("does not match what template" in f for f in findings), findings)

    def test_the_auditor_survives_an_artifact_of_any_shape(self):
        """It exists to refuse malformed artifacts, so it may not die on one.

        `for turn in receipt["turns"]` raised `TypeError` the first time a
        hostile shape reached it — the failure mode round eleven closed
        everywhere except inside the auditor itself.
        """
        probe = self.inventory()
        for hostile in (5, "turns", {}, [1, 2], [None], {"a": 1}):
            with self.subTest(turns=repr(hostile)):
                receipt = probe.specimen()
                receipt["turns"] = hostile
                findings = probe.audit(receipt, target(), probe.registry_entry())
                self.assertTrue(findings)

    def test_a_detail_with_no_template_is_refused(self):
        probe = self.inventory()
        receipt = probe.specimen()
        receipt["detail_template"] = None
        findings = probe.audit(receipt, target(), probe.registry_entry())
        self.assertTrue(any("no template to rebuild it from" in f for f in findings), findings)

    def test_a_key_env_from_another_plan_is_refused(self):
        """The trusted local value in a line comes from the registry, not the text."""
        probe = self.inventory()
        receipt = pm.qualify_target(target(), surface(), 30.0, 6, scripted([
            pm.SendResult(None, None, "no key", "no-credential", None, None,
                          "credential-missing", None, None)]), response_limit=probe.LIMIT)
        self.assertEqual(receipt["classification"], "AUTH_FAILED")
        self.assertEqual(probe.audit(receipt, target(), probe.registry_entry()), [])
        receipt["detail"] = receipt["detail"].replace("GROQ_API_KEY", "ANTHROPIC_API_KEY")
        findings = probe.audit(receipt, target(), probe.registry_entry())
        self.assertTrue(any("does not match what template" in f for f in findings), findings)

    def test_every_canary_line_is_rebuilt_from_its_own_template(self):
        receipt = pm.qualify_target(
            target(), surface(), 30.0, 6,
            scripted(OPERATION_THEN(
                (200, completion([call("qodec_answer", WRONG_ANSWER_ARGS, "call_w")]), ""))),
            response_limit=DurableFieldInventoryTests.LIMIT)
        self.assertEqual(receipt["classification"], "CANARY_ANSWER_MISMATCH")
        turn = receipt["turns"][-1]
        self.assertEqual(len(turn["canary_answer_errors"]), len(turn["canary_answer_error_templates"]))
        probe = self.inventory()
        self.assertEqual(probe.audit(receipt, target(), probe.registry_entry()), [])
        turn["canary_answer_errors"][0] = "cited handle sk-live-secret was never returned"
        findings = probe.audit(receipt, target(), probe.registry_entry())
        self.assertTrue(any("is not what" in f for f in findings), findings)

    def test_a_count_slot_admits_a_count_and_nothing_else(self):
        """A slot pattern widened to `.*` is a template that proves nothing."""
        probe = self.inventory()
        receipt = pm.qualify_target(
            target(), surface(), 30.0, 2,
            scripted([(200, completion([call("qodec_intersect", INTERSECT_ARGS, "call_a")]), ""),
                      (200, completion([call("qodec_intersect", INTERSECT_ARGS, "call_b")]), "")]),
            response_limit=probe.LIMIT)
        self.assertEqual(receipt["classification"], "NO_TERMINAL_ANSWER")
        self.assertEqual(receipt["detail"], "no terminal answer within 2 turns")
        self.assertEqual(probe.audit(receipt, target(), probe.registry_entry(), max_turns=2), [])
        for forged in ("no terminal answer within sk-live-secret turns",
                       "no terminal answer within 12345678 turns",
                       "no terminal answer within  turns"):
            with self.subTest(detail=forged):
                receipt["detail"] = forged
                findings = probe.audit(receipt, target(), probe.registry_entry(), max_turns=2)
                self.assertTrue(any("does not match what template" in f for f in findings), findings)

    def test_a_reference_in_a_line_identifies_the_value_it_stands_for(self):
        """A reference that digests something else is evidence about nothing.

        Both halves matter: the reference must not repeat the value, and it must
        be *of* the value. A wrapper around the empty string satisfies the first
        and quietly fails the second, so the digest is checked outright.
        """
        receipt = pm.qualify_target(
            target(), surface(), 30.0, 6,
            scripted([(200, completion([call("qodec_undeclared", "{}", "call_u")]), "")]))
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")
        named = pm.opaque_ref("tool-name", "qodec_undeclared")
        self.assertEqual(
            receipt["detail"], f"called 1 tool(s) that were never declared: {named.render()}")
        self.assertNotIn("qodec_undeclared", json.dumps(receipt))

    def test_an_envelope_reference_identifies_the_field_it_complains_about(self):
        label = pm.EnvelopeLabel(known="answer")
        problems, _ = pm.envelope_errors(
            {"encoding": "base64url-nopad", "data": "YWxwaGE", "surprise": 1}, label)
        rendered = " ".join(why.render() for why in problems)
        self.assertIn(pm.opaque_ref("json-value", "surprise").render(), rendered)
        self.assertNotIn("surprise", rendered.replace("surprises", ""))

        # And the character a strict decoder rejected, for the same reason.
        rejected, _ = pm.envelope_errors(
            {"encoding": "base64url-nopad", "data": "YWxwaGE="}, label)
        self.assertIn(pm.opaque_ref("json-value", "=").render(),
                      " ".join(why.render() for why in rejected))

    def test_a_rejected_envelope_character_is_named_and_never_spelled(self):
        """It used to be interpolated, and it reached `detail` through the canary."""
        padded = json.dumps({
            "handle": pm.CANNED_HANDLE,
            "answer": {"encoding": "base64url-nopad", "data": "YWxwaGE="},
            "cited": [{"store": pm.CANNED_HANDLE, "section": "attempt_1", "ordinal": 0}],
        })
        receipt = pm.qualify_target(
            target(), surface(), 30.0, 6,
            scripted(OPERATION_THEN((200, completion([call("qodec_answer", padded, "call_p")]), ""))),
            response_limit=DurableFieldInventoryTests.LIMIT)
        # The padding character is refused by the schema first; either way the
        # receipt must not contain it as a character in a sentence.
        self.assertNotEqual(receipt["classification"], "PASS")
        probe = self.inventory()
        self.assertEqual(probe.audit(receipt, target(), probe.registry_entry()), [])


class TransportTotalityTests(unittest.TestCase):
    """Nothing the peer does to the socket may become an `INTERNAL_ERROR`.

    Round nine caught `IncompleteRead` on the body reads. Round eleven caught
    the rest of the `HTTPException` family at `open`. This is the third member
    of the same family and it was found the same way — by a reviewer, not by the
    list growing on its own: urllib wraps a failure to *connect* in `URLError`,
    and does not wrap a failure that happens once the socket is already up. A
    peer that resets while the status line is being read raises
    `ConnectionResetError` straight out of `open`.
    """

    def rude_server(self, reply: bytes):
        """A listener that answers with `reply` and then sends an RST."""
        import socket
        import struct
        import threading

        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def serve():
            try:
                conn, _ = listener.accept()
            except OSError:  # pragma: no cover — the listener closed first
                return
            with conn:
                conn.recv(65536)
                if reply:
                    conn.sendall(reply)
                # SO_LINGER with a zero timeout makes `close` send RST rather
                # than FIN, which is what a peer dropping a connection mid-reply
                # actually does.
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                struct.pack("ii", 1, 0))
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.addCleanup(listener.close)
        self.addCleanup(thread.join, 5)
        return listener.getsockname()[1]

    def test_a_reset_while_the_status_line_is_read_never_escapes(self):
        """The real socket, not a patched exception.

        A partial status line followed by RST is what the defect needs, and a
        stand-in cannot be trusted to reproduce it — the point of the finding
        was that the exception arrives from a place nobody had modelled.

        What is asserted is the contract, not the scheduler. Whether the reset
        lands while urllib is still writing the request or already reading the
        status line decides between `before-response` and `response-framing`,
        and that is the kernel's timing rather than this module's rule. Both are
        typed transport results with a local reason; neither is an exception out
        of `send_json`. The exact stage mapping is pinned deterministically by
        `test_the_broad_catch_sits_below_the_narrow_one`.
        """
        port = self.rude_server(b"HTTP/1.1 20")
        sent = pm.send_json(
            f"http://127.0.0.1:{port}/v1/chat/completions", b"{}", "k", 5.0)
        self.assertIn(sent.stage, ("before-response", "response-framing"))
        self.assertIn(sent.reason, pm.TRANSPORT_REASONS)
        self.assertIn(sent.failure_kind, pm.TRANSPORT_FAILURE_KINDS)
        self.assertIsNone(sent.status)
        # Whatever it says about the failure is a class name, never the peer's.
        self.assertEqual(pm.validate_send_result(sent), sent)

    def test_a_reset_with_no_reply_at_all_is_still_a_transport_result(self):
        port = self.rude_server(b"")
        sent = pm.send_json(
            f"http://127.0.0.1:{port}/v1/chat/completions", b"{}", "k", 5.0)
        self.assertIn(sent.stage, ("before-response", "response-framing"))
        self.assertIn(sent.reason, pm.TRANSPORT_REASONS)

    def resetting_sender(self):
        """A `send` that really opens a socket, against a peer that resets it.

        The registry refuses a non-https origin, and rightly — so the local
        listener is reached through the injected sender rather than by weakening
        the rule that keeps the credential off plain HTTP. What is exercised is
        still `send_json` itself, which is where the defect was.
        """
        port = self.rude_server(b"HTTP/1.1 20")

        def send(_url, body, timeout):
            return pm.send_json(
                f"http://127.0.0.1:{port}/v1/chat/completions", body, "k", timeout)
        return send

    def test_the_probe_classifies_a_reset_rather_than_blaming_itself(self):
        result = pm.guarded_receipt(
            pm.PROBE_SCHEMA, probe_row({}),
            lambda: pm.probe_target(probe_row({}), 5.0, self.resetting_sender(), registry()))
        self.assertNotEqual(result["classification"], "INTERNAL_ERROR")
        self.assertEqual(result["classification"], "RESPONSE_CAPTURE_FAILED")
        self.assertEqual(result["transport_reason"], "http-framing-failure")

    def test_the_qualification_classifies_a_reset_rather_than_blaming_itself(self):
        receipt = pm.guarded_receipt(
            pm.QUALIFY_SCHEMA, target(),
            lambda: pm.qualify_target(
                target(), surface(), 5.0, 6, self.resetting_sender()))
        self.assertNotEqual(receipt["classification"], "INTERNAL_ERROR")
        self.assertEqual(receipt["classification"], "RESPONSE_CAPTURE_FAILED")
        self.assertEqual(receipt["turns"][0]["transport_reason"], "http-framing-failure")

    def test_the_broad_catch_sits_below_the_narrow_one(self):
        """`URLError` is an `OSError`, so order is the contract.

        A broad clause above a narrow one swallows it silently, and `URLError`
        carries a `reason` this module reads to tell a timeout from a refusal.
        """
        with patch.object(pm._OPENER, "open",
                          side_effect=urllib.error.URLError(TimeoutError())):
            sent = pm.send_json("https://x/v1/chat/completions", b"{}", "k", 1.0)
        self.assertEqual(sent.reason, "timeout")
        self.assertEqual(sent.stage, "before-response")
        with patch.object(pm._OPENER, "open", side_effect=ConnectionResetError(104, "reset")):
            sent = pm.send_json("https://x/v1/chat/completions", b"{}", "k", 1.0)
        self.assertEqual(sent.reason, "http-framing-failure")

    def test_the_failure_message_never_repeats_what_the_peer_sent(self):
        secret = "sk-live-not-a-real-key"
        with patch.object(pm._OPENER, "open",
                          side_effect=ConnectionResetError(104, f"reset {secret}")):
            sent = pm.send_json("https://x/v1/chat/completions", b"{}", "k", 1.0)
        self.assertNotIn(secret, sent.detail)
        self.assertEqual(sent.detail, "HTTP framing failure: ConnectionResetError")
        self.assertEqual(sent.failure_class, "ConnectionResetError")


class ModelIdentityTests(unittest.TestCase):
    """`present` and `a digest-bearing string substitution` are different facts.

    Three readers used to answer the identity question separately and disagree.
    `model_evidence` called a non-string `model` present and wrote no digest;
    `model_status_of` called the same value missing; and the terminal-answer
    path assumed every present-and-not-verified entry carried a digest, so
    `model: {}` raised `KeyError` and `guarded_receipt` filed a run the provider
    broke as a defect in this tool.
    """

    def answer_run(self, first, second):
        def reply(model, tool, arguments, call_id):
            return (200, json.dumps({"model": model, "choices": [{"message": {
                "role": "assistant", "content": None,
                "tool_calls": [call(tool, arguments, call_id)]}}]}).encode(), "")

        return pm.qualify_target(target(), surface(), 30.0, 6, scripted([
            reply(first, "qodec_intersect", INTERSECT_ARGS, "call_op"),
            reply(second, "qodec_answer", ANSWER_ARGS, "call_ans"),
        ]))

    def test_a_non_string_model_reaching_a_terminal_answer_is_a_substitution(self):
        """Not `INTERNAL_ERROR`, not `MODEL_IDENTITY_MISSING`, and not `PASS`."""
        for name, model in (("object", {}), ("nested object", {"name": "x"}),
                            ("array", []), ("number", 17), ("boolean", True)):
            with self.subTest(model=name):
                receipt = self.answer_run(model, model)
                self.assertEqual(receipt["classification"], "PROVIDER_SUBSTITUTED")
                self.assertEqual(receipt["decision_reason"], "identity-substituted")
                self.assertEqual(receipt["detail_template"], "identity-substituted-nontext")

    def test_a_run_that_saw_both_kinds_of_drift_says_so(self):
        receipt = self.answer_run("somebody-elses-model", {})
        self.assertEqual(receipt["classification"], "PROVIDER_SUBSTITUTED")
        self.assertEqual(receipt["detail_template"], "identity-substituted-mixed")
        self.assertIn(pm.DigestRef.of(
            pm.evidence_digest("model-name", "somebody-elses-model")).render(),
            receipt["detail"])
        self.assertIn("object", receipt["detail"])
        self.assertNotIn("somebody-elses-model", json.dumps(receipt))

    def test_a_text_only_drift_keeps_the_template_it_always_had(self):
        receipt = self.answer_run("somebody-elses-model", "somebody-elses-model")
        self.assertEqual(receipt["detail_template"], "identity-substituted")

    def test_the_three_readers_of_identity_agree(self):
        """One classifier, and the rest are projections of it.

        The disagreement was the defect: `present: True` from one function and
        `missing` from another described the same response.
        """
        for reported in ({}, [], 17, True, "other", "", None, "openai/gpt-oss-120b"):
            with self.subTest(reported=repr(reported)):
                identity = pm.model_identity("openai/gpt-oss-120b", reported)
                evidence = pm.model_evidence("openai/gpt-oss-120b", reported)
                status = pm.model_status_of("openai/gpt-oss-120b", reported)
                self.assertEqual(status, pm.status_of_identity(identity))
                present = evidence["reported_model_present"]
                self.assertEqual(present, not isinstance(identity, pm.MissingModel))
                # A digest is written exactly when the substitution is a name.
                self.assertEqual("reported_model_sha256" in evidence,
                                 isinstance(identity, pm.TextSubstitution))
                # A JSON type is written exactly when it is not.
                self.assertEqual("reported_model_type" in evidence,
                                 isinstance(identity, pm.NonTextModel))

    def test_an_empty_model_name_establishes_nothing_and_says_only_that(self):
        """It used to be `present: True` and `missing` at the same time."""
        self.assertIsInstance(pm.model_identity("m", ""), pm.MissingModel)
        self.assertEqual(pm.model_evidence("m", ""),
                         {"reported_model": None, "reported_model_present": False})
        receipt = self.answer_run("", "")
        self.assertEqual(receipt["classification"], "MODEL_IDENTITY_MISSING")

    def test_the_probe_agrees_with_the_qualification_about_a_non_string_model(self):
        body = json.dumps({"model": {"name": "x"},
                           "choices": [{"message": {"content": "QODEC_PROBE_OK"}}]}).encode()
        result = pm.probe_target(
            probe_row({}), 1, scripted([(200, body, "", "completed")]), registry())
        self.assertEqual(result["classification"], "PROVIDER_SUBSTITUTED")
        self.assertEqual(result["model_status"], "drifted")
        self.assertEqual(result["reported_model_type"], "object")

    def test_the_same_other_model_twice_is_one_finding(self):
        receipt = self.answer_run("somebody-elses-model", "somebody-elses-model")
        self.assertEqual(receipt["detail"].count("the provider reported 1 other model(s)"), 1)


class ProviderMetadataIsContentTests(unittest.TestCase):
    """A peer's oversized header is content, not a broken internal contract.

    `validate_send_result` refused a `request_id` longer than the local bound,
    and `as_send_result` runs on the *real* transport's own output — so a peer
    answering with a 257-byte `x-request-id` turned a perfectly classifiable
    200 into `INTERNAL_ERROR` on both paths. The provider chose the
    classification, which is the one thing the projection exists to deny it.
    """

    OVERSIZE = "r" * (pm.EVIDENCE_MAX_BYTES["request-id"] + 1)

    def serving(self, request_id: str, body: bytes):
        """A listener that answers 200 with the given header and body."""
        import socket
        import threading

        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def serve():
            try:
                conn, _ = listener.accept()
            except OSError:  # pragma: no cover — the listener closed first
                return
            with conn:
                read_http_request(conn)
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    + f"x-request-id: {request_id}\r\n".encode()
                    + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.addCleanup(listener.close)
        self.addCleanup(thread.join, 5)
        return listener.getsockname()[1]

    PROBE_BODY = json.dumps(
        {"model": "m", "choices": [{"message": {"content": "QODEC_PROBE_OK"}}]}).encode()

    def test_send_json_keeps_an_oversized_header_and_the_result_validates(self):
        port = self.serving(self.OVERSIZE, self.PROBE_BODY)
        sent = pm.send_json(f"http://127.0.0.1:{port}/v1/chat/completions", b"{}", "k", 5.0)
        self.assertEqual(sent.status, 200)
        self.assertEqual(len(sent.request_id), len(self.OVERSIZE))
        # The internal contract holds: this is a well-formed observation.
        self.assertEqual(pm.as_send_result(sent), sent)

    def test_the_probe_keeps_its_classification_and_projects_the_header(self):
        def send(_url, body, timeout):
            port = self.serving(self.OVERSIZE, self.PROBE_BODY)
            return pm.send_json(
                f"http://127.0.0.1:{port}/v1/chat/completions", body, "k", timeout)

        result = pm.guarded_receipt(
            pm.PROBE_SCHEMA, probe_row({}),
            lambda: pm.probe_target(probe_row({}), 5.0, send, registry()))
        self.assertEqual(result["classification"], "PASS")
        self.assertEqual(result["request_id_bytes"], pm.EVIDENCE_MAX_BYTES["request-id"])
        self.assertTrue(result["request_id_oversize"])
        self.assertNotIn(self.OVERSIZE, json.dumps(result))

    def test_the_qualification_keeps_its_classification_too(self):
        answer = json.dumps({"model": "openai/gpt-oss-120b", "choices": [{"message": {
            "role": "assistant", "content": None,
            "tool_calls": [call("qodec_answer", ANSWER_ARGS, "call_ans")]}}]}).encode()
        operation = json.dumps({"model": "openai/gpt-oss-120b", "choices": [{"message": {
            "role": "assistant", "content": None,
            "tool_calls": [call("qodec_intersect", INTERSECT_ARGS, "call_op")]}}]}).encode()
        bodies = iter((operation, answer))

        def send(_url, body, timeout):
            port = self.serving(self.OVERSIZE, next(bodies))
            return pm.send_json(
                f"http://127.0.0.1:{port}/v1/chat/completions", body, "k", timeout)

        receipt = pm.guarded_receipt(
            pm.QUALIFY_SCHEMA, target(),
            lambda: pm.qualify_target(target(), surface(), 5.0, 6, send))
        self.assertEqual(receipt["classification"], "PASS")
        self.assertTrue(receipt["turns"][0]["request_id_oversize"])
        self.assertNotIn(self.OVERSIZE, json.dumps(receipt))

    def test_a_producer_handing_over_the_wrong_type_is_still_refused(self):
        """The distinction the repair rests on, asserted from both sides."""
        with self.assertRaisesRegex(ValueError, "request_id must be a string"):
            pm.validate_send_result(pm.SendResult(200, b"{}", "", "completed", 2, 12345))
        long_but_a_string = pm.SendResult(200, b"{}", "", "completed", 2, self.OVERSIZE)
        self.assertEqual(pm.validate_send_result(long_but_a_string), long_but_a_string)


class HttpRequestReadingTests(unittest.TestCase):
    """The listener the transport tests rely on must not depend on segmentation.

    `conn.recv(65536)` once is not "read the request"; it is "read whatever
    arrived". A listener that answers with unread bytes queued can provoke an
    RST on close, and the client then reports a transport failure where the
    test asserts a 200 — a test that is green because of how the kernel sliced
    a stream today. Driven here through a fake socket that hands the bytes over
    in pieces, so the property is asserted rather than hoped for.
    """

    class Chunked:
        """A socket whose `recv` returns the caller's data one piece at a time."""

        def __init__(self, pieces):
            self.pieces = list(pieces)
            self.reads = 0

        def recv(self, _size):
            self.reads += 1
            return self.pieces.pop(0) if self.pieces else b""

    def request(self, body: bytes, header_extra: bytes = b"") -> bytes:
        return (b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\n"
                + header_extra
                + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)

    def test_a_request_split_between_headers_and_body_is_read_whole(self):
        body = json.dumps({"messages": ["x" * 4096]}).encode()
        whole = self.request(body)
        head, _, rest = whole.partition(b"\r\n\r\n")
        sock = self.Chunked([head + b"\r\n\r\n", rest[:100], rest[100:]])
        self.assertEqual(read_http_request(sock), whole)
        self.assertGreater(sock.reads, 1, "the fake socket did not fragment")

    def test_a_request_split_inside_the_headers_is_read_whole(self):
        whole = self.request(b"{}")
        sock = self.Chunked([whole[:12], whole[12:30], whole[30:]])
        self.assertEqual(read_http_request(sock), whole)

    def test_a_peer_that_stops_mid_body_is_a_failure_not_a_short_read(self):
        body = b"x" * 100
        whole = self.request(body)
        sock = self.Chunked([whole[:-40]])
        with self.assertRaisesRegex(TruncatedRequest, "of 100 declared bytes"):
            read_http_request(sock)

    def test_a_peer_that_stops_mid_headers_is_a_failure(self):
        with self.assertRaisesRegex(TruncatedRequest, "before the headers ended"):
            read_http_request(self.Chunked([b"POST / HTTP/1.1\r\nHost:"]))

    def test_a_content_length_that_is_not_a_number_is_refused(self):
        sock = self.Chunked([b"POST / HTTP/1.1\r\nContent-Length: many\r\n\r\n"])
        with self.assertRaisesRegex(TruncatedRequest, "not a number"):
            read_http_request(sock)

    def test_a_content_length_past_the_local_bound_is_refused(self):
        """Otherwise a hostile length makes the listener wait for bytes forever."""
        for declared in (-1, MAX_TEST_REQUEST_BYTES + 1):
            with self.subTest(length=declared):
                sock = self.Chunked([
                    b"POST / HTTP/1.1\r\nContent-Length: " + str(declared).encode() + b"\r\n\r\n"])
                with self.assertRaisesRegex(TruncatedRequest, "outside the local bound"):
                    read_http_request(sock)

    def test_a_header_name_is_matched_case_insensitively(self):
        body = b"abc"
        raw = (b"POST / HTTP/1.1\r\nCONTENT-LENGTH: 3\r\n\r\n" + body)
        self.assertEqual(read_http_request(self.Chunked([raw[:-3], body])), raw)

    def test_a_request_with_no_body_needs_no_second_read(self):
        raw = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        sock = self.Chunked([raw])
        self.assertEqual(read_http_request(sock), raw)
        self.assertEqual(sock.reads, 1)


class BoundClosureTests(unittest.TestCase):
    """Every bound the auditor states is applied, and demonstrated at its edge.

    Round eighteen closed two fields where the policy declared a ceiling and the
    producer had never been told about it. Round nineteen found a third the same
    way a reviewer had found the first two — which is the signal that repairing
    the sites somebody points at is still the method in use, three rounds after
    it was supposedly retired.

    So the class is closed instead. `BOUND_ENFORCEMENT` names a producer-side
    strategy for every bounded policy, `enforcement_problems` refuses any
    mismatch in either direction, and this file supplies the third set: a
    *witness* for every field whose strategy is `Refuse` or `Project`, run at
    the bound and one past it.

    `Derive` carries no witness, and that is deliberate rather than convenient:
    its claim is that the value cannot exceed the bound by construction, so
    there is no past-bound case to build. What it costs instead is a sentence
    naming what does the bounding, and `enforcement_problems` refuses one
    without it. The risk that somebody mislabels a `Refuse` as a `Derive` to
    skip writing a witness is real and is not closed here; it is stated.
    """

    LIMIT = 4096

    def entry(self):
        return pm.load_registry()["providers"]["groq"]

    def audit(self, receipt, row, entry, schema=None, response_limit=None):
        """Audited against the row the receipt was produced from.

        Never against `target()` when the witness used another: the context is
        the caller's claim about what it asked for, and handing the auditor a
        different claim would make every witness fail for a reason unrelated to
        the bound it is about.
        """
        context = receipt_policy.context_for(
            schema or pm.QUALIFY_SCHEMA, row, entry,
            response_limit=self.LIMIT if response_limit is None else response_limit,
            max_turns=6, declared_tools={op["name"] for op in surface()["operations"]})
        return receipt_policy.audit(receipt, context)

    def values_at(self, receipt, wanted):
        """Every value the receipt carries at one structural path."""
        return [value for path, value in receipt_policy.flatten(receipt) if path == wanted]

    # -- the witnesses ----------------------------------------------------
    #
    # Each returns `(receipt, row, entry)`: the artifact, the target it was
    # produced for, and the registry entry that target is bound to. The audit
    # takes all three, because a context built from a different row would make
    # every witness fail for a reason unrelated to the bound it is about.

    def qualify(self, replies, row=None, limit=None):
        row = row or target()
        return (pm.qualify_target(row, surface(), 30.0, 6, scripted(replies),
                                  response_limit=limit or self.LIMIT),
                row, pm.load_registry()["providers"]["groq"])

    def guarded_qualify(self, replies, row=None, limit=None):
        row = row or target()
        return (pm.guarded_receipt(pm.QUALIFY_SCHEMA, row, lambda: pm.qualify_target(
                    row, surface(), 30.0, 6, scripted(replies),
                    response_limit=limit or self.LIMIT)),
                row, pm.load_registry()["providers"]["groq"])

    def probe(self, replies, row=None, limit=None):
        row = row or probe_row({})
        return (pm.guarded_receipt(pm.PROBE_SCHEMA, row, lambda: pm.probe_target(
                    row, 5.0, scripted(replies), registry(),
                    response_limit=limit or self.LIMIT)),
                row, registry()["providers"][row["provider"]])

    def sent(self, **kw):
        base = dict(status=200, body=completion([call("qodec_intersect", INTERSECT_ARGS, "c1")]),
                    detail="", stage="completed", body_bytes_observed=None, request_id=None,
                    reason=None, failure_kind=None, failure_class=None)
        base.update(kw)
        return pm.SendResult(base["status"], base["body"], base["detail"], base["stage"],
                             base["body_bytes_observed"], base["request_id"], base["reason"],
                             base["failure_kind"], base["failure_class"])

    PROBE_OK = json.dumps(
        {"model": "m", "choices": [{"message": {"content": "QODEC_PROBE_OK"}}]}).encode()

    def probe_body(self, **extra):
        payload = {"model": "m", "choices": [{"message": {"content": "QODEC_PROBE_OK"}}]}
        payload.update(extra)
        return json.dumps(payload).encode()

    def sized(self, domain, over):
        return pm.EVIDENCE_MAX_BYTES[domain] + (1 if over else 0)

    # probe-side

    def w_probe_request_id(self, over):
        return self.probe([self.sent(status=200, body=self.PROBE_OK, stage="completed",
                                     request_id="r" * self.sized("request-id", over))])

    def w_probe_model_name(self, over):
        size = self.sized("model-name", over)
        return self.probe([(200, self.probe_body(model="m" * size), "", "completed")])

    def w_probe_failure_class(self, over):
        size = pm.FAILURE_CLASS_MAX_BYTES + (1 if over else 0)
        return self.probe([self.sent(status=None, body=None, detail="x",
                                     stage="before-response", reason="connection-failed",
                                     failure_kind="url-error", failure_class="F" * size)])

    def w_probe_http_status(self, over):
        status = pm.HTTP_STATUS_MAX + (1 if over else 0)
        return self.probe([self.sent(status=status, body=b"{}", stage="completed")])

    def w_probe_observed(self, over):
        count = self.LIMIT + 1 + (1 if over else 0)
        return self.probe([self.sent(status=503, body=None, detail="lost",
                                     stage="after-headers", body_bytes_observed=count)])

    def probe_request_body(self, model):
        return pm.canonical_bytes({
            "model": model,
            "messages": [{"role": "user", "content": "Return exactly: QODEC_PROBE_OK"}],
            "temperature": 0, "max_tokens": pm.PROBE_MAX_TOKENS})

    def w_probe_usage(self, over):
        """At the bound the *producer* applies, which is stricter than the policy's.

        `normalize_provider_usage` bounds a counter by the request it actually
        composed; the policy ceiling is `MAX_REQUEST_BYTES`, which that request
        is far below. The bound to demonstrate is the one that decides.
        """
        bounds = pm.usage_bounds(len(self.probe_request_body(probe_row({})["model"])),
                                 pm.PROBE_MAX_TOKENS)
        usage = {name: bounds[name] + (1 if over else 0) for name in pm.USAGE_COUNTERS}
        return self.probe([(200, self.probe_body(usage=usage), "", "completed")])

    def w_probe_request_bytes(self, over):
        overhead = len(self.probe_request_body(""))
        row = dict(probe_row({}),
                   model="m" * (pm.MAX_REQUEST_BYTES - overhead + (1 if over else 0)))
        return self.probe([(200, self.PROBE_OK, "", "completed")], row=row)

    # qualification-side

    def w_request_id(self, over):
        return self.qualify([self.sent(request_id="r" * self.sized("request-id", over))])

    def w_model_name(self, over):
        size = self.sized("model-name", over)
        body = completion([call("qodec_intersect", INTERSECT_ARGS, "c1")], model="m" * size)
        return self.qualify([(200, body, "")])

    def w_tool_name(self, over):
        size = self.sized("tool-name", over)
        return self.qualify([(200, completion([call("n" * size, "{}", "c1")]), "")])

    def w_call_id(self, over):
        size = self.sized("tool-call-id", over)
        return self.qualify([(200, completion(
            [call("qodec_intersect", INTERSECT_ARGS, "c" * size)]), "")])

    def w_failure_class(self, over):
        size = pm.FAILURE_CLASS_MAX_BYTES + (1 if over else 0)
        return self.guarded_qualify([self.sent(
            status=None, body=None, detail="x", stage="before-response",
            reason="connection-failed", failure_kind="url-error", failure_class="F" * size)])

    def w_internal_class(self, over):
        size = self.sized("failure-class", over)

        def explode():
            raise type("E" * size, (Exception,), {})("boom")

        return (pm.guarded_receipt(pm.QUALIFY_SCHEMA, target(), explode), target(),
                pm.load_registry()["providers"]["groq"])

    def w_http_status(self, over):
        status = pm.HTTP_STATUS_MAX + (1 if over else 0)
        return self.guarded_qualify([self.sent(status=status, body=b"{}")])

    def w_observed(self, over):
        count = self.LIMIT + 1 + (1 if over else 0)
        return self.guarded_qualify([self.sent(
            status=503, body=None, detail="lost", stage="after-headers",
            body_bytes_observed=count)])

    def qualify_request_body(self, model):
        return pm.canonical_bytes(pm.canonical_request(surface(), model, pm.opening_messages()))

    def w_usage(self, over):
        bounds = pm.usage_bounds(len(self.qualify_request_body(target()["model"])),
                                 pm.QUALIFY_MAX_TOKENS)
        usage = {name: bounds[name] + (1 if over else 0) for name in pm.USAGE_COUNTERS}
        body = completion([call("qodec_intersect", INTERSECT_ARGS, "c1")], usage=usage)
        return self.qualify([(200, body, "")])

    def w_request_bytes(self, over):
        overhead = len(self.qualify_request_body(""))
        row = dict(target(),
                   model="m" * (pm.MAX_REQUEST_BYTES - overhead + (1 if over else 0)))
        # One turn, and one that ends the run: a second turn composes a longer
        # body, so the at-bound witness would trip the bound on the *next*
        # request and `guarded_receipt` would discard the turn this is about.
        return self.guarded_qualify([ANSWER_REPLY], row=row)

    def w_argument_errors(self, over):
        args = json.dumps({"index": "i",
                           "sections": [0] * (pm.MAX_ARGUMENT_ERRORS + (1 if over else 0))})
        return self.qualify([(200, completion([call("qodec_intersect", args, "c1")]), "")],
                            limit=pm.MAX_RESPONSE_BYTES)

    def w_canary(self, over):
        cited = [{"store": pm.CANNED_HANDLE, "section": f"absent_{n}", "ordinal": 0}
                 for n in range(pm.MAX_CANARY_ERRORS + (1 if over else 0))]
        answer = json.dumps({"handle": pm.CANNED_HANDLE, "cited": cited,
                             "answer": {"encoding": "base64url-nopad", "data": "YWxwaGE"}})
        return self.qualify(
            OPERATION_THEN((200, completion([call("qodec_answer", answer, "c_ans")]), "")),
            limit=pm.MAX_RESPONSE_BYTES)

    def w_call_ordinal(self, over):
        calls = [call("qodec_intersect", INTERSECT_ARGS, f"c{n}")
                 for n in range(pm.MAX_TOOL_CALLS + (1 if over else 0))]
        return self.qualify([(200, completion(calls), "")], limit=pm.MAX_RESPONSE_BYTES)

    def witnesses(self):
        return {
            "probe-request-id": self.w_probe_request_id,
            "probe-model-name": self.w_probe_model_name,
            "probe-failure-class": self.w_probe_failure_class,
            "probe-http-status": self.w_probe_http_status,
            "probe-observed": self.w_probe_observed,
            "probe-usage": self.w_probe_usage,
            "probe-request-bytes": self.w_probe_request_bytes,
            "request-id": self.w_request_id,
            "model-name": self.w_model_name,
            "tool-name": self.w_tool_name,
            "call-id": self.w_call_id,
            "failure-class": self.w_failure_class,
            "internal-class": self.w_internal_class,
            "http-status": self.w_http_status,
            "observed-bytes": self.w_observed,
            "usage": self.w_usage,
            "request-bytes": self.w_request_bytes,
            "argument-errors": self.w_argument_errors,
            "canary-errors": self.w_canary,
            "call-ordinal": self.w_call_ordinal,
        }

    def named(self):
        """Which witness demonstrates which bounded path."""
        P, suffixed, extend = receipt_policy.P, receipt_policy.suffixed, receipt_policy.extend
        EACH = receipt_policy.EACH
        turn = P("turns", EACH)
        call_path = extend(turn, "tool_calls", EACH)
        return {
            P("request_id_bytes"): "probe-request-id",
            P("reported_model_bytes"): "probe-model-name",
            P("failure_class_bytes"): "probe-failure-class",
            P("http_status"): "probe-http-status",
            P("body_bytes_observed"): "probe-observed",
            P("provider_usage", "prompt_tokens"): "probe-usage",
            P("provider_usage", "completion_tokens"): "probe-usage",
            P("provider_usage", "total_tokens"): "probe-usage",
            P("request_bytes"): "probe-request-bytes",
            P("internal_failure_class_bytes"): "internal-class",
            P("reported_models", EACH, "reported_model_bytes"): "model-name",
            suffixed(turn, "request_id_bytes"): "request-id",
            suffixed(turn, "reported_model_bytes"): "model-name",
            suffixed(call_path, "name_bytes"): "tool-name",
            suffixed(call_path, "call_id_bytes"): "call-id",
            suffixed(turn, "failure_class_bytes"): "failure-class",
            suffixed(turn, "http_status"): "http-status",
            suffixed(turn, "body_bytes_observed"): "observed-bytes",
            extend(turn, "reported_usage", "prompt_tokens"): "usage",
            extend(turn, "reported_usage", "completion_tokens"): "usage",
            extend(turn, "reported_usage", "total_tokens"): "usage",
            suffixed(turn, "request_bytes"): "request-bytes",
            suffixed(turn, "argument_errors_count"): "argument-errors",
            extend(turn, "canary_answer_errors", EACH): "canary-errors",
            suffixed(turn, "canary_answer_errors_count"): "canary-errors",
            suffixed(call_path, "ordinal"): "call-ordinal",
        }

    # -- the gate ---------------------------------------------------------

    def demonstrable(self):
        return {path for path, strategy in receipt_policy.BOUND_ENFORCEMENT.items()
                if not isinstance(strategy, receipt_policy.Derive)}

    def test_the_bounded_field_inventory_is_closed(self):
        self.assertEqual(receipt_policy.enforcement_problems(), [])

    def test_every_demonstrable_bound_names_a_witness_and_back(self):
        """Set equality, the third of the three the round is about."""
        self.assertEqual(set(self.named()), self.demonstrable())
        self.assertEqual(set(self.named().values()) - set(self.witnesses()), set())
        self.assertEqual(set(self.witnesses()) - set(self.named().values()), set())

    def test_a_strategy_without_an_argument_is_reported(self):
        """The closure's own positive control for the reason requirement.

        A `Derive` that names nothing is the entry that rots quietly, so the
        table refusing it is the load-bearing part — and a check that has never
        refused anything is a check nobody has tested.
        """
        blank = {**receipt_policy.BOUND_ENFORCEMENT,
                 receipt_policy.P("http_status"): receipt_policy.Derive("  ")}
        self.assertTrue(any("without a stated reason" in problem for problem in
                            receipt_policy.enforcement_problems(None, blank)))

    def test_the_probe_records_the_size_of_what_it_actually_sent(self):
        """Presence is not the property; the number is."""
        receipt, row, _ = self.w_probe_request_bytes(False)
        self.assertEqual(receipt["request_bytes"], pm.MAX_REQUEST_BYTES)
        smaller, _, _ = self.probe([(200, self.PROBE_OK, "", "completed")])
        self.assertEqual(smaller["request_bytes"],
                         len(self.probe_request_body(probe_row({})["model"])))

    def test_the_canary_evidence_says_when_it_kept_only_a_prefix(self):
        at_bound, _, _ = self.w_canary(False)
        past, _, _ = self.w_canary(True)
        for receipt, truncated in ((at_bound, False), (past, True)):
            turn = receipt["turns"][-1]
            with self.subTest(truncated=truncated):
                self.assertEqual(turn["canary_answer_errors_count"], pm.MAX_CANARY_ERRORS)
                self.assertEqual(len(turn["canary_answer_errors"]), pm.MAX_CANARY_ERRORS)
                self.assertIs(turn["canary_answer_errors_truncated"], truncated)

    def test_the_top_level_detail_counts_what_was_kept_and_says_which(self):
        """The multiplicity crosses the boundary once, and honestly.

        Joining the findings into `detail` put the provider's chosen count
        across a second time, and that second crossing is what broke the
        `Prose` bound. What crosses now is a number — and under truncation it
        is announced as a lower bound rather than passed off as exact.
        """
        at_bound, _, _ = self.w_canary(False)
        past, _, _ = self.w_canary(True)
        self.assertEqual(at_bound["detail_template"], "canary-mismatch")
        self.assertEqual(past["detail_template"], "canary-mismatch-truncated")
        self.assertIn("at least", past["detail"])
        self.assertNotIn("at least", at_bound["detail"])
        for receipt in (at_bound, past):
            self.assertIn(str(pm.MAX_CANARY_ERRORS), receipt["detail"])
            self.assertNotIn(str(pm.MAX_CANARY_ERRORS + 1), receipt["detail"])

    def test_every_derive_entry_states_what_bounds_it(self):
        for path, strategy in receipt_policy.BOUND_ENFORCEMENT.items():
            if isinstance(strategy, receipt_policy.Derive):
                with self.subTest(path=receipt_policy.render_path(path)):
                    self.assertTrue(strategy.why.strip(), "a Derive claim with no argument")

    WIDE = ("argument-errors", "canary-errors", "call-ordinal")

    def run_witness(self, name, over):
        receipt, row, entry = self.witnesses()[name](over)
        limit = pm.MAX_RESPONSE_BYTES if name in self.WIDE else self.LIMIT
        return receipt, self.audit(receipt, row, entry, receipt["schema"], limit)

    def refuse(self, findings):
        """A finding can carry a four-megabyte value, so it is summarised here."""
        return "" if not findings else f"{len(findings)} findings, first: {findings[0][:160]}"

    def ordered(self):
        return sorted(self.named().items(),
                      key=lambda entry: receipt_policy.render_path(entry[0]))

    def test_each_witness_reaches_its_bound_and_audits_clean(self):
        """The at-bound half. A witness that never reaches the bound proves nothing."""
        for path, name in self.ordered():
            with self.subTest(path=receipt_policy.render_path(path), witness=name):
                receipt, findings = self.run_witness(name, False)
                self.assertFalse(findings, self.refuse(findings))
                self.assertTrue(self.values_at(receipt, path),
                                "the witness never produced this field")

    def test_each_witness_survives_one_past_its_bound(self):
        """The half that matters: past the bound, and still an artifact we own."""
        for path, name in self.ordered():
            strategy = receipt_policy.BOUND_ENFORCEMENT[path]
            with self.subTest(path=receipt_policy.render_path(path), witness=name):
                receipt, findings = self.run_witness(name, True)
                self.assertFalse(findings, "the producer emitted a receipt its own "
                                           f"audit refuses: {self.refuse(findings)}")
                if isinstance(strategy, receipt_policy.Refuse):
                    self.assertEqual(
                        self.values_at(receipt, path), [],
                        "a Refuse strategy still wrote the field it was meant to refuse")
                    # Absence is not enough. `INTERNAL_ERROR` also leaves the
                    # field out, and it says the matrix broke. For a quantity a
                    # provider can choose that is the wrong answer, and this
                    # assertion found two of them the moment it was written:
                    # the probe's oversized request, and a three-digit status
                    # nobody has assigned.
                    if strategy.source == "provider":
                        self.assertNotEqual(
                            receipt["classification"], "INTERNAL_ERROR",
                            "a provider-chosen overrun was filed as our own crash")


class ProducerBoundTests(unittest.TestCase):
    """A receipt this module writes must pass the audit this module runs.

    Two ceilings lived only in `receipt_policy.py`, as literals the producer had
    never been told about. Both were reachable with an unremarkable response:
    1,026 well-formed tool calls, or arguments violating 1,100 schema rules, sit
    inside every byte limit. The result was an artifact written to disk that its
    own inventory then reported a finding against — two contracts, and the one
    on disk losing.

    The invariant asserted here is the whole round:

        for every reachable provider response:
            audit(produce(response)) == clean
    """

    # The real ceiling, because the point is cardinality rather than size: a
    # thousand well-formed tool calls are a large body but not an oversized one,
    # and a test that hit the byte limit first would prove the wrong bound.
    LIMIT = pm.MAX_RESPONSE_BYTES

    def entry(self):
        return pm.load_registry()["providers"]["groq"]

    def audit(self, receipt):
        return receipt_policy.audit(receipt, receipt_policy.context_for(
            pm.QUALIFY_SCHEMA, target(), self.entry(), response_limit=self.LIMIT,
            max_turns=6,
            declared_tools={op["name"] for op in surface()["operations"]}))

    def run_with(self, replies):
        return pm.qualify_target(target(), surface(), 30.0, 6, scripted(replies),
                                 response_limit=self.LIMIT)

    def calls(self, count):
        return [call("qodec_intersect", INTERSECT_ARGS, f"call_{n}") for n in range(count)]

    def test_the_two_bounds_are_the_producer_s_and_the_policy_reads_them(self):
        """One number, one owner. Two literals agree until somebody edits one."""
        context = receipt_policy.context_for(
            pm.QUALIFY_SCHEMA, target(), self.entry(), response_limit=self.LIMIT,
            max_turns=6, declared_tools=())
        self.assertEqual(context["error_ceiling"], pm.MAX_ARGUMENT_ERRORS)
        self.assertEqual(context["max_call_ordinal"], pm.MAX_CALL_ORDINAL)

    def test_an_ordinal_is_one_less_than_a_cardinality(self):
        """`call_ceiling: 1024` admitted ordinals 0..1024 — 1,025 calls."""
        self.assertEqual(pm.MAX_CALL_ORDINAL, pm.MAX_TOOL_CALLS - 1)

    def test_the_largest_admissible_response_still_audits_clean(self):
        """The boundary case, from the producer's side rather than the table's."""
        receipt = self.run_with([(200, completion(self.calls(pm.MAX_TOOL_CALLS)), "")])
        ordinals = [c["ordinal"] for c in receipt["turns"][0]["tool_calls"]]
        self.assertEqual(max(ordinals), pm.MAX_CALL_ORDINAL)
        self.assertEqual(self.audit(receipt), [])

    def test_one_call_past_the_bound_is_refused_before_any_ordinal_exists(self):
        receipt = self.run_with([(200, completion(self.calls(pm.MAX_TOOL_CALLS + 1)), "")])
        self.assertEqual(receipt["classification"], "PROTOCOL_VIOLATION")
        self.assertEqual(receipt["detail_template"], "too-many-tool-calls")
        self.assertNotIn("tool_calls", receipt["turns"][0])
        self.assertEqual(self.audit(receipt), [])

    def test_the_refusal_names_the_local_bound_and_nothing_of_the_provider_s(self):
        receipt = self.run_with([(200, completion(self.calls(pm.MAX_TOOL_CALLS + 1)), "")])
        self.assertIn(str(pm.MAX_TOOL_CALLS), receipt["detail"])
        # Not the number the provider actually sent: that is a count it chose.
        self.assertNotIn(str(pm.MAX_TOOL_CALLS + 1), receipt["detail"])

    def flood(self, errors):
        args = json.dumps({"index": "i", "sections": [0] * errors})
        return self.run_with([(200, completion([call("qodec_intersect", args, "c1")]), "")])

    def test_the_largest_admissible_error_count_still_audits_clean(self):
        receipt = self.flood(pm.MAX_ARGUMENT_ERRORS)
        turn = receipt["turns"][0]
        self.assertEqual(turn["argument_errors_count"], pm.MAX_ARGUMENT_ERRORS)
        self.assertIs(turn["argument_errors_truncated"], False)
        self.assertEqual(self.audit(receipt), [])

    def test_one_error_past_the_bound_truncates_and_says_so(self):
        """`min(len(errors), MAX)` was the one repair not available.

        The field would have kept the name `count` and stopped being one. It
        counts what the receipt carries, and a separate flag reports that there
        were more — the same shape `opaque_text` already uses for a length.
        """
        receipt = self.flood(pm.MAX_ARGUMENT_ERRORS + 1)
        turn = receipt["turns"][0]
        self.assertEqual(turn["argument_errors_count"], pm.MAX_ARGUMENT_ERRORS)
        self.assertIs(turn["argument_errors_truncated"], True)
        self.assertEqual(turn["outcome"], "malformed-arguments")
        self.assertEqual(self.audit(receipt), [])

    def test_the_truncated_digest_describes_what_was_kept(self):
        """Every field of the evidence refers to the same list, or none do."""
        kept = pm.error_evidence("argument_errors", [f"e{n}" for n in range(pm.MAX_ARGUMENT_ERRORS)])
        more = pm.error_evidence("argument_errors", [f"e{n}" for n in range(pm.MAX_ARGUMENT_ERRORS + 5)])
        self.assertEqual(kept["argument_errors_sha256"], more["argument_errors_sha256"])
        self.assertEqual(kept["argument_errors_count"], more["argument_errors_count"])
        self.assertIs(more["argument_errors_truncated"], True)


class UsageCeilingTests(unittest.TestCase):
    """The auditor's bound comes from the bound the producer applies.

    A single `usage_ceiling` was computed from `response_limit` — a fact about
    the response — while `usage_bounds` bounds the counters by the size of the
    *request*. A caller passing a small response limit therefore made the
    auditor refuse a `prompt_tokens` the producer had every reason to admit.
    """

    def context(self, schema, response_limit):
        return receipt_policy.context_for(
            schema, target(), pm.load_registry()["providers"]["groq"],
            response_limit=response_limit)

    def test_a_legitimate_prompt_count_is_not_a_finding(self):
        context = self.context(pm.QUALIFY_SCHEMA, 4096)
        admitted = pm.usage_bounds(200_000, pm.QUALIFY_MAX_TOKENS)["prompt_tokens"]
        self.assertEqual(
            receipt_policy.BoundedInt(0, "prompt_ceiling").problems(admitted, context), [])

    def test_each_counter_carries_the_bound_that_produced_it(self):
        for schema, generation in ((pm.PROBE_SCHEMA, pm.PROBE_MAX_TOKENS),
                                   (pm.QUALIFY_SCHEMA, pm.QUALIFY_MAX_TOKENS)):
            with self.subTest(schema=schema):
                context = self.context(schema, pm.MAX_RESPONSE_BYTES)
                self.assertEqual(context["prompt_ceiling"], pm.MAX_REQUEST_BYTES)
                self.assertEqual(context["completion_ceiling"], generation)
                self.assertEqual(context["usage_ceiling"],
                                 pm.MAX_REQUEST_BYTES + generation)

    def test_a_completion_count_past_the_generation_ceiling_is_still_refused(self):
        """One shared bound would have been safe and slack; three are neither."""
        context = self.context(pm.QUALIFY_SCHEMA, pm.MAX_RESPONSE_BYTES)
        over = pm.QUALIFY_MAX_TOKENS + 1
        self.assertTrue(
            receipt_policy.BoundedInt(0, "completion_ceiling").problems(over, context))
        self.assertEqual(
            receipt_policy.BoundedInt(0, "usage_ceiling").problems(over, context), [])

    def counter_policies(self):
        """The shipped rows for the three counters, keyed by counter name.

        Asserting against a `BoundedInt` built here would prove only that
        `BoundedInt` works. The claim is about the *table*: which ceiling each
        counter was actually declared with, everywhere it appears.
        """
        found = {}
        for policy in receipt_policy.POLICIES:
            leaf = policy.path[-1]
            if isinstance(leaf, receipt_policy.Key) and leaf.value in pm.USAGE_COUNTERS:
                found.setdefault(leaf.value, set()).add(policy.kind)
        return found

    def test_every_shipped_counter_names_its_own_ceiling(self):
        wanted = {"prompt_tokens": "prompt_ceiling",
                  "completion_tokens": "completion_ceiling",
                  "total_tokens": "usage_ceiling"}
        found = self.counter_policies()
        self.assertEqual(set(found), set(wanted))
        for counter, ceiling in wanted.items():
            with self.subTest(counter=counter):
                self.assertEqual({kind.high for kind in found[counter]}, {ceiling})

    def test_the_shipped_completion_row_refuses_a_count_past_the_generation(self):
        """The slack a shared ceiling would have granted, taken from the table.

        `completion_tokens` above the `max_tokens` this module asked for is a
        finding; under one shared `usage_ceiling` it would sit comfortably
        inside the bound and be recorded as an ordinary count.
        """
        context = self.context(pm.QUALIFY_SCHEMA, pm.MAX_RESPONSE_BYTES)
        over = pm.QUALIFY_MAX_TOKENS + 1
        self.assertLess(over, context["usage_ceiling"])
        for kind in self.counter_policies()["completion_tokens"]:
            self.assertTrue(kind.problems(over, context), kind)

    def test_no_counter_is_bounded_by_the_response_limit(self):
        """The two limits describe different things and must not be confused."""
        wide = self.context(pm.QUALIFY_SCHEMA, 4096)
        narrow = self.context(pm.QUALIFY_SCHEMA, pm.MAX_RESPONSE_BYTES)
        for ceiling in ("prompt_ceiling", "completion_ceiling", "usage_ceiling"):
            with self.subTest(ceiling=ceiling):
                self.assertEqual(wide[ceiling], narrow[ceiling])


class CoverageApiTests(unittest.TestCase):
    """`ReceiptKind` closed the table and left the queries taking strings.

    `coverage("probe", ...)` matched no policy, so `declared` and `applicable`
    were both empty and both directions of the proof reported nothing wrong — a
    green answer produced by asking about a universe that does not exist.
    """

    def test_a_plain_string_is_refused_by_every_query(self):
        """Every door, including the selector they all share.

        The check lives at `policies_for` alone. Written at each of the four
        public queries it was untestable: any three could be deleted and the
        fourth would still raise, because they call one another. Here the
        claim is the one that matters — no entry point admits a string —
        and each query bypassing the selector is a mutation this notices.
        """
        for query in (receipt_policy.policies_for, receipt_policy.declared_paths,
                      receipt_policy.applicable_paths):
            with self.subTest(query=query.__name__):
                with self.assertRaisesRegex(TypeError, "a receipt kind is a ReceiptKind"):
                    query("probe")
        with self.assertRaisesRegex(TypeError, "a receipt kind is a ReceiptKind"):
            receipt_policy.coverage("probe", set())
        with self.assertRaisesRegex(TypeError, "a receipt kind is a ReceiptKind"):
            receipt_policy.coverage_gaps("probe", set())

    def test_the_real_kinds_still_answer(self):
        for kind in receipt_policy.ReceiptKind:
            with self.subTest(kind=kind):
                self.assertTrue(receipt_policy.declared_paths(kind))
                self.assertTrue(receipt_policy.applicable_paths(kind))

    def test_a_wrong_kind_object_cannot_sneak_through(self):
        for hostile in (None, 1, ("probe",), object(), "PROBE"):
            with self.subTest(value=repr(hostile)):
                with self.assertRaises(TypeError):
                    receipt_policy.coverage(hostile, set())


class MutationTableValidatorTests(unittest.TestCase):
    """The validator of the mutation table needs its own positive controls.

    Otherwise it is a check nobody checks — an architecture this vertical has
    now learned about eight times, apparently without a durable receipt.
    """

    def test_a_multi_anchor_spec_with_unequal_halves_is_refused(self):
        """`zip` truncates in silence, so two of three guards would be removed
        and the harness would report a kill for a contract it left standing."""
        lopsided = [("A", ["x", "y", "z"], ["1", "2"])]
        problems = mutations.spec_problems(lopsided)
        self.assertTrue(any("3 anchors and 2 replacements" in p for p in problems), problems)
        self.assertTrue(any("discard the difference" in p for p in problems), problems)

    def test_a_half_list_spec_is_refused(self):
        self.assertTrue(any("one half of a multi-anchor edit" in p
                            for p in mutations.spec_problems([("A", ["x"], "1")])))

    def test_an_orphaned_expectation_is_refused(self):
        """Renaming a mutation silently retires the attribution it carried."""
        problems = mutations.spec_problems([("B", "x", "y")], {"A": "test_something"})
        self.assertTrue(any("'A'" in p and "no mutation declares" in p for p in problems),
                        problems)

    def test_the_shipped_table_carries_no_orphan(self):
        self.assertEqual(
            mutations.spec_problems(mutations.MUTATIONS, mutations.EXPECTED_KILL), [])
        self.assertEqual(
            set(mutations.EXPECTED_KILL) - {spec[0] for spec in mutations.MUTATIONS}, set())

    def test_the_negative_control_for_a_failed_setup_names_its_killer(self):
        """`W4` used to die of `UnboundLocalError` before reaching the property."""
        self.assertIn("W4 a failed setup command stops being an error",
                      mutations.EXPECTED_KILL)


class ChildProcessLivenessTests(unittest.TestCase):
    """A child that reads the terminal must get EOF, not the deadline.

    The first version of this test ran the child with whatever stdin the test
    runner happened to have, which under CI is already `/dev/null`. It passed
    with `stdin=None` restored — proving the runner's environment, not the
    policy. So the parent is given a descriptor that would genuinely block:
    a pipe nobody ever writes to and nobody closes. Inherited, the child waits
    for the deadline; `DEVNULL` is the difference between the two outcomes.
    """

    def test_a_child_reading_stdin_is_not_left_waiting(self):
        import time
        read_fd, write_fd = os.pipe()
        try:
            saved = os.dup(0)
        except OSError:  # a runner with no stdin at all
            saved = None
        try:
            os.dup2(read_fd, 0)
            started = time.monotonic()
            proc = process_boundary.run_bytes(
                [sys.executable, "-c",
                 "import sys; sys.stdout.write(str(len(sys.stdin.read())))"],
                timeout=8)
            elapsed = time.monotonic() - started
        except process_boundary.ProcessTimeout:
            self.fail("the child inherited a blocking stdin and waited out its deadline")
        finally:
            if saved is None:
                with open(os.devnull, "rb") as null:
                    os.dup2(null.fileno(), 0)
            else:
                os.dup2(saved, 0)
                os.close(saved)
            os.close(read_fd)
            os.close(write_fd)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), b"0")
        self.assertLess(elapsed, 8)


class CleanTreeIsolationTests(unittest.TestCase):
    """The real verdict runs under the isolation the self-test builds.

    It did not, and the asymmetry was the defect: the control proved the check
    survives a hostile machine while the check that actually reports ran with
    ambient `os.environ`. An inherited `GIT_DIR` points both `rev-parse` and
    `status` at another repository, after which this prints `OK` about a tree it
    never looked at.
    """

    def gate(self):
        import importlib.util
        path = Path(__file__).resolve().parent / "check_clean_tree.py"
        spec = importlib.util.spec_from_file_location("check_clean_tree", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_an_inherited_git_dir_cannot_redirect_the_real_verdict(self):
        """Two repositories: the one being judged, and a clean decoy.

        The test builds both rather than assuming it runs inside a checkout —
        the mutation harness copies this tree into a temp directory that is not
        one, and a regression that assumes its surroundings is the defect it
        exists to catch, one layer out.
        """
        gate = self.gate()
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "home"
            home.mkdir()
            env = gate.isolated_env(home)

            judged = Path(td) / "judged"
            judged.mkdir()
            gate.must_git("init", "-q", cwd=judged, env=env)
            (judged / "leftover.txt").write_text("x", encoding="utf-8")

            decoy = Path(td) / "decoy"
            decoy.mkdir()
            gate.must_git("init", "-q", cwd=decoy, env=env)

            hostile = dict(os.environ, GIT_DIR=str(decoy / ".git"),
                           GIT_WORK_TREE=str(decoy))
            with patch.dict("os.environ", hostile, clear=False):
                # Under isolation the verdict is about `judged`, leftover and
                # all. The decoy is empty, so a redirected gate would say OK.
                root = gate.repo_root(start=judged, env=env)
                self.assertEqual(root.resolve(), judged.resolve())
                self.assertTrue(any("leftover.txt" in line
                                    for line in gate.dirt(root, env=env)))
                # And the ambient environment really would redirect it: this is
                # the half that makes the isolation load-bearing rather than
                # decorative.
                hijacked = gate.repo_root(start=judged)
                self.assertEqual(hijacked.resolve(), decoy.resolve())

    def test_the_gate_that_actually_reports_is_the_one_under_test(self):
        """`main`, not its parts. The parts were already isolated; `main` was not.

        A test that calls `repo_root(env=env)` and `dirt(root, env=env)` proves
        those two accept isolation — which they did before this round, while the
        one caller that produces the verdict passed neither. So the gate is
        copied into a dirty repository of its own and *run*, with `GIT_DIR`
        pointing at a clean decoy. Ambient, it prints OK about the decoy; under
        its own isolation it reports the tree it was asked about.
        """
        import importlib.util
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "home"
            home.mkdir()
            env = self.gate().isolated_env(home)

            def seed(root):
                root.mkdir()
                self.gate().must_git("init", "-q", cwd=root, env=env)
                for key, value in (("user.email", "t@example"), ("user.name", "t"),
                                   ("commit.gpgsign", "false")):
                    self.gate().must_git("config", key, value, cwd=root, env=env)
                (root / "seed.txt").write_text("seed\n", encoding="utf-8")
                self.gate().must_git("add", "seed.txt", cwd=root, env=env)
                self.gate().must_git("commit", "-qm", "seed", cwd=root, env=env)

            judged = Path(td) / "judged"
            seed(judged)
            decoy = Path(td) / "decoy"
            seed(decoy)

            # The gate lives inside the tree it judges, so a copy of it is the
            # dirt: an untracked file in `judged`, and nothing in `decoy`.
            source = Path(__file__).resolve().parent / "check_clean_tree.py"
            copied = judged / "check_clean_tree.py"
            copied.write_bytes(source.read_bytes())

            spec = importlib.util.spec_from_file_location("clean_tree_copy", copied)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            hostile = dict(os.environ, GIT_DIR=str(decoy / ".git"),
                           GIT_WORK_TREE=str(decoy))
            with patch.dict("os.environ", hostile, clear=False):
                # The gate prints its verdict; the exit code is what is asserted.
                with contextlib.redirect_stdout(io.StringIO()) as printed:
                    verdict = module.main([])
                self.assertIn("check_clean_tree.py", printed.getvalue())
                # And the hijack is real: ambient, the gate resolves to the
                # decoy, which is clean and would have been reported as OK.
                self.assertEqual(module.repo_root(start=judged).resolve(),
                                 decoy.resolve())
        self.assertEqual(verdict, 1)

    def test_a_global_excludes_file_cannot_hide_untracked_leftovers(self):
        gate = self.gate()
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "home"
            home.mkdir()
            root = Path(td) / "repo"
            root.mkdir()
            env = gate.isolated_env(home)
            gate.must_git("init", "-q", cwd=root, env=env)
            (root / "leftover.tmp").write_text("x", encoding="utf-8")
            # A global excludes file that would hide it, if the gate read one.
            (home / "excludes").write_text("*.tmp\n", encoding="utf-8")
            hostile = dict(os.environ, HOME=str(home))
            with patch.dict("os.environ", hostile, clear=False):
                gate.must_git("config", "--global", "core.excludesFile",
                              str(home / "excludes"), cwd=root,
                              env=dict(os.environ, HOME=str(home)))
                found = gate.dirt(root, env=gate.isolated_env(home))
        self.assertTrue(any("leftover.tmp" in line for line in found), found)


class NestedCorpusTests(unittest.TestCase):
    """The malformed corpus walks structural paths, not member names.

    The self-test runs the whole corpus as a subprocess and is the gate. These
    are the properties that make its number mean something, asked directly so a
    mutation has an oracle that names the defect rather than a count that moved.
    """

    def test_the_walk_unions_over_every_element_not_the_first(self):
        # The canary fields exist only on the turn that ends the exchange, so a
        # walk that stopped at `turns[0]` reported that no fixture contains
        # them — and the coverage gate would have believed it.
        receipt = {"turns": [{"a": 1}, {"b": [{"c": 2}]}]}
        found = receipt_policy.fixture_paths(receipt)
        self.assertIn(receipt_policy.P("turns", receipt_policy.EACH, "b",
                                       receipt_policy.EACH, "c"), found)

    def test_an_array_and_its_members_are_different_places(self):
        found = receipt_policy.fixture_paths({"xs": [1, 2]})
        self.assertIn(receipt_policy.P("xs"), found)
        self.assertIn(receipt_policy.P("xs", receipt_policy.EACH), found)

    def test_indices_collapse_but_keys_do_not(self):
        found = receipt_policy.fixture_paths({"xs": [{"k": 1}, {"j": 2}]})
        rendered = {receipt_policy.render_path(path) for path in found}
        self.assertEqual(rendered, {"xs", "xs[]", "xs[].k", "xs[].j"})

    def test_locate_finds_a_path_that_only_a_later_element_carries(self):
        receipt = {"turns": [{"a": 1}, {"late": "here"}]}
        found = receipt_policy.locate(
            receipt, receipt_policy.P("turns", receipt_policy.EACH, "late"))
        self.assertIsNotNone(found)
        container, step = found
        self.assertIs(container, receipt["turns"][1])
        self.assertEqual(step, "late")

    def test_locate_answers_none_rather_than_raising_on_a_wrong_shape(self):
        for receipt in ({"turns": 5}, {"turns": []}, {}, []):
            self.assertIsNone(receipt_policy.locate(
                receipt, receipt_policy.P("turns", receipt_policy.EACH, "x")))

    def test_a_path_the_locator_cannot_reach_is_not_counted_as_reached(self):
        # Discovery and addressing are two walks, and the tally answers for the
        # second. Counting the first would let the report speak for specimens
        # nobody produced.
        tally = receipt_policy.Reached()
        with patch.object(receipt_policy, "locate", return_value=None):
            list(receipt_policy.malformed_specimens({"schema": "s"}, tally))
        self.assertEqual(tally.paths, set())

    def test_every_required_place_is_one_some_policy_reads(self):
        declared = receipt_policy.declared_places()
        unread = [receipt_policy.render_path(path)
                  for path in receipt_policy.WITNESS_REQUIRED if path not in declared]
        self.assertEqual(unread, [])

    def test_the_containers_walked_through_count_as_declared_places(self):
        declared = receipt_policy.declared_places()
        self.assertIn(receipt_policy.P("turns", receipt_policy.EACH, "tool_calls",
                                       receipt_policy.EACH), declared)

    # The two narrowed-corpus controls — a missing terminal turn, a hollow
    # nested list — are not repeated here. They live in `receipt_policy.py`'s
    # self-test, which this suite runs as a subprocess and asserts the exit code
    # of, so they are enforced on every run of this file already. Asserting the
    # same thing twice cost a full corpus pass each (~22s), and the mutation
    # harness runs this suite once per mutation: the duplicate was two hours of
    # machine time buying no proof that was not already bought.
    #
    # A tally check is not the same thing as a coverage check, so the cheap
    # direction — that `coverage_problems` reports the path it was denied — is
    # asked here without building a corpus for it.

    def test_the_gap_is_named_by_its_path_not_by_a_count(self):
        tally = receipt_policy.Reached(
            paths=set(receipt_policy.WITNESS_REQUIRED)
            - {receipt_policy.P("turns", receipt_policy.EACH, "tool_calls",
                                receipt_policy.EACH)},
            root_shapes=1,
            context_keys={key for _n, _r, ctx in receipt_policy.fixtures() for key in ctx})
        gaps = receipt_policy.coverage_problems(tally)
        self.assertTrue(any("turns[].tool_calls[] never received" in line for line in gaps), gaps)

    def test_a_required_place_no_policy_reads_is_refused(self):
        invented = receipt_policy.WITNESS_REQUIRED + (receipt_policy.P("invented_leaf"),)
        tally = receipt_policy.Reached(
            paths=set(invented), root_shapes=1,
            context_keys={key for _n, _r, ctx in receipt_policy.fixtures() for key in ctx})
        gaps = receipt_policy.coverage_problems(tally, invented)
        self.assertTrue(any("no policy reads it" in line for line in gaps), gaps)

    def test_a_canary_template_that_is_not_a_string_is_a_finding_not_a_raise(self):
        import copy
        _name, receipt, context = receipt_policy.fixtures()[2]
        bad = copy.deepcopy(receipt)
        for turn in bad["turns"]:
            if "canary_answer_error_templates" in turn:
                turn["canary_answer_error_templates"] = [[]]
        findings = receipt_policy.audit(bad, context)
        self.assertTrue(any("unregistered template" in line for line in findings), findings)


if __name__ == "__main__":
    unittest.main()
