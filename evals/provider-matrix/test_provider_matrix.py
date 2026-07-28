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


if __name__ == "__main__":
    unittest.main()
