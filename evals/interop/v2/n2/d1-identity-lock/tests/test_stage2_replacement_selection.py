"""Mutation tests for verify_stage2_replacement_selection.py.

Each test independently mutates a copy of the real committed record (and
re-signs its self-hash, so the specific downstream check under test -- not
merely the self-hash gate -- is what actually fails) and asserts the
verifier fails closed. The one exception is the record-self-hash test
itself, which deliberately does NOT re-sign. No repository file is ever
modified by this suite.
"""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import verify_stage2_replacement_selection as verifier  # noqa: E402

RECORD_PATH = Path(__file__).resolve().parents[1] / "stage2-replacement-selection-v1.json"


def _write_record(tmp_path: Path, record: dict) -> Path:
    out = tmp_path / "record.json"
    out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return out


class TestBaselinePasses(unittest.TestCase):
    def test_real_committed_record_verifies(self):
        ok, message = verifier.verify()
        self.assertTrue(ok, message)


class TestMutationsAreCaught(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_record = json.loads(RECORD_PATH.read_text())

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def _verify_mutated(self, mutator) -> tuple[bool, str]:
        mutated = copy.deepcopy(self.original_record)
        mutator(mutated)
        mutated["record_sha256"] = verifier.compute_record_sha256(mutated)
        record_path = _write_record(self.tmp_path, mutated)
        return verifier.verify(record_path=record_path)

    def test_tampered_record_sha256_fails(self):
        mutated = copy.deepcopy(self.original_record)
        mutated["record_sha256"] = "sha256:" + "0" * 64
        record_path = _write_record(self.tmp_path, mutated)
        ok, message = verifier.verify(record_path=record_path)
        self.assertFalse(ok)
        self.assertIn("self-hash mismatch", message)

    def test_different_replacement_case_fails(self):
        def mutate(r):
            r["replacement_case_id"] = "repo-detekt"

        ok, message = self._verify_mutated(mutate)
        self.assertFalse(ok)
        self.assertIn("replacement_case_id", message)

    def test_reordered_ranking_causing_different_result_fails(self):
        def mutate(r):
            r["ranking"] = list(reversed(r["ranking"]))

        ok, message = self._verify_mutated(mutate)
        self.assertFalse(ok)
        self.assertIn("ranking", message)

    def test_modified_registry_hash_fails(self):
        def mutate(r):
            r["candidate_registry_sha256"] = "sha256:" + "1" * 64

        ok, message = self._verify_mutated(mutate)
        self.assertFalse(ok)
        self.assertIn("candidate_registry_sha256", message)

    def test_modified_policy_hash_fails(self):
        def mutate(r):
            r["candidate_selection_policy_sha256"] = "sha256:" + "2" * 64

        ok, message = self._verify_mutated(mutate)
        self.assertFalse(ok)
        self.assertIn("candidate_selection_policy_sha256", message)

    def test_missing_eligible_candidate_fails(self):
        def mutate(r):
            r["eligible_candidate_ids"] = r["eligible_candidate_ids"][:-1]

        ok, message = self._verify_mutated(mutate)
        self.assertFalse(ok)
        self.assertIn("eligible_candidate_ids", message)

    def test_extra_eligible_candidate_fails(self):
        def mutate(r):
            r["eligible_candidate_ids"] = sorted(r["eligible_candidate_ids"] + ["repo-not-a-real-candidate"])

        ok, message = self._verify_mutated(mutate)
        self.assertFalse(ok)
        self.assertIn("eligible_candidate_ids", message)

    def test_modified_score_fails(self):
        def mutate(r):
            r["ranking"][0]["final_score"] = 0.999999

        ok, message = self._verify_mutated(mutate)
        self.assertFalse(ok)
        self.assertIn("ranking", message)

    def test_modified_quota_trace_fails(self):
        def mutate(r):
            r["quota_trace"]["status"] = "TAMPERED"

        ok, message = self._verify_mutated(mutate)
        self.assertFalse(ok)
        self.assertIn("quota_trace", message)

    def test_missing_durable_asset_identity_fails(self):
        def mutate(r):
            r["replacement_durable_asset_name"] = None
            r["replacement_durable_asset_sha256"] = None

        ok, message = self._verify_mutated(mutate)
        self.assertFalse(ok)

    def test_forbidden_benchmark_signals_used_true_fails(self):
        def mutate(r):
            r["forbidden_benchmark_signals_used"] = True

        ok, message = self._verify_mutated(mutate)
        self.assertFalse(ok)
        self.assertIn("forbidden_benchmark_signals_used", message)

    def test_selection_is_deterministic_false_fails(self):
        def mutate(r):
            r["selection_is_deterministic"] = False

        ok, message = self._verify_mutated(mutate)
        self.assertFalse(ok)
        self.assertIn("selection_is_deterministic", message)


if __name__ == "__main__":
    unittest.main()
