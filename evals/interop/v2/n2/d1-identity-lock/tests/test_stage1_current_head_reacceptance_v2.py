"""Mutation tests for verify_stage1_current_head_reacceptance.py.

Each test independently mutates exactly one thing the hardened verifier is
supposed to catch -- the record's own self-hash, a mandatory identity
field, a policy hash, actual v1 policy bytes, job/artifact ID uniqueness,
job success, an acceptance-gate boolean, or the trigger patch's bytes --
and asserts the verifier fails closed. All mutations are written to
tempfile copies; no repository file is ever modified by this suite.
"""
import copy
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import verify_stage1_current_head_reacceptance as verifier  # noqa: E402

BASE_DIR = Path(__file__).resolve().parents[1]
RECORD_PATH = BASE_DIR / "stage1-current-head-reacceptance-v2.json"
V1_POLICY_PATH = BASE_DIR / "gradle-capture-canonicalization-policy.json"
TRIGGER_PATCH_PATH = BASE_DIR / "evidence" / "stage1-v2-trigger.patch"


def _write_record(tmp_path: Path, record: dict) -> Path:
    out = tmp_path / "record.json"
    out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return out


class TestBaselineActuallyPasses(unittest.TestCase):
    """Sanity check every other test in this file relies on: the real,
    unmutated committed record and files verify successfully. If this
    fails, every mutation test below is meaningless."""

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

    def _verify_mutated_record(self, mutator) -> tuple[bool, str]:
        """Mutates a copy of the real record AND re-signs its self-hash to
        match the mutated content, so the resulting failure comes from the
        specific downstream validator under test -- not merely from the
        (also-correct, but less informative) self-hash mismatch every
        mutation would otherwise trip first."""
        mutated = copy.deepcopy(self.original_record)
        mutator(mutated)
        mutated["record_sha256"] = verifier.compute_record_sha256(mutated)
        record_path = _write_record(self.tmp_path, mutated)
        return verifier.verify(record_path=record_path)

    def test_tampered_record_sha256_fails(self):
        # Deliberately does NOT re-sign -- this is the one test that checks
        # the self-hash gate itself, not a downstream validator.
        mutated = copy.deepcopy(self.original_record)
        mutated["record_sha256"] = "sha256:" + "0" * 64
        record_path = _write_record(self.tmp_path, mutated)
        ok, message = verifier.verify(record_path=record_path)
        self.assertFalse(ok)
        self.assertIn("self-hash mismatch", message)

    def test_tampered_schema_version_fails(self):
        ok, message = self._verify_mutated_record(lambda r: r.__setitem__("schema_version", 2))
        self.assertFalse(ok)

    def test_tampered_base_main_sha_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("base_main_sha", "0" * 40)
        )
        self.assertFalse(ok)

    def test_tampered_tested_implementation_sha_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("tested_implementation_sha", "1" * 40)
        )
        self.assertFalse(ok)

    def test_tampered_v2_policy_hash_in_record_fails(self):
        def mutate(r):
            r["gradle_canonicalization_v2"]["policy_sha256"] = "0" * 64

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("policy_sha256", message)

    def test_duplicate_job_id_fails(self):
        def mutate(r):
            r["jobs"][1]["job_id"] = r["jobs"][0]["job_id"]

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("duplicate job_id", message)

    def test_duplicate_artifact_id_fails(self):
        def mutate(r):
            r["artifacts"][1]["artifact_id"] = r["artifacts"][0]["artifact_id"]

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("duplicate artifact_id", message)

    def test_unsuccessful_individual_job_fails(self):
        def mutate(r):
            r["jobs"][0]["conclusion"] = "failure"

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("conclusion", message)

    def test_all_artifacts_content_inspected_false_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("all_artifacts_content_inspected", False)
        )
        self.assertFalse(ok)
        self.assertIn("all_artifacts_content_inspected", message)

    def test_all_cases_content_accepted_false_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("all_cases_content_accepted", False)
        )
        self.assertFalse(ok)
        self.assertIn("all_cases_content_accepted", message)

    def test_all_pairs_canonically_equal_false_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("all_pairs_canonically_equal", False)
        )
        self.assertFalse(ok)
        self.assertIn("all_pairs_canonically_equal", message)

    def test_nonempty_unexplained_raw_differences_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("unexplained_raw_differences", ["repo-moshi: unexplained line 42"])
        )
        self.assertFalse(ok)
        self.assertIn("unexplained_raw_differences", message)

    def test_token_counts_computed_true_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("token_counts_computed", True)
        )
        self.assertFalse(ok)
        self.assertIn("token_counts_computed", message)

    def test_stage2_executed_true_fails(self):
        ok, message = self._verify_mutated_record(lambda r: r.__setitem__("stage2_executed", True))
        self.assertFalse(ok)
        self.assertIn("stage2_executed", message)

    def test_stage2_authorized_next_false_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("stage2_authorized_next", False)
        )
        self.assertFalse(ok)
        self.assertIn("stage2_authorized_next", message)


class TestExternalFileMutationsAreCaught(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_tampered_v1_policy_bytes_fail(self):
        original = V1_POLICY_PATH.read_text()
        tampered_body = json.loads(original)
        tampered_body["rules"][0]["anchored_regex"] = "^TAMPERED$"
        tampered_path = self.tmp_path / "gradle-capture-canonicalization-policy.json"
        tampered_path.write_text(json.dumps(tampered_body, indent=2, sort_keys=True) + "\n")

        ok, message = verifier.verify(v1_policy_path=tampered_path)
        self.assertFalse(ok)
        self.assertIn("v1 policy", message)

    def test_tampered_trigger_patch_bytes_fail(self):
        original = TRIGGER_PATCH_PATH.read_bytes()
        tampered = original.replace(b"push:", b"pull_request:")
        self.assertNotEqual(tampered, original, "fixture patch did not contain expected 'push:' text")
        tampered_path = self.tmp_path / "stage1-v2-trigger.patch"
        tampered_path.write_bytes(tampered)

        ok, message = verifier.verify(trigger_patch_path=tampered_path)
        self.assertFalse(ok)
        self.assertIn("sha256 mismatch", message)


if __name__ == "__main__":
    unittest.main()
