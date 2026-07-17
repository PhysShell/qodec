"""Unit tests for pytest-requests-canonicalization-v1-rejection-record.json
and its builder -- documents that repo-requests' original pytest_requests_
canonicalizer.py / policy (derived from the invalid, error-heavy Stage 2
run 29544801640) is rejected historical evidence, never accepted Stage 2
identity. Mirrors the self-hash discipline of every other D1b evidence
record in this codebase.
"""
import hashlib
import json
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import build_pytest_requests_canonicalization_v1_rejection_record as builder  # noqa: E402

BASE_DIR = Path(__file__).resolve().parents[1]
RECORD_PATH = BASE_DIR / "pytest-requests-canonicalization-v1-rejection-record.json"


def _compute_record_sha256(body: dict) -> str:
    without_hash = {k: v for k, v in body.items() if k != "record_sha256"}
    text = json.dumps(without_hash, indent=2, sort_keys=True) + "\n"
    return hashlib.sha256(text.encode()).hexdigest()


class TestRejectionRecordIsCommittedAndSelfConsistent(unittest.TestCase):
    def test_record_file_exists(self):
        self.assertTrue(RECORD_PATH.is_file())

    def test_record_self_hash_verifies(self):
        record = json.loads(RECORD_PATH.read_text())
        self.assertEqual(_compute_record_sha256(record), record["record_sha256"])

    def test_builder_is_deterministic(self):
        first = builder.build_record()
        second = builder.build_record()
        self.assertEqual(first, second)

    def test_builder_output_matches_committed_file(self):
        body = builder.build_record()
        committed = json.loads(RECORD_PATH.read_text())
        self.assertEqual(body, committed)


class TestRejectionRecordFields(unittest.TestCase):
    def setUp(self):
        self.record = json.loads(RECORD_PATH.read_text())

    def test_case_id_and_classification(self):
        self.assertEqual(self.record["case_id"], "repo-requests")
        self.assertEqual(self.record["classification"], "REJECTED_DERIVED_FROM_INVALID_RUN")

    def test_rejected_module_and_policy_hashes_match_the_real_files_on_disk(self):
        module_path = BASE_DIR / "tools" / "pytest_requests_canonicalizer.py"
        policy_path = BASE_DIR / "pytest-requests-capture-canonicalization-policy.json"
        self.assertEqual(
            hashlib.sha256(module_path.read_bytes()).hexdigest(),
            self.record["rejected_module"]["sha256"],
        )
        self.assertEqual(
            hashlib.sha256(policy_path.read_bytes()).hexdigest(),
            self.record["rejected_policy"]["file_sha256"],
        )

    def test_rejected_from_evidence_documents_the_real_failing_run(self):
        evidence = self.record["rejected_from_evidence"]
        self.assertEqual(evidence["workflow_run_id"], 29544801640)
        self.assertEqual(evidence["observed_exit_code"], 1)
        self.assertIn("30 failed", evidence["observed_pytest_final_summary"])
        self.assertIn("205 errors", evidence["observed_pytest_final_summary"])

    def test_prohibited_workarounds_forbid_reusing_the_rejected_evidence(self):
        joined = " ".join(self.record["prohibited_workarounds"])
        self.assertIn("29544801640", joined)
        self.assertIn("object-address", joined)


if __name__ == "__main__":
    unittest.main()
