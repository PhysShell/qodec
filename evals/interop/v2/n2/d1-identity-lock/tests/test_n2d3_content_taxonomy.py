"""Mutation tests for verify_n2d3_content_taxonomy.py."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import build_n2d3_content_taxonomy as builder  # noqa: E402
import verify_n2d3_content_taxonomy as verifier  # noqa: E402

BASE_DIR = Path(__file__).resolve().parents[1]
RECORD_PATH = BASE_DIR / "n2d3-content-taxonomy-v1.json"


def _write_record(tmp_path: Path, record: dict) -> Path:
    out = tmp_path / "record.json"
    out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return out


class TestBaselineActuallyPasses(unittest.TestCase):
    def test_real_committed_record_verifies(self):
        ok, message = verifier.verify()
        self.assertTrue(ok, message)

    def test_all_18_cases_present(self):
        record = json.loads(RECORD_PATH.read_text())
        self.assertEqual(sorted(record["cases"].keys()), sorted(builder.EXPECTED_CASE_IDS))
        self.assertEqual(len(record["cases"]), 18)


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
        mutated = copy.deepcopy(self.original_record)
        mutator(mutated)
        mutated["record_sha256"] = verifier_module_hash(mutated)
        record_path = _write_record(self.tmp_path, mutated)
        return verifier.verify(record_path=record_path)

    def test_tampered_record_sha256_fails(self):
        mutated = copy.deepcopy(self.original_record)
        mutated["record_sha256"] = "sha256:" + "0" * 64
        record_path = _write_record(self.tmp_path, mutated)
        ok, message = verifier.verify(record_path=record_path)
        self.assertFalse(ok)
        self.assertIn("self-hash mismatch", message)

    def test_missing_case_classification_fails(self):
        ok, message = self._verify_mutated_record(lambda r: r["cases"].pop("repo-requests"))
        self.assertFalse(ok)
        self.assertIn("18-case set", message)

    def test_duplicate_case_classification_fails(self):
        def mutate(r):
            extra = copy.deepcopy(r["cases"]["repo-requests"])
            r["cases"]["repo-requests-duplicate"] = extra

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)

    def test_unauthorized_content_family_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["cases"]["repo-hyperfine"].__setitem__("content_family", "made-up-family")
        )
        self.assertFalse(ok)
        self.assertIn("content_family", message)

    def test_unauthorized_origin_kind_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["cases"]["repo-hyperfine"].__setitem__("origin_kind", "made-up-origin")
        )
        self.assertFalse(ok)
        self.assertIn("origin_kind", message)

    def test_wrong_canonical_input_sha_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["cases"]["repo-requests"]["classification_evidence"].__setitem__(
                "canonical_benchmark_input_sha256", "1" * 64
            )
        )
        self.assertFalse(ok)

    def test_wrong_canonical_source_record_hash_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["canonical_benchmark_link"].__setitem__("record_sha256", "sha256:" + "2" * 64)
        )
        self.assertFalse(ok)
        self.assertIn("canonical_benchmark_link", message)

    def test_payload_kind_disagrees_with_utf8_valid_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["cases"]["repo-requests"].__setitem__("payload_kind", "binary-container")
        )
        self.assertFalse(ok)

    def test_refusal_case_reclassified_as_utf8_text_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: (
                r["cases"]["dataset-loghub-v8"].__setitem__("payload_kind", "utf8-text"),
                r["cases"]["dataset-loghub-v8"]["classification_evidence"].__setitem__("utf8_valid", True),
            )
        )
        self.assertFalse(ok)

    def test_classification_evidence_frozen_argv_tampered_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["cases"]["repo-dockerfile-parser-rs"]["classification_evidence"].__setitem__(
                "frozen_argv", ["echo", "not-cargo-test"]
            )
        )
        self.assertFalse(ok)

    def test_post_hoc_exploratory_false_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("post_hoc_exploratory", False)
        )
        self.assertFalse(ok)
        self.assertIn("post_hoc_exploratory", message)


def verifier_module_hash(record: dict) -> str:
    import build_n2d3_content_taxonomy as b
    return b.compute_record_sha256(record)


if __name__ == "__main__":
    unittest.main()
