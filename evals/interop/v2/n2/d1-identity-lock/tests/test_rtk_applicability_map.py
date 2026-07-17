"""Mutation tests for verify_rtk_applicability_map.py."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import verify_rtk_applicability_map as verifier  # noqa: E402

BASE_DIR = Path(__file__).resolve().parents[1]
RECORD_PATH = BASE_DIR / "rtk-applicability-map-v1.json"


def _write_record(tmp_path: Path, record: dict) -> Path:
    out = tmp_path / "record.json"
    out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return out


class TestBaselineActuallyPasses(unittest.TestCase):
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

    def test_log_filter_smuggled_into_a_case_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["cases"]["repo-moshi"].__setitem__("rtk_argv", ["pipe", "--filter", "log"])
        )
        self.assertFalse(ok)
        self.assertIn("prohibited filter", message)

    def test_prohibited_filters_tampered_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("prohibited_filters", [])
        )
        self.assertFalse(ok)
        self.assertIn("prohibited_filters", message)

    def test_rustlings_reassigned_to_passthrough_fails(self):
        # repo-rustlings' real frozen_argv is ['cargo','test'] -- it MUST use
        # the cargo-test filter now that it's verified deterministic.
        ok, message = self._verify_mutated_record(
            lambda r: r["cases"]["repo-rustlings"].__setitem__("rtk_argv", ["pipe", "--passthrough"])
        )
        self.assertFalse(ok)
        self.assertIn("repo-rustlings", message)

    def test_non_cargo_test_case_wrongly_assigned_cargo_test_filter_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["cases"]["repo-requests"].__setitem__("rtk_argv", ["pipe", "--filter", "cargo-test"])
        )
        self.assertFalse(ok)
        self.assertIn("repo-requests", message)

    def test_missing_case_fails(self):
        ok, message = self._verify_mutated_record(lambda r: r["cases"].pop("repo-hyperfine"))
        self.assertFalse(ok)

    def test_git_diff_repetitions_understated_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["newly_verified_deterministic_filters"]["git-diff"].__setitem__("repetitions", 5)
        )
        self.assertFalse(ok)
        self.assertIn("git-diff", message)

    def test_cargo_test_canonical_stdout_sha256_tampered_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["newly_verified_deterministic_filters"]["cargo-test"].__setitem__(
                "canonical_stdout_sha256", "1" * 64
            )
        )
        self.assertFalse(ok)
        self.assertIn("cargo-test", message)

    def test_probe_report_sha256_tampered_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r["newly_verified_deterministic_filters"]["git-diff"].__setitem__(
                "probe_report_sha256", "2" * 64
            )
        )
        self.assertFalse(ok)
        self.assertIn("git-diff", message)


if __name__ == "__main__":
    unittest.main()
