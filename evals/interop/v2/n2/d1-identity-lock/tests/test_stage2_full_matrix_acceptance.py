"""Mutation tests for verify_stage2_full_matrix_acceptance.py.

Each test independently mutates exactly one thing the fail-closed verifier
is supposed to catch -- the record's own self-hash, a mandatory identity
field, a policy hash, job/artifact ID uniqueness, job success, an
acceptance-gate boolean, or the trigger patch's bytes -- and asserts the
verifier fails closed. All mutations are written to tempfile copies; no
repository file is ever modified by this suite. Mirrors
test_stage1_current_head_reacceptance_v2.py's structure and discipline.
"""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import verify_stage2_full_matrix_acceptance as verifier  # noqa: E402

BASE_DIR = Path(__file__).resolve().parents[1]
RECORD_PATH = BASE_DIR / "stage2-full-matrix-acceptance.json"
TRIGGER_PATCH_PATH = BASE_DIR / "evidence" / "stage2-full-matrix-trigger.patch"
CARGO_TEST_POLICY_PATH = BASE_DIR / "cargo-test-capture-canonicalization-policy.json"


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
        ok, message = self._verify_mutated_record(lambda r: r.__setitem__("schema_version", 3))
        self.assertFalse(ok)

    def test_tampered_record_version_fails(self):
        ok, message = self._verify_mutated_record(lambda r: r.__setitem__("record_version", 1))
        self.assertFalse(ok)

    def test_tampered_base_main_sha_fails(self):
        ok, message = self._verify_mutated_record(lambda r: r.__setitem__("base_main_sha", "0" * 40))
        self.assertFalse(ok)

    def test_tampered_tested_implementation_sha_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("tested_implementation_sha", "1" * 40)
        )
        self.assertFalse(ok)

    def test_tampered_pytest_requests_duration_v1_policy_hash_in_record_fails(self):
        def mutate(r):
            r["canonicalization_policies"]["pytest_requests_duration_v1"]["policy_sha256"] = "0" * 64

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("policy_sha256", message)

    def test_missing_canonicalization_policy_key_fails(self):
        def mutate(r):
            del r["canonicalization_policies"]["cargo_test"]

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("canonicalization_policies", message)

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
            lambda r: r.__setitem__("unexplained_raw_differences", ["repo-requests: unexplained line 42"])
        )
        self.assertFalse(ok)
        self.assertIn("unexplained_raw_differences", message)

    def test_token_counts_computed_true_fails(self):
        ok, message = self._verify_mutated_record(lambda r: r.__setitem__("token_counts_computed", True))
        self.assertFalse(ok)
        self.assertIn("token_counts_computed", message)

    def test_rtk_or_qodec_benchmark_arms_executed_true_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("rtk_or_qodec_benchmark_arms_executed", True)
        )
        self.assertFalse(ok)
        self.assertIn("rtk_or_qodec_benchmark_arms_executed", message)

    def test_nix_identity_builds_performed_true_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("nix_identity_builds_performed", True)
        )
        self.assertFalse(ok)
        self.assertIn("nix_identity_builds_performed", message)

    def test_n2d2_executed_true_fails(self):
        ok, message = self._verify_mutated_record(lambda r: r.__setitem__("n2d2_executed", True))
        self.assertFalse(ok)
        self.assertIn("n2d2_executed", message)

    def test_leaderboard_constructed_true_fails(self):
        ok, message = self._verify_mutated_record(lambda r: r.__setitem__("leaderboard_constructed", True))
        self.assertFalse(ok)
        self.assertIn("leaderboard_constructed", message)

    def test_physshell_007_modified_true_fails(self):
        ok, message = self._verify_mutated_record(lambda r: r.__setitem__("physshell_007_modified", True))
        self.assertFalse(ok)
        self.assertIn("physshell_007_modified", message)

    def test_rtk_nix_identity_closure_authorized_next_false_fails(self):
        ok, message = self._verify_mutated_record(
            lambda r: r.__setitem__("rtk_nix_identity_closure_authorized_next", False)
        )
        self.assertFalse(ok)
        self.assertIn("rtk_nix_identity_closure_authorized_next", message)

    def test_another_real_valid_ancestor_as_base_main_sha_fails(self):
        # 4e5691076ca400d27a45044de78f2a95bf46d70b is a REAL commit and IS a
        # real ancestor of implementation_sha -- internal ancestry alone
        # would accept it. Only the exact-constant check catches it.
        def mutate(r):
            r["base_main_sha"] = "4e5691076ca400d27a45044de78f2a95bf46d70b"

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("base_main_sha", message)

    def test_another_real_valid_ancestor_as_implementation_sha_fails(self):
        # The real base_main_sha value is itself a real, valid ancestor of
        # HEAD -- but it is not the required implementation_sha.
        def mutate(r):
            other_real_ancestor = "e7e6759298e7f5526a751bddac0cdafc3b6c28c3"
            r["implementation_sha"] = other_real_ancestor
            r["tested_implementation_sha"] = other_real_ancestor

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("implementation_sha", message)

    def test_synchronized_workflow_run_id_mutation_fails(self):
        # Both copies of the run ID are mutated together, so internal
        # cross-field consistency (record.workflow_run_id ==
        # workflow.run_id) alone would not catch this.
        def mutate(r):
            r["workflow_run_id"] = 1
            r["workflow"]["run_id"] = 1

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("workflow_run_id", message)

    def test_synchronized_trigger_sha_mutation_to_fabricated_sha_fails(self):
        # A syntactically valid but entirely fabricated 40-hex SHA -- not a
        # real commit in this repository at all. Both copies (top-level and
        # nested under workflow) are mutated together.
        def mutate(r):
            fabricated = "f" * 40
            r["execution_trigger_sha"] = fabricated
            r["workflow"]["head_sha"] = fabricated

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("not a valid commit", message)

    def test_trigger_sha_that_is_a_real_ancestor_of_head_fails(self):
        # base_main_sha IS a genuine, valid commit and IS an ancestor of
        # HEAD (and distinct from implementation_sha, so the earlier
        # "must differ from implementation_sha" check does not mask this
        # one) -- exactly the forbidden shape for a disposable trigger
        # commit, which must never be merged into the implementation
        # branch's own history.
        def mutate(r):
            real_ancestor_of_head = "e7e6759298e7f5526a751bddac0cdafc3b6c28c3"
            r["execution_trigger_sha"] = real_ancestor_of_head
            r["workflow"]["head_sha"] = real_ancestor_of_head

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("IS an ancestor", message)

    def test_removal_of_one_rederivation_case_fails(self):
        def mutate(r):
            del r["independent_rederivation_verification"]["repo-requests"]

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("independent_rederivation_verification", message)

    def test_rederivation_canonically_equal_false_fails(self):
        def mutate(r):
            r["independent_rederivation_verification"]["repo-requests"][
                "capture_a_and_b_canonicalize_to_identical_bytes"
            ] = False

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("repo-requests", message)

    def test_replacement_of_one_job_name_preserving_count_and_uniqueness_fails(self):
        # The renamed job stays unique among all job names (so the
        # uniqueness checks alone would pass) -- only the exact-name-set
        # check catches a case name that is simply wrong.
        def mutate(r):
            r["jobs"][0]["name"] = "pilot-repo-requests-capture-a-RENAMED"

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("job names", message)

    def test_replacement_of_one_artifact_name_preserving_count_and_uniqueness_fails(self):
        def mutate(r):
            r["artifacts"][0]["name"] = "n2d1b-pilot-repo-requests-capture-a-RENAMED"

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("artifact names", message)

    def test_incorrect_pull_request_number_fails(self):
        def mutate(r):
            r["pull_request"]["number"] = 999

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("pull_request.number", message)

    def test_missing_case_from_cases_map_fails(self):
        def mutate(r):
            del r["cases"]["repo-requests"]

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("cases", message)

    def test_case_canonical_bytes_equal_false_fails(self):
        def mutate(r):
            r["cases"]["repo-hyperfine"]["canonical_bytes_equal"] = False

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("canonical_bytes_equal", message)

    def test_case_canonical_capture_not_capture_a_fails(self):
        def mutate(r):
            r["cases"]["repo-moshi"]["canonical_capture"] = "capture_b"

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("canonical_capture", message)

    def test_case_final_sha256_diverges_from_by_case_id_map_fails(self):
        # Only the per-case field is mutated; canonical_benchmark_input_sha256_by_case_id
        # is left untouched, so the two must be cross-checked against each other, not
        # merely each independently well-formed.
        def mutate(r):
            r["cases"]["repo-pyflakes"]["canonical_benchmark_input_sha256_final"] = "1" * 64
            r["cases"]["repo-pyflakes"]["canonical_benchmark_input_sha256"]["capture_a"] = "1" * 64
            r["cases"]["repo-pyflakes"]["canonical_benchmark_input_sha256"]["capture_b"] = "1" * 64

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("canonical_benchmark_input_sha256_by_case_id", message)

    def test_canonical_benchmark_input_sha256_by_case_id_diverges_from_case_fails(self):
        def mutate(r):
            r["canonical_benchmark_input_sha256_by_case_id"]["repo-rustlings"] = "2" * 64

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("canonical_benchmark_input_sha256_by_case_id", message)

    def test_repo_requests_detailed_acceptance_exit_code_false_fails(self):
        def mutate(r):
            r["repo_requests_detailed_acceptance"]["exit_code_zero_both_captures"] = False

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("exit_code_zero_both_captures", message)

    def test_repo_requests_detailed_acceptance_replacement_count_not_one_fails(self):
        def mutate(r):
            r["repo_requests_detailed_acceptance"]["canonicalization_replacement_count"] = 2

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("canonicalization_replacement_count", message)

    def test_repo_requests_detailed_acceptance_raw_diff_count_not_one_fails(self):
        def mutate(r):
            r["repo_requests_detailed_acceptance"]["raw_ab_diff_line_count"] = 0

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("raw_ab_diff_line_count", message)

    def test_repo_requests_detailed_acceptance_timeout_sink_target_wrong_fails(self):
        def mutate(r):
            r["repo_requests_detailed_acceptance"]["timeout_sink_target"] = "10.0.0.1"

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("timeout_sink_target", message)

    def test_repo_requests_detailed_acceptance_timeout_sink_argv_wrong_fails(self):
        def mutate(r):
            r["repo_requests_detailed_acceptance"]["timeout_sink_probe_argv"] = ["python3", "wrong.py"]

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("timeout_sink_probe_argv", message)

    def test_repo_requests_detailed_acceptance_timeout_sink_verified_false_fails(self):
        def mutate(r):
            r["repo_requests_detailed_acceptance"]["timeout_sink_verified_both_captures"] = False

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("timeout_sink_verified_both_captures", message)

    def test_repo_requests_network_enforcement_approval_silently_merged_with_fixture_fails(self):
        # Setting the two distinct authorization identities to the SAME string
        # is exactly the forbidden "silently broaden the existing loopback-only
        # approval into this behavior" shape the user explicitly ruled out.
        def mutate(r):
            same = r["repo_requests_detailed_acceptance"]["network_enforcement_approval_identity"]
            r["repo_requests_detailed_acceptance"]["test_network_fixture_approval_identity"] = same
            r["timeout_sink_approval_identities"]["repo-requests"] = same

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("distinct authorizations", message)

    def test_repo_requests_detailed_acceptance_mtime_epoch_wrong_fails(self):
        def mutate(r):
            r["repo_requests_detailed_acceptance"]["source_mtime_materialization_fixed_timestamp_epoch_seconds"] = 0

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("source_mtime", message)

    def test_replacement_selection_wrong_replacement_case_id_fails(self):
        def mutate(r):
            r["replacement_selection"]["replacement_case_id"] = "repo-something-else"

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("replacement_case_id", message)

    def test_replacement_selection_record_sha256_mismatch_fails(self):
        def mutate(r):
            r["replacement_selection"]["record_sha256"] = "sha256:" + "0" * 64

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("record_sha256", message)

    def test_replacement_selection_not_verified_at_build_time_fails(self):
        def mutate(r):
            r["replacement_selection"]["verified_by_its_own_verifier_at_build_time"] = False

        ok, message = self._verify_mutated_record(mutate)
        self.assertFalse(ok)
        self.assertIn("verified_by_its_own_verifier_at_build_time", message)


class TestExternalFileMutationsAreCaught(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_tampered_cargo_test_policy_bytes_fail(self):
        original = CARGO_TEST_POLICY_PATH.read_text()
        tampered_body = json.loads(original)
        tampered_body["rules"][0]["anchored_regex"] = "^TAMPERED$"
        # Deliberately do NOT re-sign here -- an untouched policy file whose
        # own self-hash no longer matches its own content must be rejected
        # by load_and_verify_policy's own integrity check, independent of
        # this record's verifier.
        tampered_path = self.tmp_path / "cargo-test-capture-canonicalization-policy.json"
        tampered_path.write_text(json.dumps(tampered_body, indent=2, sort_keys=True) + "\n")

        import cargo_test_canonicalizer  # noqa: E402

        with self.assertRaises(cargo_test_canonicalizer.PolicyIntegrityError):
            cargo_test_canonicalizer.load_and_verify_policy(tampered_path)

    def test_tampered_trigger_patch_bytes_fail(self):
        original = TRIGGER_PATCH_PATH.read_bytes()
        tampered = original.replace(b"push:", b"pull_request:")
        self.assertNotEqual(tampered, original, "fixture patch did not contain expected 'push:' text")
        tampered_path = self.tmp_path / "stage2-full-matrix-trigger.patch"
        tampered_path.write_bytes(tampered)

        ok, message = verifier.verify(trigger_patch_path=tampered_path)
        self.assertFalse(ok)
        self.assertIn("sha256 mismatch", message)


if __name__ == "__main__":
    unittest.main()
