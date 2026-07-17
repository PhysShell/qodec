"""Unit tests for content_acceptance.py -- the fail-closed content-
acceptance gate added after real inspection of CI run #6 found all 18
"successful" captures were actually infrastructure/sandbox failures that
nothing had ever validated against.
"""
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import content_acceptance as ca  # noqa: E402

# Real stderr bytes captured from CI run #6 (see capture-content-audit-run6.json)
REAL_RUSTUP_FAILURE_STDERR = (
    b"sandboy: warning: Landlock only PARTIALLY enforced (kernel too old for some access rights)\n"
    b"error: rustup could not choose a version of cargo to run, because one wasn't specified explicitly, "
    b"and no default is configured.\n"
    b"help: run 'rustup default stable' to download the latest stable release of Rust and set it as your "
    b"default toolchain.\n"
    b"Command exited with non-zero status 1\n"
)
REAL_DEV_NULL_FAILURE_STDERR = (
    b"sandboy: warning: Landlock only PARTIALLY enforced (kernel too old for some access rights)\n"
    b"/usr/bin/mvn: 61: cannot create /dev/null: Permission denied\n"
    b"/usr/bin/mvn: 1: cd: can't cd to /usr/bin//etc/alternatives/..\n"
    b"Command exited with non-zero status 1\n"
)
REAL_VENV_FAILURE_STDERR = (
    b"sandboy: warning: Landlock only PARTIALLY enforced (kernel too old for some access rights)\n"
    b"Fatal Python error: init_import_site: Failed to import the site module\n"
    b"PermissionError: [Errno 13] Permission denied: '/home/runner/work/_temp/venv-repo-pyflakes/pyvenv.cfg'\n"
)
REAL_NU1301_STDOUT = (
    b"  Determining projects to restore...\n"
    b"error NU1301: Unable to load the service index for source https://api.nuget.org/v3/index.json.\n"
)
HARMLESS_LANDLOCK_WARNING_STDERR = b"sandboy: warning: Landlock only PARTIALLY enforced (kernel too old for some access rights)\n"

# Real stdout/stderr shape from the Stage 2 run wrongly accepted as final
# evidence (29544801640, since rejected) -- repo-requests' 205 pytest
# ERRORs from pytest-httpbin's own local WSGI server hitting a
# PermissionError binding its loopback socket under (at that time, blanket)
# network denial.
REAL_SOCKET_BIND_PERMISSION_DENIED_STDERR = (
    b"        self.socket.bind(self.server_address)\n"
    b'        ~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^\n'
    b"      File \"/usr/lib/python3.12/socketserver.py\", line 473, in server_bind\n"
    b"        self.socket.bind(self.server_address)\n"
    b"E       PermissionError: [Errno 13] Permission denied\n"
    b"/usr/lib/python3.12/socketserver.py:473: PermissionError\n"
)


class TestDetectInfrastructureFailure(unittest.TestCase):
    def test_rustup_no_default_toolchain_detected(self):
        self.assertEqual(ca.detect_infrastructure_failure(b"", REAL_RUSTUP_FAILURE_STDERR), "rustup-no-default-toolchain")

    def test_dev_null_permission_denied_detected(self):
        self.assertEqual(ca.detect_infrastructure_failure(b"", REAL_DEV_NULL_FAILURE_STDERR), "dev-null-permission-denied")

    def test_python_venv_permission_denied_detected(self):
        self.assertEqual(ca.detect_infrastructure_failure(b"", REAL_VENV_FAILURE_STDERR), "python-venv-permission-denied")

    def test_nuget_nu1301_detected(self):
        self.assertEqual(ca.detect_infrastructure_failure(REAL_NU1301_STDOUT, b""), "nuget-restore-failure-nu1301")

    def test_harmless_landlock_warning_alone_is_not_a_failure(self):
        # The partial-enforcement warning line is expected on every real run
        # (including eventually-valid ones) -- it must never itself trigger
        # a false-positive rejection.
        self.assertIsNone(ca.detect_infrastructure_failure(b"real test output here", HARMLESS_LANDLOCK_WARNING_STDERR))

    def test_clean_output_has_no_detected_failure(self):
        self.assertIsNone(ca.detect_infrastructure_failure(b"test result: ok. 3 passed; 0 failed\n", b""))


class TestTerminationAllowed(unittest.TestCase):
    def test_zero_is_allowed(self):
        self.assertTrue(ca.termination_allowed(0))

    def test_pytest_style_nonzero_is_allowed(self):
        self.assertTrue(ca.termination_allowed(1))

    def test_command_not_found_style_codes_rejected(self):
        self.assertFalse(ca.termination_allowed(126))
        self.assertFalse(ca.termination_allowed(127))


class TestCaseSemanticMarkers(unittest.TestCase):
    def test_cargo_test_marker(self):
        ok, _ = ca.CASE_SEMANTIC_VALIDATORS["repo-rustlings"]("running 3 tests\ntest result: ok. 3 passed; 0 failed\n")
        self.assertTrue(ok)
        ok, _ = ca.CASE_SEMANTIC_VALIDATORS["repo-rustlings"]("")
        self.assertFalse(ok)

    def test_hyperfine_marker(self):
        ok, _ = ca.CASE_SEMANTIC_VALIDATORS["repo-hyperfine"]("hyperfine 1.19.0\n")
        self.assertTrue(ok)
        ok, _ = ca.CASE_SEMANTIC_VALIDATORS["repo-hyperfine"]("")
        self.assertFalse(ok)

    def test_maven_marker(self):
        ok, _ = ca.CASE_SEMANTIC_VALIDATORS["repo-docker-java-parser"]("[INFO] BUILD SUCCESS\n")
        self.assertTrue(ok)
        ok, _ = ca.CASE_SEMANTIC_VALIDATORS["repo-docker-java-parser"]("Tests run: 42, Failures: 0\n")
        self.assertTrue(ok)

    def test_dotnet_test_marker(self):
        ok, _ = ca.CASE_SEMANTIC_VALIDATORS["repo-kubeops-generator"]("Passed!  - Failed: 0, Passed: 61, Total: 61\n")
        self.assertTrue(ok)

    def test_pytest_marker_accepts_genuinely_zero_failure_summary(self):
        ok, _ = ca.CASE_SEMANTIC_VALIDATORS["repo-requests"]("========== 614 passed in 12.34s ==========\n")
        self.assertTrue(ok)

    def test_pytest_marker_rejects_any_failed_count(self):
        # D1b remediation (2026-07-17): a summary containing the literal
        # word "failed" or "error" must never be accepted merely because
        # pytest reached its final report -- only a ZERO failed/error count
        # is a genuine success.
        ok, desc = ca.CASE_SEMANTIC_VALIDATORS["repo-requests"]("========== 614 passed, 5 failed in 12.34s ==========\n")
        self.assertFalse(ok)
        self.assertIn("5 failed", desc)

    def test_pytest_marker_rejects_real_stage2_run5_broken_summary(self):
        # The exact real summary line from run 29544801640 (since rejected
        # as final evidence): 30 failed, 205 errors, all from pytest-
        # httpbin's own local WSGI server hitting a sandbox-confinement
        # socket.bind PermissionError under network denial.
        ok, desc = ca.CASE_SEMANTIC_VALIDATORS["repo-requests"](
            "= 30 failed, 384 passed, 15 skipped, 1 xfailed, 32 warnings, 205 errors in 14.43s =\n"
        )
        self.assertFalse(ok)
        self.assertIn("30 failed", desc)
        self.assertIn("205 error", desc)

    def test_pytest_marker_rejects_passed_with_one_error(self):
        ok, desc = ca.CASE_SEMANTIC_VALIDATORS["repo-requests"]("========== 10 passed, 1 error in 1.0s ==========\n")
        self.assertFalse(ok)
        self.assertIn("1 error", desc)

    def test_pytest_marker_rejects_collection_error_with_no_pass_fail_words(self):
        ok, desc = ca.CASE_SEMANTIC_VALIDATORS["repo-requests"](
            "!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!\n"
            "========== 1 error in 0.05s ==========\n"
        )
        self.assertFalse(ok)
        self.assertIn("1 error", desc)

    def test_pytest_marker_rejects_when_no_final_summary_line_present(self):
        # A catastrophic import/collection failure that never reaches
        # pytest's own final report line at all.
        ok, desc = ca.CASE_SEMANTIC_VALIDATORS["repo-requests"]("ImportError: cannot import name 'foo' from 'bar'\n")
        self.assertFalse(ok)
        self.assertIn("not found", desc)

    def test_gradle_marker(self):
        ok, _ = ca.CASE_SEMANTIC_VALIDATORS["repo-spotless"]("BUILD SUCCESSFUL in 3s\n")
        self.assertTrue(ok)
        ok, _ = ca.CASE_SEMANTIC_VALIDATORS["repo-moshi"]("BUILD FAILED in 3s\n")
        self.assertTrue(ok)

    def test_pyflakes_marker_requires_nonempty(self):
        ok, _ = ca.CASE_SEMANTIC_VALIDATORS["repo-pyflakes"]("foo.py:1:1 'os' imported but unused\n")
        self.assertTrue(ok)
        ok, _ = ca.CASE_SEMANTIC_VALIDATORS["repo-pyflakes"]("")
        self.assertFalse(ok)


class TestValidateCaptureContent(unittest.TestCase):
    def test_real_rustup_failure_is_rejected(self):
        report = ca.validate_capture_content(
            case_id="repo-hyperfine", canonical_stream_bytes=b"",
            raw_stdout=b"", raw_stderr=REAL_RUSTUP_FAILURE_STDERR, exit_code=1,
        )
        self.assertFalse(report["accepted"])
        self.assertEqual(report["infrastructure_failure_detected"], "rustup-no-default-toolchain")
        self.assertFalse(report["checks"]["canonical_is_nonempty"])

    def test_real_dotnet_nu1301_is_rejected_even_though_nonempty(self):
        # This is exactly the repo-kubeops-generator finding: real, nonempty
        # stdout that is NOT genuine workload output.
        report = ca.validate_capture_content(
            case_id="repo-kubeops-generator", canonical_stream_bytes=REAL_NU1301_STDOUT,
            raw_stdout=REAL_NU1301_STDOUT, raw_stderr=b"", exit_code=1,
        )
        self.assertFalse(report["accepted"])
        self.assertEqual(report["infrastructure_failure_detected"], "nuget-restore-failure-nu1301")
        self.assertTrue(report["checks"]["canonical_is_nonempty"])  # nonempty, but still rejected

    def test_genuinely_valid_capture_is_accepted(self):
        stdout = b"running 3 tests\ntest result: ok. 3 passed; 0 failed; 0 ignored\n"
        report = ca.validate_capture_content(
            case_id="repo-rustlings", canonical_stream_bytes=stdout,
            raw_stdout=stdout, raw_stderr=b"", exit_code=0,
        )
        self.assertTrue(report["accepted"])
        self.assertEqual(report["rejection_reasons"], [])

    def test_pytest_test_failures_are_rejected_not_permitted(self):
        # D1b remediation (2026-07-17): this test used to assert ACCEPTANCE
        # of a real-failure summary -- exactly the defect the user
        # identified in the Stage 2 run wrongly accepted as final evidence
        # (29544801640: 30 failed, 205 errors, silently accepted). A
        # completion with real test FAILURES and a nonzero exit code must
        # now be REJECTED: repo-requests requires a genuinely successful,
        # zero-failure, exit-0 run.
        stdout = b"===== 614 passed, 5 failed, 15 skipped in 42.1s =====\n"
        report = ca.validate_capture_content(
            case_id="repo-requests", canonical_stream_bytes=stdout,
            raw_stdout=stdout, raw_stderr=b"", exit_code=1,
        )
        self.assertFalse(report["accepted"])
        self.assertFalse(report["checks"]["termination_allowed"])
        self.assertFalse(report["checks"]["case_semantic_marker_found"])

    def test_pytest_genuinely_successful_run_is_accepted(self):
        stdout = b"===== 619 passed, 15 skipped in 42.1s =====\n"
        report = ca.validate_capture_content(
            case_id="repo-requests", canonical_stream_bytes=stdout,
            raw_stdout=stdout, raw_stderr=b"", exit_code=0,
        )
        self.assertTrue(report["accepted"])
        self.assertEqual(report["rejection_reasons"], [])
        self.assertEqual(report["content_classification"], "genuine-workload-output")

    def test_pytest_nonzero_exit_is_rejected_even_with_a_zero_failure_summary(self):
        # A pathological case (e.g. a plugin crash after the summary
        # printed, or a warnings-as-errors nonzero exit) -- repo-requests
        # requires exit code 0 unconditionally, not merely inferred from
        # the summary's own failed/error counts.
        stdout = b"===== 619 passed, 15 skipped in 42.1s =====\n"
        report = ca.validate_capture_content(
            case_id="repo-requests", canonical_stream_bytes=stdout,
            raw_stdout=stdout, raw_stderr=b"", exit_code=2,
        )
        self.assertFalse(report["accepted"])
        self.assertFalse(report["checks"]["termination_allowed"])
        self.assertIn("exit code 2 != 0", report["rejection_reasons"][0])

    def test_real_stage2_run5_broken_capture_is_rejected_end_to_end(self):
        # The exact real raw.stdout shape from run 29544801640's accepted
        # (wrongly) repo-requests capture-a: exit_code=1, 30 failed, 205
        # errors, all from pytest-httpbin's own socket.bind PermissionError
        # under network denial.
        stdout = (
            b"= 30 failed, 384 passed, 15 skipped, 1 xfailed, 32 warnings, 205 errors in 14.43s =\n"
        )
        report = ca.validate_capture_content(
            case_id="repo-requests", canonical_stream_bytes=stdout,
            raw_stdout=stdout, raw_stderr=REAL_SOCKET_BIND_PERMISSION_DENIED_STDERR, exit_code=1,
        )
        self.assertFalse(report["accepted"])
        self.assertEqual(report["infrastructure_failure_detected"], "socket-bind-permission-denied")
        self.assertFalse(report["checks"]["termination_allowed"])
        self.assertFalse(report["checks"]["case_semantic_marker_found"])
        self.assertEqual(report["content_classification"], "rejected")

    def test_real_stage2_run6_timeout_and_mtime_failure_is_rejected_end_to_end(self):
        # D1b remediation round 2 (2026-07-17): the exact real raw.stdout
        # final-summary shape from run 29547420247's repo-requests
        # capture-a, AFTER the run-5 (29544801640) remediation above was
        # applied -- the fixed content gate correctly rejected it too. Two
        # NEW, genuine execution-environment incompatibilities caused this
        # (four TestTimeout tests hitting an immediate ENETUNREACH instead
        # of a socket.timeout against 10.255.255.1; test_zipped_paths_
        # extracted hitting Python zipfile's 1980 timestamp floor against
        # the source tar's epoch-0 mtimes) -- neither is an infrastructure-
        # failure-signature match (no socket.bind PermissionError here), so
        # this must be rejected purely on the summary's own failed count,
        # exactly like a genuine upstream test regression would be.
        stdout = (
            b"= 5 failed, 614 passed, 15 skipped, 1 xfailed, 18 warnings in 78.62s =\n"
        )
        report = ca.validate_capture_content(
            case_id="repo-requests", canonical_stream_bytes=stdout,
            raw_stdout=stdout, raw_stderr=b"", exit_code=1,
        )
        self.assertFalse(report["accepted"])
        self.assertFalse(report["checks"]["termination_allowed"])
        self.assertFalse(report["checks"]["case_semantic_marker_found"])
        self.assertEqual(report["content_classification"], "rejected")
        self.assertIn("exit code 1 != 0", report["rejection_reasons"][0])

    def test_pytest_passed_with_one_error_is_rejected_end_to_end(self):
        stdout = b"===== 10 passed, 1 error in 1.0s =====\n"
        report = ca.validate_capture_content(
            case_id="repo-requests", canonical_stream_bytes=stdout,
            raw_stdout=stdout, raw_stderr=b"", exit_code=1,
        )
        self.assertFalse(report["accepted"])

    def test_pytest_collection_error_is_rejected_end_to_end(self):
        stdout = (
            b"!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!\n"
            b"===== 1 error in 0.05s =====\n"
        )
        report = ca.validate_capture_content(
            case_id="repo-requests", canonical_stream_bytes=stdout,
            raw_stdout=stdout, raw_stderr=b"", exit_code=2,
        )
        self.assertFalse(report["accepted"])

    def test_pytest_import_error_with_no_final_summary_is_rejected_end_to_end(self):
        stdout = b"ImportError: cannot import name 'foo' from 'bar'\n"
        report = ca.validate_capture_content(
            case_id="repo-requests", canonical_stream_bytes=stdout,
            raw_stdout=stdout, raw_stderr=b"", exit_code=1,
        )
        self.assertFalse(report["accepted"])
        self.assertFalse(report["checks"]["case_semantic_marker_found"])

    def test_genuinely_empty_pyflakes_after_clean_run_is_rejected_not_synthesized(self):
        # Without the authorized erratum resolution signal (e.g. a caller
        # that never passes execution_argv_resolution), a genuinely empty
        # pyflakes result still fails closed -- the bypass below requires
        # ALL of its conditions, not just emptiness+exit-0.
        report = ca.validate_capture_content(
            case_id="repo-pyflakes", canonical_stream_bytes=b"",
            raw_stdout=b"", raw_stderr=b"", exit_code=0,
        )
        self.assertFalse(report["accepted"])
        self.assertIn("canonical stream is empty", report["rejection_reasons"])

    def test_invalid_utf8_canonical_stream_is_rejected(self):
        report = ca.validate_capture_content(
            case_id="repo-hyperfine", canonical_stream_bytes=b"hyperfine \xff\xfe garbage",
            raw_stdout=b"hyperfine \xff\xfe garbage", raw_stderr=b"", exit_code=0,
        )
        self.assertFalse(report["accepted"])
        self.assertFalse(report["checks"]["canonical_is_valid_utf8"])

    def test_abnormal_exit_code_is_rejected(self):
        report = ca.validate_capture_content(
            case_id="repo-hyperfine", canonical_stream_bytes=b"hyperfine 1.19.0\n",
            raw_stdout=b"hyperfine 1.19.0\n", raw_stderr=b"", exit_code=127,
        )
        self.assertFalse(report["accepted"])
        self.assertFalse(report["checks"]["termination_allowed"])

    def test_report_written_even_when_rejected_has_all_expected_keys(self):
        report = ca.validate_capture_content(
            case_id="repo-hyperfine", canonical_stream_bytes=b"",
            raw_stdout=b"", raw_stderr=REAL_RUSTUP_FAILURE_STDERR, exit_code=1,
        )
        for key in ("report_type", "case_id", "exit_code", "checks", "infrastructure_failure_detected",
                    "case_semantic_marker_description", "accepted", "rejection_reasons",
                    "content_classification", "empty_output_authorized", "approving_decision_identity"):
            self.assertIn(key, report)


class TestAuthorizedPyflakesEmptyOutput(unittest.TestCase):
    """D1b decision (2026-07-15): repo-pyflakes, and ONLY repo-pyflakes, may
    pass with a genuinely empty canonical stream when every one of the
    authorized conditions holds. Every other case keeps the unconditional
    nonempty-canonical-stream requirement."""

    def test_empty_pyflakes_exit_0_clean_stderr_authorized_erratum_passes(self):
        report = ca.validate_capture_content(
            case_id="repo-pyflakes", canonical_stream_bytes=b"",
            raw_stdout=b"", raw_stderr=HARMLESS_LANDLOCK_WARNING_STDERR, exit_code=0,
            execution_argv_resolution="authorized-n2d1b-erratum",
        )
        self.assertTrue(report["accepted"])
        self.assertEqual(report["rejection_reasons"], [])
        self.assertEqual(report["content_classification"], "successful-empty-domain-result")
        self.assertTrue(report["empty_output_authorized"])
        self.assertEqual(report["approving_decision_identity"], ca.PYFLAKES_EMPTY_OUTPUT_AUTHORIZATION_ID)
        self.assertFalse(report["checks"]["canonical_is_nonempty"])

    def test_empty_pyflakes_with_nonzero_exit_fails(self):
        report = ca.validate_capture_content(
            case_id="repo-pyflakes", canonical_stream_bytes=b"",
            raw_stdout=b"", raw_stderr=HARMLESS_LANDLOCK_WARNING_STDERR, exit_code=1,
            execution_argv_resolution="authorized-n2d1b-erratum",
        )
        self.assertFalse(report["accepted"])
        self.assertFalse(report["empty_output_authorized"])

    def test_empty_pyflakes_with_infrastructure_signature_fails(self):
        report = ca.validate_capture_content(
            case_id="repo-pyflakes", canonical_stream_bytes=b"",
            raw_stdout=b"", raw_stderr=REAL_VENV_FAILURE_STDERR, exit_code=0,
            execution_argv_resolution="authorized-n2d1b-erratum",
        )
        self.assertFalse(report["accepted"])
        self.assertEqual(report["infrastructure_failure_detected"], "python-venv-permission-denied")
        self.assertFalse(report["empty_output_authorized"])

    def test_empty_pyflakes_without_the_authorized_erratum_resolution_fails(self):
        # Exit 0 and clean stderr alone are not sufficient -- the effective
        # argv must specifically be the authorized pyflakes erratum.
        report = ca.validate_capture_content(
            case_id="repo-pyflakes", canonical_stream_bytes=b"",
            raw_stdout=b"", raw_stderr=HARMLESS_LANDLOCK_WARNING_STDERR, exit_code=0,
            execution_argv_resolution="frozen",
        )
        self.assertFalse(report["accepted"])
        self.assertFalse(report["empty_output_authorized"])

    def test_empty_pyflakes_with_traceback_in_stderr_fails(self):
        stderr = HARMLESS_LANDLOCK_WARNING_STDERR + b"Traceback (most recent call last):\n  File \"x.py\"\nValueError\n"
        report = ca.validate_capture_content(
            case_id="repo-pyflakes", canonical_stream_bytes=b"",
            raw_stdout=b"", raw_stderr=stderr, exit_code=0,
            execution_argv_resolution="authorized-n2d1b-erratum",
        )
        self.assertFalse(report["accepted"])
        self.assertFalse(report["empty_output_authorized"])

    def test_empty_output_for_any_other_case_still_fails(self):
        # The exact same otherwise-qualifying conditions, for a DIFFERENT
        # case_id, must never trigger the bypass -- it is repo-pyflakes-only.
        report = ca.validate_capture_content(
            case_id="repo-hyperfine", canonical_stream_bytes=b"",
            raw_stdout=b"", raw_stderr=HARMLESS_LANDLOCK_WARNING_STDERR, exit_code=0,
            execution_argv_resolution="authorized-n2d1b-erratum",
        )
        self.assertFalse(report["accepted"])
        self.assertFalse(report["empty_output_authorized"])
        self.assertIsNone(report["approving_decision_identity"])

    def test_nonempty_pyflakes_violations_remain_accepted_when_semantically_valid(self):
        stdout = b"foo.py:1:1 'os' imported but unused\n"
        report = ca.validate_capture_content(
            case_id="repo-pyflakes", canonical_stream_bytes=stdout,
            raw_stdout=stdout, raw_stderr=HARMLESS_LANDLOCK_WARNING_STDERR, exit_code=1,
            execution_argv_resolution="authorized-n2d1b-erratum",
        )
        self.assertTrue(report["accepted"])
        self.assertFalse(report["empty_output_authorized"])
        self.assertEqual(report["content_classification"], "genuine-workload-output")

    def test_empty_string_sha256_is_the_well_known_constant(self):
        # Documents the invariant referenced by the D1b authorization: a
        # genuinely empty canonical stream always hashes to the same
        # well-known SHA-256 of the empty byte string, for both captures.
        import hashlib
        self.assertEqual(
            hashlib.sha256(b"").hexdigest(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )


if __name__ == "__main__":
    unittest.main()
