"""Unit tests for timeout_sink_probe.py -- the repo-requests-only
timeout-sink network fixture live-verification gate (D1b remediation round
2, 2026-07-17). Mocks capture_build.run_real_build so these tests never
require a real kernel netns/veth environment (only real CI runners have
that); they test the aggregation/decision logic against canned, realistic
probe output shapes, including the real run 29547420247 failure shape this
fixture exists to fix.
"""
import json
import sys
import unittest
import unittest.mock as mock
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import timeout_sink_probe as tsp  # noqa: E402


def _fake_run_real_build_factory(sink_stdout: bytes, sink_exit: int,
                                  negative_stdout: bytes, negative_exit: int,
                                  positive_stdout: bytes, positive_exit: int):
    def _fake(sandboy_bin, policy_path, cwd, argv, env):
        # timeout_sink_target_probe.py is invoked with the sink target
        # appended as an extra argv element (argv[-1] is the target IP, not
        # the script path) -- check membership across the whole argv, not
        # just the last element.
        if any("timeout_sink_target_probe.py" in a for a in argv):
            return {"argv": argv, "exit_code": sink_exit, "raw_stdout": sink_stdout, "raw_stderr": b""}
        script = argv[-1]
        if "network_probe.py" in script:
            return {"argv": argv, "exit_code": negative_exit, "raw_stdout": negative_stdout, "raw_stderr": b""}
        return {"argv": argv, "exit_code": positive_exit, "raw_stdout": positive_stdout, "raw_stderr": b""}
    return _fake


REAL_SINK_GENUINE_TIMEOUT = json.dumps({
    "result": "TIMEOUT", "target": "10.255.255.1", "elapsed_s": 0.201, "elapsed_within_bounds": True,
}).encode()

# The real failure this fixture exists to fix -- run 29547420247's actual
# repo-requests capture hit exactly this: an immediate synchronous errno,
# never a timeout, because the isolated netns had no route at all.
REAL_SINK_SYNCHRONOUS_ERROR = json.dumps({
    "result": "SYNCHRONOUS_ERROR", "target": "10.255.255.1", "elapsed_s": 0.00004,
    "errno": 101, "error": "[Errno 101] Network is unreachable",
}).encode()

REAL_NEGATIVE_ALL_BLOCKED = json.dumps({
    "probe_results": [
        {"host": "1.1.1.1", "port": 443, "kind": "tcp", "result": "UNREACHABLE"},
        {"host": "8.8.8.8", "port": 53, "kind": "udp", "result": "UNREACHABLE"},
    ]
}).encode()

REAL_NEGATIVE_ONE_REACHABLE = json.dumps({
    "probe_results": [{"host": "1.1.1.1", "port": 443, "kind": "tcp", "result": "REACHABLE"}]
}).encode()

REAL_POSITIVE_ALLOWED = json.dumps({"result": "ALLOWED", "bound_port": 54321, "echoed_correctly": True}).encode()
REAL_POSITIVE_DENIED = json.dumps({"result": "DENIED", "errno": 13, "error": "[Errno 13] Permission denied"}).encode()


class TestRunTimeoutSinkChecks(unittest.TestCase):
    def _run(self, sink_stdout, sink_exit, negative_stdout, negative_exit, positive_stdout, positive_exit,
              case_id="repo-requests"):
        fake = _fake_run_real_build_factory(sink_stdout, sink_exit, negative_stdout, negative_exit,
                                             positive_stdout, positive_exit)
        with mock.patch.object(tsp.capture_build, "run_real_build", side_effect=fake):
            return tsp.run_timeout_sink_checks(
                case_id=case_id, sink_target="10.255.255.1", test_network_fixture="repo-requests-timeout-sink-v1",
                sandboy_bin=Path("/nonexistent/sandboy"), policy_path=Path("/nonexistent/policy.toml"),
                cwd=Path("/nonexistent/cwd"), env={"N2D1B_TIMEOUT_SINK_TARGET": "10.255.255.1"},
            )

    def test_genuine_timeout_and_everything_else_blocked_verifies_the_fixture(self):
        report = self._run(REAL_SINK_GENUINE_TIMEOUT, 0, REAL_NEGATIVE_ALL_BLOCKED, 0, REAL_POSITIVE_ALLOWED, 0)
        self.assertTrue(report["sink_target_confirmed_genuine_timeout"])
        self.assertTrue(report["other_external_connectivity_confirmed_blocked"])
        self.assertTrue(report["loopback_bind_connect_confirmed_allowed"])
        self.assertTrue(report["timeout_sink_verified"])

    def test_synchronous_error_instead_of_timeout_fails_verification(self):
        # This is exactly what a blackhole/unreachable/prohibit route type
        # (or simply no route at all, as in run 29547420247) would produce
        # -- the fixture must reject it, not just require SOME response.
        report = self._run(REAL_SINK_SYNCHRONOUS_ERROR, 1, REAL_NEGATIVE_ALL_BLOCKED, 0, REAL_POSITIVE_ALLOWED, 0)
        self.assertFalse(report["sink_target_confirmed_genuine_timeout"])
        self.assertFalse(report["timeout_sink_verified"])

    def test_a_reachable_other_target_fails_verification_even_if_sink_is_correct(self):
        # The fixture must not permit arbitrary RFC1918/external
        # connectivity -- only the one authorized sink target may behave
        # differently from full denial.
        report = self._run(REAL_SINK_GENUINE_TIMEOUT, 0, REAL_NEGATIVE_ONE_REACHABLE, 1, REAL_POSITIVE_ALLOWED, 0)
        self.assertFalse(report["other_external_connectivity_confirmed_blocked"])
        self.assertFalse(report["timeout_sink_verified"])

    def test_a_denied_loopback_bind_fails_verification_even_if_sink_is_correct(self):
        report = self._run(REAL_SINK_GENUINE_TIMEOUT, 0, REAL_NEGATIVE_ALL_BLOCKED, 0, REAL_POSITIVE_DENIED, 1)
        self.assertFalse(report["loopback_bind_connect_confirmed_allowed"])
        self.assertFalse(report["timeout_sink_verified"])

    def test_report_type_and_fixture_name_fields_present(self):
        report = self._run(REAL_SINK_GENUINE_TIMEOUT, 0, REAL_NEGATIVE_ALL_BLOCKED, 0, REAL_POSITIVE_ALLOWED, 0)
        self.assertEqual(report["report_type"], "n2d1b-timeout-sink-probe-v1")
        self.assertEqual(report["test_network_fixture"], "repo-requests-timeout-sink-v1")
        self.assertEqual(report["sink_target"], "10.255.255.1")

    def test_authorized_case_id_recorded_in_report(self):
        report = self._run(REAL_SINK_GENUINE_TIMEOUT, 0, REAL_NEGATIVE_ALL_BLOCKED, 0, REAL_POSITIVE_ALLOWED, 0,
                            case_id="repo-requests")
        self.assertEqual(report["authorized_case_id"], "repo-requests")

    def test_report_records_all_three_raw_probe_reports_with_hashes(self):
        import hashlib
        report = self._run(REAL_SINK_GENUINE_TIMEOUT, 0, REAL_NEGATIVE_ALL_BLOCKED, 0, REAL_POSITIVE_ALLOWED, 0)
        self.assertEqual(
            report["sink_target_probe"]["raw_stdout_sha256"], hashlib.sha256(REAL_SINK_GENUINE_TIMEOUT).hexdigest(),
        )
        self.assertEqual(
            report["other_external_connectivity_probe"]["raw_stdout_sha256"],
            hashlib.sha256(REAL_NEGATIVE_ALL_BLOCKED).hexdigest(),
        )
        self.assertEqual(
            report["loopback_bind_connect_probe"]["raw_stdout_sha256"],
            hashlib.sha256(REAL_POSITIVE_ALLOWED).hexdigest(),
        )

    def test_sink_target_is_passed_as_argv_not_only_env(self):
        # Real CI evidence (run 29548972173): Sandboy's own env_clear() +
        # env_allow confinement strips N2D1B_TIMEOUT_SINK_TARGET before
        # exec'ing the confined probe script, even though the OUTER sudo/
        # unshare wrapper correctly preserves it for its own veth-pair route
        # setup. argv is not subject to that allowlist -- the sink probe's
        # argv must carry the target explicitly, not rely on env alone.
        report = self._run(REAL_SINK_GENUINE_TIMEOUT, 0, REAL_NEGATIVE_ALL_BLOCKED, 0, REAL_POSITIVE_ALLOWED, 0)
        self.assertIn("10.255.255.1", report["sink_target_probe"]["argv"])


if __name__ == "__main__":
    unittest.main()
