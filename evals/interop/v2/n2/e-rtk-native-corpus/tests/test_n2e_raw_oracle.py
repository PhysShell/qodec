"""Strict target-aware RAW test oracle: only the declared target failure qualifies
a buggy case (item 2). A package/compile/panic failure or an unrelated failing test
must not qualify; a failed count without the target ID must not qualify."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import n2e_oracles as ora  # noqa: E402

CADDY = {"command_family": "go", "command_subfamily": "test", "snapshot_variant": "buggy",
         "target_test_ids": ["TestUnsyncedConfigAccess"]}


def verdict(out: bytes, exit_code: int) -> bool:
    return ora.raw_outcome(CADDY, out, exit_code)["verdict"]


class TestStrictRawOracle(unittest.TestCase):
    def test_target_failure_qualifies(self):
        self.assertTrue(verdict(b"=== RUN   TestUnsyncedConfigAccess\n"
                                b"--- FAIL: TestUnsyncedConfigAccess (0.01s)\nFAIL\n", 1))

    def test_unrelated_failure_does_not_qualify(self):
        self.assertFalse(verdict(b"--- FAIL: TestSomethingElse (0.01s)\nFAIL\n", 1))

    def test_altered_subtest_identity_is_observable(self):
        self.assertFalse(verdict(b"--- FAIL: TestUnsyncedConfigAccessX (0.01s)\nFAIL\n", 1))

    def test_panic_before_discovery_does_not_qualify(self):
        # framework never reached a test summary -> not qualified
        self.assertFalse(verdict(b"panic: runtime error: invalid memory address\n", 2))

    def test_package_setup_failure_does_not_qualify(self):
        self.assertFalse(verdict(b"# github.com/caddyserver/caddy/v2\n./admin.go:1:1: syntax error\n"
                                 b"FAIL\tgithub.com/caddyserver/caddy/v2 [build failed]\n", 2))

    def test_failed_without_target_id_does_not_qualify(self):
        # a cargo-style summary with a failed count but NO named failing id
        out = b"test result: FAILED. 0 passed; 1 failed; 0 ignored\n"
        self.assertFalse(verdict(out, 101))

    def test_exit_zero_does_not_qualify_a_buggy_case(self):
        self.assertFalse(verdict(b"--- PASS: TestUnsyncedConfigAccess (0.01s)\nok\n", 0))

    def test_target_name_only_in_argv_echo_does_not_qualify(self):
        # the target appears only as a `-run` selector echo, never as a FAIL line; an
        # UNRELATED test is what actually failed -> the buggy target is not qualified.
        out = (b"=== RUN   go test -run TestUnsyncedConfigAccess\n"
               b"--- FAIL: TestSomethingElse (0.01s)\nFAIL\n")
        self.assertFalse(verdict(out, 1))

    def test_target_name_only_in_tee_sidecar_line_does_not_qualify(self):
        # the identity is present only inside an unmeasured tee-sidecar reference line,
        # not as a parsed failing id -> must NOT qualify (measured stream is the artifact).
        out = (b"--- FAIL: TestSomethingElse (0.00s)\n"
               b"[full output: /tmp/n2e/rtk/tee/1737_caddy.log :: TestUnsyncedConfigAccess]\nFAIL\n")
        self.assertFalse(verdict(out, 1))


if __name__ == "__main__":
    unittest.main()
