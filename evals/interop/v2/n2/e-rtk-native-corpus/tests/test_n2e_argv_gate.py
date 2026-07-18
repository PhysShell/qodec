"""Deterministic RTK/RAW argv-gate tests (CURRENT correction 1).

The prior gate compared argv[1:] == CONTRACT[1:], silently dropping the leading `cargo`
element -- a run could inject `+1.81.0` after `cargo`, or drop `cargo` entirely, and still
pass. Both the probe producer (probe.argv_equals_contract / probe.expected_argv) and the
independent verifier (verify._argv_ok) now compare the FULL argv:

  RAW: argv == ["cargo","test","backslash","--no-fail-fast"]
  RTK: argv == [rtk_bin, "cargo","test","backslash","--no-fail-fast"]

These tests pin: exact RAW passes; exact RTK passes; missing `cargo` fails; injected
`+1.81.0` fails; extra flags fail; reordered flags fail -- for BOTH the producer and the
independent verifier, so a run reaching RTK_DIALECT_UNPROVEN with a malformed argv cannot
survive the verifier gate."""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import probe_coreutils_diagnostic as probe  # noqa: E402
import verify_coreutils_diagnostic as verify  # noqa: E402

RTK_BIN = "/nix/store/deadbeef-rtk/bin/rtk"
RAW_OK = ["cargo", "test", "backslash", "--no-fail-fast"]
RTK_OK = [RTK_BIN, "cargo", "test", "backslash", "--no-fail-fast"]


class TestProbeAndVerifierAgree(unittest.TestCase):
    """The producer and verifier gates must be byte-identical on the exact same contract."""

    def test_contract_constant_shared(self):
        self.assertEqual(probe.CONTRACT_RAW_ARGV, verify.CONTRACT_RAW_ARGV)
        self.assertEqual(probe.CONTRACT_RAW_ARGV, RAW_OK)

    def _both(self, argv, is_rtk):
        p = probe.argv_equals_contract(argv, is_rtk, RTK_BIN)
        v = verify._argv_ok(argv, is_rtk, RTK_BIN)
        self.assertEqual(p, v, f"producer/verifier disagree on argv={argv!r} is_rtk={is_rtk}")
        return p


class TestRawArgvGate(TestProbeAndVerifierAgree):
    def test_exact_raw_passes(self):
        self.assertTrue(self._both(list(RAW_OK), False))

    def test_missing_cargo_fails(self):
        # the exact defect the old argv[1:] slice masked
        self.assertFalse(self._both(["test", "backslash", "--no-fail-fast"], False))

    def test_injected_toolchain_fails(self):
        self.assertFalse(self._both(["cargo", "+1.81.0", "test", "backslash", "--no-fail-fast"], False))

    def test_extra_flag_fails(self):
        self.assertFalse(self._both(["cargo", "test", "backslash", "--no-fail-fast", "--release"], False))

    def test_reordered_flags_fail(self):
        self.assertFalse(self._both(["cargo", "test", "--no-fail-fast", "backslash"], False))

    def test_rtk_shaped_argv_rejected_as_raw(self):
        # a RAW arm must NOT carry the rtk_bin prefix
        self.assertFalse(self._both(list(RTK_OK), False))


class TestRtkArgvGate(TestProbeAndVerifierAgree):
    def test_exact_rtk_passes(self):
        self.assertTrue(self._both(list(RTK_OK), True))

    def test_missing_cargo_fails(self):
        self.assertFalse(self._both([RTK_BIN, "test", "backslash", "--no-fail-fast"], True))

    def test_injected_toolchain_fails(self):
        self.assertFalse(self._both([RTK_BIN, "cargo", "+1.81.0", "test", "backslash", "--no-fail-fast"], True))

    def test_extra_flag_fails(self):
        self.assertFalse(self._both([RTK_BIN, "cargo", "test", "backslash", "--no-fail-fast", "--release"], True))

    def test_reordered_flags_fail(self):
        self.assertFalse(self._both([RTK_BIN, "cargo", "test", "--no-fail-fast", "backslash"], True))

    def test_missing_rtk_bin_fails(self):
        # RTK arm without the wrapper binary is just the RAW argv -> not the RTK contract
        self.assertFalse(self._both(list(RAW_OK), True))

    def test_wrong_rtk_bin_fails(self):
        self.assertFalse(self._both(["/other/bin/rtk", *RAW_OK], True))


class TestExpectedArgvHelper(unittest.TestCase):
    def test_expected_raw(self):
        self.assertEqual(probe.expected_argv(False, RTK_BIN), RAW_OK)

    def test_expected_rtk(self):
        self.assertEqual(probe.expected_argv(True, RTK_BIN), RTK_OK)


class TestVerifierRejectsAnyPlusToken(unittest.TestCase):
    """verify._argv_ok additionally rejects ANY '+'-prefixed token even if it somehow
    matched positionally -- defense in depth against a toolchain override."""

    def test_plus_token_anywhere_rejected(self):
        # positional match is impossible here, but assert the explicit '+' guard independently
        self.assertFalse(verify._argv_ok(["+nightly", "cargo", "test", "backslash", "--no-fail-fast"], False, RTK_BIN))


if __name__ == "__main__":
    unittest.main()
