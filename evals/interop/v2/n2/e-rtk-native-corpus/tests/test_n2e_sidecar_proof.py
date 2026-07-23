"""Correction 2: the RTK sidecar semantic-loss proof is PARSER-BOUNDED. A required
failing identity is established only when the SAME test-output parser used for the
measured streams parses it as a failing id in the sidecar; mere textual presence
(argv/selector echo, `=== RUN`, discovery, stack trace, the tee pointer itself) does
NOT establish semantic loss. For Caddy the qualifying evidence must be a parsed
`--- FAIL: TestUnsyncedConfigAccess`."""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import run_canary_case as rc  # noqa: E402

REQ = {"TestUnsyncedConfigAccess"}
POINTER = "/tmp/n2e/rtk/tee/1737_caddy.log"


def proof(sidecar: bytes, measured: bytes = b""):
    return rc._parse_sidecar_proof(sidecar, measured, REQ, POINTER)


class TestParserBoundedSidecar(unittest.TestCase):
    def test_real_fail_line_establishes_loss(self):
        p = proof(b"=== RUN   TestUnsyncedConfigAccess\n"
                  b"--- FAIL: TestUnsyncedConfigAccess (0.01s)\nFAIL\n", measured=b"ok\n")
        self.assertEqual(p["sidecar_failing_ids"], ["TestUnsyncedConfigAccess"])
        self.assertEqual(p["semantic_loss_ids_this_rep"], ["TestUnsyncedConfigAccess"])

    def test_argv_selector_echo_only_does_not_establish_loss(self):
        p = proof(b"go test -v . -run TestUnsyncedConfigAccess\nok  \tpkg\t0.2s\n")
        self.assertEqual(p["sidecar_failing_ids"], [])
        self.assertEqual(p["semantic_loss_ids_this_rep"], [])

    def test_run_line_only_does_not_establish_loss(self):
        p = proof(b"=== RUN   TestUnsyncedConfigAccess\n=== PAUSE TestUnsyncedConfigAccess\n")
        self.assertEqual(p["semantic_loss_ids_this_rep"], [])

    def test_discovery_text_only_does_not_establish_loss(self):
        p = proof(b"Discovered tests:\n  TestUnsyncedConfigAccess\n  TestOther\n")
        self.assertEqual(p["semantic_loss_ids_this_rep"], [])

    def test_stack_trace_mention_only_does_not_establish_loss(self):
        p = proof(b"panic: boom\n\tcaddy.TestUnsyncedConfigAccess(0xc0001)\n\t/src/x_test.go:12\n")
        self.assertEqual(p["semantic_loss_ids_this_rep"], [])

    def test_tee_pointer_line_only_does_not_establish_loss(self):
        p = proof(b"[full output: /tmp/n2e/rtk/tee/1737_caddy.log :: TestUnsyncedConfigAccess]\n")
        self.assertEqual(p["semantic_loss_ids_this_rep"], [])

    def test_no_loss_when_measured_also_has_the_fail(self):
        # RTK preserved the failing id in the MEASURED stream in its own [FAIL] form
        # (measured is parsed with the RTK dialect) -> not semantic loss
        sidecar = b"--- FAIL: TestUnsyncedConfigAccess (0.01s)\nFAIL\n"
        measured = b"Go test: 0 passed, 1 failed in 1 packages\n  [FAIL] TestUnsyncedConfigAccess\n"
        p = proof(sidecar, measured=measured)
        self.assertEqual(p["measured_failing_ids"], ["TestUnsyncedConfigAccess"])
        self.assertEqual(p["semantic_loss_ids_this_rep"], [])

    def test_records_sidecar_bytes_and_sha(self):
        body = b"--- FAIL: TestUnsyncedConfigAccess (0.01s)\nFAIL\n"
        p = proof(body)
        self.assertEqual(p["sidecar_bytes"], len(body))
        self.assertTrue(p["sidecar_sha256"])
        self.assertTrue(p["tee_pointer_present"])


if __name__ == "__main__":
    unittest.main()
