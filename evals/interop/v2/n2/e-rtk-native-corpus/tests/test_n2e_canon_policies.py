"""Mutation tests for per-tool canonicalization policies (§3/§15).

Proves each policy (a) normalizes ONLY its declared nondeterministic grammar
(durations), and (b) NEVER masks a semantic change — a changed diagnostic,
path, test name, error message, or count always survives canonicalization
(i.e. produces different canonical bytes).
"""
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import n2e_canon_policies as canon  # noqa: E402


class TestCanonPolicies(unittest.TestCase):
    def test_identity_changes_nothing(self):
        b = b"anything\nat all 1.23s\n"
        self.assertEqual(canon.canonicalize(b, "identity-v1"), b)

    def test_duration_normalized(self):
        a = canon.canonicalize(b"test result: ok. finished in 0.12s", "cargo-test-v1")
        b = canon.canonicalize(b"test result: ok. finished in 9.99s", "cargo-test-v1")
        self.assertEqual(a, b, "different durations must canonicalize equal")

    def test_go_duration_normalized(self):
        a = canon.canonicalize(b"ok  \tpkg/x\t0.123s", "go-test-v1")
        b = canon.canonicalize(b"ok  \tpkg/x\t4.567s", "go-test-v1")
        self.assertEqual(a, b)

    def test_pytest_duration_normalized(self):
        a = canon.canonicalize(b"===== 3 passed in 0.12s =====", "pytest-v1")
        b = canon.canonicalize(b"===== 3 passed in 5.00s =====", "pytest-v1")
        self.assertEqual(a, b)

    # ---- semantic changes MUST survive every policy ----
    SEMANTIC_PAIRS = [
        (b"test result: ok. 5 passed; 0 failed; finished in 0.1s",
         b"test result: FAILED. 4 passed; 1 failed; finished in 0.1s"),
        (b"--- FAIL: TestA (0.1s)", b"--- FAIL: TestB (0.1s)"),
        (b"src/lib.rs:10:5: error: bad", b"src/lib.rs:11:5: error: bad"),
        (b"===== 3 passed in 0.1s =====", b"===== 2 passed in 0.1s ====="),
        (b"E   assert 1 == 2", b"E   assert 1 == 3"),
    ]

    def test_semantic_changes_never_masked(self):
        for pid in canon.all_policy_ids():
            for a, b in self.SEMANTIC_PAIRS:
                ca = canon.canonicalize(a, pid)
                cb = canon.canonicalize(b, pid)
                self.assertNotEqual(ca, cb, f"policy {pid} masked a semantic change: {a!r} vs {b!r}")

    def test_unknown_policy_raises(self):
        with self.assertRaises(KeyError):
            canon.canonicalize(b"x", "no-such-policy")

    def test_policy_resolution_deterministic(self):
        self.assertEqual(canon.policy_for("rust_cargo", "test"), "cargo-test-v1")
        self.assertEqual(canon.policy_for("jvm", "test", jvm_build="maven"), "maven-test-v1")
        self.assertEqual(canon.policy_for("jvm", "test", jvm_build="gradle"), "gradle-test-v1")
        self.assertEqual(canon.policy_for("git", "commit"), "git-v1")


if __name__ == "__main__":
    unittest.main()
