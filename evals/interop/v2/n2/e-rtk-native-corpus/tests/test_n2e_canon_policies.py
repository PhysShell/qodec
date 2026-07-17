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

    def test_go_zap_ts_and_origins_normalized(self):
        # a tested server's zap logs: wall-clock ts float + map-ordered origins set
        a = b'{"ts":1784320522.46,"msg":"x","origins":["//localhost:2019","//[::1]:2019"]}'
        b = b'{"ts":1784320599.99,"msg":"x","origins":["//[::1]:2019","//localhost:2019"]}'
        self.assertEqual(canon.canonicalize(a, "go-test-v1"), canon.canonicalize(b, "go-test-v1"))
        # a dropped/changed origin (semantic multiset change) must remain observable
        c1 = canon.canonicalize(a, "go-test-v1")
        c2 = canon.canonicalize(b'{"ts":1.0,"msg":"x","origins":["//[::1]:2019"]}', "go-test-v1")
        self.assertNotEqual(c1, c2)
        # a changed msg must remain observable
        c3 = canon.canonicalize(b'{"ts":1.0,"msg":"y","origins":["//localhost:2019","//[::1]:2019"]}', "go-test-v1")
        self.assertNotEqual(canon.canonicalize(a, "go-test-v1"), c3)

    def test_vitest_walltime_phases_and_chromium_ids_normalized(self):
        a = (b"   Start at  21:37:10\n   Duration 1.2s (transform 5.92s, setup 643ms, tests 9.28s)\n"
             b"[4945:4945:0717/213801.172445:FATAL:zygote.cc(126)] No usable sandbox!\n")
        b = (b"   Start at  21:38:45\n   Duration 1.3s (transform 6.19s, setup 619ms, tests 9.30s)\n"
             b"[7774:7774:0717/213936.290729:FATAL:zygote.cc(126)] No usable sandbox!\n")
        self.assertEqual(canon.canonicalize(a, "vitest-v1"), canon.canonicalize(b, "vitest-v1"))
        # the semantic crash reason must remain observable
        self.assertNotEqual(canon.canonicalize(a, "vitest-v1"),
                            canon.canonicalize(a.replace(b"No usable sandbox!", b"Segfault!"), "vitest-v1"))

    def test_vitest_per_file_duration_normalized(self):
        # per-file trailing elapsed ("(150 tests) 110ms") is pure duration jitter
        a = canon.canonicalize(b"  \xe2\x9c\x93 parse.spec.ts  (150 tests) 110ms", "vitest-v1")
        b = canon.canonicalize(b"  \xe2\x9c\x93 parse.spec.ts  (150 tests) 109ms", "vitest-v1")
        self.assertEqual(a, b)
        # but a changed test COUNT must never be masked
        c1 = canon.canonicalize(b"  \xe2\x9c\x93 parse.spec.ts  (150 tests) 110ms", "vitest-v1")
        c2 = canon.canonicalize(b"  \xe2\x9c\x93 parse.spec.ts  (149 tests) 110ms", "vitest-v1")
        self.assertNotEqual(c1, c2)

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
