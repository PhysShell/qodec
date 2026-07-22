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

    def test_go_test_v1_is_duration_cache_only(self):
        # generic go-test-v1 must NOT touch app-log ts/origins (that is scoped to
        # the Caddy policy). It only normalizes go's own duration/cache grammar.
        z = b'{"level":"info","ts":1784320522.46,"logger":"admin","msg":"x","origins":["//b","//a"]}'
        self.assertEqual(canon.canonicalize(z, "go-test-v1"), z)  # untouched
        a = canon.canonicalize(b"ok  \tpkg\t0.123s", "go-test-v1")
        b = canon.canonicalize(b"ok  \tpkg\t9.999s", "go-test-v1")
        self.assertEqual(a, b)

    def test_caddy_policy_is_case_scoped(self):
        # bound only to the exact Caddy case_id, never selected from family/subfamily
        self.assertEqual(canon.policy_for("go", "test",
                         case_id="caddyserver__caddy-5870::go::test::buggy"), "caddy-go-test-v1")
        self.assertEqual(canon.policy_for("go", "test", case_id="gohugoio__hugo-12768::go::test::buggy"),
                         "go-test-v1")
        self.assertEqual(canon.policy_for("go", "test"), "go-test-v1")

    def test_caddy_zap_ts_and_origins_parser_bounded(self):
        P = "caddy-go-test-v1"
        base = b'{"level":"info","ts":1784320522.46,"logger":"admin","msg":"started","origins":["//localhost:2019","//[::1]:2019","//127.0.0.1:2019"]}'
        reordered = b'{"level":"info","ts":1784320599.99,"logger":"admin","msg":"started","origins":["//[::1]:2019","//127.0.0.1:2019","//localhost:2019"]}'
        self.assertEqual(canon.canonicalize(base, P), canon.canonicalize(reordered, P))  # ts + reorder normalized
        # commas + escaped quotes inside an origin string (real parser, not comma-split)
        weird = b'{"level":"info","ts":1.0,"logger":"admin","msg":"m","origins":["//a,b:1","//c\\"d:2"]}'
        weird2 = b'{"level":"info","ts":2.0,"logger":"admin","msg":"m","origins":["//c\\"d:2","//a,b:1"]}'
        self.assertEqual(canon.canonicalize(weird, P), canon.canonicalize(weird2, P))
        # duplicate origins: exact multiset preserved (dropping one differs)
        dup = b'{"level":"info","ts":1.0,"logger":"admin","msg":"m","origins":["//a","//a"]}'
        one = b'{"level":"info","ts":1.0,"logger":"admin","msg":"m","origins":["//a"]}'
        self.assertNotEqual(canon.canonicalize(dup, P), canon.canonicalize(one, P))
        # changed/removed origin, changed msg, changed level/logger all survive
        for mutated in (
            b'{"level":"info","ts":1.0,"logger":"admin","msg":"started","origins":["//localhost:2019","//[::1]:2019"]}',
            b'{"level":"info","ts":1.0,"logger":"admin","msg":"stopped","origins":["//localhost:2019","//[::1]:2019","//127.0.0.1:2019"]}',
            b'{"level":"error","ts":1.0,"logger":"admin","msg":"started","origins":["//localhost:2019","//[::1]:2019","//127.0.0.1:2019"]}',
            b'{"level":"info","ts":1.0,"logger":"http","msg":"started","origins":["//localhost:2019","//[::1]:2019","//127.0.0.1:2019"]}',
        ):
            self.assertNotEqual(canon.canonicalize(base, P), canon.canonicalize(mutated, P))

    def test_caddy_policy_leaves_unrelated_and_malformed_untouched(self):
        P = "caddy-go-test-v1"
        # an unrelated JSON object that merely has a "ts" field (no zap schema) is untouched
        unrelated_a = b'{"ts":123,"data":"x"}'
        unrelated_b = b'{"ts":999,"data":"x"}'
        self.assertEqual(canon.canonicalize(unrelated_a, P), unrelated_a)
        self.assertNotEqual(canon.canonicalize(unrelated_a, P), canon.canonicalize(unrelated_b, P))
        # malformed JSON is byte-identical
        bad = b'{"level":"info","ts":1.0,"logger":"admin","msg":'
        self.assertEqual(canon.canonicalize(bad, P), bad)
        # a plain go-test line is untouched by the zap canon (only duration normalized)
        self.assertEqual(canon.canonicalize(b"?   \tpkg\t[no test files]", P), b"?   \tpkg\t[no test files]")

    def test_caddy_policy_does_not_reorder_lines(self):
        # residual goroutine LINE interleaving must remain observable (nondeterministic)
        P = "caddy-go-test-v1"
        l1 = b'{"level":"info","ts":1.0,"logger":"admin","msg":"started"}'
        l2 = b'{"level":"info","ts":2.0,"logger":"admin","msg":"stopped"}'
        self.assertNotEqual(canon.canonicalize(l1 + b"\n" + l2, P),
                            canon.canonicalize(l2 + b"\n" + l1, P))

    def test_vitest_per_file_duration_normalized(self):
        # per-file trailing elapsed ("(150 tests) 110ms") is pure duration jitter
        a = canon.canonicalize(b"  \xe2\x9c\x93 parse.spec.ts  (150 tests) 110ms", "vitest-v1")
        b = canon.canonicalize(b"  \xe2\x9c\x93 parse.spec.ts  (150 tests) 109ms", "vitest-v1")
        self.assertEqual(a, b)
        # but a changed test COUNT must never be masked
        c1 = canon.canonicalize(b"  \xe2\x9c\x93 parse.spec.ts  (150 tests) 110ms", "vitest-v1")
        c2 = canon.canonicalize(b"  \xe2\x9c\x93 parse.spec.ts  (149 tests) 110ms", "vitest-v1")
        self.assertNotEqual(c1, c2)

    def test_vitest_total_duration_integer_ms_normalized(self):
        # regression (run 29865050045): the vitest TOTAL "Duration  828ms" is emitted as INTEGER ms
        # (no decimal) and was the SOLE per-rep nondeterminism for vue; it must canonicalize away, like
        # the decimal form and the per-phase breakdown already do.
        a = canon.canonicalize(b"   Duration  828ms (transform 5ms, setup 6ms, tests 12ms)", "vitest-v1")
        b = canon.canonicalize(b"   Duration  744ms (transform 5ms, setup 6ms, tests 12ms)", "vitest-v1")
        self.assertEqual(a, b)
        self.assertIn(b"Duration <dur>", a)
        # the decimal-seconds form still normalizes too
        self.assertEqual(canon.canonicalize(b"Duration  1.23s", "vitest-v1"),
                         canon.canonicalize(b"Duration  4.56s", "vitest-v1"))
        # a changed PASS/FAIL summary is never masked by the duration rule
        self.assertNotEqual(
            canon.canonicalize(b"Tests  1 failed | 78 passed (79)\n Duration  828ms", "vitest-v1"),
            canon.canonicalize(b"Tests  2 failed | 77 passed (79)\n Duration  744ms", "vitest-v1"))

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

    def test_policy_definition_sha256_pins_rules(self):
        # deterministic, and distinct policies hash differently -- so a record can pin the policy BYTES
        a = canon.policy_definition_sha256("vitest-v1")
        self.assertEqual(a, canon.policy_definition_sha256("vitest-v1"))
        self.assertNotEqual(a, canon.policy_definition_sha256("pytest-v1"))
        self.assertNotEqual(a, canon.policy_definition_sha256("identity-v1"))
        with self.assertRaises(KeyError):
            canon.policy_definition_sha256("no-such-policy")

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
