"""Resolved-scope loader (contract step 3) + native Cargo target-execution proof (step 11)."""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_resolved_loader as L  # noqa: E402
import n2e_oracles as ora  # noqa: E402

COREUTILS = "uutils__coreutils-6731::rust_cargo::test::fixed"
TOKIO = "tokio-rs__tokio-4384::rust_cargo::test::fixed"
CADDY = "caddyserver__caddy-5870::go::test::buggy"

CARGO_GOOD = (b"     Running tests/test_tr.rs (target/debug/deps/test_tr-1a2b3c4d5e)\n\n"
              b"running 2 tests\ntest test_trailing_backslash ... ok\n"
              b"test test_interpret_backslash_escapes ... ok\n\n"
              b"test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 45 filtered out\n")


class TestResolvedLoader(unittest.TestCase):
    def test_coreutils_routes_to_overlay(self):
        b = L.load_case_bundle(COREUTILS, "resolved")
        self.assertEqual(b["source"], "replacement_overlay")
        self.assertIsNotNone(b["publisher_recipe"])
        self.assertEqual(b["publisher_recipe"]["install"], ["cargo test backslash --no-run"])
        self.assertEqual(b["toolchain_contract"]["resolved_channel"], "1.81.0")
        self.assertIn("resolved_membership_sha256", b["effective_record_hash_map"])

    def test_nonreplacement_routes_to_base(self):
        b = L.load_case_bundle(CADDY, "resolved")
        self.assertEqual(b["source"], "frozen_base")
        self.assertIsNone(b["publisher_recipe"])

    def test_tokio_absent_from_effective(self):
        with self.assertRaises(L.ResolvedScopeError):
            L.load_case_bundle(TOKIO, "resolved")

    def test_coreutils_not_in_base_scope(self):
        with self.assertRaises(L.ResolvedScopeError):
            L.load_case_bundle(COREUTILS, "base")

    def test_closure_validates(self):
        cl = L.validate_resolved_closure()
        self.assertNotIn(TOKIO, cl["effective_ids"])
        self.assertEqual(cl["effective_ids"].count(COREUTILS), 1)
        self.assertEqual(len(cl["effective_ids"]), 12)


class TestCargoTargetProof(unittest.TestCase):
    def test_good_passes(self):
        p = ora.cargo_target_execution_proof(CARGO_GOOD, 0, ["test_tr::test_trailing_backslash"])
        self.assertTrue(p["executed_ok"])
        self.assertIn("test_tr::test_trailing_backslash", p["executed_ok_ids"])

    def test_compile_only_fails(self):
        p = ora.cargo_target_execution_proof(b"   Compiling coreutils\n    Finished test\n", 0,
                                             ["test_tr::test_trailing_backslash"])
        self.assertFalse(p["executed_ok"])
        self.assertFalse(p["checks"]["not_compile_only"])

    def test_zero_filtered_fails(self):
        z = (b"     Running tests/test_tr.rs (target/debug/deps/test_tr-1a2b3c4d5e)\n\n"
             b"running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 47 filtered out\n")
        p = ora.cargo_target_execution_proof(z, 0, ["test_tr::test_trailing_backslash"])
        self.assertFalse(p["executed_ok"])
        self.assertFalse(p["checks"]["nonzero_tests_executed"])

    def test_target_failed_fails(self):
        f = (b"     Running tests/test_tr.rs (target/debug/deps/test_tr-1a2b3c4d5e)\n\n"
             b"running 1 test\ntest test_trailing_backslash ... FAILED\n\n"
             b"test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 45 filtered out\n")
        p = ora.cargo_target_execution_proof(f, 101, ["test_tr::test_trailing_backslash"])
        self.assertFalse(p["executed_ok"])

    def test_exit_zero_alone_insufficient(self):
        # cargo exit 0 but no test result line (e.g. only build) -> not proven
        p = ora.cargo_target_execution_proof(b"Finished\n", 0, ["test_tr::test_trailing_backslash"])
        self.assertFalse(p["executed_ok"])


if __name__ == "__main__":
    unittest.main()
