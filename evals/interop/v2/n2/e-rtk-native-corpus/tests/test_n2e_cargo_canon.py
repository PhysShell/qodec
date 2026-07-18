"""cargo-test-v2 bounded canonicalizer: adversarial preservation + run-29642866948 fixture
regression (corrections 1-3). cargo-test-v1 must remain historical/unchanged."""
import sys
import unittest
import zlib
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_canon_policies as canon  # noqa: E402
import n2e_oracles as ora  # noqa: E402

FIX = N2E_DIR / "tests" / "fixtures" / "coreutils_v1_raw"
TARGET = ["test_tr::test_trailing_backslash"]

# real Cargo status lines that MUST be removed
REAL_CARGO = [
    b"   Compiling libc v0.2.159",
    b"   Compiling coreutils v0.0.27 (/home/runner/work/_temp/n2e-fixedwork/repo)",
    b"    Finished `test` profile [unoptimized + debuginfo] target(s) in 2m 38s",
    b"    Updating crates.io index",
    b"   Locking 250 packages to latest compatible versions",
    b"   Blocking waiting for file lock on package cache",
    b" Downloading crates ...",
]
# lookalike lines that MUST be preserved byte-for-byte
PRESERVE = [
    b"    Finished processing sample",
    b"    Waiting for child process",
    b"    Checking generated output",
    b"    Building expected AST",
    b"    Removing temporary fixture",
    b"    Downloading was intentionally disabled",
    b"    Updating snapshot",
    b"    Blocking operation completed",
    b"test test_trailing_backslash ... ok",
    b"thread 'main' panicked at 'Compiling failed unexpectedly'",
    b"    assertion failed: Finished == expected",
]


class TestCargoTestV2Canon(unittest.TestCase):
    def test_real_cargo_status_removed(self):
        for line in REAL_CARGO:
            out = canon.canonicalize(line + b"\n", "cargo-test-v2")
            self.assertEqual(out, b"", f"not removed: {line!r}")

    def test_lookalikes_preserved_byte_for_byte(self):
        blob = b"\n".join(PRESERVE) + b"\n"
        out = canon.canonicalize(blob, "cargo-test-v2")
        self.assertEqual(out, blob, "a lookalike/test-output line was altered")

    def test_line_without_final_newline_preserved(self):
        line = b"test test_x ... ok"  # no trailing newline
        self.assertEqual(canon.canonicalize(line, "cargo-test-v2"), line)

    def test_mixed_stream_semantics_preserved(self):
        stream = (b"   Compiling libc v0.2.159\n"
                  b"    Finished `test` profile [unoptimized + debuginfo] target(s) in 2m 38s\n"
                  b"     Running tests/test_tr.rs (target/debug/deps/test_tr-a9c6f48e4a525f99)\n\n"
                  b"running 1 test\ntest test_trailing_backslash ... ok\n\n"
                  b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.05s\n")
        out = canon.canonicalize(stream, "cargo-test-v2")
        self.assertNotIn(b"Compiling", out)
        self.assertNotIn(b"Finished `test`", out)
        self.assertIn(b"Running tests/test_tr.rs", out)   # binary context kept
        self.assertIn(b"test result:", out)
        pr = ora.cargo_target_execution_proof(stream, 0, TARGET)
        pc = ora.cargo_target_execution_proof(out, 0, TARGET)
        self.assertEqual(pr["executed_ok_ids"], pc["executed_ok_ids"])
        self.assertTrue(pc["executed_ok"])

    def test_removed_diag_records_count_and_sha(self):
        d = canon.cargo_test_v2_removed_diag(b"   Compiling libc v0.2.159\n   Compiling cfg-if v1.0.0\ntest x ... ok\n")
        self.assertEqual(d["removed_line_count"], 2)
        self.assertEqual(len(d["removed_sha256"]), 64)


@unittest.skipUnless(FIX.is_dir() and (FIX / "raw.raw.rep0.zst").is_file(),
                     "run-29642866948 raw fixtures absent")
class TestV1FixtureRegression(unittest.TestCase):
    def _raw(self, i):
        return zlib.decompress((FIX / f"raw.raw.rep{i}.zst").read_bytes())

    def test_three_raw_captures_one_canonical_sha(self):
        import hashlib
        canon_h = {hashlib.sha256(canon.canonicalize(self._raw(i), "cargo-test-v2")).hexdigest()
                   for i in range(3)}
        self.assertEqual(len(canon_h), 1, "three raw captures did not collapse to one canonical sha256")

    def test_target_and_result_records_survive(self):
        out = canon.canonicalize(self._raw(0), "cargo-test-v2")
        self.assertIn(b"test_trailing_backslash", out)
        self.assertIn(b"test result:", out)
        proof = ora.cargo_target_execution_proof(self._raw(0), 0, TARGET)
        proof_c = ora.cargo_target_execution_proof(out, 0, TARGET)
        self.assertTrue(proof["executed_ok"])
        self.assertEqual(proof["executed_ok_ids"], proof_c["executed_ok_ids"])

    def test_cargo_test_v1_unchanged_keeps_compiling(self):
        out = canon.canonicalize(self._raw(0), "cargo-test-v1")
        self.assertIn(b"Compiling", out)  # historical policy must NOT strip build progress


if __name__ == "__main__":
    unittest.main()
