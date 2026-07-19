"""cargo-test-v3 canonicalization policy: cargo-test-v2 + exactly one added rule that normalizes
the RTK cargo-test COMPACT ALL-PASS summary duration (rust RTK @5d32d07 format_compact grammar).
cargo-test-v2 is left byte-for-byte intact.

Proves (the seven-point discipline for the versioned canon fix):
  1. prior 0.04s and current 0.05s RTK compact streams canonicalize identically under v3;
  2. changing passed / filtered / suite counts still changes the canonical digest;
  3. a duration outside the exact compact-summary grammar is NOT silently normalized;
  4. failure output, build projection, and no-summary fallback are untouched (v3 == v2 there);
  5. old cargo-test-v2 fixtures retain their previous bytes + semantics (v2 unchanged).
"""
import hashlib
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_canon_policies as canon  # noqa: E402

V2, V3 = "cargo-test-v2", "cargo-test-v3"
RTK_004 = b"cargo test: 10 passed, 3205 filtered out (3 suites, 0.04s)\n"
RTK_005 = b"cargo test: 10 passed, 3205 filtered out (3 suites, 0.05s)\n"
RTK_NORM = b"cargo test: 10 passed, 3205 filtered out (3 suites, <dur>)\n"


def _sha(b):
    return hashlib.sha256(b).hexdigest()


class TestCargoTestV3(unittest.TestCase):
    # ---- point 1: duration normalized; both durations collapse to one canonical ----
    def test_004_and_005_canonicalize_identically(self):
        c4, c5 = canon.canonicalize(RTK_004, V3), canon.canonicalize(RTK_005, V3)
        self.assertEqual(c4, RTK_NORM)
        self.assertEqual(c5, RTK_NORM)
        self.assertEqual(_sha(c4), _sha(c5))

    def test_no_duration_compact_form_unchanged(self):
        # the has_duration=False compact form "(3 suites)" has no duration -> unchanged
        s = b"cargo test: 10 passed, 3205 filtered out (3 suites)\n"
        self.assertEqual(canon.canonicalize(s, V3), s)

    def test_single_suite_form_normalized(self):
        s = b"cargo test: 5 passed (1 suite, 0.10s)\n"
        self.assertEqual(canon.canonicalize(s, V3), b"cargo test: 5 passed (1 suite, <dur>)\n")

    # ---- point 2: counts remain semantic -- any change survives canonicalization ----
    def test_passed_count_change_changes_digest(self):
        a = canon.canonicalize(RTK_005, V3)
        b = canon.canonicalize(b"cargo test: 11 passed, 3205 filtered out (3 suites, 0.05s)\n", V3)
        self.assertNotEqual(_sha(a), _sha(b))

    def test_filtered_count_change_changes_digest(self):
        a = canon.canonicalize(RTK_005, V3)
        b = canon.canonicalize(b"cargo test: 10 passed, 3206 filtered out (3 suites, 0.05s)\n", V3)
        self.assertNotEqual(_sha(a), _sha(b))

    def test_suite_count_change_changes_digest(self):
        a = canon.canonicalize(RTK_005, V3)
        b = canon.canonicalize(b"cargo test: 10 passed, 3205 filtered out (4 suites, 0.05s)\n", V3)
        self.assertNotEqual(_sha(a), _sha(b))

    def test_ignored_count_preserved(self):
        s = b"cargo test: 10 passed, 2 ignored, 3205 filtered out (3 suites, 0.05s)\n"
        out = canon.canonicalize(s, V3)
        self.assertIn(b"2 ignored", out)
        self.assertEqual(out, b"cargo test: 10 passed, 2 ignored, 3205 filtered out (3 suites, <dur>)\n")

    # ---- point 3: out-of-grammar durations are NOT normalized ----
    def test_out_of_grammar_duration_not_normalized(self):
        # a bare duration not in the compact-summary grammar
        self.assertEqual(canon.canonicalize(b"elapsed 0.05s here\n", V3), b"elapsed 0.05s here\n")
        # trailing tail after the ")" defeats the end-anchor -> duration untouched
        s = b"cargo test: 10 passed (3 suites, 0.05s) trailing\n"
        self.assertEqual(canon.canonicalize(s, V3), s)
        # a lookalike that is not the "cargo test:" compact form
        s2 = b"note: finished (3 suites, 0.05s)\n"
        self.assertEqual(canon.canonicalize(s2, V3), s2)

    # ---- point 4: failure / build / no-summary forms untouched (v3 adds nothing there) ----
    def test_failure_form_untouched(self):
        fail = (b"FAILURES (2):\n1. ---- test_tr::t stdout ----\n2. ---- test_x::y stdout ----\n\n"
                b"test result: FAILED. 8 passed; 2 failed; 0 ignored; 0 measured; 5 filtered out\n")
        self.assertEqual(canon.canonicalize(fail, V3), canon.canonicalize(fail, V2))

    def test_build_projection_untouched(self):
        build = b"cargo test (3 crates compiled)\nerror[E0308]: mismatched types\n"
        self.assertEqual(canon.canonicalize(build, V3), canon.canonicalize(build, V2))

    def test_no_summary_fallback_untouched(self):
        nosum = b"some meaningful line\nanother line\n"
        self.assertEqual(canon.canonicalize(nosum, V3), canon.canonicalize(nosum, V2))

    def test_v3_equals_v2_on_native_cargo_test_result(self):
        # a native cargo "test result: ... finished in Ds" is handled identically by v2 and v3
        native = (b"running 10 tests\ntest test_tr::x ... ok\n\n"
                  b"test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 3127 filtered out; "
                  b"finished in 0.04s\n")
        self.assertEqual(canon.canonicalize(native, V3), canon.canonicalize(native, V2))
        self.assertIn(b"finished in <dur>", canon.canonicalize(native, V3))

    # ---- point 5: cargo-test-v2 is unchanged (no in-place mutation) ----
    def test_v2_leaves_rtk_compact_duration_untouched(self):
        # v2 has NO RTK-compact rule -> the compact duration survives under v2 (proves v3's rule
        # is genuinely additive and v2's meaning is unchanged)
        self.assertEqual(canon.canonicalize(RTK_005, V2), RTK_005)
        self.assertEqual(canon.canonicalize(RTK_004, V2), RTK_004)

    def test_v2_still_registered_and_distinct_from_v3(self):
        self.assertIn(V2, canon.all_policy_ids())
        self.assertIn(V3, canon.all_policy_ids())
        # they differ exactly on the RTK compact form and agree elsewhere
        self.assertNotEqual(canon.canonicalize(RTK_005, V2), canon.canonicalize(RTK_005, V3))


if __name__ == "__main__":
    unittest.main()
