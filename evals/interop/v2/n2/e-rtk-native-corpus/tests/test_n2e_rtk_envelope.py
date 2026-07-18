"""rtk-envelope-v1: bounded, RTK-arm-only normalization of the epoch in RTK's own
tee-log envelope line. Mutation tests prove it is scoped to the exact grammar."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import n2e_canon_policies as canon  # noqa: E402

ENV = canon.rtk_envelope


class TestRtkEnvelope(unittest.TestCase):
    def test_two_timestamps_become_equal(self):
        a = b"admin_test.go:117: fail\n[full output: /home/u/.local/share/rtk/tee/1784346289_go_test.log]\n"
        b = b"admin_test.go:117: fail\n[full output: /home/u/.local/share/rtk/tee/1784346290_go_test.log]\n"
        self.assertNotEqual(a, b)
        self.assertEqual(ENV(a), ENV(b))
        self.assertIn(b"<ts>", ENV(a))

    def test_lookalike_path_without_envelope_stays_different(self):
        # a COMMAND printing a lookalike path (no "[full output: ... ]" envelope)
        a = b"saved to rtk/tee/1784346289_go_test.log done\n"
        b = b"saved to rtk/tee/1784346290_go_test.log done\n"
        self.assertNotEqual(ENV(a), ENV(b))  # untouched -> still differ
        self.assertNotIn(b"<ts>", ENV(a))

    def test_changed_name_suffix_stays_observable(self):
        a = b"[full output: ~/.local/share/rtk/tee/100_go_test.log]"
        b = b"[full output: ~/.local/share/rtk/tee/200_go_bench.log]"
        # epochs normalize but the differing suffix (go_test vs go_bench) remains
        self.assertNotEqual(ENV(a), ENV(b))

    def test_unrelated_numeric_path_untouched(self):
        s = b"opened /tmp/123_datafile.log and /var/45_run.log\n"
        self.assertEqual(ENV(s), s)

    def test_multiple_envelopes_all_normalized(self):
        s = (b"[full output: a/rtk/tee/111_x.log]\n[full output: b/rtk/tee/222_x.log]\n")
        out = ENV(s)
        self.assertEqual(out.count(b"<ts>"), 2)
        # two identical-suffix envelopes with different epochs collapse equal
        self.assertEqual(ENV(b"[full output: a/rtk/tee/111_x.log]"),
                         ENV(b"[full output: a/rtk/tee/999_x.log]"))

    def test_malformed_envelope_not_normalized(self):
        # missing ".log]" terminator -> not the exact grammar -> untouched (fail closed)
        s = b"[full output: ~/.local/share/rtk/tee/100_go_test.txt"
        self.assertEqual(ENV(s), s)

    def test_raw_arm_is_never_enveloped(self):
        # the driver applies rtk_envelope ONLY to the RTK arm; canonicalize() itself
        # (used for both arms) must NOT strip the rtk tee epoch.
        s = b"[full output: ~/.local/share/rtk/tee/100_go_test.log]"
        self.assertEqual(canon.canonicalize(s, "go-test-v1"), s)


if __name__ == "__main__":
    unittest.main()
