"""Promotion P5.2B (preact+lombok): rtk-files-read-oracle-v1 semantics, proven against the pinned RTK
source (rtk-ai/rtk @5d32d07). `rtk read FILE` at the frozen default level `none` is the IDENTITY of
the file content (NoFilter + no window + never_worse keeps filtered==content), so its faithful
RAW<->RTK equivalence is CONTENT FIDELITY: RTK reproduces every non-blank content line of `cat FILE`,
unchanged and in order, without emptying a non-empty file. RED matrix: a dropped / altered /
reordered / fabricated / truncated line breaks equivalence; ANSI, CRLF, trailing-newline, and
blank-line-run differences do not.
"""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_rtk_files_read_oracle as fr  # noqa: E402

# a small representative README-like Markdown body
README = b"""# preact

Fast 3kB alternative to React with the same modern API.

## Install

    npm install preact

## Usage

```js
import { h, render } from 'preact';
render(h('h1', null, 'Hello!'), document.body);
```

## License

MIT
"""


class TestFilesReadOracle(unittest.TestCase):
    # ---------- identity (the default `rtk read` path) ----------
    def test_identity_equivalent(self):
        # rtk read (none) == cat, byte-for-byte
        rp, kp = fr.parse_raw(README), fr.parse_rtk(README)
        self.assertEqual(rp["outcome"], "text")
        eq = fr.equivalence(rp, kp)
        self.assertTrue(eq["equivalent"], eq["mismatches"])
        self.assertEqual(eq["retained_line_coverage"], 1.0)

    def test_projection_shape(self):
        rp = fr.parse_raw(README)
        for k in ("outcome", "byte_count", "content_sha256", "nonblank_line_count",
                  "nonblank_sha256", "trailing_newline"):
            self.assertIn(k, rp)

    # ---------- allowed non-semantic normalizations ----------
    def test_trailing_newline_non_semantic(self):
        # RTK emits identical content but without the final newline (gin-style presentation)
        rp, kp = fr.parse_raw(README), fr.parse_rtk(README.rstrip(b"\n"))
        self.assertTrue(fr.equivalence(rp, kp)["equivalent"])

    def test_crlf_non_semantic(self):
        rp, kp = fr.parse_raw(README), fr.parse_rtk(README.replace(b"\n", b"\r\n"))
        self.assertTrue(fr.equivalence(rp, kp)["equivalent"])

    def test_ansi_non_semantic(self):
        noisy = README.replace(b"preact", b"\x1b[1mpreact\x1b[0m")
        self.assertTrue(fr.equivalence(fr.parse_raw(README), fr.parse_rtk(noisy))["equivalent"])

    def test_blank_line_run_collapse_non_semantic(self):
        # simulates a non-default filter level collapsing >=3 blank lines: non-blank sequence intact
        collapsed = README.replace(b"\n\n", b"\n\n\n\n")  # RAW has extra blank runs
        rp, kp = fr.parse_raw(collapsed), fr.parse_rtk(README)
        self.assertTrue(fr.equivalence(rp, kp)["equivalent"])

    # ---------- empty ----------
    def test_empty_both_sides(self):
        rp, kp = fr.parse_raw(b""), fr.parse_rtk(b"")
        self.assertEqual(rp["outcome"], "empty")
        self.assertTrue(fr.equivalence(rp, kp)["equivalent"])

    def test_whitespace_only_is_empty(self):
        self.assertEqual(fr.parse_raw(b"   \n\n  \n")["outcome"], "empty")

    # ---------- RED matrix: content divergence breaks equivalence ----------
    def test_dropped_line_breaks(self):
        dropped = README.replace(b"MIT\n", b"")
        eq = fr.equivalence(fr.parse_raw(README), fr.parse_rtk(dropped))
        self.assertFalse(eq["equivalent"])
        self.assertIn("content", eq["mismatches"])
        self.assertEqual(eq["retained_line_coverage"], 0.0)

    def test_altered_byte_breaks(self):
        altered = README.replace(b"npm install preact", b"npm install react")
        self.assertFalse(fr.equivalence(fr.parse_raw(README), fr.parse_rtk(altered))["equivalent"])

    def test_reordered_lines_break(self):
        lines = README.split(b"\n")
        reordered = b"\n".join(lines[::-1])
        self.assertFalse(fr.equivalence(fr.parse_raw(README), fr.parse_rtk(reordered))["equivalent"])

    def test_fabricated_line_breaks(self):
        fabricated = README + b"\nrtk: injected summary line\n"
        self.assertFalse(fr.equivalence(fr.parse_raw(README), fr.parse_rtk(fabricated))["equivalent"])

    def test_truncated_breaks(self):
        truncated = b"\n".join(README.split(b"\n")[:5])
        self.assertFalse(fr.equivalence(fr.parse_raw(README), fr.parse_rtk(truncated))["equivalent"])

    def test_emptied_nonempty_breaks(self):
        eq = fr.equivalence(fr.parse_raw(README), fr.parse_rtk(b""))
        self.assertFalse(eq["equivalent"])
        self.assertIn("outcome", eq["mismatches"])

    # ---------- source-grounding self-attestation ----------
    def test_declares_pinned_source(self):
        self.assertEqual(fr.ORACLE_ID, "rtk-files-read-oracle-v1")
        self.assertEqual(fr.RTK_SOURCE_COMMIT, "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2")
        files = {r["source_file"] for r in fr.RTK_SOURCE_REFS}
        self.assertIn("src/cmds/system/read.rs", files)
        self.assertIn("src/core/filter.rs", files)
        self.assertIn("src/core/guard.rs", files)
        self.assertIn("src/main.rs", files)


if __name__ == "__main__":
    unittest.main()
