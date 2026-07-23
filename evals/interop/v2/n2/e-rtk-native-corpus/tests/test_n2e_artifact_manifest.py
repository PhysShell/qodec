"""Regression: _artifact_manifest must tolerate RELATIVE --evidence/--out paths.

The CI diagnostic step runs `cd $N2E` then invokes the probe with relative
`--evidence out/evidence/coreutils-6731` and `--out coreutils-6731-diagnostic-v1.json`.
Before the fix, evidence.rglob("*") yielded RELATIVE paths and _artifact_manifest called
f.relative_to(N2E_DIR) with an ABSOLUTE N2E_DIR -> ValueError, so the probe crashed into
outcome=COREUTILS_DIAGNOSTIC_ERROR (observed in run 29644714364 / impl 7f6f883) before ever
reaching RTK_DIALECT_UNPROVEN. The manifest builder now resolves each path absolutely first,
producing the SAME stable N2E-relative manifest strings the verifier expects."""
import os
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import probe_coreutils_diagnostic as probe  # noqa: E402

# a scratch evidence tree under N2E_DIR/out so relative_to(N2E_DIR) is well-defined
REL_EVID = Path("out") / "evidence" / "_test_manifest_regression"
REL_DIAG = Path("_test_manifest_regression-diag.json")


class TestArtifactManifestRelativePaths(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        os.chdir(N2E_DIR)  # reproduce the workflow's `cd $N2E`
        (N2E_DIR / REL_EVID / "rtk-source-evidence").mkdir(parents=True, exist_ok=True)
        (N2E_DIR / REL_EVID / "raw.rep0.zst").write_bytes(b"\x00rep0")
        (N2E_DIR / REL_EVID / "rtk.rep0.zst").write_bytes(b"\x00rtk0")
        # a dotfile in a subdir -- the exact shape that surfaced the crash first
        (N2E_DIR / REL_EVID / "rtk-source-evidence" / ".flattened__name.md").write_bytes(b"x")
        (N2E_DIR / REL_DIAG).write_bytes(b"{}")

    def tearDown(self):
        import shutil
        shutil.rmtree(N2E_DIR / REL_EVID, ignore_errors=True)
        (N2E_DIR / REL_DIAG).unlink(missing_ok=True)
        os.chdir(self._cwd)

    def test_relative_evidence_does_not_raise_and_paths_are_n2e_relative(self):
        # RELATIVE Path args, exactly as the workflow passes them
        man = probe._artifact_manifest(Path(REL_EVID), Path(REL_DIAG))
        files = {e["file"] for e in man}
        self.assertIn("out/evidence/_test_manifest_regression/raw.rep0.zst", files)
        self.assertIn("out/evidence/_test_manifest_regression/rtk.rep0.zst", files)
        self.assertIn("out/evidence/_test_manifest_regression/rtk-source-evidence/.flattened__name.md", files)
        self.assertIn("_test_manifest_regression-diag.json", files)
        for e in man:
            self.assertFalse(e["file"].startswith("/"), f"manifest path not N2E-relative: {e['file']}")
            self.assertFalse(e["file"].startswith(".."), f"manifest path escapes N2E: {e['file']}")
            self.assertEqual(len(e["sha256"]), 64)
            self.assertGreaterEqual(e["bytes"], 0)

    def test_manifest_is_cwd_independent(self):
        # from a DIFFERENT cwd, absolute evidence arg must produce identical relative strings
        abs_evid = N2E_DIR / REL_EVID
        abs_diag = N2E_DIR / REL_DIAG
        os.chdir(self._cwd)  # move away from N2E_DIR
        man_abs = probe._artifact_manifest(abs_evid, abs_diag)
        os.chdir(N2E_DIR)
        man_rel = probe._artifact_manifest(Path(REL_EVID), Path(REL_DIAG))
        self.assertEqual(sorted(e["file"] for e in man_abs), sorted(e["file"] for e in man_rel))


if __name__ == "__main__":
    unittest.main()
