"""Toolchain-lock runtime verification: exact version equality + failure tests."""
import sys
import tempfile
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import verify_n2e_toolchain_lock as V  # noqa: E402


def _rec(d: Path, kind: str, execs: dict):
    tc = {k: {"version": v, "sha256": "deadbeef"} for k, v in execs.items()}
    c.write_record(d / f"n2e-canary-case-{kind}.json", c.envelope(
        record_type="n2e-canary-case", generated_by="t", case_id=f"x::{kind}",
        acquisition={"publisher_recipe": "S[1]",
                     "environment_identity": {"toolchain_pin": {"kind": kind}, "toolchain": tc}}))


GOOD = {
    "rust": {"rustc": "rustc 1.83.0 (abc 2024)", "cargo": "cargo 1.83.0 (abc 2024)"},
    "go": {"go": "go version go1.23.8 linux/amd64"},
    "node": {"node": "v20.20.2"},
    "java": {"java": 'openjdk version "21.0.11" 2026-04-21 LTS'},
}


class TestToolchainLock(unittest.TestCase):
    def _dir(self, overrides=None):
        d = Path(tempfile.mkdtemp())
        for k, execs in {**GOOD, **(overrides or {})}.items():
            _rec(d, k, execs)
        return d

    def test_all_correct_passes(self):
        ok, msg = V.verify(self._dir())
        self.assertTrue(ok, msg)

    def test_wrong_rust_1_84_fails(self):
        ok, msg = V.verify(self._dir({"rust": {"rustc": "rustc 1.84.0 (x)", "cargo": "cargo 1.84.0 (x)"}}))
        self.assertFalse(ok)
        self.assertIn("rustc", msg)

    def test_wrong_go_fails(self):
        ok, _ = V.verify(self._dir({"go": {"go": "go version go1.22.0 linux/amd64"}}))
        self.assertFalse(ok)

    def test_wrong_node_patch_major_fails(self):
        ok, _ = V.verify(self._dir({"node": {"node": "v22.23.1"}}))
        self.assertFalse(ok)

    def test_wrong_jdk_fails(self):
        ok, _ = V.verify(self._dir({"java": {"java": 'openjdk version "17.0.9"'}}))
        self.assertFalse(ok)

    def test_binary_sha_equality_when_pinned(self):
        # if the lock pins an expected binary sha256, a mismatch must fail. Patch a
        # copy of the lock in-memory via monkeypatch on the loaded record.
        import n2e_common as cc
        lock = cc.load_record(V.LOCK)
        lock["toolchains"]["go"]["executables"]["go"]["expected_binary_sha256"] = "f00dfeed"
        orig = cc.load_record
        try:
            cc.load_record = lambda p, _l=lock, _o=orig: _l if str(p) == str(V.LOCK) else _o(p)
            # our synthetic records carry sha256 'deadbeef' != 'f00dfeed' -> fail
            ok, msg = V.verify(self._dir())
            self.assertFalse(ok)
            self.assertIn("sha256", msg)
        finally:
            cc.load_record = orig


if __name__ == "__main__":
    unittest.main()
