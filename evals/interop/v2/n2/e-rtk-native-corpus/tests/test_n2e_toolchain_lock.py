"""Fail-closed toolchain-lock verification: exact structured matching + failure tests."""
import sys
import tempfile
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import verify_n2e_toolchain_lock as V  # noqa: E402

CID = {"go": "caddyserver__caddy-5870::go::test::buggy",
       "rust": "tokio-rs__tokio-4384::rust_cargo::test::fixed",
       "node": "vuejs__core-11589::js_ts::test::buggy",
       "java": "apache__lucene-13704::jvm::test::buggy"}

GO_SHA = "0cdc4480040b5ef62eb17ba283ab92eca991794a937620604a2b5772201c2b59"
RUSTC_SHA = "6703c8f287653aae59b27849343fe64fa3893353f1c1d6037a608c18257afc2c"
CARGO_SHA = "da77b17765651b7a4405178a21d3dab1fa39dddec927d37c0fd5663b7c8623de"
NODE_SHA = "6295488653f0d93b0a157841746fef7e72cc4328cfb60c4bbe0ca2668a836ffd"


def _tc(kind, execs, pnpm=None):
    tc = {k: {"version": v[0], "sha256": v[1]} for k, v in execs.items()}
    if pnpm:
        tc["pnpm"] = {"version": pnpm[0], "sha256": pnpm[1]}
    return tc


def GOOD():
    return {
        "go": _tc("go", {"go": ("go version go1.23.8 linux/amd64", GO_SHA)}),
        "rust": _tc("rust", {"rustc": ("rustc 1.83.0 (abc 2024)", RUSTC_SHA),
                             "cargo": ("cargo 1.83.0 (abc 2024)", CARGO_SHA)}),
        "node": _tc("node", {"node": ("v20.20.2", NODE_SHA)}, pnpm=("9.7.0", "pn")),
        "java": _tc("java", {"java": ('openjdk version "21.0.11" 2026-04-21 LTS', "jj")}),
    }


def _write(d, tcs):
    for kind, tc in tcs.items():
        c.write_record(d / f"n2e-canary-case-{kind}.json", c.envelope(
            record_type="n2e-canary-case", generated_by="t", case_id=CID[kind],
            acquisition={"publisher_recipe": "S[1]", "publisher_case_id": CID[kind],
                         "environment_identity": {"toolchain_pin": {"kind": kind}, "toolchain": tc}}))


class TestToolchainLock(unittest.TestCase):
    def _dir(self, overrides=None):
        d = Path(tempfile.mkdtemp())
        tcs = GOOD()
        tcs.update(overrides or {})
        _write(d, tcs)
        return d

    def test_all_correct_passes_noncanonical(self):
        ok, msg = V.verify(self._dir())
        self.assertTrue(ok, msg)

    def test_canonical_requires_complete_lock(self):
        # the committed lock is HARVEST (java/pnpm/gradle pending) -> canonical fails
        ok, msg = V.verify(self._dir(), canonical=True)
        self.assertFalse(ok)
        self.assertIn("lock_state", msg)

    def test_wrong_rust_1_84_fails(self):
        ok, _ = V.verify(self._dir({"rust": _tc("rust",
            {"rustc": ("rustc 1.84.0 (x)", RUSTC_SHA), "cargo": ("cargo 1.84.0 (x)", CARGO_SHA)})}))
        self.assertFalse(ok)

    def test_wrong_go_binary_hash_fails(self):
        ok, msg = V.verify(self._dir({"go": _tc("go", {"go": ("go version go1.23.8 linux/amd64", "f00d")})}))
        self.assertFalse(ok)
        self.assertIn("sha256", msg)

    def test_wrong_node_major_fails(self):
        ok, _ = V.verify(self._dir({"node": _tc("node", {"node": ("v22.23.1", NODE_SHA)}, pnpm=("9.7.0", "pn"))}))
        self.assertFalse(ok)

    def test_missing_pnpm_fails(self):
        ok, msg = V.verify(self._dir({"node": _tc("node", {"node": ("v20.20.2", NODE_SHA)})}))
        self.assertFalse(ok)
        self.assertIn("pnpm", msg)

    def test_wrong_jdk_fails(self):
        ok, _ = V.verify(self._dir({"java": _tc("java", {"java": ('openjdk version "17.0.9"', "jj")})}))
        self.assertFalse(ok)

    def test_missing_expected_case_fails_closed(self):
        d = Path(tempfile.mkdtemp())
        tcs = GOOD(); del tcs["rust"]  # omit tokio entirely
        _write(d, tcs)
        ok, msg = V.verify(d)
        self.assertFalse(ok)
        self.assertIn("missing publisher evidence", msg)

    def test_unknown_kind_fails_not_skipped(self):
        d = Path(tempfile.mkdtemp())
        _write(d, GOOD())
        c.write_record(d / "n2e-canary-case-x.json", c.envelope(
            record_type="n2e-canary-case", generated_by="t", case_id="x::y",
            acquisition={"publisher_recipe": "S", "publisher_case_id": "x::y",
                         "environment_identity": {"toolchain_pin": {"kind": "haskell"}, "toolchain": {}}}))
        ok, _ = V.verify(d)
        self.assertFalse(ok)  # unknown case + kind -> fail, never continue


if __name__ == "__main__":
    unittest.main()
