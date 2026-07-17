"""Tests for build_n2d3_input_bundle.py / verify_n2d3_input_bundle.py."""
import hashlib
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import build_n2d3_input_bundle as builder  # noqa: E402
import verify_n2d3_input_bundle as verifier  # noqa: E402

BASE_DIR = Path(__file__).resolve().parents[1]
BUNDLE_PATH = BASE_DIR / "n2d3-model-free-input-bundle-v1.tar"


class TestBaselineActuallyPasses(unittest.TestCase):
    def test_real_committed_bundle_verifies(self):
        ok, message = verifier.verify()
        self.assertTrue(ok, message)


class TestBundleIsDeterministic(unittest.TestCase):
    def test_double_build_byte_identical(self):
        identity_closure = json.loads((BASE_DIR / "n2d-current-identity-closure-v1.json").read_text())
        rtk_map = json.loads((BASE_DIR / "rtk-applicability-map-v1.json").read_text())

        with tempfile.TemporaryDirectory() as tmp:
            staged = Path(tmp)
            with tarfile.open(BUNDLE_PATH, mode="r:") as tar:
                for case_id, entry in json.loads(
                    tar.extractfile("manifest.json").read()
                )["cases"].items():
                    data = tar.extractfile(entry["bundle_member_path"]).read()
                    (staged / f"{case_id}.bin").write_bytes(data)

            b1, b2 = builder.build_twice_and_compare(staged, rtk_map, identity_closure)
            self.assertEqual(b1, b2)
            self.assertEqual(hashlib.sha256(b1).hexdigest(), hashlib.sha256(b2).hexdigest())


class TestMutationsAreCaught(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def _mutated_bundle(self, mutate_members) -> Path:
        with tarfile.open(BUNDLE_PATH, mode="r:") as tar:
            members_data = {}
            infos = {}
            for m in tar.getmembers():
                infos[m.name] = m
                members_data[m.name] = tar.extractfile(m).read()
        mutate_members(members_data, infos)

        out_path = self.tmp_path / "mutated.tar"
        with tarfile.open(out_path, mode="w", format=tarfile.GNU_FORMAT) as tar:
            for name in sorted(members_data.keys()):
                data = members_data[name]
                orig = infos[name]
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                info.mtime = orig.mtime
                info.uid = orig.uid
                info.gid = orig.gid
                info.uname = orig.uname
                info.gname = orig.gname
                info.mode = orig.mode
                info.type = tarfile.REGTYPE
                import io
                tar.addfile(info, io.BytesIO(data))
        return out_path

    def test_tampered_case_bytes_fails(self):
        def mutate(members, infos):
            members["inputs/repo-requests/input.bin"] = b"tampered"

        path = self._mutated_bundle(mutate)
        ok, message = verifier.verify(bundle_path=path)
        self.assertFalse(ok)

    def test_tampered_manifest_self_hash_fails(self):
        def mutate(members, infos):
            manifest = json.loads(members["manifest.json"])
            manifest["case_count"] = 99
            members["manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")

        path = self._mutated_bundle(mutate)
        ok, message = verifier.verify(bundle_path=path)
        self.assertFalse(ok)
        self.assertIn("self-hash", message)

    def test_wrong_mtime_fails(self):
        def mutate(members, infos):
            infos["inputs/repo-requests/input.bin"].mtime = 0

        path = self._mutated_bundle(mutate)
        ok, message = verifier.verify(bundle_path=path)
        self.assertFalse(ok)
        self.assertIn("mtime", message)

    def test_wrong_uname_fails(self):
        def mutate(members, infos):
            infos["inputs/repo-requests/input.bin"].uname = "root"

        path = self._mutated_bundle(mutate)
        ok, message = verifier.verify(bundle_path=path)
        self.assertFalse(ok)
        self.assertIn("uname", message)

    def test_missing_case_member_fails(self):
        def mutate(members, infos):
            del members["inputs/repo-requests/input.bin"]
            del infos["inputs/repo-requests/input.bin"]
            manifest = json.loads(members["manifest.json"])
            del manifest["cases"]["repo-requests"]
            manifest["case_count"] = 17
            members["manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")

        path = self._mutated_bundle(mutate)
        ok, message = verifier.verify(bundle_path=path)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
