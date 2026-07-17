"""Unit tests for source_mtime_materialization.py -- the repo-requests-only
deterministic ZIP-safe source metadata materialization fixture (D1b
remediation round 2, 2026-07-17).
"""
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import source_mtime_materialization as smm  # noqa: E402

BASE_DIR = Path(__file__).resolve().parents[1]
POLICY_PATH = BASE_DIR / "source-mtime-materialization-policy-v1.json"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TestMaterializeSourceMtimes(unittest.TestCase):
    def _make_tree(self, root: Path):
        (root / "sub").mkdir(parents=True)
        regular = root / "a.txt"
        regular.write_bytes(b"hello world\n")
        nested = root / "sub" / "b.py"
        nested.write_bytes(b"print('hi')\n")
        executable = root / "run.sh"
        executable.write_bytes(b"#!/bin/sh\necho hi\n")
        executable.chmod(0o755)
        # Every extracted file starts at Unix epoch 0 -- the real defect.
        epoch_zero = 0
        for p in (regular, nested, executable):
            os.utime(p, (epoch_zero, epoch_zero))
        link_target = root / "a.txt"
        link = root / "link_to_a.txt"
        link.symlink_to(link_target)
        return {"regular": regular, "nested": nested, "executable": executable, "link": link}

    def test_source_file_content_hashes_are_identical_before_and_after(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._make_tree(root)
            before = {name: _sha256(p.read_bytes()) for name, p in paths.items() if name != "link"}
            smm.materialize_source_mtimes(case_id="repo-requests", source_root=root)
            after = {name: _sha256(p.read_bytes()) for name, p in paths.items() if name != "link"}
            self.assertEqual(before, after)

    def test_modes_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._make_tree(root)
            before_mode = stat.S_IMODE(paths["executable"].stat().st_mode)
            smm.materialize_source_mtimes(case_id="repo-requests", source_root=root)
            after_mode = stat.S_IMODE(paths["executable"].stat().st_mode)
            self.assertEqual(before_mode, after_mode)
            self.assertTrue(after_mode & stat.S_IXUSR)

    def test_symlinks_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._make_tree(root)
            before_target = os.readlink(paths["link"])
            before_link_mtime = os.lstat(paths["link"]).st_mtime
            smm.materialize_source_mtimes(case_id="repo-requests", source_root=root)
            after_target = os.readlink(paths["link"])
            after_link_mtime = os.lstat(paths["link"]).st_mtime
            self.assertEqual(before_target, after_target)
            # The symlink's OWN mtime (lstat, not stat) must be untouched --
            # this policy never dereferences or rewrites symlinks.
            self.assertEqual(before_link_mtime, after_link_mtime)

    def test_mtimes_become_the_exact_fixed_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._make_tree(root)
            smm.materialize_source_mtimes(case_id="repo-requests", source_root=root)
            expected_epoch = smm._iso8601_utc_to_epoch_seconds("2000-01-01T00:00:00Z")
            for name in ("regular", "nested", "executable"):
                self.assertEqual(int(paths[name].stat().st_mtime), expected_epoch)

    def test_a_file_with_the_resulting_timestamp_can_be_added_through_python_zipfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._make_tree(root)
            smm.materialize_source_mtimes(case_id="repo-requests", source_root=root)
            zip_path = root / "out.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                # This is exactly what raised "ValueError: ZIP does not
                # support timestamps before 1980" before materialization.
                zf.write(paths["regular"], arcname="a.txt")
            with zipfile.ZipFile(zip_path) as zf:
                self.assertIn("a.txt", zf.namelist())

    def test_policy_cannot_apply_to_another_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._make_tree(root)
            with self.assertRaises(smm.MtimeMaterializationError):
                smm.materialize_source_mtimes(case_id="repo-pyflakes", source_root=root)

    def test_report_records_exact_epoch_and_affected_file_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._make_tree(root)
            report = smm.materialize_source_mtimes(case_id="repo-requests", source_root=root)
            self.assertEqual(report["fixed_timestamp_iso8601_utc"], "2000-01-01T00:00:00Z")
            self.assertEqual(report["fixed_timestamp_epoch_seconds"], 946684800)
            # 3 regular files -- the symlink is not counted (it is skipped).
            self.assertEqual(report["affected_file_count"], 3)
            self.assertEqual(len(report["affected_relative_paths"]), 3)

    def test_only_repo_requests_is_authorized(self):
        self.assertEqual(set(smm.MTIME_MATERIALIZATION_AUTHORIZED_CASES), {"repo-requests"})

    def test_fixed_timestamp_is_safely_later_than_1980(self):
        epoch_1980 = smm._iso8601_utc_to_epoch_seconds("1980-01-01T00:00:00Z")
        for ts in smm.MTIME_MATERIALIZATION_AUTHORIZED_CASES.values():
            self.assertGreater(smm._iso8601_utc_to_epoch_seconds(ts), epoch_1980)


class TestPolicyRecordIsCommittedAndSelfConsistent(unittest.TestCase):
    def test_policy_file_exists(self):
        self.assertTrue(POLICY_PATH.is_file())

    def test_policy_loads_and_verifies(self):
        body = smm.load_and_verify_policy(POLICY_PATH)
        self.assertEqual(body["policy_identity"], "n2d1b-repo-requests-source-mtime-materialization-v1")

    def test_tampered_self_hash_fails_closed(self):
        body = json.loads(POLICY_PATH.read_text())
        body["policy_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as tmp:
            tampered = Path(tmp) / "tampered.json"
            tampered.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
            with self.assertRaises(smm.PolicyIntegrityError):
                smm.load_and_verify_policy(tampered)

    def test_tampered_applicable_case_ids_fails_closed(self):
        body = json.loads(POLICY_PATH.read_text())
        body["applicable_case_ids"] = {"repo-requests": "2000-01-01T00:00:00Z", "repo-pyflakes": "2000-01-01T00:00:00Z"}
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        body["policy_sha256"] = hashlib.sha256((json.dumps(without_hash, indent=2, sort_keys=True) + "\n").encode()).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            tampered = Path(tmp) / "tampered.json"
            tampered.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
            with self.assertRaises(smm.PolicyIntegrityError):
                smm.load_and_verify_policy(tampered)

    def test_tampered_timestamp_fails_closed(self):
        body = json.loads(POLICY_PATH.read_text())
        body["applicable_case_ids"] = {"repo-requests": "1999-01-01T00:00:00Z"}
        without_hash = {k: v for k, v in body.items() if k != "policy_sha256"}
        body["policy_sha256"] = hashlib.sha256((json.dumps(without_hash, indent=2, sort_keys=True) + "\n").encode()).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            tampered = Path(tmp) / "tampered.json"
            tampered.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
            with self.assertRaises(smm.PolicyIntegrityError):
                smm.load_and_verify_policy(tampered)


if __name__ == "__main__":
    unittest.main()
