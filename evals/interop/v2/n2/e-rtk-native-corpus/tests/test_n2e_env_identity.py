"""Correction #2 regression tests: exact environment identity + protected-file
mutation guards + RuboCop-style merge-representation git-acquisition evidence.

These exercise the driver helpers directly against a tiny local git repo so the
merge/parent/output-identity evidence is proven without any network fetch.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import run_canary_case as R  # noqa: E402


def _git(repo, *args, env=None):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True, env=env)


def _make_merge_repo(root: Path, home: Path):
    """Build a repo whose HEAD is a real merge commit with two parents."""
    env = R._git_env(home)
    subprocess.run(["git", "init", "-q", str(root)], check=True, env=env)
    (root / "base.txt").write_text("base\n")
    _git(root, "add", "-A", env=env)
    _git(root, "commit", "-q", "-m", "base", env=env)
    _git(root, "branch", "-q", "-M", "main", env=env)
    _git(root, "checkout", "-q", "-b", "feature", env=env)
    (root / "feature.txt").write_text("feature\n")
    _git(root, "add", "-A", env=env)
    _git(root, "commit", "-q", "-m", "feature", env=env)
    _git(root, "checkout", "-q", "main", env=env)
    (root / "other.txt").write_text("other\n")
    _git(root, "add", "-A", env=env)
    _git(root, "commit", "-q", "-m", "other", env=env)
    _git(root, "merge", "-q", "--no-ff", "-m", "merge feature", "feature", env=env)
    return _git(root, "rev-parse", "HEAD", env=env).stdout.strip()


class TestGitAcquisitionEvidence(unittest.TestCase):
    def test_merge_representation_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"
            home = Path(td) / "home"
            home.mkdir()
            commit = _make_merge_repo(root, home)
            ev = R._git_acquisition_evidence(root, home, commit, "show", 2,
                                             ["git", "show"])
            self.assertTrue(ev["head_matches_pin"])
            self.assertEqual(ev["commit_type"], "commit")
            self.assertTrue(ev["is_merge_commit"])
            self.assertEqual(ev["parent_count"], 2)
            self.assertTrue(ev["all_parents_present"])
            self.assertTrue(ev["intended_merge_representation"])
            # output identity is captured and reproducible
            self.assertEqual(len(ev["show_output_sha256"]), 64)
            self.assertIsInstance(ev["show_output_bytes"], int)
            self.assertEqual(ev["show_effective_argv"], ["git", "show"])
            ev2 = R._git_acquisition_evidence(root, home, commit, "show", 2,
                                              ["git", "show"])
            self.assertEqual(ev["show_output_sha256"], ev2["show_output_sha256"])

    def test_non_merge_is_not_flagged_as_merge(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"
            home = Path(td) / "home"
            home.mkdir()
            env = R._git_env(home)
            subprocess.run(["git", "init", "-q", str(root)], check=True, env=env)
            (root / "a.txt").write_text("a\n")
            _git(root, "add", "-A", env=env)
            _git(root, "commit", "-q", "-m", "a", env=env)
            (root / "b.txt").write_text("b\n")
            _git(root, "add", "-A", env=env)
            _git(root, "commit", "-q", "-m", "b", env=env)
            commit = _git(root, "rev-parse", "HEAD", env=env).stdout.strip()
            ev = R._git_acquisition_evidence(root, home, commit, "show", 2,
                                             ["git", "show"])
            self.assertFalse(ev["is_merge_commit"])
            self.assertEqual(ev["parent_count"], 1)
            self.assertTrue(ev["intended_merge_representation"])  # non-merge is trivially intended


class TestProtectedFileMutationGuard(unittest.TestCase):
    def test_protected_hashes_and_mutation_detection(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "go.mod").write_text("module x\n")
            before = R._protected_hashes(repo, "go")
            self.assertIsNotNone(before["go.mod"])
            self.assertIsNone(before["go.sum"])  # absent -> None, still tracked as a key
            after_same = R._protected_hashes(repo, "go")
            self.assertEqual(before, after_same)  # guard_ok
            (repo / "go.mod").write_text("module x\nrequire y v1\n")
            after_diff = R._protected_hashes(repo, "go")
            self.assertNotEqual(before, after_diff)  # mutation detected


if __name__ == "__main__":
    unittest.main()
