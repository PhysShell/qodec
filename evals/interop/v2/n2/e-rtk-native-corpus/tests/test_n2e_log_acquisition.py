"""Bounded streaming acquisition for the Loghub full-stream capsule: the pinned member is
stream-extracted (no whole-file read, no 1500-line slice) and its uncompressed byte count +
streaming sha256 + line count are the input identity both arms share. Unit-tests the network-free
core (stream_digest, extract_member_streaming); the full acquire_loghub download is exercised in CI.
"""
import hashlib
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_log_evidence_capsule as cap  # noqa: E402


class TestStreamDigest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def _digest(self, data):
        p = self.d / "f"; p.write_bytes(data)
        return cap.stream_digest(p, chunk_bytes=8)  # tiny chunk -> exercises chunk-boundary counting

    def test_sha_bytes_lines_terminated(self):
        data = b"line1\nline2\nline3\n"
        dg = self._digest(data)
        self.assertEqual(dg["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(dg["bytes"], len(data))
        self.assertEqual(dg["line_count"], 3)

    def test_final_unterminated_line_counts(self):
        dg = self._digest(b"a\nb\nc")  # no trailing newline -> 3 lines
        self.assertEqual(dg["line_count"], 3)

    def test_empty(self):
        dg = self._digest(b"")
        self.assertEqual(dg["line_count"], 0)
        self.assertEqual(dg["bytes"], 0)


class TestMemberExtraction(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.zip = self.d / "a.zip"
        self.payload = b"081109 203615 148 INFO x: Receiving block blk_1 src: /a:1 dest: /b:2\n" * 100
        with zipfile.ZipFile(self.zip, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("HDFS/HDFS_full.log", self.payload)
            z.writestr("HDFS/other.csv", b"noise")

    def test_extracts_member_streaming(self):
        dest = self.d / "out.log"
        n = cap.extract_member_streaming(self.zip, "HDFS/HDFS_full.log", dest,
                                         expected_bytes=len(self.payload), chunk_bytes=64)
        self.assertEqual(n, len(self.payload))
        self.assertEqual(dest.read_bytes(), self.payload)

    def test_wrong_expected_bytes_rejected(self):
        dest = self.d / "out.log"
        with self.assertRaises(cap.LogCapsuleError):
            cap.extract_member_streaming(self.zip, "HDFS/HDFS_full.log", dest, expected_bytes=len(self.payload) + 1)

    def test_unsafe_member_path_rejected(self):
        with self.assertRaises(cap.LogCapsuleError):
            cap.extract_member_streaming(self.zip, "../escape", self.d / "x")

    def test_extract_then_digest_roundtrip(self):
        dest = self.d / "out.log"
        cap.extract_member_streaming(self.zip, "HDFS/HDFS_full.log", dest, expected_bytes=len(self.payload))
        dg = cap.stream_digest(dest)
        self.assertEqual(dg["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(dg["line_count"], 100)


if __name__ == "__main__":
    unittest.main()
