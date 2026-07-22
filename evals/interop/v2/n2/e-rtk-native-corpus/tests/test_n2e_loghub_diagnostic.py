"""Loghub diagnostic-only capture: streams the RAW arm through the capsule collector (stdout never
buffered whole), captures the small RTK arm, and emits a diagnostic record_kind that the qualification
verifier rejects UNCONDITIONALLY. The diagnostic moves no gate; it validates parse_rtk against real
output at CI time.
"""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import probe_loghub_diagnostic as D  # noqa: E402
import n2e_log_evidence_capsule as lcap  # noqa: E402
import verify_case_qualification as vq  # noqa: E402


class TestStreamingRunner(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.payload = (b"081109 203615 148 INFO dfs.DataNode: Receiving block blk_1 src: /a:1 dest: /b:2\n"
                        b"081109 203615 148 WARN dfs.DataNode: PacketResponder 2 2 Exception java.io.IOException: Broken pipe\n") * 40
        (self.d / "HDFS.log").write_bytes(self.payload)

    def test_streams_without_buffering_whole(self):
        import hashlib
        col = lcap._Collector(lcap.load_reference())
        res = D._stream_isolated(["cat", "HDFS.log"], str(self.d), [], col.feed, 60)
        col.finish()
        self.assertEqual(res["exit_code"], 0)
        self.assertFalse(res["timed_out"])
        self.assertEqual(col.stream_sha256, hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(col.total_lines, 80)
        self.assertEqual(col.summary()["rtk_semantic_projection"], {"error": 0, "warn": 40, "info": 40, "other": 0})


class TestBarredFromQualification(unittest.TestCase):
    def test_diag_record_kind_is_not_acceptance(self):
        self.assertNotEqual(D.DIAG_RECORD_KIND, "resolved_case_qualification_acceptance")

    def test_qualification_verifier_rejects_diagnostic_record(self):
        # a diagnostic capture (wrong record_type + record_kind + outcome) is UNCONDITIONALLY rejected
        # by the qualification verifier -- so a diagnostic artifact can never be laundered into a PASS
        ev = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, ev, ignore_errors=True)
        (ev / "raw.canonical.bin").write_bytes(b"")
        (ev / "rtk.canonical.bin").write_bytes(b"")
        recdir = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, recdir, ignore_errors=True)
        p = recdir / "diag.json"
        c.write_record(p, c.envelope(
            record_type="n2e-loghub-diagnostic-capture", generated_by="test",
            case_id="loghub::HDFS::log", record_kind=D.DIAG_RECORD_KIND,
            barred_from_qualification=True, outcome="LOGHUB_DIAGNOSTIC_OBSERVED"))
        ok, fail, _ = vq.verify(p, ev)
        self.assertFalse(ok)

    def test_barred_record_kind_string(self):
        self.assertEqual(D.DIAG_RECORD_KIND, "loghub_diagnostic_capture")


if __name__ == "__main__":
    unittest.main()
