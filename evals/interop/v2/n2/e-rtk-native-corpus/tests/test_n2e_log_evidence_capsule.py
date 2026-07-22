"""log-evidence-capsule-v1: the bounded, independently-verifiable representation of a large log
stream. Proves the two-path invariant BEFORE any CI run: the full stream is hashed to EOF (never
truncated), the semantic summary is bounded (capped template table, fail-closed on overflow), and
every excerpt is anchored to the stream by byte range + chunk hash + Merkle proof. Line framing is
correct across chunk boundaries; the masking canon collapses only declared noise and never a real
message difference.
"""
import hashlib
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_log_evidence_capsule as cap  # noqa: E402

# a tiny synthetic HDFS log: 2 templates (block ids masked) + 1 WARN + 1 unparsed line
HDFS = (
    b"081109 203615 148 INFO dfs.DataNode: Receiving block blk_1 src: /10.0.0.1:5 dest: /10.0.0.2:6\n"
    b"081109 203807 222 INFO dfs.DataNode: Receiving block blk_2 src: /10.0.0.3:7 dest: /10.0.0.4:8\n"
    b"081109 204005 333 WARN dfs.DataNode: PacketResponder blk_3 Interrupted\n"
    b"this is not an hdfs line at all\n"
)


def _reroot(leaf_hex: str, proof: list[dict]) -> str:
    h = bytes.fromhex(leaf_hex)
    for step in proof:
        sib = bytes.fromhex(step["hash"])
        h = hashlib.sha256((h + sib) if step["side"] == "right" else (sib + h)).digest()
    return h.hex()


class TestStreamingHash(unittest.TestCase):
    def test_full_byte_hash_matches_and_reads_to_eof(self):
        c = cap.build_capsule(HDFS, "raw", ["cat", "HDFS.log"], 0)
        self.assertEqual(c["stream"]["sha256"], hashlib.sha256(HDFS).hexdigest())
        self.assertEqual(c["stream"]["bytes"], len(HDFS))
        self.assertTrue(c["stream"]["read_to_eof"])

    def test_chunk_boundary_framing_is_transparent(self):
        # feed the SAME bytes split at a boundary that cuts a line in half; the summary must match a
        # whole-read summary (residual buffer across chunks), and the hash must be identical.
        whole = cap._Collector()
        whole.feed(HDFS); whole.finish()
        split = cap._Collector()
        cut = 50  # mid first line
        split.feed(HDFS[:cut]); split.feed(HDFS[cut:]); split.finish()
        self.assertEqual(whole.stream_sha256, split.stream_sha256)
        self.assertEqual(whole.summary()["summary_sha256"], split.summary()["summary_sha256"])
        self.assertEqual(whole.total_lines, split.total_lines)

    def test_empty_stream(self):
        c = cap.build_capsule(b"", "raw", ["cat", "x"], 0)
        self.assertEqual(c["stream"]["bytes"], 0)
        self.assertEqual(c["stream"]["chunking"]["chunk_count"], 0)
        self.assertEqual(c["summary"]["total_lines"], 0)
        self.assertTrue(c["stream"]["read_to_eof"])


class TestSemanticSummary(unittest.TestCase):
    def setUp(self):
        self.c = cap.build_capsule(HDFS, "raw", ["cat", "HDFS.log"], 0)
        self.s = self.c["summary"]

    def test_severity_counts(self):
        self.assertEqual(self.s["severity_counts"]["INFO"], 2)
        self.assertEqual(self.s["severity_counts"]["WARN"], 1)
        self.assertEqual(self.s["severity_counts"]["unparsed"], 1)

    def test_block_ids_masked_to_one_template(self):
        # the two INFO "Receiving block blk_N ..." lines differ only in masked noise -> one template
        self.assertEqual(self.s["total_lines"], 4)
        # 3 templates: the two-INFO one, the WARN one, and <unparsed>
        self.assertEqual(self.s["unique_template_count"], 3)
        # the shared INFO template has occurrence 2
        self.assertIn(2, self.s["occurrence_counts"].values())

    def test_real_message_difference_survives_masking(self):
        a = cap.build_capsule(b"081109 203615 148 INFO x: alpha blk_1\n", "raw", ["cat"], 0)["summary"]
        b = cap.build_capsule(b"081109 203615 148 INFO x: beta blk_1\n", "raw", ["cat"], 0)["summary"]
        self.assertNotEqual(a["unique_template_ids"], b["unique_template_ids"])

    def test_first_last_occurrence_tracked(self):
        info_tid = next(t for t, n in self.s["occurrence_counts"].items() if n == 2)
        fl = self.s["first_last_occurrence"][info_tid]
        self.assertEqual(fl["first"]["line"], 1)
        self.assertEqual(fl["last"]["line"], 2)
        self.assertLess(fl["first"]["byte_start"], fl["last"]["byte_start"])

    def test_unparsed_line_counted_not_dropped(self):
        self.assertIn("unparsed", self.s["severity_counts"])


class TestBoundedFailClosed(unittest.TestCase):
    def test_template_cardinality_overflow_fails_closed_but_reads_to_eof(self):
        # generate > TEMPLATE_CAP distinct templates (distinct unmaskable words); the hash must still
        # reach EOF (full byte count) while the semantic summary is DISQUALIFIED, never a silent pass.
        n = cap.TEMPLATE_CAP + 50
        blob = b"".join(f"081109 203615 148 INFO comp{i}: fixed message\n".encode() for i in range(n))
        c = cap.build_capsule(blob, "raw", ["cat"], 0)
        self.assertEqual(c["stream"]["bytes"], len(blob))
        self.assertEqual(c["stream"]["sha256"], hashlib.sha256(blob).hexdigest())
        self.assertTrue(c["summary"]["overflow"])
        self.assertEqual(c["summary"]["outcome"], "DISQUALIFIED_TEMPLATE_CARDINALITY")
        self.assertLessEqual(c["summary"]["unique_template_count"], cap.TEMPLATE_CAP)


class TestExcerptAnchoring(unittest.TestCase):
    def test_excerpts_bounded_and_anchored(self):
        c = cap.build_capsule(HDFS, "raw", ["cat", "HDFS.log"], 0)
        self.assertLessEqual(len(c["excerpts"]), cap.MAX_EXCERPTS)
        for ex in c["excerpts"]:
            # content == the exact stream bytes at [byte_start, byte_end)
            window = HDFS[ex["byte_start"]:ex["byte_end"]]
            self.assertEqual(ex["content"], window.decode("utf-8", "replace"))
            self.assertEqual(ex["sha256"], hashlib.sha256(window).hexdigest())
            self.assertLessEqual(ex["byte_end"] - ex["byte_start"], cap.MAX_EXCERPT_BYTES)

    def test_excerpt_chunk_hash_and_merkle_proof_reroot(self):
        # a multi-chunk stream so chunk anchoring is non-trivial; re-root every excerpt proof
        big = HDFS * 20000  # a few MiB -> multiple 1 MiB chunks
        c = cap.build_capsule(big, "raw", ["cat"], 0)
        root = c["stream"]["chunking"]["merkle_root"]
        self.assertGreater(c["stream"]["chunking"]["chunk_count"], 1)
        for ex in c["excerpts"]:
            self.assertEqual(_reroot(ex["chunk_sha256"], ex["merkle_proof"]), root)


if __name__ == "__main__":
    unittest.main()


import copy  # noqa: E402
import verify_n2e_log_evidence_capsule as vcap  # noqa: E402


class TestVerifierReplay(unittest.TestCase):
    def setUp(self):
        self.src = HDFS * 20000            # multi-chunk so Merkle/excerpt anchoring is non-trivial
        self.c = cap.build_capsule(self.src, "raw", ["cat", "HDFS.log"], 0)

    def test_green_faithful_capsule_verifies(self):
        f = vcap.verify(self.c, self.src)
        self.assertEqual(f["bytes"], len(self.src))
        self.assertEqual(f["outcome"], "parsed")

    def test_red_byte_undercount_claiming_eof(self):
        bad = copy.deepcopy(self.c)
        bad["stream"]["bytes"] -= 100        # claims read_to_eof but under-counts
        with self.assertRaises(vcap.LogCapsuleVerifyError):
            vcap.verify(bad, self.src)

    def test_red_tampered_full_hash(self):
        bad = copy.deepcopy(self.c); bad["stream"]["sha256"] = "0" * 64
        with self.assertRaises(vcap.LogCapsuleVerifyError):
            vcap.verify(bad, self.src)

    def test_red_tampered_merkle_root(self):
        bad = copy.deepcopy(self.c); bad["stream"]["chunking"]["merkle_root"] = "0" * 64
        with self.assertRaises(vcap.LogCapsuleVerifyError):
            vcap.verify(bad, self.src)

    def test_red_mutated_summary(self):
        bad = copy.deepcopy(self.c); bad["summary"]["severity_counts"]["INFO"] += 1
        with self.assertRaises(vcap.LogCapsuleVerifyError):
            vcap.verify(bad, self.src)

    def test_red_forged_excerpt_content(self):
        bad = copy.deepcopy(self.c)
        if not bad["excerpts"]:
            self.skipTest("no excerpts")
        bad["excerpts"][0]["content"] = "forged line not in the stream\n"
        with self.assertRaises(vcap.LogCapsuleVerifyError):
            vcap.verify(bad, self.src)

    def test_red_canon_module_drift(self):
        bad = copy.deepcopy(self.c); bad["canon"]["module_sha256"] = "f" * 64
        with self.assertRaises(vcap.LogCapsuleVerifyError):
            vcap.verify(bad, self.src)

    def test_red_source_swapped_under_capsule(self):
        # the capsule is faithful to self.src, but verifying it against a DIFFERENT stream fails
        with self.assertRaises(vcap.LogCapsuleVerifyError):
            vcap.verify(self.c, self.src + b"081109 203615 148 ERROR x: extra\n")
