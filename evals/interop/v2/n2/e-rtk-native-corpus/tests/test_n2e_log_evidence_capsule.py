"""log-evidence-capsule-v1: bounded, independently-verifiable representation of a large log stream,
with template identity GROUNDED in the published Loghub HDFS set (n2e-loghub-hdfs-reference-v1), not
our masking canon. Proves the two-path invariant + the published-authority rules BEFORE any CI run:
the full stream is hashed to EOF (never truncated); each line's EventId is assigned by EXACTLY-ONE
match against the published templates (0/>1 -> fail-closed); the published Occurrences are the
occurrence-count authority; masking is a diagnostic cross-check only; every excerpt is anchored to
the stream by byte range + chunk hash + Merkle proof.
"""
import copy
import hashlib
import re
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_log_evidence_capsule as cap  # noqa: E402
import verify_n2e_log_evidence_capsule as vcap  # noqa: E402

# real HDFS lines that match published templates E42 (Receiving block ...) + E31 (PacketResponder ... terminating)
HDFS = (
    b"081109 203615 148 INFO dfs.DataNode: Receiving block blk_1 src: /10.0.0.1:50010 dest: /10.0.0.2:50010\n"
    b"081109 203807 222 INFO dfs.DataNode: PacketResponder 1 for block blk_9 terminating\n"
    b"081109 203807 222 INFO dfs.DataNode: Receiving block blk_2 src: /10.0.0.3:1 dest: /10.0.0.4:2\n"
)


def _custom_ref(templates: dict, published: dict) -> dict:
    matchers = {e: cap._template_to_regex(t) for e, t in templates.items()}
    body = "".join(str(v) for v in published.values()).encode()
    return {"sha256": hashlib.sha256(body).hexdigest(), "event_ids": sorted(templates),
            "published": published, "templates": templates, "matchers": matchers, "record": {}}


def _reroot(leaf_hex, proof):
    h = bytes.fromhex(leaf_hex)
    for step in proof:
        sib = bytes.fromhex(step["hash"])
        h = hashlib.sha256((h + sib) if step["side"] == "right" else (sib + h)).digest()
    return h.hex()


class TestReferenceAuthority(unittest.TestCase):
    def test_reference_self_check_and_46_templates(self):
        ref = cap.load_reference()
        self.assertEqual(len(ref["event_ids"]), 46)
        self.assertEqual(ref["sha256"], "0a105b8dd2f8d3784faada4443c726e6e4aec76f9c8a14298d5e3b8295b4aa63")
        self.assertEqual(sum(ref["published"].values()), 11167740)  # == full HDFS line count

    def test_exactly_one_match(self):
        ref = cap.load_reference()
        self.assertEqual(cap.assign_event_id("Receiving block blk_1 src: /a:1 dest: /b:2", ref["matchers"]), ("E42", 1))
        self.assertEqual(cap.assign_event_id("PacketResponder 1 for block blk_9 terminating", ref["matchers"]), ("E31", 1))
        self.assertEqual(cap.assign_event_id("nothing published matches this", ref["matchers"])[0], "<unmatched>")

    def test_ambiguous_rejected(self):
        # two published templates that BOTH full-match the same content -> <ambiguous>
        ref = _custom_ref({"A": "foo <*>", "B": "foo bar <*>"}, {"A": 1, "B": 1})
        eid, n = cap.assign_event_id("foo bar baz", ref["matchers"])
        self.assertEqual(eid, "<ambiguous>")
        self.assertGreaterEqual(n, 2)


class TestStreamingHash(unittest.TestCase):
    def test_full_byte_hash_and_eof(self):
        c = cap.build_capsule(HDFS, "raw", ["cat", "HDFS.log"], 0)
        self.assertEqual(c["stream"]["sha256"], hashlib.sha256(HDFS).hexdigest())
        self.assertEqual(c["stream"]["bytes"], len(HDFS))
        self.assertTrue(c["stream"]["read_to_eof"])

    def test_chunk_boundary_framing_transparent(self):
        ref = cap.load_reference()
        whole = cap._Collector(ref); whole.feed(HDFS); whole.finish()
        split = cap._Collector(ref); split.feed(HDFS[:50]); split.feed(HDFS[50:]); split.finish()
        self.assertEqual(whole.stream_sha256, split.stream_sha256)
        self.assertEqual(whole.summary()["summary_sha256"], split.summary()["summary_sha256"])

    def test_empty_stream(self):
        c = cap.build_capsule(b"", "raw", ["cat", "x"], 0)
        self.assertEqual(c["stream"]["bytes"], 0)
        self.assertEqual(c["stream"]["chunking"]["chunk_count"], 0)
        self.assertEqual(c["summary"]["total_lines"], 0)


class TestSemanticSummary(unittest.TestCase):
    def setUp(self):
        self.c = cap.build_capsule(HDFS, "raw", ["cat", "HDFS.log"], 0)
        self.s = self.c["summary"]

    def test_published_event_ids_observed(self):
        self.assertEqual(self.s["observed_event_ids"], ["E31", "E42"])
        self.assertEqual(self.s["streamed_occurrence_counts"], {"E31": 1, "E42": 2})

    def test_occurrence_authority_is_published(self):
        # the published counts for the observed ids come from the reference authority (not our stream)
        ref = cap.load_reference()
        self.assertEqual(self.s["published_occurrence_counts"]["E42"], ref["published"]["E42"])

    def test_partial_stream_flagged_not_full(self):
        # a partial stream is valid but streamed != published -> outcome streamed_partial, not parsed
        self.assertEqual(self.s["outcome"], "streamed_partial")
        self.assertFalse(self.s["occurrence_counts_match_published"])

    def test_severity_and_first_last(self):
        self.assertEqual(self.s["severity_counts"]["INFO"], 3)
        fl = self.s["first_last_occurrence"]["E42"]
        self.assertEqual(fl["first"]["line"], 1)
        self.assertEqual(fl["last"]["line"], 3)

    def test_masking_is_diagnostic_only(self):
        self.assertFalse(self.s["masking_cross_check"]["authority"])


class TestFailClosed(unittest.TestCase):
    def test_unmatched_line_disqualifies(self):
        blob = HDFS + b"081109 203615 148 INFO x: a line no published template matches at all\n"
        c = cap.build_capsule(blob, "raw", ["cat"], 0)
        self.assertGreaterEqual(c["summary"]["unmatched_lines"], 1)
        self.assertEqual(c["summary"]["outcome"], "DISQUALIFIED_UNMATCHED_OR_AMBIGUOUS")
        # the hash still reached EOF -- bounded record, not a truncated data region
        self.assertEqual(c["stream"]["bytes"], len(blob))

    def test_full_stream_match_published_is_parsed(self):
        # a custom reference whose published Occurrences EXACTLY equal a small synthetic stream ->
        # outcome 'parsed' + occurrence_counts_match_published True (the full-log acceptance shape)
        ref = _custom_ref({"A": "alpha <*>", "B": "beta <*>"}, {"A": 2, "B": 1})
        blob = (b"081109 203615 148 INFO c: alpha 1\n081109 203615 148 INFO c: alpha 2\n"
                b"081109 203615 148 WARN c: beta 9\n")
        c = cap.build_capsule(blob, "raw", ["cat"], 0, reference=ref)
        self.assertEqual(c["summary"]["outcome"], "parsed")
        self.assertTrue(c["summary"]["occurrence_counts_match_published"])
        self.assertEqual(c["summary"]["streamed_occurrence_counts"], {"A": 2, "B": 1})


class TestExcerpts(unittest.TestCase):
    def test_excerpts_bounded_and_anchored(self):
        c = cap.build_capsule(HDFS, "raw", ["cat"], 0)
        self.assertLessEqual(len(c["excerpts"]), cap.MAX_EXCERPTS)
        for ex in c["excerpts"]:
            window = HDFS[ex["byte_start"]:ex["byte_end"]]
            self.assertEqual(ex["content"], window.decode("utf-8", "replace"))
            self.assertEqual(ex["sha256"], hashlib.sha256(window).hexdigest())
            self.assertIn(ex["event_id"], c["summary"]["observed_event_ids"])

    def test_merkle_reroot_multichunk(self):
        big = HDFS * 20000
        c = cap.build_capsule(big, "raw", ["cat"], 0)
        root = c["stream"]["chunking"]["merkle_root"]
        self.assertGreater(c["stream"]["chunking"]["chunk_count"], 1)
        for ex in c["excerpts"]:
            self.assertEqual(_reroot(ex["chunk_sha256"], ex["merkle_proof"]), root)


class TestVerifierReplay(unittest.TestCase):
    def setUp(self):
        self.src = HDFS * 20000
        self.c = cap.build_capsule(self.src, "raw", ["cat", "HDFS.log"], 0)

    def test_green(self):
        f = vcap.verify(self.c, self.src)
        self.assertEqual(f["bytes"], len(self.src))

    def test_red_byte_undercount(self):
        bad = copy.deepcopy(self.c); bad["stream"]["bytes"] -= 100
        with self.assertRaises(vcap.LogCapsuleVerifyError):
            vcap.verify(bad, self.src)

    def test_red_tampered_hash(self):
        bad = copy.deepcopy(self.c); bad["stream"]["sha256"] = "0" * 64
        with self.assertRaises(vcap.LogCapsuleVerifyError):
            vcap.verify(bad, self.src)

    def test_red_mutated_summary(self):
        bad = copy.deepcopy(self.c); bad["summary"]["severity_counts"]["INFO"] += 1
        with self.assertRaises(vcap.LogCapsuleVerifyError):
            vcap.verify(bad, self.src)

    def test_red_forged_excerpt(self):
        bad = copy.deepcopy(self.c)
        if not bad["excerpts"]:
            self.skipTest("no excerpts")
        bad["excerpts"][0]["content"] = "forged\n"
        with self.assertRaises(vcap.LogCapsuleVerifyError):
            vcap.verify(bad, self.src)

    def test_red_reference_drift(self):
        bad = copy.deepcopy(self.c); bad["canon"]["reference_sha256"] = "f" * 64
        with self.assertRaises(vcap.LogCapsuleVerifyError):
            vcap.verify(bad, self.src)

    def test_red_source_swapped(self):
        with self.assertRaises(vcap.LogCapsuleVerifyError):
            vcap.verify(self.c, self.src + b"081109 203615 148 INFO x: Receiving block blk_9 src: /a:1 dest: /b:2\n")


if __name__ == "__main__":
    unittest.main()
