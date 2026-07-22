"""Builder gates for the loghub dispatch-v2 qualification record (Loghub step 6, checkpoint 2).

The builder assembles the record from a FRESH acceptance observation and must fail closed on a dirty
observation (GATE 1) and only succeed when the freshly built record independently binds + recomputes
True through dispatch-v2 (GATE 2). The RTK measurement here is stood in by the frozen real fixture
(the same bytes a fresh `rtk log` run reproduces); the network two-arm run is a CI concern, not a
unit-test one. Every created artifact is removed in cleanup so no synthetic record leaks into the
disk aggregator used by sibling tests.
"""
import copy
import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import build_n2e_loghub_dispatch_qualification as BLD  # noqa: E402

FIXTURE = N2E_DIR / "evidence" / "loghub-diag" / "rtk-log-summary.real.txt"
REAL_TOTALS = {"error": 5545, "warn": 356273, "info": 10805922, "other": 0}
OUT_RECORD = N2E_DIR / "n2e-resolved-case-qualification-loghub-v1.json"
OUT_EVDIR = N2E_DIR / "evidence" / "loghub"


def _observation(**over) -> dict:
    fix = FIXTURE.read_bytes()
    body = {
        "case_id": "loghub::HDFS::log", "record_kind": "loghub_acceptance_capture",
        "barred_from_qualification": False, "outcome": "LOGHUB_ACCEPTANCE_OBSERVED",
        "rtk_binary_sha256": "41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf",
        "raw_arm": {"capsule_summary": {
            "outcome": "parsed", "unmatched_lines": 0, "ambiguous_lines": 0,
            "occurrence_counts_match_published": True, "unique_template_count": 46,
            "rtk_semantic_projection": dict(REAL_TOTALS)}},
        "rtk_arm": {"stdout": {"sha256": hashlib.sha256(fix).hexdigest(), "bytes": len(fix)}},
        "same_input_proof": {"raw_stdout_equals_member": True, "member_unchanged_after": True,
                             "rtk_read_same_member_path": True, "input_member_sha256": "deadbeef"},
        "oracle_observation": {"equivalence": {"equivalent": True}},
    }
    body.update(over)
    return c.envelope(record_type="n2e-loghub-acceptance-capture", generated_by="test", **body)


class TestBuilderGates(unittest.TestCase):
    def setUp(self):
        # register cleanup FIRST so a crash mid-build cannot leak the synthetic record on disk
        self.addCleanup(lambda: OUT_RECORD.exists() and OUT_RECORD.unlink())
        self.addCleanup(lambda: OUT_EVDIR.exists() and shutil.rmtree(OUT_EVDIR, ignore_errors=True))
        self.tmp = Path(tempfile.mkdtemp(prefix="n2e-loghub-buildtest-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        (self.tmp / "evidence").mkdir()
        (self.tmp / "evidence" / "raw.rtk.stdout.bin").write_bytes(FIXTURE.read_bytes())
        self.run = dict(run_id="39999999999", run_attempt="1", impl_commit="acceptimpl0",
                        artifact_sha256="f" * 64, artifact_bytes=4242)

    def _obs_path(self, obs):
        p = self.tmp / "obs.json"
        c.write_record(p, obs)
        return p

    def _build(self, obs=None, run=None):
        return BLD.build("loghub::HDFS::log", self._obs_path(obs or _observation()),
                         self.tmp / "evidence", "loghub", run or self.run)

    # ---------- GREEN ----------
    def test_green_builds_and_recomputes(self):
        out = self._build()
        rec = c.load_record(out)
        self.assertTrue(rec["case_qualification_pass"])
        self.assertEqual(rec["dispatch_policy_id"], "n2e-qualification-dispatch-v2")
        self.assertIsNone(rec.get("frozen_code_identity"))  # dispatch path carries NO cq identity
        self.assertEqual(rec["rtk_output"]["bytes"], FIXTURE.stat().st_size)

    # ---------- GATE 1: dirty observation ----------
    def test_red_barred_run_rejected(self):
        import n2e_resolved_loader as L
        run = {**self.run, "run_id": next(iter(L.BARRED_DIAGNOSTIC_RUNS))}
        with self.assertRaises(SystemExit):
            self._build(run=run)

    def test_red_barred_impl_rejected(self):
        run = {**self.run, "impl_commit": "2c1a523"}  # the loghub diagnostic impl
        with self.assertRaises(SystemExit):
            self._build(run=run)

    def test_red_capsule_not_parsed(self):
        obs = _observation()
        obs["raw_arm"]["capsule_summary"]["outcome"] = "unmatched_line"
        with self.assertRaises(SystemExit):
            self._build(obs=obs)

    def test_red_published_authority_not_held(self):
        obs = _observation()
        obs["raw_arm"]["capsule_summary"]["occurrence_counts_match_published"] = False
        with self.assertRaises(SystemExit):
            self._build(obs=obs)

    def test_red_same_input_proof_broken(self):
        obs = _observation()
        obs["same_input_proof"]["member_unchanged_after"] = False
        with self.assertRaises(SystemExit):
            self._build(obs=obs)

    def test_red_observed_equivalence_not_closed(self):
        obs = _observation()
        obs["oracle_observation"]["equivalence"]["equivalent"] = False
        with self.assertRaises(SystemExit):
            self._build(obs=obs)

    def test_red_barred_flag_on_observation(self):
        with self.assertRaises(SystemExit):
            self._build(obs=_observation(barred_from_qualification=True))

    def test_red_rtk_evidence_sha_mismatch(self):
        # the frozen fresh RTK evidence bytes disagree with the observed rtk_arm stdout digest
        obs = _observation()
        obs["rtk_arm"]["stdout"]["sha256"] = "0" * 64
        with self.assertRaises(SystemExit):
            self._build(obs=obs)


if __name__ == "__main__":
    unittest.main()
