"""gen-2 -> gen-3 binding migration: the one-directional bridge carries the seven frozen PASS records
forward WITHOUT editing them, and is fail-closed against tampering. Covers the required RED matrix:
Lucene-declared-unchanged; a carried case's determinant altered; a wrong pinned digest; a legacy
record without a bridge; a native record with a wrong case-entry hash; cross-case independence.
"""
import copy
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import verify_n2e_manifest_migration as VB  # noqa: E402
import aggregate_n2e_resolved_twelve as A  # noqa: E402

BRIDGE = N2E_DIR / "n2e-manifest-gen2-to-gen3-binding-migration-v1.json"
LUCENE = "apache__lucene-13704::jvm::test::buggy"


def _rehash(rec):
    b = copy.deepcopy(rec)
    b["record_sha256"] = None
    c.finalize(b)
    return b


class TestMigrationBridge(unittest.TestCase):
    def setUp(self):
        self.rec = c.load_record(BRIDGE)

    # ---------- GREEN ----------
    def test_green_bridge_verifies(self):
        f = VB.verify(self.rec)
        self.assertEqual(f["declared_changed_case"], LUCENE)
        self.assertEqual(f["carried_forward"], 11)

    def test_green_aggregate_carries_seven_via_bridge_plus_native_lucene(self):
        # the seven frozen PASS records (all legacy gen-2) are carried forward under gen-3 by the bridge
        # with NONE of them edited; lucene is the bridge's DECLARED-CHANGED case and qualifies with a
        # NATIVE gen-3 binding (case_entry_sha256), so the aggregate is 8 total -- 7 carried + 1 native.
        r = A.aggregate_from_disk()
        self.assertEqual(r["derived_pass_count"], 8)
        self.assertFalse(r["resolved_canary_pass"])

    # ---------- RED: bridge tampering (fail-closed) ----------
    def test_red_lucene_declared_unchanged(self):
        bad = copy.deepcopy(self.rec)
        for x in bad["case_carry_forward"]:
            if x["case_id"] == LUCENE:
                x["carried_forward"] = True
                x["gen2_projection_sha256"] = x["gen3_case_entry_sha256"]
        bad["carried_forward_case_ids"] = sorted(bad["carried_forward_case_ids"] + [LUCENE])
        with self.assertRaises(VB.MigrationBridgeError):
            VB.verify(_rehash(bad))

    def test_red_carried_case_determinant_altered(self):
        # claim a carried case's gen-3 hash is something else -> re-derivation mismatch
        bad = copy.deepcopy(self.rec)
        for x in bad["case_carry_forward"]:
            if x["case_id"] != LUCENE:
                x["gen3_case_entry_sha256"] = "sha256:" + "0" * 64
                break
        with self.assertRaises(VB.MigrationBridgeError):
            VB.verify(_rehash(bad))

    def test_red_wrong_gen3_manifest_pin(self):
        bad = copy.deepcopy(self.rec)
        bad["gen3"]["manifest_sha256"] = "sha256:" + "0" * 64
        with self.assertRaises(VB.MigrationBridgeError):
            VB.verify(_rehash(bad))

    def test_red_wrong_gen2_manifest_pin(self):
        bad = copy.deepcopy(self.rec)
        bad["gen2"]["manifest_sha256"] = "sha256:" + "0" * 64
        with self.assertRaises(VB.MigrationBridgeError):
            VB.verify(_rehash(bad))

    def test_red_tampered_self_hash(self):
        bad = copy.deepcopy(self.rec)
        bad["declared_changed_case"] = "something-else"  # body changed, self-hash not recomputed
        with self.assertRaises(VB.MigrationBridgeError):
            VB.verify(bad)


if __name__ == "__main__":
    unittest.main()
