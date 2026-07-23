"""Per-case manifest binding (gen-3): case_entry_sha256 is CASE-LOCAL -- a change to one case's
determinants changes only that case's digest, never the others. This is the property that lets a
case-local policy upgrade (Lucene v2, later the git/docker/log oracles) advance without re-freezing
the other eleven cases' frozen evidence.
"""
import copy
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402
import n2e_manifest_binding as mb  # noqa: E402

MANIFEST = N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"


def _all():
    man = c.load_record(MANIFEST)
    con = c.load_record(L.CONTRACT)
    ov = c.load_record(L.OV_CONTRACT)
    out = {}
    for e in man["cases"]:
        cid = e["case_id"]
        out[cid] = (e, mb.contract_entry_for(cid, con), mb.overlay_entry_for(cid, ov))
    return out


class TestCaseEntryBinding(unittest.TestCase):
    def setUp(self):
        self.cases = _all()

    def test_twelve_distinct_deterministic(self):
        shas = {cid: mb.case_entry_sha256(*v) for cid, v in self.cases.items()}
        self.assertEqual(len(shas), 12)
        self.assertEqual(len(set(shas.values())), 12, "case_entry_sha256 must be distinct per case")
        again = {cid: mb.case_entry_sha256(*v) for cid, v in self.cases.items()}
        self.assertEqual(shas, again, "must be deterministic")
        for s in shas.values():
            self.assertTrue(s.startswith("sha256:"))

    def test_change_to_one_case_is_local(self):
        # mutate ONE case's canonicalization policy id -> only that case's digest changes
        cid = "vuejs__core-11589::js_ts::test::buggy"
        base = {k: mb.case_entry_sha256(*v) for k, v in self.cases.items()}
        me, ce, oe = self.cases[cid]
        me2 = copy.deepcopy(me); me2["canonicalization_policy_id"] = "pytest-v1"
        changed = mb.case_entry_sha256(me2, ce, oe)
        self.assertNotEqual(changed, base[cid], "the mutated case's digest MUST change")
        for other, v in self.cases.items():
            if other == cid:
                continue
            self.assertEqual(mb.case_entry_sha256(*v), base[other],
                             f"{other} digest must NOT change when {cid} changes")

    def test_execution_policy_change_is_local(self):
        # simulate Lucene v2: a changed execution_control on the contract entry changes only lucene
        cid = "apache__lucene-13704::jvm::test::buggy"
        me, ce, oe = self.cases[cid]
        ce2 = copy.deepcopy(ce)
        ce2["execution_control"] = {**(ce.get("execution_control") or {}),
                                    "policy_id": "lucene-gradle-test-execution-v2",
                                    "args": ["-Ptests.seed=X", "-Ptests.jvms=1", "--max-workers=1"]}
        self.assertNotEqual(mb.case_entry_sha256(me, ce2, oe), mb.case_entry_sha256(me, ce, oe))

    def test_unmaterialized_oracle_digest_is_none_not_crash(self):
        # the four not-yet-built command oracles have no registered module -> None, not an exception
        for cid in ("container::redis::docker::images", "loghub::HDFS::log",
                    "rubocop__rubocop-13687::git::show",
                    "php-cs-fixer__php-cs-fixer-8075::git::commit"):
            me, ce, oe = self.cases[cid]
            proj = mb.case_entry_projection(me, ce, oe)
            self.assertIsNone(proj["dialect_or_oracle"]["digest"])
            self.assertTrue(mb.case_entry_sha256(me, ce, oe).startswith("sha256:"))

    def test_materialized_case_pins_module_and_policy_digests(self):
        # a qualified case pins BOTH its canon-policy definition digest and its dialect module digest
        me, ce, oe = self.cases["caddyserver__caddy-5870::go::test::buggy"]
        proj = mb.case_entry_projection(me, ce, oe)
        self.assertIsNotNone(proj["canonicalization_policy"]["digest"])
        self.assertIsNotNone(proj["dialect_or_oracle"]["digest"])
        self.assertIsNotNone(proj["contract_entry_digest"])


if __name__ == "__main__":
    unittest.main()
