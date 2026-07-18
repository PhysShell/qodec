"""Independent Coreutils diagnostic verifier is fail-closed (correction 8)."""
import sys
import tempfile
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import verify_coreutils_diagnostic as V  # noqa: E402
import n2e_common as c  # noqa: E402


def _rec(td, **over):
    body = dict(record_type="n2e-coreutils-diagnostic", generated_by="x", acceptance_pass=False)
    body.update(over)
    r = c.envelope(**body)
    p = td / "d.json"
    c.write_record(p, r)
    return p


class TestDiagVerifier(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())

    def test_fatal_outcome_fails(self):
        ok, fail, _ = V.verify(_rec(self.td, outcome="COREUTILS_DIAGNOSTIC_ERROR"), self.td / "ev")
        self.assertFalse(ok)

    def test_missing_outcome_fails(self):
        ok, fail, _ = V.verify(_rec(self.td), self.td / "ev")
        self.assertFalse(ok)

    def test_unproven_without_evidence_fails_closed(self):
        ok, fail, _ = V.verify(_rec(self.td, outcome="RTK_DIALECT_UNPROVEN", file_manifest=[]), self.td / "ev")
        self.assertFalse(ok)
        self.assertTrue(len(fail) >= 5)

    def test_acceptance_true_rejected(self):
        ok, fail, _ = V.verify(_rec(self.td, outcome="RTK_DIALECT_UNPROVEN",
                                    acceptance_pass=True, file_manifest=[]), self.td / "ev")
        self.assertFalse(ok)
        self.assertTrue(any("acceptance_pass" in f for f in fail))

    def test_self_hash_tamper_fails(self):
        p = _rec(self.td, outcome="RTK_DIALECT_UNPROVEN", file_manifest=[])
        txt = p.read_text().replace("RTK_DIALECT_UNPROVEN", "publisher_install_dependency_snapshot")
        p.write_text(txt)
        ok, fail, _ = V.verify(p, self.td / "ev")
        self.assertFalse(ok)
        self.assertTrue(any("self-hash" in f for f in fail))

    def test_acquisition_failure_needs_acquisition_evidence(self):
        ok, fail, _ = V.verify(_rec(self.td, outcome="COREUTILS_ACQUISITION_NONDETERMINISTIC",
                                    file_manifest=[]), self.td / "ev")
        self.assertFalse(ok)
        self.assertTrue(any("acquisition" in f.lower() for f in fail))


if __name__ == "__main__":
    unittest.main()
