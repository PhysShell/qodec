"""Resolved-scope overlays + coreutils applicability (contract steps 3-4).

Overlays never modify the frozen base: each links its base by whole-file sha256, carries
only the coreutils replacement, shadows no base case id, is self-hash-locked, and records
resolved_membership_sha256. Coreutils applicability proves the pinned harness maps
(uutils/coreutils, 6731) to exactly the overlay recipe and records full instance identity.
"""
import sys
import unittest
from pathlib import Path

N2E_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(N2E_DIR / "tools"))
import n2e_common as c  # noqa: E402

CASE_ID = "uutils__coreutils-6731::rust_cargo::test::fixed"
RM = N2E_DIR / "n2e-canary-resolved-membership-v1.json"
OVERLAYS = {
    "n2e-resolved-publisher-env-overlay-v1.json":
        ("base_publisher_registry_sha256", "n2e-publisher-env-registry-v1.json"),
    "n2e-resolved-toolchain-overlay-v1.json":
        ("base_toolchain_lock_sha256", "n2e-toolchain-lock-v1.json"),
    "n2e-resolved-command-scenario-overlay-v1.json":
        ("base_command_scenarios_sha256", "n2e-command-scenarios-v1.json"),
    "n2e-resolved-execution-contract-v1.json":
        ("base_execution_contract_sha256", "n2e-canary-execution-contract-v1.json"),
}


class TestResolvedOverlays(unittest.TestCase):
    def test_overlays_selfhash_and_link_frozen_base(self):
        rm_sha = c.sha256_json_file(RM)
        import n2e_resolved_loader as L
        for fname, (base_key, base_file) in OVERLAYS.items():
            r = c.load_record(N2E_DIR / fname)
            self.assertTrue(c.verify_self_hash(r)[0], fname)
            if base_key == "base_execution_contract_sha256":
                # gen-3: the execution-contract overlay is a FROZEN gen-2 artifact carried forward by
                # the migration bridge -> it pins a bridge-acceptable base contract sha (the gen-2
                # predecessor), not necessarily the current one.
                self.assertIn(r[base_key], L.acceptable_base_contract_shas(), fname)
            else:
                self.assertEqual(r[base_key], c.sha256_json_file(N2E_DIR / base_file), fname)
            self.assertEqual(r["resolved_membership_sha256"], rm_sha, fname)
            self.assertEqual(r["resolved_case_id"], CASE_ID)

    def test_no_overlay_shadows_base_case_id(self):
        base_ids = set()
        for _, recs in (("registry", c.load_record(N2E_DIR / "n2e-publisher-env-registry-v1.json")["recipes"]),
                        ("scen", c.load_record(N2E_DIR / "n2e-command-scenarios-v1.json")["scenarios"]),
                        ("contract", c.load_record(N2E_DIR / "n2e-canary-execution-contract-v1.json")["contracts"])):
            base_ids |= {x["case_id"] for x in recs}
        self.assertNotIn(CASE_ID, base_ids)

    def test_toolchain_overlay_pins_rust_181_immutably(self):
        r = c.load_record(N2E_DIR / "n2e-resolved-toolchain-overlay-v1.json")
        t = r["resolved_rust_toolchain"]
        self.assertEqual(t["resolved_channel"], "1.81.0")
        self.assertEqual(t["publisher_docker_rust_version"], "1.81")
        self.assertEqual(len(t["channel_manifest"]["sha256"]), 64)
        for comp in ("rust", "cargo", "rustc"):
            self.assertEqual(len(t["components_x86_64_unknown_linux_gnu"][comp]["hash"]), 64)
        # exact on-disk identity is captured at acquisition -- base discipline not weakened
        self.assertEqual(t["exact_binary_identity_ref"]["status"], "captured_at_acquisition")

    def test_coreutils_applicability(self):
        r = c.load_record(N2E_DIR / "coreutils-6731-instance-recipe-applicability-v1.json")
        self.assertTrue(c.verify_self_hash(r)[0])
        self.assertTrue(r["instance_recipe_applicable"])
        self.assertTrue(all(r["equalities"].values()), r["equalities"])
        self.assertTrue(all(r["anchor_to_pinned_reduced_row"].values()))
        self.assertEqual(r["install_command_bytes"], ["cargo test backslash --no-run"])
        self.assertEqual(r["test_command_bytes"], ["cargo test backslash --no-fail-fast"])
        self.assertEqual(r["fail_to_pass"], ["test_tr::test_trailing_backslash"])
        for k in ("gold_patch_sha256", "test_patch_sha256", "fail_to_pass_sha256",
                  "pass_to_pass_sha256", "complete_instance_row_sha256"):
            self.assertTrue(r[k].startswith("sha256:"), k)
        # agreement anchor: applicability links the exact overlay it agrees with
        self.assertEqual(r["resolved_publisher_overlay_sha256"],
                         c.sha256_json_file(N2E_DIR / "n2e-resolved-publisher-env-overlay-v1.json"))


if __name__ == "__main__":
    unittest.main()
