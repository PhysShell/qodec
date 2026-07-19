#!/usr/bin/env python3
"""Build the resolved-scope OVERLAY records for the Coreutils replacement (contract step 3).

The frozen four-case base records (publisher registry, toolchain lock, command scenarios,
execution contract, canary membership) are NEVER modified. Each overlay:
  * links its immutable base by WHOLE-FILE sha256 and records resolved_membership_sha256;
  * contains ONLY the coreutils-6731 replacement;
  * rejects any duplicate / shadowing case id already present in the base;
  * is self-hash-locked and rebuilt mechanically from pinned source.

The effective resolved contract is `frozen base + verified replacement overlay`.

Produces:
  n2e-resolved-publisher-env-overlay-v1.json    (coreutils recipe, extracted from pinned source)
  n2e-resolved-toolchain-overlay-v1.json        (rust 1.81 -> 1.81.0 immutable channel pins)
  n2e-resolved-command-scenario-overlay-v1.json (coreutils scenario, from inventory + row)
  n2e-resolved-execution-contract-v1.json       (coreutils effective execution contract)
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_swebench_extract as ex  # noqa: E402
import n2e_publisher_registry as pub  # noqa: E402
import n2e_oracles as ora  # noqa: E402

SRC = N2E_DIR / "fixtures" / "swebench-source"
REGISTRY = N2E_DIR / "n2e-publisher-env-registry-v1.json"
LOCK = N2E_DIR / "n2e-toolchain-lock-v1.json"
SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
CONTRACT = N2E_DIR / "n2e-canary-execution-contract-v1.json"
MEMBERSHIP = N2E_DIR / "n2e-canary-membership-v1.json"
RESOLVED_MEMBERSHIP = N2E_DIR / "n2e-canary-resolved-membership-v1.json"
INSTANCES = N2E_DIR / "n2e-swebench-instances-v1.json"
INVENTORY = N2E_DIR / "n2e-candidate-inventory-v1.json"
ROW = N2E_DIR / "evidence" / "coreutils-6731" / "uutils__coreutils-6731.row.json"

CASE_ID = "uutils__coreutils-6731::rust_cargo::test::fixed"
INSTANCE_ID = "uutils__coreutils-6731"

# Rust 1.81 pinned EXACTLY from the published channel manifest (immutable-artifact
# discipline): channel-rust-1.81.0.toml @ static.rust-lang.org. Component tarball hashes
# pin which cargo/rustc artifacts the toolchain provides; the on-disk binary sha256 are
# additionally captured at acquisition and verified against these.
RUST_181 = {
    "publisher_docker_rust_version": "1.81",
    "resolved_channel": "1.81.0",
    "host_target": "x86_64-unknown-linux-gnu",
    "channel_manifest": {
        "url": "https://static.rust-lang.org/dist/channel-rust-1.81.0.toml",
        "sha256": "5596679723faf7e63772bacb1d0c898abaa51eb4ed193b328929d907c8c4bd5a",
        "manifest_date": "2024-09-05",
    },
    "components_x86_64_unknown_linux_gnu": {
        "rust": {"hash": "4ca7c24e573dae2f382d8d266babfddc307155e1a0a4025f3bc11db58a6cab3e",
                 "xz_hash": "1a9ee8caaa18a3e433fef93cea8a55dc1ebd478ed761b2fef69d4565f9d00e7f"},
        "cargo": {"hash": "e735432b85349aa78ed164ff03a31c43298f46a085fef047a33607adee80adc3",
                  "xz_hash": "c50ee4b1ae8695461930e36d5465dddb7c7a0e0f0aa6cbd60de120b17c38b841"},
        "rustc": {"hash": "d1e8db8c3ce0bd4b8a99e29bbd5132a3cf6a7e88ba4004bf7ce889fac7aa7e8d",
                  "xz_hash": "988a4e4cdecebe4f4a0c52ec4ade5a5bfc58d6958969f5b1e8aac033bda2613e"},
    },
    # exact on-disk identity captured at acquisition. Verification is TWO-STEP and the two
    # steps are NEVER conflated: (1) verify the fetched distribution artifacts (cargo/rustc
    # component archives) against the channel manifest hashes above; (2) SEPARATELY capture
    # the installed executable identities (their own on-disk SHA-256). Installed-binary
    # SHA-256 are NOT compared to the component-archive SHA-256.
    "exact_binary_identity_ref": {
        "status": "captured_at_acquisition",
        "verification_discipline": "verify distribution artifacts against channel manifest, "
                                   "then capture installed executable identities separately; "
                                   "do not compare installed-binary sha256 to component-archive sha256",
        "required_keys": ["resolved_channel_exact", "cargo_binary_sha256", "rustc_binary_sha256",
                          "rustup_shim_path", "rustup_shim_realpath", "rustup_realpath_sha256",
                          "host_target", "cargo_version_verbose", "rustc_version_verbose",
                          "installed_components", "channel_manifest_sha256",
                          "cargo_component_artifact_sha256", "rustc_component_artifact_sha256"],
        "where": "focused coreutils diagnostic: acquisition.environment_identity.toolchain",
    },
}


def _resolved_recipe() -> dict:
    """Extract the coreutils recipe from pinned source (same shape as registry recipes)."""
    r = ex.extract(SRC, CASE_ID)
    inv = {x["candidate_id"]: x for x in c.load_record(INVENTORY)["candidates"]}[CASE_ID]
    src_ident = ex.verify_recipe_extractable(SRC, "rust_cargo", "uutils/coreutils", "6731")["source"]
    warm_env, _ = pub.split_env(r["install"][0]) if r["install"] else ({}, [])
    test_env, test_argv = pub.split_env(r["test_cmd"][0])
    return {
        "case_id": CASE_ID, "instance_id": INSTANCE_ID, "repository": "uutils/coreutils",
        "command_family": "rust_cargo", "command_subfamily": "test", "snapshot_variant": "fixed",
        "slot": "rust_test_pass", "language": "rust_cargo",
        "source": {"file": r["source_file"], "spec_dict": r["spec_dict"], "spec_key": r["spec_key"],
                   "git_blob_sha1": src_ident["git_blob_sha1"], "sha256": src_ident["sha256"]},
        "toolchain": {"kind": "rust", "version": "1.81", "docker_specs": r["docker_specs"]},
        "pre_install": r["pre_install"], "install": r["install"], "install_env": warm_env,
        "test_cmd": r["test_cmd"], "test_argv": test_argv, "test_env": test_env,
        "oracle_policy_id": inv.get("oracle_policy_id", "n2e-oracle-test-v1"),
    }


def _base_case_ids(record_path, extract) -> set:
    return set(extract(c.load_record(record_path)))


def _guard_no_shadow(base_ids: set, base_name: str):
    if CASE_ID in base_ids:
        raise SystemExit(f"overlay rejects shadowing: {CASE_ID} already in {base_name}")


def _overlay_env(record_type: str, base_key: str, base_path: Path, **fields) -> dict:
    return c.envelope(
        record_type=record_type,
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_resolved_overlays.py",
        purpose="Resolved-scope overlay for the coreutils-6731 replacement; frozen base is never "
                "modified. Effective contract = frozen base + verified replacement overlay.",
        replaces="tokio-rs__tokio-4384::rust_cargo::test::fixed",
        resolved_case_id=CASE_ID,
        resolved_membership_sha256=c.sha256_json_file(RESOLVED_MEMBERSHIP),
        **{base_key: c.sha256_json_file(base_path)},
        **fields,
    )


def build_publisher_env_overlay() -> dict:
    _guard_no_shadow({r["case_id"] for r in c.load_record(REGISTRY)["recipes"]}, "publisher registry")
    return _overlay_env("n2e-resolved-publisher-env-overlay",
                        "base_publisher_registry_sha256", REGISTRY,
                        overlay_recipe_count=1, overlay_recipes=[_resolved_recipe()])


def build_toolchain_overlay() -> dict:
    lock = c.load_record(LOCK)
    return _overlay_env("n2e-resolved-toolchain-overlay",
                        "base_toolchain_lock_sha256", LOCK,
                        base_lock_state=lock.get("lock_state"),
                        does_not_weaken_base=("adds the resolved rust 1.81.0 toolchain; the base "
                                              "lock's exact-identity discipline is preserved -- "
                                              "on-disk binaries are captured at acquisition and "
                                              "verified against the immutable channel pins"),
                        resolved_rust_toolchain=RUST_181)


def build_command_scenario_overlay() -> dict:
    _guard_no_shadow({s["case_id"] for s in c.load_record(SCEN)["scenarios"]}, "command scenarios")
    inv = {x["candidate_id"]: x for x in c.load_record(INVENTORY)["candidates"]}[CASE_ID]
    row = c.load_record(ROW)
    recipe = _resolved_recipe()
    scenario = {
        "case_id": CASE_ID, "command_family": "rust_cargo", "command_subfamily": "test",
        "snapshot_variant": "fixed",
        "original_argv": recipe["test_argv"],  # RAW runs the publisher test command
        "explicit_rtk_argv": ["rtk", *recipe["test_argv"]],
        "rtk_argv_resolution": None,
        "base_commit": row["base_commit"],
        "target_test_ids": inv["target_test_ids"],
        "semantic_oracle_type": "test_oracle",
        "timeout_seconds": 600,
        "source_image_identity": {"instance_id": INSTANCE_ID, "repository": "uutils/coreutils",
                                  "dataset": {"id": c.load_record(INSTANCES)["dataset_id"],
                                              "revision": c.load_record(INSTANCES)["pinned_revision"]}},
        "resolution_rule": "publisher_recipe",
    }
    return _overlay_env("n2e-resolved-command-scenario-overlay",
                        "base_command_scenarios_sha256", SCEN,
                        overlay_scenario_count=1, overlay_scenarios=[scenario])


def build_execution_contract_overlay() -> dict:
    _guard_no_shadow({x["case_id"] for x in c.load_record(CONTRACT)["contracts"]}, "execution contract")
    recipe = _resolved_recipe()
    argv = recipe["test_argv"]
    contract = {
        "case_id": CASE_ID, "command_family": "rust_cargo", "command_subfamily": "test",
        "snapshot_variant": "fixed",
        "original_raw_argv": ["cargo", "test"], "original_rtk_argv": ["rtk", "cargo", "test"],
        "frozen_rtk_resolution_rule": None,
        "argv_resolver_policy_id": "n2e-argv-resolver-v1",
        "resolution_rule": "publisher_recipe", "runtime_resolved": False,
        "effective_raw_argv": argv, "effective_rtk_argv": ["rtk", *argv],
        "execution_control": None,
        # effective runtime selector uses the EXACT resolved channel (1.81.0), not the
        # publisher-facing docker rust_version "1.81".
        "scheduler_env": {"CARGO_BUILD_JOBS": "1", "CARGO_NET_OFFLINE": "true",
                          "RUST_TEST_THREADS": "1", "RUSTUP_TOOLCHAIN": "1.81.0"},
        "scheduler_flags": None,
        # resolved coreutils uses the BOUNDED build-progress-stripping variant. Generation 2 of
        # this contract migrates cargo-test-v2 -> cargo-test-v3: v3 is cargo-test-v2 PLUS exactly
        # one added rule (normalize the RTK cargo-test compact all-pass summary duration), so the
        # RTK canonical stream is byte-reproducible across determinant-neutral runs. cargo-test-v2
        # is left byte-for-byte intact (no versioning fraud); the SOLE contract delta is this
        # policy id. Historical tokio evidence stays bound to cargo-test-v1.
        "canonicalization_policy_id": "cargo-test-v3",
        "canonicalization_policy_generation": {
            "generation": 2, "previous_policy_id": "cargo-test-v2",
            "delta": "added one rule normalizing the RTK cargo-test compact all-pass summary "
                     "duration (rust RTK @5d32d07 format_compact); cargo-test-v2 unchanged"},
        "semantic_oracle_policy_id": recipe["oracle_policy_id"],
        # rust RTK dialect is not yet proven -> None (fail-closed) until step 9 binds it
        "rtk_test_dialect_policy_id": ora.rtk_dialect_for("rust_cargo"),
        "toolchain_identity_ref": {
            "where": "focused coreutils diagnostic: acquisition.environment_identity.toolchain",
            "required_keys": [
                "resolved_channel_exact", "cargo_binary_sha256", "rustc_binary_sha256",
                "rustup_shim_path", "rustup_shim_realpath", "rustup_realpath_sha256",
                "host_target", "cargo_version_verbose", "rustc_version_verbose",
                "installed_components", "channel_manifest_sha256",
                "cargo_component_artifact_sha256", "rustc_component_artifact_sha256"]},
        "dependency_environment_identity_ref": {
            "where": "focused coreutils diagnostic: acquisition.environment_identity.dependencies",
            "protected_files": ["Cargo.lock", "Cargo.toml"]},
        "timeout_seconds": 600, "timeout_tier": "extended-600s",
        "isolation_method": "network-denied-netns(lo-up); positive denial probe",
        "protected_files": ["Cargo.lock", "Cargo.toml"],
        "mutation_guard": "before/after SHA-256 equality across acquisition + every measurement arm; "
                          "any change is a typed harness rejection even on success exit",
    }
    return _overlay_env("n2e-resolved-execution-contract-overlay",
                        "base_execution_contract_sha256", CONTRACT,
                        overlay_contract_count=1, overlay_contracts=[contract])


# ---- additive resolved-ENVIRONMENT overlay: Model B frozen dependency snapshot ----
# The frozen Model B resolved dependency snapshot proven PROMOTABLE by run 29654373144
# (producer impl c43b9c5), whose corrected normative verifier replay (verify_coreutils_
# diagnostic.py @ c43b9c5) returned normative_evidence_eligible=True with every frozen
# determinant present. The committed frozen evidence (Cargo.lock + host resolve graph) is the
# immutable substrate; this overlay pins its determinants so the loader can re-derive and check
# them against the referenced artifacts (not schema shape).
DEPSNAP_DIR = N2E_DIR / "evidence" / "coreutils-6731" / "resolved-dependency-snapshot"
DEPSNAP_LOCK = DEPSNAP_DIR / "Cargo.lock"
DEPSNAP_GRAPH = DEPSNAP_DIR / "resolved-graph.json"
# DESCRIPTIVE provenance only -- eligibility derives solely from the corrected normative verifier
# result, never from these fields. Diagnostic-only runs (bcd4164=29651849616, 3dbbf2b=29652684349)
# must satisfy NO provenance/promotion predicate (the loader bars them explicitly).
DEPSNAP_PROVENANCE = {
    "run_id": "29654373144",
    "artifact_sha256": "213563f991967c20365f076740b1278838bb1b07de3dcb546186cad6d6c61a6d",
    "producer_implementation": "c43b9c5",
    "verifier_implementation": "c43b9c5",
    "eligibility_source": "corrected normative verifier replay (tools/verify_coreutils_diagnostic.py "
                          "@ c43b9c5): normative_evidence_eligible=True. DESCRIPTIVE ONLY -- the loader "
                          "never derives eligibility from provenance.",
}


def _manifest_hash(obj) -> str:
    """sha256 over sort-keyed JSON with DEFAULT separators -- matches the producer's
    _manifest_hash / the verifier's _canon_sha exactly (NOT the compact sha256_json_file)."""
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def _frozen_snapshot_entry() -> dict:
    lock = DEPSNAP_LOCK.read_bytes()
    graph = c.load_record(DEPSNAP_GRAPH)
    hg = graph["host_resolve_graph"]
    return {
        "case_id": CASE_ID,
        "measurement_model": "B_frozen_resolved_dependency_snapshot",
        "cargo_lock_scope": "full cross-platform resolution",
        "cargo_lock_sha256": c.sha256_bytes(lock),
        "cargo_lock_bytes": len(lock),
        "host_resolve_graph_sha256": _manifest_hash(hg),
        "full_packages_metadata_sha256": _manifest_hash(graph["full_packages_metadata"]),
        "host_resolved_package_count": len(hg["reachable_package_ids"]),
        "frozen_evidence": {
            "cargo_lock": "evidence/coreutils-6731/resolved-dependency-snapshot/Cargo.lock",
            "resolved_graph": "evidence/coreutils-6731/resolved-dependency-snapshot/resolved-graph.json",
        },
        "provenance": DEPSNAP_PROVENANCE,
    }


def build_dependency_snapshot_overlay() -> dict:
    # materialize the RESOLVED execution contract's stable-logical dependency_environment_identity_ref.
    dep_ref = build_execution_contract_overlay()["overlay_contracts"][0]["dependency_environment_identity_ref"]
    # anti-cycle (option a): the execution contract stores a stable LOGICAL identity (a 'where'
    # pointer + protected_files), NOT this overlay's content digest. This overlay pins the base
    # execution contract's whole-file hash and materializes that logical ref -> strictly one-way
    # (overlay -> contract); no content-hash cycle to construct around.
    return _overlay_env("n2e-resolved-dependency-snapshot-overlay",
                        "base_execution_contract_sha256", CONTRACT,
                        overlay_kind="resolved_environment",
                        materializes_dependency_environment_identity_ref=dep_ref,
                        overlay_dependency_snapshot_count=1,
                        overlay_dependency_snapshots=[_frozen_snapshot_entry()])


BUILDERS = {
    "n2e-resolved-publisher-env-overlay-v1.json": build_publisher_env_overlay,
    "n2e-resolved-toolchain-overlay-v1.json": build_toolchain_overlay,
    "n2e-resolved-command-scenario-overlay-v1.json": build_command_scenario_overlay,
    "n2e-resolved-execution-contract-v1.json": build_execution_contract_overlay,
    "n2e-resolved-dependency-snapshot-overlay-v1.json": build_dependency_snapshot_overlay,
}


def main() -> int:
    for fname, fn in BUILDERS.items():
        c.write_record(N2E_DIR / fname, fn())
        print(f"wrote {fname}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
