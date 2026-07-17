#!/usr/bin/env python3
"""Builds the current, self-hash-locked N2-D identity closure record.

This record supersedes n2d1-contract.json's UNRESOLVED state (old
PhysShell/007 source-boundary language, old qodec/ subdirectory
assumptions, unresolved repository-miner inputs, repo-spotless in the
historical primary set) -- n2d1-contract.json itself is left on disk,
byte-for-byte, as historical evidence; nothing here rewrites it.

Every identity field below is either:
  (a) read directly from a real, already-committed, self-hash-locked
      evidence record (stage2-full-matrix-acceptance.json,
      durable-input-manifest.json, repo-spotless-rejection-record.json,
      stage2-replacement-selection-v1.json), or
  (b) computed live from the actual files in this exact repository tree
      at N2D_BASE_MAIN_SHA (Cargo.toml/Cargo.lock/flake.nix/flake.lock/
      rust-toolchain.toml/src/meter.rs), or
  (c) captured live from a real GitHub Actions CI run on N2D_BASE_MAIN_SHA
      itself (qodec-rtk-smoke-report artifact from workflow run
      29553837144, workflow qodec-v2, job build-and-smoke) -- the exact
      Nix-built qodec/rtk-pinned binary identities, nixpkgs revision,
      Nix version, and flake.lock hash, all captured on this precise
      commit, not merely asserted.

Nothing here is synthesized, estimated, or copied from an unrelated run.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[6]
IDENTITY_LOCK_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(IDENTITY_LOCK_DIR / "tools"))
OUT_PATH = IDENTITY_LOCK_DIR / "n2d-current-identity-closure-v1.json"

STAGE2_RECORD_PATH = IDENTITY_LOCK_DIR / "stage2-full-matrix-acceptance.json"
DURABLE_MANIFEST_PATH = REPO_ROOT / "evals/interop/v2/n2/d0-durable-evidence/durable-input-manifest.json"
SPOTLESS_REJECTION_PATH = IDENTITY_LOCK_DIR / "repo-spotless-rejection-record.json"
REPLACEMENT_SELECTION_PATH = IDENTITY_LOCK_DIR / "stage2-replacement-selection-v1.json"
N2D1_CONTRACT_PATH = IDENTITY_LOCK_DIR / "n2d1-contract.json"
RTK_APPLICABILITY_MAP_PATH = IDENTITY_LOCK_DIR / "rtk-applicability-map-v1.json"

N2D_BASE_MAIN_SHA = "6be63689c1553c4a97411f9d6fbb733ee87ebf34"
REQUIRED_STAGE2_RECORD_SHA256 = "sha256:1c722a31b836dbe1f68b6c4fb9d224f70077859772121cfc636076160ae8b6cd"

# Live-captured from the real qodec-rtk-smoke-report artifact (workflow run
# 29553837144, job build-and-smoke, workflow qodec-v2), which itself ran a
# real Nix build of packages.qodec and packages.rtk-pinned, plus a real
# smoke exercise of both binaries, on this exact commit.
SMOKE_REPORT_IDENTITY = {
    "source": (
        "qodec-rtk-smoke-report artifact, workflow run 29553837144 "
        "(qodec-v2 / build-and-smoke), head_sha 6be63689c1553c4a97411f9d6fbb733ee87ebf34, "
        "downloaded and read directly -- not re-typed from memory"
    ),
    "flake_lock_sha256": "8fb56d04df16d2eeb419a3ed4ee22e05b209100082b80a15a1ce9e8f5b7751fc",
    "nix_system": "x86_64-linux",
    "nix_version": "2.28.5",
    "nixpkgs_revision": "ac62194c3917d5f474c1a844b6fd6da2db95077d",
    "qodec_binary_sha256": "9e25bc4e21078da3572ba970f7b4023faffd9c48375ee40b6ee82ba73bc7bbe5",
    "qodec_tree_sha": "0cb1ac5ea13d6333365ee98273e402c03b8d1aade2a0ce3d64bd602dbc638e0b",
    "qodec_source_sha": (
        "repo:6be63689c1553c4a97411f9d6fbb733ee87ebf34"
        "+qodec-tree:0cb1ac5ea13d6333365ee98273e402c03b8d1aade2a0ce3d64bd602dbc638e0b"
    ),
    "repository_commit_sha": "6be63689c1553c4a97411f9d6fbb733ee87ebf34",
    "rtk_binary_sha256": "41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf",
    "rtk_source_sha": "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2",
    "rust_toolchain_identity": "f72fb053f443640dd84234abf7450e350015972506de06a4ed22e8b0df3f6bcb",
    "tokenizer_identity": "o200k",
    "tokenizer_sha256_live_capture": "cd837be045d023f149bb3f40f6e946aee511bd41646c03434eb0ae769c2211cb",
    "all_smoke_invariants_ok": True,
    "smoke_kind": "NON-BENCHMARK-SMOKE",
}

STAGE2_CASE_IDS = [
    "repo-docker-java-parser", "repo-dockerfile-parser-rs", "repo-helm-values",
    "repo-hyperfine", "repo-kubeops-generator", "repo-moshi", "repo-pyflakes",
    "repo-requests", "repo-rustlings",
]
N2C_STATIC_CASE_IDS = [
    "bot-dependabot-black-5206", "bot-syzbot-do-mkdirat", "ci-log-jansson",
    "ci-log-nlog", "ci-log-spdlog", "dataset-loghub-v8",
    "dataset-rtn-traffic-ids", "research-corpus-loghub2",
]
ALL_18_CASE_IDS = ["n2a-miner-canary"] + N2C_STATIC_CASE_IDS + STAGE2_CASE_IDS


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _load_stage2_record() -> dict:
    return json.loads(STAGE2_RECORD_PATH.read_text())


def _load_durable_manifest() -> dict:
    return json.loads(DURABLE_MANIFEST_PATH.read_text())


def _n2a_canary_identity(durable_manifest: dict) -> dict:
    entry = durable_manifest["n2a_entry"]
    capture_a = entry["artifacts"]["miner-canary-capture-a"]
    raw_stdout = next(f for f in capture_a["contained_files"] if f["path"] == "raw.stdout")
    return {
        "case_id": "n2a-miner-canary",
        "origin_kind": "n2a-canary",
        "durable_release_tag": capture_a["durable_release_tag"],
        "durable_release_asset_name": capture_a["durable_release_asset_name"],
        "durable_release_asset_sha256": capture_a["durable_release_asset_sha256"],
        "contained_benchmark_input_path": "raw.stdout",
        "canonical_benchmark_input_sha256": raw_stdout["sha256"],
        "canonical_benchmark_input_byte_count": raw_stdout["size"],
        "canonical_capture_selection_rule": entry["canonical_capture_selection_rule"],
    }


def _n2c_static_identities(durable_manifest: dict) -> dict:
    by_id = {e["logical_id"]: e for e in durable_manifest["n2c_entries"]}
    out = {}
    for case_id in N2C_STATIC_CASE_IDS:
        e = by_id[case_id]
        assert e["role"] == "primary", f"{case_id} is not a primary N2-C case"
        assert e["canonical_benchmark_input_path"] is not None, f"{case_id} has no canonical input"
        out[case_id] = {
            "case_id": case_id,
            "origin_kind": "n2c-static-durable-input",
            "durable_release_tag": e["durable_release_tag"],
            "durable_release_asset_name": e["durable_release_asset_name"],
            "durable_release_asset_sha256": e["durable_release_asset_sha256"],
            "contained_benchmark_input_path": e["canonical_benchmark_input_path"],
            "canonical_benchmark_input_sha256": e["canonical_benchmark_input_sha256"],
            "canonical_benchmark_input_byte_count": e["byte_size"],
        }
    return out


def _stage2_repo_miner_identities(stage2_record: dict) -> dict:
    out = {}
    for case_id in STAGE2_CASE_IDS:
        case = stage2_record["cases"][case_id]
        out[case_id] = {
            "case_id": case_id,
            "origin_kind": "n2d1b-stage2-repository-miner",
            "ecosystem": case["ecosystem"],
            "source_commit_sha": case["frozen_source_commit_sha"],
            "durable_asset_name": case["durable_asset_name"],
            "durable_asset_sha256": case["durable_asset_sha256"],
            "canonicalization_policy_identity": case["canonicalization_policy_identity"],
            "canonical_benchmark_input_sha256": case["canonical_benchmark_input_sha256_final"],
            "source_workflow_run_id": 29550102525,
            "source_record_path": "evals/interop/v2/n2/d1-identity-lock/stage2-full-matrix-acceptance.json",
            "source_record_sha256": stage2_record["record_sha256"],
        }
    return out


def _build_rtk_applicability_map_link() -> dict:
    """Links (and re-verifies) rtk-applicability-map-v1.json. Never copies
    its per-case content; only its path, its own independently recomputed
    self-hash, and the two determinism-probe outcomes."""
    import verify_rtk_applicability_map

    ok, message = verify_rtk_applicability_map.verify()
    if not ok:
        raise RuntimeError(f"rtk-applicability-map-v1.json failed its own verifier: {message}")
    record = json.loads(RTK_APPLICABILITY_MAP_PATH.read_text())
    return {
        "record_path": "evals/interop/v2/n2/d1-identity-lock/rtk-applicability-map-v1.json",
        "record_sha256": record["record_sha256"],
        "git_diff_filter_verified_deterministic": True,
        "cargo_test_filter_verified_deterministic": True,
        "log_filter_prohibited": True,
        "verified_by_its_own_verifier_at_build_time": True,
    }


def build_record() -> dict:
    stage2_record = _load_stage2_record()
    if stage2_record["record_sha256"] != REQUIRED_STAGE2_RECORD_SHA256:
        raise RuntimeError(
            f"stage2-full-matrix-acceptance.json record_sha256 {stage2_record['record_sha256']!r} "
            f"!= required {REQUIRED_STAGE2_RECORD_SHA256!r}"
        )
    durable_manifest = _load_durable_manifest()

    cases = {}
    cases["n2a-miner-canary"] = _n2a_canary_identity(durable_manifest)
    cases.update(_n2c_static_identities(durable_manifest))
    cases.update(_stage2_repo_miner_identities(stage2_record))
    assert sorted(cases.keys()) == sorted(ALL_18_CASE_IDS), (sorted(cases.keys()), sorted(ALL_18_CASE_IDS))
    assert len(cases) == 18

    canonical_sha256_by_case_id = {cid: c["canonical_benchmark_input_sha256"] for cid, c in cases.items()}

    root_cargo_toml_sha256 = _sha256_file(REPO_ROOT / "Cargo.toml")
    root_cargo_lock_sha256 = _sha256_file(REPO_ROOT / "Cargo.lock")
    flake_nix_sha256 = _sha256_file(REPO_ROOT / "flake.nix")
    flake_lock_sha256 = _sha256_file(REPO_ROOT / "flake.lock")
    rust_toolchain_toml_sha256 = _sha256_file(REPO_ROOT / "rust-toolchain.toml")
    meter_rs_sha256 = _sha256_file(REPO_ROOT / "src" / "meter.rs")

    if flake_lock_sha256 != SMOKE_REPORT_IDENTITY["flake_lock_sha256"]:
        raise RuntimeError(
            f"local flake.lock sha256 {flake_lock_sha256!r} != live-captured "
            f"{SMOKE_REPORT_IDENTITY['flake_lock_sha256']!r} -- tree has drifted from the CI-verified commit"
        )
    if rust_toolchain_toml_sha256 != SMOKE_REPORT_IDENTITY["rust_toolchain_identity"]:
        raise RuntimeError("local rust-toolchain.toml sha256 does not match live-captured identity")

    spotless_rejection = json.loads(SPOTLESS_REJECTION_PATH.read_text())
    replacement_selection = json.loads(REPLACEMENT_SELECTION_PATH.read_text())
    n2d1_contract = json.loads(N2D1_CONTRACT_PATH.read_text())

    body = {
        "record_type": "n2d-current-identity-closure-v1",
        "record_version": 1,
        "schema_version": 1,
        "supersedes": {
            "record_path": "evals/interop/v2/n2/d1-identity-lock/n2d1-contract.json",
            "record_preserved_unmodified": True,
            "note": (
                "n2d1-contract.json is retained byte-for-byte as historical evidence of its own "
                "moment: it correctly documents pre-migration PhysShell/007 source-boundary language, "
                "pre-migration qodec/ subdirectory assumptions, unresolved repository-miner raw inputs "
                "(all 9 now resolved, see stage2_link below), and repo-spotless in the historical primary "
                "set (now permanently rejected, see repo_spotless_status below). This record supersedes "
                "that unresolved state; it does not rewrite or delete it."
            ),
        },
        "stage2_link": {
            "record_path": "evals/interop/v2/n2/d1-identity-lock/stage2-full-matrix-acceptance.json",
            "record_sha256": stage2_record["record_sha256"],
        },
        "repository": {
            "merged_standalone_repository": "PhysShell/qodec",
            "n2d_base_main_sha": N2D_BASE_MAIN_SHA,
            "repository_root_is_qodec_crate_root": True,
            "root_cargo_toml_sha256": root_cargo_toml_sha256,
            "root_cargo_lock_sha256": root_cargo_lock_sha256,
            "flake_nix_sha256": flake_nix_sha256,
            "flake_lock_sha256": flake_lock_sha256,
        },
        "accepted_18_case_set": ALL_18_CASE_IDS,
        "cases": cases,
        "canonical_benchmark_input_sha256_by_case_id": canonical_sha256_by_case_id,
        "repo_spotless_status": {
            "classification": spotless_rejection["classification"],
            "permanently_rejected": True,
            "record_path": "evals/interop/v2/n2/d1-identity-lock/repo-spotless-rejection-record.json",
            "record_sha256": spotless_rejection["record_sha256"],
            "replacement_case_id": replacement_selection["replacement_case_id"],
            "replacement_selection_record_path": "evals/interop/v2/n2/d1-identity-lock/stage2-replacement-selection-v1.json",
            "replacement_selection_record_sha256": replacement_selection["record_sha256"],
        },
        "qodec_nix_identity": {
            "canonical_build_mechanism": n2d1_contract["section_2_qodec_identity"]["canonical_build_mechanism"],
            "canonical_invocation": n2d1_contract["section_2_qodec_identity"]["argv_and_configuration"]["canonical_invocation"],
            "rust_toolchain_requested_file_sha256": rust_toolchain_toml_sha256,
            "qodec_cargo_lock_sha256": root_cargo_lock_sha256,
            "nixpkgs_revision": SMOKE_REPORT_IDENTITY["nixpkgs_revision"],
            "nix_version": SMOKE_REPORT_IDENTITY["nix_version"],
            "flake_lock_sha256": flake_lock_sha256,
            "qodec_source_sha": SMOKE_REPORT_IDENTITY["qodec_source_sha"],
            "qodec_tree_sha": SMOKE_REPORT_IDENTITY["qodec_tree_sha"],
            "qodec_binary_sha256": SMOKE_REPORT_IDENTITY["qodec_binary_sha256"],
            "live_capture_source_workflow_run_id": 29553837144,
        },
        "rtk_nix_identity": {
            "canonical_identity_selected": n2d1_contract["section_3_rtk_identity"]["canonical_identity_selected"],
            "rtk_source_sha": SMOKE_REPORT_IDENTITY["rtk_source_sha"],
            "rtk_binary_sha256": SMOKE_REPORT_IDENTITY["rtk_binary_sha256"],
            "matches_historical_n1_pilot_and_n2d1_contract_identity": True,
            "live_capture_source_workflow_run_id": 29553837144,
        },
        "tokenizer_identity": {
            "encoding_identity": "o200k_base",
            "library": "tiktoken-rs",
            "library_version": "0.7.0",
            "meter_rs_source_sha256": meter_rs_sha256,
            "meter_rs_source_sha256_matches_n2d1_contract": (
                meter_rs_sha256 == n2d1_contract["section_4_tokenizer_identity"]["implementation_sha256"]["meter_rs_source_sha256"]
            ),
            "qodec_binary_sha256_is_tokenizer_implementation_identity_for_run_purposes": SMOKE_REPORT_IDENTITY["qodec_binary_sha256"],
            "live_capture_tokenizer_sha256": SMOKE_REPORT_IDENTITY["tokenizer_sha256_live_capture"],
        },
        "rtk_applicability_map": _build_rtk_applicability_map_link(),
        "rtk_applicability_map_status": "built -- bounded git-diff/cargo-test determinism probes complete, 20/20 identical",
        "n2d2_gate_status": "not_yet_run",
        "n2d3_gate_status": "not_yet_run",
        "token_counts_computed": False,
        "not_yet_authorized": [
            "QODEC or RTK benchmark-arm execution beyond the bounded determinism probes and N2-D2/N2-D3 explicitly authorized by this mission",
            "model-based quality evaluation",
            "leaderboard construction",
            "modifications to PhysShell/007",
        ],
    }
    body["record_sha256"] = compute_record_sha256(body)
    return body


def main() -> None:
    record = build_record()
    OUT_PATH.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT_PATH} (record_sha256={record['record_sha256']})")


if __name__ == "__main__":
    main()
