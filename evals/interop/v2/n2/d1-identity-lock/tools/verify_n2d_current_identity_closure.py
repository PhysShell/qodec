#!/usr/bin/env python3
"""Independently, fail-closedly verifies n2d-current-identity-closure-v1.json.

Recomputes the record's self-hash from its own committed content, then
cross-checks every claim against real, independently-loaded evidence:
the actual repository tree (Cargo.toml/Cargo.lock/flake.nix/flake.lock/
rust-toolchain.toml/src/meter.rs, hashed live -- never trusting the
record's own recorded hash), the real committed stage2-full-matrix-
acceptance.json (re-verified via its own verifier), the real committed
durable-input-manifest.json, and the real committed repo-spotless-
rejection-record.json / stage2-replacement-selection-v1.json. Never
trusts the builder or the record's own recorded values.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
IDENTITY_LOCK_DIR = TOOLS_DIR.parent
REPO_ROOT = IDENTITY_LOCK_DIR.parents[4]

RECORD_PATH = IDENTITY_LOCK_DIR / "n2d-current-identity-closure-v1.json"
STAGE2_RECORD_PATH = IDENTITY_LOCK_DIR / "stage2-full-matrix-acceptance.json"
DURABLE_MANIFEST_PATH = REPO_ROOT / "evals/interop/v2/n2/d0-durable-evidence/durable-input-manifest.json"
SPOTLESS_REJECTION_PATH = IDENTITY_LOCK_DIR / "repo-spotless-rejection-record.json"
REPLACEMENT_SELECTION_PATH = IDENTITY_LOCK_DIR / "stage2-replacement-selection-v1.json"
N2D1_CONTRACT_PATH = IDENTITY_LOCK_DIR / "n2d1-contract.json"

REQUIRED_N2D_BASE_MAIN_SHA = "6be63689c1553c4a97411f9d6fbb733ee87ebf34"
REQUIRED_STAGE2_RECORD_SHA256 = "sha256:1c722a31b836dbe1f68b6c4fb9d224f70077859772121cfc636076160ae8b6cd"
REQUIRED_QODEC_BINARY_SHA256 = "9e25bc4e21078da3572ba970f7b4023faffd9c48375ee40b6ee82ba73bc7bbe5"
REQUIRED_RTK_BINARY_SHA256 = "41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf"
REQUIRED_RTK_SOURCE_SHA = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
REQUIRED_LIVE_CAPTURE_WORKFLOW_RUN_ID = 29553837144

REQUIRED_18_CASE_IDS = [
    "n2a-miner-canary",
    "bot-dependabot-black-5206", "bot-syzbot-do-mkdirat", "ci-log-jansson",
    "ci-log-nlog", "ci-log-spdlog", "dataset-loghub-v8",
    "dataset-rtn-traffic-ids", "research-corpus-loghub2",
    "repo-docker-java-parser", "repo-dockerfile-parser-rs", "repo-helm-values",
    "repo-hyperfine", "repo-kubeops-generator", "repo-moshi", "repo-pyflakes",
    "repo-requests", "repo-rustlings",
]

REQUIRED_CANONICAL_SHA256_BY_CASE_ID = {
    "repo-docker-java-parser": "6ec603bdb9461abfc170dcc4a3ab562883b8d02b6af4aabb6a421bc57b45dd36",
    "repo-dockerfile-parser-rs": "d6100fd52cb44f1e76632430cdf1087c5442c59ab402387c735aac576a52684a",
    "repo-helm-values": "cf967cb267dd5d59c7d0b4f56f7a34fde10ed7129297882233d56202fdd81694",
    "repo-hyperfine": "3ecde90858d8ec63c1eafbc0e9945547b4bef7c2fcf6741934421bc18276b48d",
    "repo-kubeops-generator": "e38369406a00c3d049970971e5b13b9c0ed4b834ee0b7d4e309809932ee4cf4b",
    "repo-moshi": "c98f69759fb34ade6cbb60fe0d4632f9d906de5474c6e358359c2fd60293eb84",
    "repo-pyflakes": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "repo-requests": "cf78ccb2ec1f801530576a96d25cda8d9a92399759e6f5cf2c13ebeac2d92c27",
    "repo-rustlings": "11e611c7c40807f5be8639c9e6b511649ea4b8617c998786e97c8b8f0892dcaf",
    "n2a-miner-canary": "09b023837a4a969f9bf12401595429aeefe65263a2705e8e3a3e62ee5aa437db",
}


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(record_path: Path = RECORD_PATH) -> tuple[bool, str]:
    if not record_path.is_file():
        return False, f"{record_path} does not exist"
    record = json.loads(record_path.read_text())

    recorded = record.get("record_sha256")
    if not isinstance(recorded, str) or not recorded.startswith("sha256:"):
        return False, "record_sha256 missing or malformed"
    recomputed = compute_record_sha256(record)
    if recomputed != recorded:
        return False, f"self-hash mismatch: recorded={recorded} recomputed={recomputed}"

    if record.get("record_type") != "n2d-current-identity-closure-v1":
        return False, f"unexpected record_type: {record.get('record_type')!r}"

    repo = record.get("repository", {})
    if repo.get("merged_standalone_repository") != "PhysShell/qodec":
        return False, "repository.merged_standalone_repository must be 'PhysShell/qodec'"
    if repo.get("n2d_base_main_sha") != REQUIRED_N2D_BASE_MAIN_SHA:
        return False, f"repository.n2d_base_main_sha != required {REQUIRED_N2D_BASE_MAIN_SHA!r}"
    if repo.get("repository_root_is_qodec_crate_root") is not True:
        return False, "repository.repository_root_is_qodec_crate_root must be true"

    if not N2D1_CONTRACT_PATH.is_file():
        return False, f"{N2D1_CONTRACT_PATH} (historical contract) missing -- must be preserved, not deleted"
    supersedes = record.get("supersedes", {})
    if supersedes.get("record_preserved_unmodified") is not True:
        return False, "supersedes.record_preserved_unmodified must be true"

    # --- live tree hashes, recomputed independently, never trusted from the record
    for field, relpath in (
        ("root_cargo_toml_sha256", "Cargo.toml"),
        ("root_cargo_lock_sha256", "Cargo.lock"),
        ("flake_nix_sha256", "flake.nix"),
        ("flake_lock_sha256", "flake.lock"),
    ):
        actual = _sha256_file(REPO_ROOT / relpath)
        if repo.get(field) != actual:
            return False, f"repository.{field} {repo.get(field)!r} != actual live hash {actual!r}"

    actual_meter = _sha256_file(REPO_ROOT / "src" / "meter.rs")
    tok = record.get("tokenizer_identity", {})
    if tok.get("meter_rs_source_sha256") != actual_meter:
        return False, "tokenizer_identity.meter_rs_source_sha256 != actual live src/meter.rs hash"
    if tok.get("encoding_identity") != "o200k_base":
        return False, "tokenizer_identity.encoding_identity must be 'o200k_base'"

    # --- 18-case set -----------------------------------------------------
    if record.get("accepted_18_case_set") != REQUIRED_18_CASE_IDS:
        return False, "accepted_18_case_set does not match the required exact 18-case list/order-independent content"
    cases = record.get("cases", {})
    if sorted(cases.keys()) != sorted(REQUIRED_18_CASE_IDS):
        return False, f"cases keys {sorted(cases.keys())} != required {sorted(REQUIRED_18_CASE_IDS)}"
    if len(cases) != 18:
        return False, f"expected exactly 18 cases, got {len(cases)}"

    sha_map = record.get("canonical_benchmark_input_sha256_by_case_id", {})
    if sorted(sha_map.keys()) != sorted(REQUIRED_18_CASE_IDS):
        return False, "canonical_benchmark_input_sha256_by_case_id keys != required 18-case set"
    for case_id, required_sha in REQUIRED_CANONICAL_SHA256_BY_CASE_ID.items():
        if sha_map.get(case_id) != required_sha:
            return False, f"canonical_benchmark_input_sha256_by_case_id[{case_id!r}] != required {required_sha!r}"
        if cases[case_id].get("canonical_benchmark_input_sha256") != required_sha:
            return False, f"cases[{case_id!r}].canonical_benchmark_input_sha256 != required {required_sha!r}"

    # --- independent re-verification against stage2-full-matrix-acceptance.json
    if not STAGE2_RECORD_PATH.is_file():
        return False, f"{STAGE2_RECORD_PATH} does not exist"
    stage2_record = json.loads(STAGE2_RECORD_PATH.read_text())
    if stage2_record.get("record_sha256") != REQUIRED_STAGE2_RECORD_SHA256:
        return False, "stage2-full-matrix-acceptance.json record_sha256 != required exact hash"
    stage2_link = record.get("stage2_link", {})
    if stage2_link.get("record_sha256") != REQUIRED_STAGE2_RECORD_SHA256:
        return False, "stage2_link.record_sha256 != required exact hash"
    sys.path.insert(0, str(TOOLS_DIR))
    import verify_stage2_full_matrix_acceptance as stage2_verifier  # noqa: E402
    stage2_ok, stage2_msg = stage2_verifier.verify()
    if not stage2_ok:
        return False, f"stage2-full-matrix-acceptance.json failed independent re-verification: {stage2_msg}"

    for case_id in ("repo-docker-java-parser", "repo-dockerfile-parser-rs", "repo-helm-values",
                    "repo-hyperfine", "repo-kubeops-generator", "repo-moshi", "repo-pyflakes",
                    "repo-requests", "repo-rustlings"):
        stage2_case = stage2_record["cases"][case_id]
        if cases[case_id].get("durable_asset_sha256") != stage2_case["durable_asset_sha256"]:
            return False, f"cases[{case_id!r}].durable_asset_sha256 does not match stage2 record"
        if cases[case_id].get("source_commit_sha") != stage2_case["frozen_source_commit_sha"]:
            return False, f"cases[{case_id!r}].source_commit_sha does not match stage2 record"

    # --- independent re-verification against durable-input-manifest.json ----
    if not DURABLE_MANIFEST_PATH.is_file():
        return False, f"{DURABLE_MANIFEST_PATH} does not exist"
    durable = json.loads(DURABLE_MANIFEST_PATH.read_text())
    by_id = {e["logical_id"]: e for e in durable["n2c_entries"]}
    n2a_entry = durable["n2a_entry"]
    n2a_capture_a = n2a_entry["artifacts"]["miner-canary-capture-a"]
    n2a_raw_stdout = next(f for f in n2a_capture_a["contained_files"] if f["path"] == "raw.stdout")
    if cases["n2a-miner-canary"].get("canonical_benchmark_input_sha256") != n2a_raw_stdout["sha256"]:
        return False, "cases['n2a-miner-canary'] canonical sha256 does not match durable-input-manifest.json"
    if cases["n2a-miner-canary"].get("durable_release_asset_sha256") != n2a_capture_a["durable_release_asset_sha256"]:
        return False, "cases['n2a-miner-canary'] durable asset sha256 does not match durable-input-manifest.json"

    for case_id in ("bot-dependabot-black-5206", "bot-syzbot-do-mkdirat", "ci-log-jansson",
                    "ci-log-nlog", "ci-log-spdlog", "dataset-loghub-v8",
                    "dataset-rtn-traffic-ids", "research-corpus-loghub2"):
        manifest_entry = by_id[case_id]
        if manifest_entry["role"] != "primary":
            return False, f"durable-input-manifest.json: {case_id} is not role=primary"
        if cases[case_id].get("canonical_benchmark_input_sha256") != manifest_entry["canonical_benchmark_input_sha256"]:
            return False, f"cases[{case_id!r}] canonical sha256 does not match durable-input-manifest.json"
        if cases[case_id].get("durable_release_asset_sha256") != manifest_entry["durable_release_asset_sha256"]:
            return False, f"cases[{case_id!r}] durable asset sha256 does not match durable-input-manifest.json"

    # --- repo-spotless / replacement ------------------------------------
    if not SPOTLESS_REJECTION_PATH.is_file() or not REPLACEMENT_SELECTION_PATH.is_file():
        return False, "repo-spotless-rejection-record.json / stage2-replacement-selection-v1.json missing"
    spotless = json.loads(SPOTLESS_REJECTION_PATH.read_text())
    replacement = json.loads(REPLACEMENT_SELECTION_PATH.read_text())
    status = record.get("repo_spotless_status", {})
    if status.get("permanently_rejected") is not True:
        return False, "repo_spotless_status.permanently_rejected must be true"
    if status.get("record_sha256") != spotless.get("record_sha256"):
        return False, "repo_spotless_status.record_sha256 does not match the real committed rejection record"
    if status.get("replacement_case_id") != replacement.get("replacement_case_id"):
        return False, "repo_spotless_status.replacement_case_id does not match the real committed replacement record"
    if status.get("replacement_selection_record_sha256") != replacement.get("record_sha256"):
        return False, "repo_spotless_status.replacement_selection_record_sha256 does not match the real committed record"
    if "repo-spotless" in record.get("accepted_18_case_set", []):
        return False, "repo-spotless must NOT be in the accepted 18-case set"

    # --- QODEC/RTK Nix identity -------------------------------------------
    qi = record.get("qodec_nix_identity", {})
    if qi.get("qodec_binary_sha256") != REQUIRED_QODEC_BINARY_SHA256:
        return False, f"qodec_nix_identity.qodec_binary_sha256 != required {REQUIRED_QODEC_BINARY_SHA256!r}"
    if qi.get("live_capture_source_workflow_run_id") != REQUIRED_LIVE_CAPTURE_WORKFLOW_RUN_ID:
        return False, "qodec_nix_identity.live_capture_source_workflow_run_id != required run id"
    if qi.get("qodec_cargo_lock_sha256") != repo.get("root_cargo_lock_sha256"):
        return False, "qodec_nix_identity.qodec_cargo_lock_sha256 must equal repository.root_cargo_lock_sha256"

    ri = record.get("rtk_nix_identity", {})
    if ri.get("rtk_binary_sha256") != REQUIRED_RTK_BINARY_SHA256:
        return False, f"rtk_nix_identity.rtk_binary_sha256 != required {REQUIRED_RTK_BINARY_SHA256!r}"
    if ri.get("rtk_source_sha") != REQUIRED_RTK_SOURCE_SHA:
        return False, f"rtk_nix_identity.rtk_source_sha != required {REQUIRED_RTK_SOURCE_SHA!r}"
    if ri.get("live_capture_source_workflow_run_id") != REQUIRED_LIVE_CAPTURE_WORKFLOW_RUN_ID:
        return False, "rtk_nix_identity.live_capture_source_workflow_run_id != required run id"

    # --- gate status fields must be present and type-correct --------------
    if not isinstance(record.get("rtk_applicability_map_status"), str):
        return False, "rtk_applicability_map_status must be a string"

    rtk_map_link = record.get("rtk_applicability_map")
    if rtk_map_link is not None:
        rtk_map_path = IDENTITY_LOCK_DIR / "rtk-applicability-map-v1.json"
        if not rtk_map_path.is_file():
            return False, f"{rtk_map_path} does not exist"
        rtk_map_record = json.loads(rtk_map_path.read_text())
        if rtk_map_link.get("record_sha256") != rtk_map_record.get("record_sha256"):
            return False, "rtk_applicability_map.record_sha256 does not match the real committed record"
        if rtk_map_link.get("verified_by_its_own_verifier_at_build_time") is not True:
            return False, "rtk_applicability_map.verified_by_its_own_verifier_at_build_time must be true"
        sys.path.insert(0, str(TOOLS_DIR))
        import verify_rtk_applicability_map  # noqa: E402
        rtk_map_ok, rtk_map_msg = verify_rtk_applicability_map.verify()
        if not rtk_map_ok:
            return False, f"rtk-applicability-map-v1.json failed independent re-verification: {rtk_map_msg}"

    if record.get("n2d2_gate_status") not in ("not_yet_run", "passed", "failed"):
        return False, f"n2d2_gate_status has an unrecognized value: {record.get('n2d2_gate_status')!r}"
    if record.get("n2d3_gate_status") not in ("not_yet_run", "passed", "failed"):
        return False, f"n2d3_gate_status has an unrecognized value: {record.get('n2d3_gate_status')!r}"
    if not isinstance(record.get("token_counts_computed"), bool):
        return False, "token_counts_computed must be a boolean"
    if record.get("token_counts_computed") is True and record.get("n2d3_gate_status") != "passed":
        return False, "token_counts_computed=true requires n2d3_gate_status=='passed'"

    n2d2_link = record.get("n2d2_report_link")
    if record.get("n2d2_gate_status") == "passed":
        if n2d2_link is None:
            return False, "n2d2_gate_status=='passed' requires n2d2_report_link"
        n2d2_report_path = IDENTITY_LOCK_DIR / "n2d2-determinism-canary-report-v1.json"
        if not n2d2_report_path.is_file():
            return False, f"{n2d2_report_path} does not exist"
        n2d2_record = json.loads(n2d2_report_path.read_text())
        if n2d2_link.get("record_sha256") != n2d2_record.get("record_sha256"):
            return False, "n2d2_report_link.record_sha256 does not match the real committed report"
        sys.path.insert(0, str(TOOLS_DIR))
        import n2d2_determinism_canary  # noqa: E402
        if n2d2_determinism_canary.compute_record_sha256(n2d2_record) != n2d2_record.get("record_sha256"):
            return False, "n2d2-determinism-canary-report-v1.json self-hash does not verify"
        if n2d2_record.get("case_id") != n2d2_determinism_canary.CANARY_CASE_ID:
            return False, "n2d2 report case_id does not match the pinned canary case id"
        if n2d2_record.get("all_cases_deterministic") is not True:
            return False, "n2d2_gate_status=='passed' but the report itself does not show all_cases_deterministic=true"

    n2d3_link = record.get("n2d3_benchmark_link")
    if record.get("n2d3_gate_status") == "passed":
        if n2d3_link is None:
            return False, "n2d3_gate_status=='passed' requires n2d3_benchmark_link"
        n2d3_report_path = IDENTITY_LOCK_DIR / "n2d3-primary-token-benchmark-v1.json"
        if not n2d3_report_path.is_file():
            return False, f"{n2d3_report_path} does not exist"
        n2d3_record = json.loads(n2d3_report_path.read_text())
        if n2d3_link.get("record_sha256") != n2d3_record.get("record_sha256"):
            return False, "n2d3_benchmark_link.record_sha256 does not match the real committed benchmark"
        sys.path.insert(0, str(TOOLS_DIR))
        import build_n2d3_primary_benchmark  # noqa: E402
        if build_n2d3_primary_benchmark.compute_record_sha256(n2d3_record) != n2d3_record.get("record_sha256"):
            return False, "n2d3-primary-token-benchmark-v1.json self-hash does not verify"
        corpus = n2d3_record.get("corpus", {})
        if (
            corpus.get("total_corpus_cases") != 18
            or corpus.get("token_measurable_cases") != 16
            or corpus.get("non_utf8_measurement_refusals") != 2
            or corpus.get("runtime_failure_count") != 0
        ):
            return False, "n2d3_gate_status=='passed' but the benchmark's own corpus breakdown is not 18/16/2/0"
        if n2d3_link.get("corpus") != corpus:
            return False, "n2d3_benchmark_link.corpus does not match the real committed benchmark's own corpus breakdown"

    return True, "OK"


def main() -> int:
    ok, message = verify()
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
