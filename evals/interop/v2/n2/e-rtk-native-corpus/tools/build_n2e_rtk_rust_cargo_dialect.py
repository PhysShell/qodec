#!/usr/bin/env python3
"""Promotion P3: build the identity-bound Rust cargo-test RTK dialect record.

Binds the dialect SEMANTICS (defined in n2e_rtk_rust_cargo_dialect from rtk @5d32d07) to a complete
identity chain, and records the three structurally distinct layers -- captured bytes, execution
binding, semantic projection -- for the coreutils-6731 case, from the determinant-neutral v3 run
29667956749 (impl 65b8714). Case-scoped: proven for coreutils-6731 only. Sets no promotion flag.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_oracles as ora  # noqa: E402
import n2e_rtk_rust_cargo_dialect as rcd  # noqa: E402

LOCK = N2E_DIR / "n2e-toolchain-lock-v1.json"
CONTRACT = N2E_DIR / "n2e-canary-execution-contract-v1.json"
OV_CONTRACT = N2E_DIR / "n2e-resolved-execution-contract-v1.json"
RESOLVED_MEMBERSHIP = N2E_DIR / "n2e-canary-resolved-membership-v1.json"
P2_RECORD = N2E_DIR / "n2e-resolved-toolchain-binary-identity-v1.json"
DIALECT_DIR = N2E_DIR / "evidence" / "coreutils-6731" / "rtk-rust-cargo-dialect"
FROZEN_IDENTITY = DIALECT_DIR / "dialect-identity.json"
STREAMS_MANIFEST = DIALECT_DIR / "streams-manifest.json"

CASE_ID = "uutils__coreutils-6731::rust_cargo::test::fixed"
# the exact committed contract argv/env for the coreutils case (execution binding)
RAW_ARGV = ["cargo", "test", "backslash", "--no-fail-fast"]
SEMANTIC_ENV = {"RUSTUP_TOOLCHAIN": "1.81.0", "CARGO_NET_OFFLINE": "true",
                "RUST_TEST_THREADS": "1", "CARGO_BUILD_JOBS": "1"}
PRESERVED_SEMANTICS = [
    "process success/failure", "cargo compile failure vs test failure",
    "total passed/failed/ignored/measured/filtered counts (measured lossless only when 0)",
    "all failing test identities", "termination/truncation state",
    "presence/absence of a valid terminal summary",
]


def build_dialect() -> dict:
    frozen = c.load_record(FROZEN_IDENTITY)
    manifest = c.load_record(STREAMS_MANIFEST)
    # the contract's bound dialect policy id (materialize one-way)
    contract = c.load_record(OV_CONTRACT)["overlay_contracts"][0]
    dialect_id = contract["rtk_test_dialect_policy_id"]

    # semantic-projection layer: re-derive from the frozen v3-canonical streams
    raw_can = (DIALECT_DIR / "streams" / "raw.canonical.rep0.bin").read_bytes()
    rtk_can = (DIALECT_DIR / "streams" / "rtk.canonical.rep0.bin").read_bytes()
    raw_proj, rtk_proj = rcd.parse_raw(raw_can), rcd.parse_rtk(rtk_can)
    eq = rcd.equivalence(raw_proj, rtk_proj)

    body = c.envelope(
        record_type="n2e-resolved-rtk-rust-cargo-dialect",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_rtk_rust_cargo_dialect.py",
        purpose="Identity-bound, case-scoped Rust cargo-test RTK dialect for coreutils-6731. "
                "Semantics defined from rtk @5d32d07; validated against the real captured streams. "
                "Sets no promotion flag.",
        resolved_case_id=CASE_ID,
        resolved_membership_sha256=c.sha256_json_file(RESOLVED_MEMBERSHIP),
        base_execution_contract_sha256=c.sha256_json_file(CONTRACT),
        resolved_execution_contract_sha256=c.sha256_json_file(OV_CONTRACT),
        dialect_policy_id=ora.RTK_RUST_CARGO_DIALECT,
        # one-way materialization of the resolved contract's rtk_test_dialect_policy_id
        materializes_rtk_test_dialect_policy_id=dialect_id,
        dialect_scope="case_scoped",
        # ---------- identity chain ----------
        rtk_source_identity=frozen["rtk_source_identity"],
        rtk_executable_identity=frozen["rtk_executable_identity"],
        p2_binary_identity_ref={"record": "n2e-resolved-toolchain-binary-identity-v1.json",
                                "sha256": c.sha256_json_file(P2_RECORD)},
        provenance={"run_id": frozen["run_id"], "artifact_sha256": frozen["artifact_sha256"],
                    "producer_implementation": frozen["producer_implementation"], "case_id": CASE_ID,
                    "note": "DESCRIPTIVE ONLY -- diagnostic-only runs/impls barred by the loader."},
        # ---------- layer 1: captured bytes ----------
        captured_bytes={
            "streams_manifest": "evidence/coreutils-6731/rtk-rust-cargo-dialect/streams-manifest.json",
            "streams_manifest_sha256": c.sha256_json_file(STREAMS_MANIFEST),
            "run_id": manifest["run_id"], "case_id": manifest["case_id"],
            "canonicalization_policy_id": manifest["canonicalization_policy_id"],
            "streams": manifest["streams"]},
        # ---------- layer 2: execution binding ----------
        execution_binding={
            "case_id": CASE_ID, "raw_argv": RAW_ARGV, "rtk_argv_shape": ["<rtk_bin>", *RAW_ARGV],
            "semantic_env": SEMANTIC_ENV,
            "rust_identity_ref": "n2e-resolved-toolchain-binary-identity-v1.json#rust",
            "cargo_identity_ref": "n2e-resolved-toolchain-binary-identity-v1.json#cargo",
            "rtk_identity_ref": "self.rtk_executable_identity",
            "stream_routing": {"raw": "combined stdout+stderr of the RAW arm",
                               "rtk": "combined stdout+stderr of the RTK arm"}},
        # ---------- layer 3: semantic projection ----------
        semantic_projection={
            "raw_projection": raw_proj, "rtk_projection": rtk_proj,
            "equivalence": eq, "preserved_semantics": PRESERVED_SEMANTICS,
            "allowed_normalizations": ["elapsed duration (native finished-in + RTK compact <dur>)",
                                       "ANSI SGR escapes", "CR of CRLF line endings",
                                       "cargo build-progress lines (via cargo-test-v3)"]},
    )
    return body


def main() -> int:
    c.write_record(N2E_DIR / "n2e-resolved-rtk-rust-cargo-dialect-v1.json", build_dialect())
    print("wrote n2e-resolved-rtk-rust-cargo-dialect-v1.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
