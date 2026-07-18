#!/usr/bin/env python3
"""Promotion P2: build the narrowly-evidentiary executed-binary identity record.

Records WHAT ACTUALLY EXECUTED for the resolved coreutils-6731 Rust cargo-test path: the exact
rustc and cargo binaries the pinned toolchain selected, from the determinant-neutral producer run
29656538775 (impl 1157bb8; its Cargo.lock + resolved graph are byte-identical to the frozen
Phase 1 evidence, and its corrected verifier replay is normative_evidence_eligible=True).

Per role (rust, cargo) the record keeps SEPARATE and DISTINCT:
  * requested toolchain (RUSTUP_TOOLCHAIN),
  * resolved executable = invoked path (PATH proxy) + its resolved wrapper realpath + the measured
    toolchain-binary path,
  * measured executable identity = on-disk sha256 + byte length of that measured binary,
plus version-verbose (attesting the role + channel), platform/arch, channel, installation
provenance (installed components + channel-manifest sha), and producer run/case linkage.

Rust and Cargo identities are NEVER merged (same toolchain != same artifact). Identity is taken
ONLY from the measured binaries -- never inferred from rust-toolchain.toml, Nix names, package
metadata, or $PATH. Provenance is DESCRIPTIVE; this record sets no promotion flag.

The record MATERIALIZES the frozen toolchain overlay's stable-logical exact_binary_identity_ref
(a one-way link: the overlay stores the logical ref, not this record's digest -> no hash cycle).
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

LOCK = N2E_DIR / "n2e-toolchain-lock-v1.json"
OV_TOOLCHAIN = N2E_DIR / "n2e-resolved-toolchain-overlay-v1.json"
RESOLVED_MEMBERSHIP = N2E_DIR / "n2e-canary-resolved-membership-v1.json"
FROZEN_IDENTITY = N2E_DIR / "evidence" / "coreutils-6731" / "toolchain-binary-identity" / "installed-identity.json"

CASE_ID = "uutils__coreutils-6731::rust_cargo::test::fixed"
CHANNEL = "1.81.0"
HOST = "x86_64-unknown-linux-gnu"
# per-role capture keys in installed_identity: role -> (binary_name, measured_path, sha, bytes,
# invoked_path, invoked_realpath, version_verbose)
_ROLE_KEYS = {
    "rust": ("rustc", "rustc_binary_path", "rustc_binary_sha256", "rustc_binary_bytes",
             "rustc_shim_path", "rustc_shim_realpath", "rustc_version_verbose"),
    "cargo": ("cargo", "cargo_binary_path", "cargo_binary_sha256", "cargo_binary_bytes",
              "cargo_shim_path", "cargo_shim_realpath", "cargo_version_verbose"),
}


def _role_identity(role: str, ii: dict, prov_run: str) -> dict:
    binname, p_path, p_sha, p_bytes, p_inv, p_invreal, p_vv = _ROLE_KEYS[role]
    invoked, measured = ii[p_inv], ii[p_path]
    return {
        "role": role,
        "binary_name": binname,
        "requested_toolchain": CHANNEL,               # requested toolchain (distinct layer)
        "case_id": CASE_ID,
        "run_id": prov_run,
        # resolved executable: invoked PATH proxy -> resolved wrapper realpath -> measured binary
        "invoked_path": invoked,
        "invoked_realpath": ii[p_invreal],
        "measured_path": measured,
        "invoked_differs_from_measured": invoked != measured,
        # measured executable identity (distinct layer): on-disk sha256 + byte length
        "measured_sha256": ii[p_sha],
        "measured_bytes": ii[p_bytes],
        "version_verbose": ii[p_vv],
        "host_target": ii["host_target"],
        "channel": CHANNEL,
    }


def build_toolchain_binary_identity() -> dict:
    frozen = c.load_record(FROZEN_IDENTITY)
    ii = frozen["installed_identity"]
    prov_run = frozen["source_run_id"]
    ref = c.load_record(OV_TOOLCHAIN)["resolved_rust_toolchain"]["exact_binary_identity_ref"]
    body = c.envelope(
        record_type="n2e-resolved-toolchain-binary-identity",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_toolchain_binary_identity.py",
        purpose="Narrowly-evidentiary record of the exact executed rustc/cargo binaries (measured "
                "identity) for the resolved coreutils-6731 Rust cargo-test path. Sets no promotion flag.",
        resolved_case_id=CASE_ID,
        resolved_membership_sha256=c.sha256_json_file(RESOLVED_MEMBERSHIP),
        base_toolchain_lock_sha256=c.sha256_json_file(LOCK),
        resolved_toolchain_overlay_sha256=c.sha256_json_file(OV_TOOLCHAIN),
        # one-way materialization of the toolchain overlay's stable-logical exact_binary_identity_ref
        materializes_exact_binary_identity_ref=ref,
        requested_toolchain=CHANNEL,
        host_target=HOST,
        channel=CHANNEL,
        # the invoked wrapper (rustup) the PATH proxies resolve to -- its own measured identity
        invoked_wrapper={
            "name": "rustup",
            "path": ii["rustup_executable_path"],
            "sha256": ii["rustup_executable_sha256"],
            "bytes": ii["rustup_executable_bytes"],
        },
        role_identities=[_role_identity("rust", ii, prov_run), _role_identity("cargo", ii, prov_run)],
        installation_provenance={
            "installed_components": ii["installed_components"],
            "channel_manifest_sha256": frozen["channel_manifest_sha256"],
            "manifest_date": frozen["manifest_date"],
        },
        provenance={
            "run_id": prov_run,
            "artifact_sha256": frozen["source_artifact_sha256"],
            "producer_implementation": frozen["producer_implementation"],
            "case_id": CASE_ID,
            "note": "DESCRIPTIVE ONLY -- eligibility derives from the corrected normative verifier "
                    "result, never from provenance. Diagnostic-only runs/impls are barred by the loader.",
        },
    )
    return body


def main() -> int:
    c.write_record(N2E_DIR / "n2e-resolved-toolchain-binary-identity-v1.json", build_toolchain_binary_identity())
    print("wrote n2e-resolved-toolchain-binary-identity-v1.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
