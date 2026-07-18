#!/usr/bin/env python3
"""Build the self-hash-locked toolchain lock: the EXPECTED identity of every
publisher-pinned toolchain artifact, against which runtime evidence is compared by
exact equality. CI installs exactly these (download + SHA-256 verify), and the
runtime verifier rejects any run whose observed toolchain differs.

Artifact download SHA-256s are pinned here (Go/Node from the official distribution
manifests). `expected_binary_sha256` for executables produced by an installer
(rustc/cargo, java, gradle) is filled from a clean network-denied probe run and,
once present, is required to match exactly; until then the verifier still enforces
the exact version string (which alone catches wrong-toolchain substitution, e.g.
rustc 1.97.1 in place of 1.83.0, or Node 22 in place of Node 20).
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

OUT = N2E_DIR / "n2e-toolchain-lock-v1.json"

# expected version STRING (exact, as `<tool> --version` reports), download artifacts
# (immutable, SHA-256-verified at install), and per-executable expected binary
# SHA-256 (null until pinned from a clean probe). Keyed by publisher toolchain kind.
TOOLCHAINS = {
    "go": {
        "publisher_version": "1.23.8",
        "expected_version_contains": "go1.23.8",
        "artifact": {"name": "go1.23.8.linux-amd64.tar.gz",
                     "url": "https://go.dev/dl/go1.23.8.linux-amd64.tar.gz",
                     "sha256": "45b87381172a58d62c977f27c4683c8681ef36580abecd14fd124d24ca306d3f"},
        "executables": {"go": {"expected_binary_sha256": None}},
    },
    "rust": {
        "publisher_version": "1.83",
        "channel": "1.83.0",
        "expected_version_contains": "1.83.0",
        "install": "rustup toolchain install 1.83.0 --profile minimal --no-self-update",
        "target": "x86_64-unknown-linux-gnu",
        "executables": {"rustc": {"expected_binary_sha256": None},
                        "cargo": {"expected_binary_sha256": None}},
    },
    "node": {
        "publisher_version": "20",
        "pinned_version": "v20.20.2",
        "expected_version_contains": "v20.20.2",
        "artifact": {"name": "node-v20.20.2-linux-x64.tar.xz",
                     "url": "https://nodejs.org/dist/v20.20.2/node-v20.20.2-linux-x64.tar.xz",
                     "sha256": "df770b2a6f130ed8627c9782c988fda9669fa23898329a61a871e32f965e007d"},
        "package_manager": {"kind": "pnpm", "provisioned_by": "corepack",
                            "version_source": "repo package.json packageManager field",
                            "expected_binary_sha256": None},
        "executables": {"node": {"expected_binary_sha256": None}},
    },
    "java": {
        "publisher_version": "21",
        "vendor": "eclipse-temurin",
        "expected_version_contains": "21.0",
        "source": "runner JAVA_HOME_21_X64 (Temurin 21); exact build pinned from probe",
        "executables": {"java": {"expected_binary_sha256": None}},
        "gradle": {"resolved_from": "repo gradle/wrapper/gradle-wrapper.properties",
                   "distribution_url": None, "distribution_sha256": None,
                   "runtime_version": None},
    },
}


def build() -> dict:
    return c.envelope(
        record_type="n2e-toolchain-lock",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_toolchain_lock.py",
        purpose="Expected identities of the publisher-pinned toolchains; runtime evidence is "
                "compared by exact equality. Wrong-version substitution is a HARNESS_DEFECT.",
        note="Download artifacts are SHA-256 pinned; per-executable binary SHA-256 is filled "
             "from a clean probe and then required to match exactly.",
        toolchains=TOOLCHAINS,
    )


def main() -> int:
    c.write_record(OUT, build())
    print(f"wrote {OUT.name}: {len(TOOLCHAINS)} toolchains "
          f"(go {TOOLCHAINS['go']['publisher_version']}, rust {TOOLCHAINS['rust']['channel']}, "
          f"node {TOOLCHAINS['node']['pinned_version']}, java {TOOLCHAINS['java']['publisher_version']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
