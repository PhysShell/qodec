#!/usr/bin/env python3
"""Build the self-hash-locked toolchain lock from IMMUTABLE UPSTREAM ARTIFACTS.

Every expected identity is derived from a pinned upstream artifact (not the moving
CI runner): official distribution archives (Go, Node), the Rust channel manifest +
component tarballs, an exact Eclipse Temurin JDK release, the repo-pinned Gradle
wrapper + distribution, and the repo-pinned pnpm release. Download-archive SHA-256s
and the executable SHA-256s that can be extracted deterministically offline are
pinned here directly; the few that require installing the (already SHA-256-pinned)
artifact -- the java binary, the gradle-wrapper.jar, and corepack's resolved pnpm
entrypoint -- are harvested from a TOOLCHAIN_IDENTITY_HARVEST run that installs the
pinned artifacts, then committed.

lock_state:
  HARVEST  -- at least one required expected identity is still null; NOT eligible
              for a canonical acceptance run.
  COMPLETE -- every required expected identity is present; canonical runs allowed.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

OUT = N2E_DIR / "n2e-toolchain-lock-v1.json"

TOOLCHAINS = {
    "go": {
        "publisher_version": "1.23.8", "release": "go1.23.8", "platform": "linux-amd64",
        "artifact": {"name": "go1.23.8.linux-amd64.tar.gz",
                     "url": "https://go.dev/dl/go1.23.8.linux-amd64.tar.gz",
                     "sha256": "45b87381172a58d62c977f27c4683c8681ef36580abecd14fd124d24ca306d3f"},
        # extracted deterministically from the SHA-256-pinned archive:
        "executables": {"go": {"resolve": "path",
                               "expected_sha256": "0cdc4480040b5ef62eb17ba283ab92eca991794a937620604a2b5772201c2b59"}},
    },
    "rust": {
        "publisher_version": "1.83", "release": "1.83.0", "channel": "1.83.0",
        "target": "x86_64-unknown-linux-gnu",
        "install": "rustup toolchain install 1.83.0 --profile minimal --no-self-update",
        "channel_manifest": {"url": "https://static.rust-lang.org/dist/channel-rust-1.83.0.toml",
                             "sha256": "b3544fb72bc3189697fc18ac2d3fa27d57ee8434f59d9919d4d70af2c6f010b3"},
        "components": {
            "rustc": {"url": "https://static.rust-lang.org/dist/2024-11-28/rustc-1.83.0-x86_64-unknown-linux-gnu.tar.xz",
                      "xz_sha256": "6ec40e0405c8cbed3b786a97d374c144b012fc831b7c22b535f8ecb524f495ad"},
            "cargo": {"url": "https://static.rust-lang.org/dist/2024-11-28/cargo-1.83.0-x86_64-unknown-linux-gnu.tar.xz",
                      "xz_sha256": "de834a4062d9cd200f8e0cdca894c0b98afe26f1396d80765df828880a39b98c"},
        },
        # extracted from the component tarballs; the driver hashes the REAL toolchain
        # binary via `rustup which` (NOT the ~/.cargo/bin shim).
        "executables": {
            "rustc": {"resolve": "rustup_which",
                      "expected_sha256": "6703c8f287653aae59b27849343fe64fa3893353f1c1d6037a608c18257afc2c"},
            "cargo": {"resolve": "rustup_which",
                      "expected_sha256": "da77b17765651b7a4405178a21d3dab1fa39dddec927d37c0fd5663b7c8623de"},
        },
    },
    "node": {
        "publisher_version": "20", "release": "v20.20.2", "platform": "linux-x64",
        "artifact": {"name": "node-v20.20.2-linux-x64.tar.xz",
                     "url": "https://nodejs.org/dist/v20.20.2/node-v20.20.2-linux-x64.tar.xz",
                     "sha256": "df770b2a6f130ed8627c9782c988fda9669fa23898329a61a871e32f965e007d"},
        "executables": {"node": {"resolve": "path",
                                "expected_sha256": "6295488653f0d93b0a157841746fef7e72cc4328cfb60c4bbe0ca2668a836ffd"}},
        "corepack": {"bundled_js_sha256": "3655bc798f300951f2070fee411b337d626b0c3ae80c2d24c46ccac4595d4bf9"},
        "pnpm": {"release": "9.7.0", "source": "repo package.json packageManager (pnpm@9.7.0)",
                 "tarball": "https://registry.npmjs.org/pnpm/-/pnpm-9.7.0.tgz",
                 "npm_shasum": "8f12c476122faede7aed9a2126ef551c0dc65d7e",
                 "npm_integrity": "sha512-3AlDAVa0J/Xs/HmIiJnhw50taQ8AS+cOBSMLcssXPZaDlYdUXQlCm1WsPEKcgBtNw8DgAvZTgwpCD6LdTjz5zw==",
                 # corepack resolves pnpm@9.7.0 from the SHA-512-integrity-pinned tarball;
                 # its resolved entrypoint hash is harvested from the pinned install.
                 "resolved_entrypoint_sha256": "7c2a67995976b5b592b611d8b236e3b0633bd654fb49aedd96c6eb7ce04c9cbb"},
    },
    "java": {
        "publisher_version": "21", "vendor": "eclipse-temurin",
        "release_name": "jdk-21.0.11+10", "openjdk_version": "21.0.11+10-LTS", "platform": "x64_linux",
        "artifact": {"name": "OpenJDK21U-jdk_x64_linux_hotspot_21.0.11_10.tar.gz",
                     "url": "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.11%2B10/OpenJDK21U-jdk_x64_linux_hotspot_21.0.11_10.tar.gz",
                     "sha256": "4b2220e232a97997b436ca6ab15cbf70171ecff52958a46159dfa5a8c44ca4de"},
        # java binary is deterministic given the SHA-256-pinned artifact; harvested
        # from the run that installs exactly that artifact (not the moving runner JDK).
        "executables": {"java": {"resolve": "path", "expected_sha256": "b1b0a09aaa036695716c829cd7c5213ea055eecd475d1462020330e251b717b2"}},
    },
    "gradle": {
        "publisher_version": "8.10", "runtime_version": "8.10",
        "resolved_from": "apache/lucene@ce4f56e gradle/wrapper/gradle-wrapper.properties",
        "distribution": {"url": "https://services.gradle.org/distributions/gradle-8.10-bin.zip",
                         "sha256": "5b9c5eb3f9fc2c94abaea57d90bd78747ca117ddbbf96c859d3741181a12bf2a"},
        "wrapper": {"gradlew_sha256": "fcd0fe684623b73d79454ede0834762ac7b547ef5291ca32c7691b2251406f32",
                    "properties_sha256": "2caec011a749b18ab9a7dea68bf7639a179a3b8316b0e35655d0a62a1d7390fd",
                    "wrapper_jar_sha256": "2db75c40782f5e8ba1fc278a5574bab070adccb2d21ca5a6e5ed840888448046"},
    },
}

# per toolchain: which executable expected_sha256 fields MUST be non-null for COMPLETE
_REQUIRED_EXE_HASHES = {
    "go": [("executables", "go")],
    "rust": [("executables", "rustc"), ("executables", "cargo")],
    "node": [("executables", "node")],
    "java": [("executables", "java")],
}
_REQUIRED_EXTRA = [  # (toolchain, dotted-path) that must be non-null for COMPLETE
    ("node", ("pnpm", "resolved_entrypoint_sha256")),
    ("gradle", ("wrapper", "wrapper_jar_sha256")),
]


def _missing() -> list[str]:
    miss = []
    for tk, paths in _REQUIRED_EXE_HASHES.items():
        for p in paths:
            node = TOOLCHAINS[tk]
            for k in p:
                node = node[k]
            if node.get("expected_sha256") is None:
                miss.append(f"{tk}.{'.'.join(p)}.expected_sha256")
    for tk, path in _REQUIRED_EXTRA:
        node = TOOLCHAINS[tk]
        for k in path:
            node = node[k]
        if node is None:
            miss.append(f"{tk}.{'.'.join(path)}")
    return miss


def build() -> dict:
    missing = _missing()
    return c.envelope(
        record_type="n2e-toolchain-lock",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_toolchain_lock.py",
        purpose="Expected identities of the publisher-pinned toolchains derived from immutable "
                "upstream artifacts; runtime evidence is compared by exact structured equality. "
                "Wrong-version or wrong-binary substitution is a HARNESS_DEFECT.",
        lock_state="COMPLETE" if not missing else "HARVEST",
        missing_expected_identities=missing,
        acceptance_eligible=not missing,
        toolchains=TOOLCHAINS,
    )


def main() -> int:
    c.write_record(OUT, build())
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name}: lock_state={rec['lock_state']} "
          f"(missing={len(rec['missing_expected_identities'])})")
    for m in rec["missing_expected_identities"]:
        print(f"  MISSING: {m}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
