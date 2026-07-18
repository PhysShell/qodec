#!/usr/bin/env python3
"""Build the self-hash-locked SWE-bench Multilingual PUBLISHER environment registry.

The single normative source for how a SWE-bench case must be acquired is the
publisher's per-instance environment recipe -- the publisher-curated toolchain,
pre-install, install (warm/compile), and test commands, plus any per-instance
dependency lockfile. These live in the SWE-bench harness source
(`SWE-bench/SWE-bench`, module `swebench/harness/constants/{rust,go,javascript,
java}.py`), NOT in the HuggingFace dataset. This builder pins that harness commit,
records each instance's exact recipe, verifies committed fixture bytes by SHA-256,
and emits a self-hash-locked registry from which the execution contract + driver
derive the effective commands (instead of repository-specific guesses).

Provenance (confirmed by reading the harness source at the pinned commit):
  harness repo    : SWE-bench/SWE-bench
  harness commit  : f7bbbb2ccdf479001d6467c9e34af59e44a840f9
  dataset         : SWE-bench/SWE-bench_Multilingual @ 2b7aced941b4873e9cad3e76abbae93f481d1beb
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

OUT = N2E_DIR / "n2e-publisher-env-registry-v1.json"
FIX = N2E_DIR / "fixtures" / "swebench"

HARNESS = {
    "repo": "SWE-bench/SWE-bench",
    "commit": "f7bbbb2ccdf479001d6467c9e34af59e44a840f9",
    "constants_module": "swebench/harness/constants",
}
DATASET = {"id": "SWE-bench/SWE-bench_Multilingual",
           "revision": "2b7aced941b4873e9cad3e76abbae93f481d1beb"}

# Curated per-instance recipes, transcribed verbatim from the pinned harness source.
# `install` is the publisher warm/compile step (network-enabled during acquisition);
# `test_cmd` is the measured command. `env` is prepended to BOTH arms identically.
# `pre_install` actions: {"materialize_lockfile": fixture} copies a committed
# per-instance lockfile to its target byte-for-byte; {"shell_fixture": path} runs a
# committed shell script byte-for-byte.
RECIPES = [
    {
        "case_id": "caddyserver__caddy-5870::go::test::buggy",
        "instance_id": "caddyserver__caddy-5870", "slot": "go_test_fail",
        "language": "go", "repo": "caddyserver/caddy",
        "spec": "GO caddy 5870",
        "toolchain": {"kind": "go", "version": "1.23.8"},
        "base_image": "golang:1.23.8",
        "pre_install": [],
        "install": ['go test -c . -run "TestUnsyncedConfigAccess"'],
        "test_cmd": ['go test -v . -run "TestUnsyncedConfigAccess"'],
        "env": {},
        "lockfile": None,
        "oracle_policy_id": "n2e-oracle-test-v1",
    },
    {
        "case_id": "tokio-rs__tokio-4384::rust_cargo::test::fixed",
        "instance_id": "tokio-rs__tokio-4384", "slot": "rust_test_pass",
        "language": "rust", "repo": "tokio-rs/tokio",
        "spec": "TOKIO 4384",
        "toolchain": {"kind": "rust", "version": "1.83"},
        "base_image": "rust:1.83",
        "pre_install": [{"materialize_lockfile": "tokio-rs__tokio-4384.Cargo.lock",
                         "target": "Cargo.lock"}],
        "install": ["cargo test --locked --package tokio --test net_lookup_host "
                    "--features full --no-fail-fast --no-run"],
        "test_cmd": ["cargo test --package tokio --test net_types_unwind "
                     "--features full --no-fail-fast"],
        "env": {"RUSTFLAGS": "-Awarnings"},
        "lockfile": {"fixture": "tokio-rs__tokio-4384.Cargo.lock", "target": "Cargo.lock",
                     "sha256": "6f7401a1c6c2690bc5b48d54b1be4a87a443252febe89ccc74ac4e9e65f38dba"},
        "oracle_policy_id": "n2e-oracle-test-v1",
    },
    {
        "case_id": "vuejs__core-11589::js_ts::test::buggy",
        "instance_id": "vuejs__core-11589", "slot": "js_test_fail",
        "language": "js_ts", "repo": "vuejs/core",
        "spec": "SPECS_VUEJS 11589 (js_2 variant)",
        "toolchain": {"kind": "node", "version": "20", "package_manager": "pnpm"},
        "base_image": "ubuntu:22.04+nodesource20",
        "pre_install": [],
        "install": ["pnpm i"],
        "test_cmd": ["pnpm run test packages/runtime-core/__tests__/apiWatch.spec.ts "
                     "--no-watch --reporter=verbose"],
        "env": {},
        "lockfile": None,  # uses repo pnpm-lock.yaml at base_commit
        "oracle_policy_id": "n2e-oracle-test-v1",
    },
    {
        "case_id": "apache__lucene-13704::jvm::test::buggy",
        "instance_id": "apache__lucene-13704", "slot": "jvm_test_fail",
        "language": "jvm", "repo": "apache/lucene",
        "spec": "SPECS_LUCENE 13704",
        "toolchain": {"kind": "java", "version": "21", "build": "gradle_wrapper"},
        "base_image": "maven:3.9-eclipse-temurin-21",
        "pre_install": [{"shell_fixture": "apache__lucene-13704.pre_install.sh"}],
        "install": [],
        "test_cmd": ["./gradlew test --tests org.apache.lucene.search.TestLatLonDocValuesQueries"],
        "env": {},
        "lockfile": None,
        "oracle_policy_id": "n2e-oracle-test-v1",
    },
]


def _fixture_hashes() -> dict:
    out = {}
    for f in sorted(FIX.glob("*")):
        out[f.name] = c.sha256_file(str(f))
    return out


def build() -> dict:
    fix = _fixture_hashes()
    # verify every referenced fixture is present + matches its declared sha256
    for r in RECIPES:
        lf = r.get("lockfile")
        if lf:
            got = fix.get(lf["fixture"])
            assert got == lf["sha256"], f"{r['instance_id']} lockfile sha mismatch: {got} != {lf['sha256']}"
        for pa in r["pre_install"]:
            if "materialize_lockfile" in pa:
                assert pa["materialize_lockfile"] in fix, f"missing lockfile fixture {pa['materialize_lockfile']}"
            if "shell_fixture" in pa:
                assert pa["shell_fixture"] in fix, f"missing shell fixture {pa['shell_fixture']}"
    return c.envelope(
        record_type="n2e-publisher-env-registry",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_publisher_registry.py",
        purpose="Self-hash-locked SWE-bench Multilingual publisher environment registry: the "
                "normative per-instance toolchain + pre-install/warm/test recipe + fixture "
                "hashes from which the execution contract and driver derive effective commands.",
        harness=HARNESS,
        dataset=DATASET,
        fixture_sha256=fix,
        recipe_count=len(RECIPES),
        recipes=RECIPES,
    )


def main() -> int:
    body = build()
    c.write_record(OUT, body)
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name}: {rec['recipe_count']} recipes; fixtures={list(rec['fixture_sha256'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
