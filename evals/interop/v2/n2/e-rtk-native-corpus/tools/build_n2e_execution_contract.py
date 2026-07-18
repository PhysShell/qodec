#!/usr/bin/env python3
"""Build the self-hash-locked N2-E canary execution-contract record (correction #3).

For every frozen canary case this derives, from the frozen scenario plus the
declared argv-resolver policy (n2e_argv_resolver) and the canonicalization policy
binding (n2e_canon_policies.policy_for), an immutable execution contract with:

  original frozen case_id; original RAW argv; original RTK argv or declared RTK
  resolution rule; effective RAW argv; effective RTK argv (None where the rule is
  runtime-resolved from the repo -- the driver records the concrete argv and the
  verifier checks it against the rule); argv resolver policy id; canonicalization
  policy id; scheduler configuration; toolchain-identity reference; dependency-
  environment-identity reference; timeout tier; isolation method; protected files
  + mutation guards; semantic-oracle policy id.

For the Caddy case the record explicitly carries canonicalization_policy_id =
caddy-go-test-v1. The record links by hash to the frozen membership + scenarios,
and is self-hash-locked. It is the NORMATIVE source; the _CASE_POLICY lookup must
agree with it (checked by verify_n2e_execution_contract.py).
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_canon_policies as canon  # noqa: E402
import n2e_argv_resolver as resolver  # noqa: E402

CANARY = N2E_DIR / "n2e-canary-membership-v1.json"
SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
OUT = N2E_DIR / "n2e-canary-execution-contract-v1.json"

# semantic_oracle_type (frozen) -> versioned oracle policy id
ORACLE_POLICY = {
    "test_oracle": "n2e-oracle-test-v1",
    "diagnostics_oracle": "n2e-oracle-diagnostics-v1",
    "git_state_oracle": "n2e-oracle-git-state-v1",
    "git_diff_oracle": "n2e-oracle-git-diff-v1",
    "file_read_oracle": "n2e-oracle-file-read-v1",
    "log_oracle": "n2e-oracle-log-v1",
    "docker_oracle": "n2e-oracle-docker-v1",
}

# protected dependency/build inputs whose before/after hashes MUST match across
# acquisition and every measurement arm (a mutation is a typed harness rejection).
PROTECTED_FILES = {
    "rust_cargo": ["Cargo.lock", "Cargo.toml"],
    "go": ["go.mod", "go.sum"],
    "js_ts": ["package.json", "pnpm-lock.yaml", "package-lock.json", "yarn.lock"],
    "python": ["requirements.txt", "setup.py", "setup.cfg", "pyproject.toml", "poetry.lock"],
    "jvm": ["build.gradle", "build.gradle.kts", "settings.gradle", "gradle.lockfile", "pom.xml"],
}

# per-family toolchain/runtime whose exact identity must be captured at runtime
TOOLCHAIN_KEYS = {
    "rust_cargo": ["rustc", "cargo"],
    "go": ["go"],
    "js_ts": ["node", "corepack", "pnpm"],  # pnpm executes acquisition + measurement
    "jvm": ["java", "gradlew_or_mvn"],
    "python": ["python3", "pip"],
}


def _timeout_tier(secs) -> str:
    return {120: "standard-120s", 600: "extended-600s"}.get(secs, f"custom-{secs}s")


def _canon_policy_id(scen, cid) -> str:
    fam, sub = scen["command_family"], scen["command_subfamily"]
    if fam == "jvm" and sub == "test":
        # depends on the resolved build system; declared rule, concrete recorded at runtime
        return "RUNTIME:gradle-test-v1|maven-test-v1"
    return canon.policy_for(fam, sub, git=(fam == "git"), case_id=cid)


def build_contract(scen, cid) -> dict:
    fam, sub = scen["command_family"], scen["command_subfamily"]
    r = resolver.resolve(scen)  # static/declared derivation (no repo)
    container = fam == "containers"
    return {
        "case_id": cid,
        "command_family": fam, "command_subfamily": sub,
        "snapshot_variant": scen.get("snapshot_variant"),
        "original_raw_argv": scen["original_argv"],
        "original_rtk_argv": scen.get("explicit_rtk_argv"),
        "frozen_rtk_resolution_rule": scen.get("rtk_argv_resolution"),
        "argv_resolver_policy_id": resolver.RESOLVER_POLICY_ID,
        "resolution_rule": r["resolution_rule"],
        "runtime_resolved": r["runtime_resolved"],
        "effective_raw_argv": r["effective_raw_argv"],  # None when runtime_resolved
        "effective_rtk_argv": r["effective_rtk_argv"],
        "execution_control": r.get("execution_control"),  # e.g. lucene-randomized-seed-v1
        "scheduler_env": r["scheduler_env"],
        "scheduler_flags": r.get("scheduler_flags"),
        "canonicalization_policy_id": _canon_policy_id(scen, cid),
        "semantic_oracle_policy_id": ORACLE_POLICY.get(scen.get("semantic_oracle_type"), "n2e-oracle-none-v1"),
        "toolchain_identity_ref": {"where": "per-case record: acquisition.environment_identity.toolchain",
                                   "required_keys": TOOLCHAIN_KEYS.get(fam, [])},
        "dependency_environment_identity_ref": {
            "where": "per-case record: acquisition.environment_identity.dependencies",
            "protected_files": PROTECTED_FILES.get(fam, [])},
        "timeout_tier": _timeout_tier(scen.get("timeout_seconds")),
        "timeout_seconds": scen.get("timeout_seconds"),
        "isolation_method": ("host_side_docker_observation" if container
                             else "network-denied-netns(lo-up); positive denial probe"),
        "protected_files": PROTECTED_FILES.get(fam, []),
        "mutation_guard": "before/after SHA-256 equality across acquisition + every measurement arm; "
                          "any change is a typed harness rejection even on success exit",
    }


def build() -> dict:
    membership = c.load_record(CANARY)
    scen_by_id = {s["case_id"]: s for s in c.load_record(SCEN)["scenarios"]}
    contracts = []
    for m in sorted(membership["membership"], key=lambda x: x["case_id"]):
        cid = m["case_id"]
        contracts.append(build_contract(scen_by_id[cid], cid))
    return c.envelope(
        record_type="n2e-canary-execution-contract",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_execution_contract.py",
        purpose="Immutable per-case effective-execution contract; normative source for argv/canon/oracle "
                "resolution, toolchain+dependency identity references, and mutation guards (correction #3).",
        argv_resolver_policy_id=resolver.RESOLVER_POLICY_ID,
        canary_membership_sha256=c.sha256_json_file(CANARY),
        command_scenarios_sha256=c.sha256_json_file(SCEN),
        contract_count=len(contracts),
        contracts=contracts,
    )


def main() -> int:
    body = build()
    c.write_record(OUT, body)
    rec = c.load_record(OUT)
    caddy = next(x for x in rec["contracts"] if x["case_id"] == "caddyserver__caddy-5870::go::test::buggy")
    assert caddy["canonicalization_policy_id"] == "caddy-go-test-v1", caddy["canonicalization_policy_id"]
    print(f"wrote {OUT.name}: {rec['contract_count']} contracts; caddy canon={caddy['canonicalization_policy_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
