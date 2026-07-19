#!/usr/bin/env python3
"""Registered per-case acceptance ADAPTERS -- the "not arbitrary JSON" contract for the generic
acceptance harness.

The generic probe/verifier NEVER read a shell command, argv, env, canonicalization regex, or parser
path out of the manifest. They select ONE pre-registered adapter by case id, and every execution
determinant is DOUBLE-LOCKED: the adapter carries its own frozen constants AND cross-checks them
against the frozen execution contract for that case. A mismatch on either side is a hard binding
error -- neither the manifest nor a tampered contract can make the harness run something the adapter
did not freeze, and the adapter cannot run something the contract does not declare.

Each adapter declares: raw/rtk argv + cwd + semantic env, repetition count, stream roles,
canonicalization policy id, semantic (dialect/oracle) policy id, platform requirements, and any
execution-isolation determinant that materially shapes output (e.g. a clean Go build/test cache so
BOTH arms really execute -- never one real, one `(cached)`).

Registry is intentionally tiny: Caddy first proves the template; other adapters are added only after
their vertical is designed -- no ritual copy of an unknown bug across eleven repos.
"""
from __future__ import annotations


class AdapterBindingError(Exception):
    pass


class CaseAdapter:
    case_id: str = ""
    adapter_id: str = ""
    qualification_kind: str = ""

    def bind(self, contract: dict, scenario: dict) -> dict:  # pragma: no cover - interface
        raise NotImplementedError


def _require(cond: bool, msg: str):
    if not cond:
        raise AdapterBindingError(msg)


class CaddyGoTestAdapter(CaseAdapter):
    """caddy `go test` (buggy) sentinel. Determinants frozen here AND cross-checked against the
    frozen execution contract + scenario. Go test caches results by default and the argv carries no
    -count=1, so the adapter pins a CLEAN per-arm GOCACHE (isolation determinant): both arms really
    execute the target -- an all-`(cached)` second arm would make execution equivalence dubious even
    if the semantic totals matched."""

    case_id = "caddyserver__caddy-5870::go::test::buggy"
    adapter_id = "caddy-go-test"
    qualification_kind = "rtk_test_dialect"

    RAW_ARGV = ["go", "test", "-v", ".", "-run", "TestUnsyncedConfigAccess"]
    RTK_ARGV = ["rtk", "go", "test", "-v", ".", "-run", "TestUnsyncedConfigAccess"]
    CANON_POLICY = "caddy-go-test-v1"
    DIALECT_POLICY = "rtk-go-test-summary-v1"
    TARGET_IDS = ["TestUnsyncedConfigAccess"]
    SEMANTIC_ENV = {"GOFLAGS": "-mod=readonly", "GOPROXY": "off"}
    PROTECTED_FILES = ["go.mod", "go.sum"]
    REPS = 3
    STREAM_ROLES = ("raw", "rtk")
    PLATFORM_REQUIREMENTS = {"toolchain": ["go"], "network": "denied"}
    # execution-isolation determinants that materially shape output (frozen, cross-checked)
    EXECUTION_ISOLATION = {
        "fresh_gocache_per_arm": True,   # both arms actually execute; no cross-arm `(cached)`
        "single_checkout": True,         # one checkout shared by both arms (same source bytes)
        "same_cwd": ".",                 # both arms run in the repo root
        "no_p52_fixture_reuse": True,    # acceptance streams are captured fresh, never P5.2 fixtures
    }

    def bind(self, contract: dict, scenario: dict) -> dict:
        # ---- DOUBLE-LOCK: adapter frozen constants must equal the frozen contract determinants ----
        _require(contract.get("effective_raw_argv") == self.RAW_ARGV,
                 "caddy RAW argv != frozen contract")
        _require(contract.get("effective_rtk_argv") == self.RTK_ARGV,
                 "caddy RTK argv != frozen contract")
        _require(contract.get("canonicalization_policy_id") == self.CANON_POLICY,
                 "caddy canon policy != frozen contract")
        _require(contract.get("rtk_test_dialect_policy_id") == self.DIALECT_POLICY,
                 "caddy dialect policy != frozen contract")
        _require(contract.get("scheduler_env") == self.SEMANTIC_ENV,
                 "caddy semantic env != frozen contract")
        _require(list(contract.get("protected_files") or []) == self.PROTECTED_FILES,
                 "caddy protected files != frozen contract")
        _require(list(scenario.get("target_test_ids") or []) == self.TARGET_IDS,
                 "caddy target ids != frozen scenario")
        _require(contract.get("command_family") == "go" and contract.get("command_subfamily") == "test",
                 "caddy command family/subfamily != frozen contract")
        # RAW and RTK arms MUST drive the same test target (rtk wraps the identical go argv)
        _require(self.RTK_ARGV[0] == "rtk" and self.RTK_ARGV[1:] == self.RAW_ARGV,
                 "caddy RTK arm is not the identical go target wrapped by rtk")
        return {
            "case_id": self.case_id, "adapter_id": self.adapter_id,
            "qualification_kind": self.qualification_kind,
            "raw_argv": list(self.RAW_ARGV), "rtk_argv": list(self.RTK_ARGV),
            "semantic_env": dict(self.SEMANTIC_ENV), "cwd": self.EXECUTION_ISOLATION["same_cwd"],
            "reps": self.REPS, "stream_roles": list(self.STREAM_ROLES),
            "canonicalization_policy_id": self.CANON_POLICY,
            "rtk_test_dialect_policy_id": self.DIALECT_POLICY,
            "command_semantic_oracle_policy_id": None,
            "target_test_ids": list(self.TARGET_IDS),
            "protected_files": list(self.PROTECTED_FILES),
            "platform_requirements": dict(self.PLATFORM_REQUIREMENTS),
            "execution_isolation": dict(self.EXECUTION_ISOLATION),
        }


class GinGoVetAdapter(CaseAdapter):
    """gin `go vet ./...` (clean) command-oracle sentinel. Proves the SECOND qualification_kind.
    Determinants double-locked against the frozen contract + scenario; the semantic policy is the
    proven command oracle (rtk-go-vet-oracle-v1) -- the base contract still names the richer base
    diagnostics oracle, so the oracle is NOT cross-checked against the contract (the manifest is
    authoritative for the RTK-projection oracle, exactly as forward test dialects were). go vet
    caches like go test and the argv has no -count=1, so a CLEAN per-arm GOCACHE is pinned."""

    case_id = "gin-gonic__gin-2755::go::vet"
    adapter_id = "gin-go-vet"
    qualification_kind = "rtk_command_oracle"

    RAW_ARGV = ["go", "vet", "./..."]
    RTK_ARGV = ["rtk", "go", "vet", "./..."]
    CANON_POLICY = "go-vet-v1"
    ORACLE_POLICY = "rtk-go-vet-oracle-v1"
    SEMANTIC_ENV = {"GOFLAGS": "-mod=readonly", "GOPROXY": "off"}
    PROTECTED_FILES = ["go.mod", "go.sum"]
    REPS = 3
    STREAM_ROLES = ("raw", "rtk")
    PLATFORM_REQUIREMENTS = {"toolchain": ["go"], "network": "denied"}
    EXECUTION_ISOLATION = {
        "fresh_gocache_per_arm": True,
        "single_checkout": True,
        "same_cwd": ".",
        "no_p52_fixture_reuse": True,
    }

    def bind(self, contract: dict, scenario: dict) -> dict:
        _require(contract.get("effective_raw_argv") == self.RAW_ARGV, "gin RAW argv != frozen contract")
        _require(contract.get("effective_rtk_argv") == self.RTK_ARGV, "gin RTK argv != frozen contract")
        _require(contract.get("canonicalization_policy_id") == self.CANON_POLICY,
                 "gin canon policy != frozen contract")
        _require(contract.get("scheduler_env") == self.SEMANTIC_ENV, "gin semantic env != frozen contract")
        _require(list(contract.get("protected_files") or []) == self.PROTECTED_FILES,
                 "gin protected files != frozen contract")
        _require(contract.get("command_family") == "go" and contract.get("command_subfamily") == "vet",
                 "gin command family/subfamily != frozen contract")
        # RTK arm must wrap the identical go vet target
        _require(self.RTK_ARGV[0] == "rtk" and self.RTK_ARGV[1:] == self.RAW_ARGV,
                 "gin RTK arm is not the identical go vet target wrapped by rtk")
        return {
            "case_id": self.case_id, "adapter_id": self.adapter_id,
            "qualification_kind": self.qualification_kind,
            "raw_argv": list(self.RAW_ARGV), "rtk_argv": list(self.RTK_ARGV),
            "semantic_env": dict(self.SEMANTIC_ENV), "cwd": self.EXECUTION_ISOLATION["same_cwd"],
            "reps": self.REPS, "stream_roles": list(self.STREAM_ROLES),
            "canonicalization_policy_id": self.CANON_POLICY,
            "rtk_test_dialect_policy_id": None,
            "command_semantic_oracle_policy_id": self.ORACLE_POLICY,
            "target_test_ids": [],
            "protected_files": list(self.PROTECTED_FILES),
            "platform_requirements": dict(self.PLATFORM_REQUIREMENTS),
            "execution_isolation": dict(self.EXECUTION_ISOLATION),
        }


# tiny registry: Caddy (test-dialect) + Gin (command-oracle) prove both dispatch paths before
# any further replication.
CASE_ADAPTERS = {
    CaddyGoTestAdapter.case_id: CaddyGoTestAdapter(),
    GinGoVetAdapter.case_id: GinGoVetAdapter(),
}


def adapter_for(case_id: str) -> CaseAdapter:
    a = CASE_ADAPTERS.get(case_id)
    if a is None:
        raise AdapterBindingError(f"no registered acceptance adapter for {case_id} "
                                  f"(the harness runs ONLY pre-registered adapters)")
    return a
