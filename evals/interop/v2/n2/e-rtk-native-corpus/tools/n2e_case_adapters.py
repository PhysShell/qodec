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


class FilesReadAdapter(CaseAdapter):
    """`rtk read README.md` file-read command oracle. RAW is `cat README.md`; RTK is `rtk read
    README.md` -- a DIFFERENT command RTK reimplements (NOT rtk-wrapping cat), so the "rtk wraps the
    identical target" invariant does NOT apply; instead both argv are double-locked verbatim against
    the frozen contract. The frozen argv carries no --level (default `none` -> NoFilter identity), so
    RTK reproduces the file content byte-for-byte; the oracle asserts content fidelity.

    ONE policy (rtk-files-read-oracle-v1) is shared by preact AND lombok as TWO INDEPENDENT case
    bindings: each is a distinct subclass with its own frozen case_id, each double-locked against its
    OWN contract, each qualified by its own run/artifact/evidence -- never a family-level
    files_search::read scope. No toolchain, no daemon, no wall-clock: the command is a read-only
    `cat`/`rtk read` on a pinned checkout, so no GOCACHE/toolchain isolation is needed."""

    adapter_id = "files-read"
    qualification_kind = "rtk_command_oracle"

    RAW_ARGV = ["cat", "README.md"]
    RTK_ARGV = ["rtk", "read", "README.md"]
    CANON_POLICY = "files-v1"
    ORACLE_POLICY = "rtk-files-read-oracle-v1"
    SEMANTIC_ENV = {}
    PROTECTED_FILES = []
    REPS = 3
    STREAM_ROLES = ("raw", "rtk")
    PLATFORM_REQUIREMENTS = {"toolchain": [], "network": "denied"}
    EXECUTION_ISOLATION = {
        "fresh_gocache_per_arm": False,  # read-only command; no build/test cache involved
        "single_checkout": True,         # one pinned checkout shared by both arms (same source bytes)
        "same_cwd": ".",                 # both arms run in the repo root
        "no_p52_fixture_reuse": True,    # acceptance streams are captured fresh
        "read_only_command": True,       # neither arm mutates the checkout
    }

    def bind(self, contract: dict, scenario: dict) -> dict:
        _require(contract.get("effective_raw_argv") == self.RAW_ARGV,
                 f"{self.adapter_id} RAW argv != frozen contract")
        _require(contract.get("effective_rtk_argv") == self.RTK_ARGV,
                 f"{self.adapter_id} RTK argv != frozen contract")
        _require(contract.get("canonicalization_policy_id") == self.CANON_POLICY,
                 f"{self.adapter_id} canon policy != frozen contract")
        _require(contract.get("scheduler_env") == self.SEMANTIC_ENV,
                 f"{self.adapter_id} semantic env != frozen contract")
        _require(list(contract.get("protected_files") or []) == self.PROTECTED_FILES,
                 f"{self.adapter_id} protected files != frozen contract")
        _require(contract.get("command_family") == "files_search"
                 and contract.get("command_subfamily") == "read",
                 f"{self.adapter_id} command family/subfamily != frozen contract")
        # RTK is a distinct reimplementation of cat, not `rtk <cat-argv>`: assert the exact frozen shape
        _require(self.RTK_ARGV[0] == "rtk" and self.RTK_ARGV[1] == "read",
                 f"{self.adapter_id} RTK arm is not `rtk read`")
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


class PreactReadAdapter(FilesReadAdapter):
    case_id = "preactjs__preact-3345::files_search::read"


class LombokReadAdapter(FilesReadAdapter):
    case_id = "projectlombok__lombok-3312::files_search::read"


class VueVitestAdapter(CaseAdapter):
    """vue `pnpm run test <spec> --no-watch --reporter=verbose` (buggy) test-dialect. Second proven
    test dialect after caddy (go), on the js_ts family. The RTK arm wraps the identical pnpm command
    (`rtk pnpm run test ...`), exactly as caddy wraps `go test`.

    Dialect authority: the frozen execution contract carries rtk_test_dialect_policy_id=None (only the
    first test-dialect vertical, caddy, had it populated), so -- exactly as the command oracles do --
    the MANIFEST is authoritative for the RTK-projection dialect. The adapter declares the proven
    dialect (rtk-js-vitest-summary-v1) and the independent verifier cross-checks it against the frozen
    manifest classification; it is NOT cross-checked against the contract (which is None).

    Determinism: vitest is scoped to a SINGLE spec file + `--no-watch`, and run_arm reuses a FIXED work
    path so vitest's "RUN vX <abs-path>" line is not a source of per-rep variance. Whether RAW is
    deterministic is decided empirically by the probe + verifier gate (the sentinel), never asserted."""

    case_id = "vuejs__core-11589::js_ts::test::buggy"
    adapter_id = "vue-vitest"
    qualification_kind = "rtk_test_dialect"

    RAW_ARGV = ["pnpm", "run", "test", "packages/runtime-core/__tests__/apiWatch.spec.ts",
                "--no-watch", "--reporter=verbose"]
    RTK_ARGV = ["rtk", "pnpm", "run", "test", "packages/runtime-core/__tests__/apiWatch.spec.ts",
                "--no-watch", "--reporter=verbose"]
    CANON_POLICY = "vitest-v1"
    DIALECT_POLICY = "rtk-js-vitest-summary-v1"   # manifest-authoritative (contract dialect is None)
    TARGET_IDS = ["packages/runtime-core/__tests__/apiWatch.spec.ts > api: watch > should be executed correctly"]
    SEMANTIC_ENV = {}
    PROTECTED_FILES = ["package.json", "pnpm-lock.yaml", "package-lock.json", "yarn.lock"]
    REPS = 3
    STREAM_ROLES = ("raw", "rtk")
    PLATFORM_REQUIREMENTS = {"toolchain": ["node", "pnpm"], "network": "denied"}
    EXECUTION_ISOLATION = {
        "fresh_gocache_per_arm": False,   # not a go build/test cache case
        "single_checkout": True,          # one checkout shared by both arms (same source bytes)
        "same_cwd": ".",                  # both arms run in the repo root
        "no_p52_fixture_reuse": True,     # acceptance streams captured fresh
        "fixed_work_path": True,          # run_arm's constant work path removes vitest abs-path variance
    }

    def bind(self, contract: dict, scenario: dict) -> dict:
        _require(contract.get("effective_raw_argv") == self.RAW_ARGV, "vue RAW argv != frozen contract")
        _require(contract.get("effective_rtk_argv") == self.RTK_ARGV, "vue RTK argv != frozen contract")
        _require(contract.get("canonicalization_policy_id") == self.CANON_POLICY,
                 "vue canon policy != frozen contract")
        _require(contract.get("scheduler_env") == self.SEMANTIC_ENV, "vue semantic env != frozen contract")
        _require(list(contract.get("protected_files") or []) == self.PROTECTED_FILES,
                 "vue protected files != frozen contract")
        _require(list(scenario.get("target_test_ids") or []) == self.TARGET_IDS,
                 "vue target ids != frozen scenario")
        _require(contract.get("command_family") == "js_ts" and contract.get("command_subfamily") == "test",
                 "vue command family/subfamily != frozen contract")
        # RTK arm must wrap the identical pnpm test target
        _require(self.RTK_ARGV[0] == "rtk" and self.RTK_ARGV[1:] == self.RAW_ARGV,
                 "vue RTK arm is not the identical pnpm target wrapped by rtk")
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


# tiny registry: Caddy (test-dialect) + Gin (command-oracle) prove both dispatch paths; the two
# files-read adapters are the FIRST replication -- one shared oracle policy, two INDEPENDENT bindings;
# Vue is the second proven test dialect (js_ts), manifest-authoritative like the command oracles.
CASE_ADAPTERS = {
    CaddyGoTestAdapter.case_id: CaddyGoTestAdapter(),
    GinGoVetAdapter.case_id: GinGoVetAdapter(),
    PreactReadAdapter.case_id: PreactReadAdapter(),
    LombokReadAdapter.case_id: LombokReadAdapter(),
    VueVitestAdapter.case_id: VueVitestAdapter(),
}


def adapter_for(case_id: str) -> CaseAdapter:
    a = CASE_ADAPTERS.get(case_id)
    if a is None:
        raise AdapterBindingError(f"no registered acceptance adapter for {case_id} "
                                  f"(the harness runs ONLY pre-registered adapters)")
    return a
