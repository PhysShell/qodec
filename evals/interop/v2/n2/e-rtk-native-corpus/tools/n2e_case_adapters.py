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

import n2e_execution_control as ec


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


class ScrapyPytestAdapter(CaseAdapter):
    """scrapy `pytest tests/test_mail.py` (fixed) test-dialect on the python family. Third proven test
    dialect (rtk-python-pytest-summary-v1), manifest-authoritative (contract dialect is None). The RTK
    arm wraps the identical pytest target (`rtk pytest ...`).

    Python is version-pinned: scrapy needs CPython 3.8 (inspect.getargspec, removed in 3.11), which the
    workflow provisions and exposes via N2E_PY_INTERPRETERS; the acquisition warm builds a 3.8 venv,
    installs the repo + pytest online, and the offline measurement resolves `pytest` to that venv (venv
    bin prepended to PATH via the acquisition offline_env). Determinism is enforced by the frozen
    scheduler env (PYTHONHASHSEED=0, PYTHONDONTWRITEBYTECODE=1) and decided empirically by the probe +
    verifier gate (sentinel) -- this is also the case flagged RESOURCE_LIMIT, so the sentinel settles
    whether the scoped single-file pytest qualifies rather than a prior broad-suite classification."""

    case_id = "bugsinpy::scrapy-9::python::pytest::fixed"
    adapter_id = "scrapy-pytest"
    qualification_kind = "rtk_test_dialect"

    RAW_ARGV = ["pytest", "tests/test_mail.py"]
    RTK_ARGV = ["rtk", "pytest", "tests/test_mail.py"]
    CANON_POLICY = "pytest-v1"
    DIALECT_POLICY = "rtk-python-pytest-summary-v1"   # manifest-authoritative (contract dialect None)
    TARGET_IDS = ["python -m unittest -q tests.test_mail.MailSenderTest.test_send_single_values_to_and_cc"]
    SEMANTIC_ENV = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"}
    PROTECTED_FILES = ["requirements.txt", "setup.py", "setup.cfg", "pyproject.toml", "poetry.lock"]
    REPS = 3
    STREAM_ROLES = ("raw", "rtk")
    PLATFORM_REQUIREMENTS = {"toolchain": ["python"], "network": "denied"}
    EXECUTION_ISOLATION = {
        "fresh_gocache_per_arm": False,
        "single_checkout": True,
        "same_cwd": ".",
        "no_p52_fixture_reuse": True,
        "case_pinned_interpreter": "3.8",   # venv on the pinned CPython; frozen pytest resolves offline
    }

    def bind(self, contract: dict, scenario: dict) -> dict:
        _require(contract.get("effective_raw_argv") == self.RAW_ARGV, "scrapy RAW argv != frozen contract")
        _require(contract.get("effective_rtk_argv") == self.RTK_ARGV, "scrapy RTK argv != frozen contract")
        _require(contract.get("canonicalization_policy_id") == self.CANON_POLICY,
                 "scrapy canon policy != frozen contract")
        _require(contract.get("scheduler_env") == self.SEMANTIC_ENV, "scrapy semantic env != frozen contract")
        _require(list(contract.get("protected_files") or []) == self.PROTECTED_FILES,
                 "scrapy protected files != frozen contract")
        _require(list(scenario.get("target_test_ids") or []) == self.TARGET_IDS,
                 "scrapy target ids != frozen scenario")
        _require(contract.get("command_family") == "python" and contract.get("command_subfamily") == "pytest",
                 "scrapy command family/subfamily != frozen contract")
        _require(self.RTK_ARGV[0] == "rtk" and self.RTK_ARGV[1:] == self.RAW_ARGV,
                 "scrapy RTK arm is not the identical pytest target wrapped by rtk")
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


class LuceneGradleAdapter(CaseAdapter):
    """lucene `./gradlew test --tests <class>` (buggy) test-dialect on the JVM family. Fourth proven
    test dialect (rtk-jvm-test-summary-v1), manifest-authoritative (contract dialect is None). The RTK
    arm wraps the identical gradlew invocation (`rtk ./gradlew ...`).

    v2 execution-determinant double-lock: this case does NOT freeze a literal argv tail. Lucene's argv
    is deterministic ONLY under the execution-control policy, so the adapter re-derives the exact
    ordered tail from n2e_execution_control.policy_for_case(case_id) -- seed FIRST (the reproduce-line
    token), then the Gradle-concurrency determinants (-Ptests.jvms=1, --max-workers=1,
    -Dorg.gradle.parallel=false, --console=plain) -- and requires BOTH the frozen contract argv AND
    the contract's execution_control block to equal that derivation. A mutated seed, a dropped
    concurrency flag, or a reordered tail is a hard binding error on either side. The seed is never a
    hardcoded magic string; it is recomputed from lucene-randomized-seed-v1 over the frozen selection
    seed, so no post-hoc seed choice can slip in.

    Canonicalization is runtime-resolved (RUNTIME:gradle-test-v1|maven-test-v1); Lucene builds with
    Gradle (argv[0] == './gradlew'), so the gradle branch is the resolved policy and the adapter
    asserts the gradle branch is the one selected. Daemon/offline isolation stays owned by
    gradle-offline-isolation-v1 (applied at runtime with a fresh per-rep GRADLE_USER_HOME); v2 does not
    restate those flags. Whether the fixed-seed, single-worker, no-parallel, plain-console execution is
    byte-deterministic is decided empirically by the probe + verifier gate (the sentinel): if it is
    still nondeterministic, that is genuine DISQUALIFIED_INTRINSIC_NONDETERMINISM, never a silent pass."""

    case_id = "apache__lucene-13704::jvm::test::buggy"
    adapter_id = "lucene-gradle-test"
    qualification_kind = "rtk_test_dialect"

    # base command WITHOUT the execution-control tail; the tail is re-derived, never frozen literally
    BASE_ARGV = ["./gradlew", "test", "--tests", "org.apache.lucene.search.TestLatLonDocValuesQueries"]
    CANON_POLICY = "RUNTIME:gradle-test-v1|maven-test-v1"
    RESOLVED_CANON_BRANCH = "gradle-test-v1"   # argv[0] == ./gradlew -> the gradle disjunct is selected
    DIALECT_POLICY = "rtk-jvm-test-summary-v1"   # manifest-authoritative (contract dialect is None)
    EXECUTION_POLICY_ID = "lucene-gradle-test-execution-v2"
    TARGET_IDS = ["TestLatLonDocValuesQueries > testNarrowPolygonCloseToNorthPole"]
    SEMANTIC_ENV = {}
    PROTECTED_FILES = ["build.gradle", "build.gradle.kts", "settings.gradle", "gradle.lockfile", "pom.xml"]
    REPS = 3
    STREAM_ROLES = ("raw", "rtk")
    PLATFORM_REQUIREMENTS = {"toolchain": ["java", "gradlew_or_mvn"], "network": "denied"}
    EXECUTION_ISOLATION = {
        "fresh_gocache_per_arm": False,          # not a go case
        "single_checkout": True,                 # one checkout shared by both arms (same source bytes)
        "same_cwd": ".",                         # both arms run in the repo root
        "no_p52_fixture_reuse": True,            # acceptance streams captured fresh
        "gradle_user_home_isolation": True,      # per-rep fresh GRADLE_USER_HOME (offline policy)
        "execution_control_policy_id": EXECUTION_POLICY_ID,
    }

    def _expected_argv(self):
        pol = ec.policy_for_case(self.case_id)
        _require(pol is not None, "lucene has no execution-control policy")
        _require(pol["policy_id"] == self.EXECUTION_POLICY_ID,
                 "lucene execution-control policy id != v2")
        tail = list(pol["args"])
        # ordered double-lock: seed FIRST, then the Gradle-concurrency determinants (exact order)
        _require(tail and tail[0].startswith("-Ptests.seed="),
                 "lucene execution-control tail is not seed-first")
        _require(tail[1:] == ["-Ptests.jvms=1", "--max-workers=1",
                              "-Dorg.gradle.parallel=false", "--console=plain"],
                 "lucene execution-control determinants != frozen v2 ordered set")
        raw = self.BASE_ARGV + tail
        return raw, ["rtk"] + raw, tail

    def bind(self, contract: dict, scenario: dict) -> dict:
        raw_argv, rtk_argv, exec_tail = self._expected_argv()
        # ---- DOUBLE-LOCK: adapter-derived argv must equal the frozen contract argv ----
        _require(contract.get("effective_raw_argv") == raw_argv, "lucene RAW argv != frozen contract")
        _require(contract.get("effective_rtk_argv") == rtk_argv, "lucene RTK argv != frozen contract")
        # the contract's execution_control block must pin the SAME v2 policy + SAME ordered tail
        exctl = contract.get("execution_control") or {}
        _require(exctl.get("policy_id") == self.EXECUTION_POLICY_ID,
                 "lucene contract execution_control policy id != v2")
        _require(list(exctl.get("args") or []) == exec_tail,
                 "lucene contract execution_control args != re-derived v2 ordered tail")
        _require(contract.get("canonicalization_policy_id") == self.CANON_POLICY,
                 "lucene canon policy != frozen contract")
        # runtime-resolved canon: Gradle build -> the gradle disjunct is the selected branch
        _require(raw_argv[0] == "./gradlew"
                 and self.RESOLVED_CANON_BRANCH in self.CANON_POLICY.split("RUNTIME:")[1].split("|"),
                 "lucene resolved canon branch is not the gradle disjunct")
        _require(contract.get("rtk_test_dialect_policy_id") in (None, self.DIALECT_POLICY),
                 "lucene contract dialect policy is neither None nor the proven jvm dialect")
        _require(contract.get("scheduler_env") == self.SEMANTIC_ENV, "lucene semantic env != frozen contract")
        _require(list(contract.get("protected_files") or []) == self.PROTECTED_FILES,
                 "lucene protected files != frozen contract")
        _require(list(scenario.get("target_test_ids") or []) == self.TARGET_IDS,
                 "lucene target ids != frozen scenario")
        _require(contract.get("command_family") == "jvm" and contract.get("command_subfamily") == "test",
                 "lucene command family/subfamily != frozen contract")
        # RTK arm must wrap the identical gradlew invocation
        _require(rtk_argv[0] == "rtk" and rtk_argv[1:] == raw_argv,
                 "lucene RTK arm is not the identical gradlew target wrapped by rtk")
        return {
            "case_id": self.case_id, "adapter_id": self.adapter_id,
            "qualification_kind": self.qualification_kind,
            "raw_argv": list(raw_argv), "rtk_argv": list(rtk_argv),
            "semantic_env": dict(self.SEMANTIC_ENV), "cwd": self.EXECUTION_ISOLATION["same_cwd"],
            "reps": self.REPS, "stream_roles": list(self.STREAM_ROLES),
            "canonicalization_policy_id": self.CANON_POLICY,
            "resolved_canonicalization_policy_id": self.RESOLVED_CANON_BRANCH,
            "rtk_test_dialect_policy_id": self.DIALECT_POLICY,
            "command_semantic_oracle_policy_id": None,
            "execution_control_policy_id": self.EXECUTION_POLICY_ID,
            "target_test_ids": list(self.TARGET_IDS),
            "protected_files": list(self.PROTECTED_FILES),
            "platform_requirements": dict(self.PLATFORM_REQUIREMENTS),
            "execution_isolation": dict(self.EXECUTION_ISOLATION),
        }


class LoghubHdfsAdapter(CaseAdapter):
    """loghub HDFS `rtk log HDFS.log` command oracle. RAW is `cat HDFS.log` (the full ~1.5 GB /
    11 167 740-line stream); RTK is `rtk log HDFS.log`, a DIFFERENT command RTK reimplements (NOT
    rtk-wrapping cat), so both argv are double-locked verbatim against the frozen contract.

    Two invariants beyond the usual double-lock:
      * BOTH arms read the SAME pinned input member (HDFS.log, one extraction shared by both arms) --
        so RAW and RTK see identical input bytes (the acquisition's input_sha256);
      * the RAW arm is measured through the log-evidence-capsule-v1 (full stream, bounded memory,
        NO 1500-line slice); template identity is the PUBLISHED Loghub set (n2e-loghub-hdfs-
        reference-v1), never our masking. The proven oracle (rtk-log-hdfs-oracle-v1) is
        manifest-authoritative -- the base contract names the generic base oracle, so the oracle is
        NOT cross-checked against the contract (exactly as gin / the files-read oracle)."""

    case_id = "loghub::HDFS::log"
    adapter_id = "loghub-hdfs-log"
    qualification_kind = "rtk_command_oracle"

    INPUT_FILE = "HDFS.log"
    RAW_ARGV = ["cat", "HDFS.log"]
    RTK_ARGV = ["rtk", "log", "HDFS.log"]
    CANON_POLICY = "log-v1"
    ORACLE_POLICY = "rtk-log-hdfs-oracle-v1"           # manifest-authoritative (contract oracle is base)
    EVIDENCE_MODEL = "log-evidence-capsule-v1"
    PUBLISHED_REFERENCE = "n2e-loghub-hdfs-reference-v1"
    SEMANTIC_ENV = {}
    PROTECTED_FILES = []
    REPS = 3
    STREAM_ROLES = ("raw", "rtk")
    PLATFORM_REQUIREMENTS = {"toolchain": [], "network": "denied"}
    EXECUTION_ISOLATION = {
        "fresh_gocache_per_arm": False,
        "single_checkout": True,          # one extracted member, shared by both arms (same input bytes)
        "same_cwd": ".",
        "no_p52_fixture_reuse": True,
        "read_only_command": True,        # neither arm mutates the member
        "shared_input_file": INPUT_FILE,  # RAW + RTK read the SAME pinned member
        "full_stream_no_slice": True,     # bounded capsule over the full stream; NEVER a 1500-line slice
    }

    def bind(self, contract: dict, scenario: dict) -> dict:
        _require(contract.get("effective_raw_argv") == self.RAW_ARGV, "loghub RAW argv != frozen contract")
        _require(contract.get("effective_rtk_argv") == self.RTK_ARGV, "loghub RTK argv != frozen contract")
        _require(contract.get("canonicalization_policy_id") == self.CANON_POLICY,
                 "loghub canon policy != frozen contract")
        _require(contract.get("scheduler_env") == self.SEMANTIC_ENV, "loghub semantic env != frozen contract")
        _require(list(contract.get("protected_files") or []) == self.PROTECTED_FILES,
                 "loghub protected files != frozen contract")
        _require(contract.get("command_family") == "logs" and contract.get("command_subfamily") == "log",
                 "loghub command family/subfamily != frozen contract")
        # RTK is a DISTINCT reimplementation of the log summary, not `rtk <cat-argv>`
        _require(self.RTK_ARGV[0] == "rtk" and self.RTK_ARGV[1] == "log", "loghub RTK arm is not `rtk log`")
        # CRITICAL: both arms read the SAME input file -> identical input bytes
        _require(self.RAW_ARGV[-1] == self.INPUT_FILE and self.RTK_ARGV[-1] == self.INPUT_FILE,
                 "loghub RAW/RTK arms do not read the same input file")
        return {
            "case_id": self.case_id, "adapter_id": self.adapter_id,
            "qualification_kind": self.qualification_kind,
            "raw_argv": list(self.RAW_ARGV), "rtk_argv": list(self.RTK_ARGV),
            "semantic_env": dict(self.SEMANTIC_ENV), "cwd": self.EXECUTION_ISOLATION["same_cwd"],
            "reps": self.REPS, "stream_roles": list(self.STREAM_ROLES),
            "canonicalization_policy_id": self.CANON_POLICY,
            "rtk_test_dialect_policy_id": None,
            "command_semantic_oracle_policy_id": self.ORACLE_POLICY,
            "input_file": self.INPUT_FILE, "evidence_model": self.EVIDENCE_MODEL,
            "published_reference": self.PUBLISHED_REFERENCE,
            "target_test_ids": [],
            "protected_files": list(self.PROTECTED_FILES),
            "platform_requirements": dict(self.PLATFORM_REQUIREMENTS),
            "execution_isolation": dict(self.EXECUTION_ISOLATION),
        }


class RubocopGitShowAdapter(CaseAdapter):
    """rubocop `rtk git show` command oracle. RAW is `git show` (bare, HEAD = the pinned base commit);
    RTK is `rtk git show`, a DIFFERENT command RTK reimplements (summary + --stat + compacted diff,
    OR the raw passthrough when never_worse falls back) -- so both argv are double-locked verbatim
    against the frozen contract, and the RTK arm is NOT `rtk <git-argv>`-wrapping the RAW arm.

    The proven oracle (rtk-git-show-oracle-v1) is grounded in the pinned RTK source (run_show +
    compact_diff + never_worse) and preserves ONLY the STAT + IDENTITY core (full_commit_oid via an
    unambiguous abbreviated-hash prefix, affected_paths SET, files_changed / insertions / deletions).
    %ar / author / subject / dates / the full patch are non-normative.

    The RAW projection is derived from the RAW `git show` bytes and INDEPENDENTLY cross-checked, on the
    same pinned checkout, against git plumbing (rev-parse HEAD + --numstat + --name-status + --shortstat)
    -- these are recorded as VERIFIER OBSERVATIONS, never substituted for the RAW arm. The oracle is
    manifest-authoritative (the base contract names the generic git-diff oracle), exactly as gin / the
    files-read / loghub oracles."""

    case_id = "rubocop__rubocop-13687::git::show"
    adapter_id = "rubocop-git-show"
    qualification_kind = "rtk_command_oracle"

    RAW_ARGV = ["git", "show"]
    RTK_ARGV = ["rtk", "git", "show"]
    CANON_POLICY = "git-v1"
    ORACLE_POLICY = "rtk-git-show-oracle-v1"          # manifest-authoritative (contract oracle is base)
    SEMANTIC_ENV = {}
    PROTECTED_FILES = []
    REPS = 3
    STREAM_ROLES = ("raw", "rtk")
    PLATFORM_REQUIREMENTS = {"toolchain": ["git"], "network": "denied"}
    # git plumbing the probe/verifier runs on the SAME pinned checkout to cross-check the RAW projection.
    # These are OBSERVATIONS (an independent authority for oid + paths + totals), never the RAW arm.
    PLUMBING_OBSERVATIONS = {
        "rev_parse_head": ["git", "rev-parse", "HEAD"],
        "numstat": ["git", "show", "--numstat", "--format="],
        "name_status": ["git", "show", "--name-status", "--format="],
        "shortstat": ["git", "show", "--shortstat", "--format="],
    }
    EXECUTION_ISOLATION = {
        "fresh_gocache_per_arm": False,
        "single_checkout": True,          # one pinned checkout shared by both arms + plumbing
        "same_cwd": ".",
        "no_p52_fixture_reuse": True,
        "read_only_command": True,        # neither arm nor the plumbing mutates the checkout
    }

    def bind(self, contract: dict, scenario: dict) -> dict:
        _require(contract.get("effective_raw_argv") == self.RAW_ARGV, "rubocop RAW argv != frozen contract")
        _require(contract.get("effective_rtk_argv") == self.RTK_ARGV, "rubocop RTK argv != frozen contract")
        _require(contract.get("canonicalization_policy_id") == self.CANON_POLICY,
                 "rubocop canon policy != frozen contract")
        _require(contract.get("scheduler_env") == self.SEMANTIC_ENV, "rubocop semantic env != frozen contract")
        _require(list(contract.get("protected_files") or []) == self.PROTECTED_FILES,
                 "rubocop protected files != frozen contract")
        _require(contract.get("command_family") == "git" and contract.get("command_subfamily") == "show",
                 "rubocop command family/subfamily != frozen contract")
        _require(self.RTK_ARGV[0] == "rtk" and self.RTK_ARGV[1] == "git" and self.RTK_ARGV[2] == "show",
                 "rubocop RTK arm is not `rtk git show`")
        # full commit OID authority: the pinned base commit (from the scenario recipe identity)
        base_commit = (((scenario.get("setup_recipe") or {}).get("identity") or {}).get("base_commit")
                       or (scenario.get("source_image_identity") or {}).get("base_commit"))
        _require(bool(base_commit) and len(base_commit) == 40 and all(ch in "0123456789abcdef" for ch in base_commit),
                 "rubocop scenario has no valid 40-hex base_commit OID")
        return {
            "case_id": self.case_id, "adapter_id": self.adapter_id,
            "qualification_kind": self.qualification_kind,
            "raw_argv": list(self.RAW_ARGV), "rtk_argv": list(self.RTK_ARGV),
            "semantic_env": dict(self.SEMANTIC_ENV), "cwd": self.EXECUTION_ISOLATION["same_cwd"],
            "reps": self.REPS, "stream_roles": list(self.STREAM_ROLES),
            "canonicalization_policy_id": self.CANON_POLICY,
            "rtk_test_dialect_policy_id": None,
            "command_semantic_oracle_policy_id": self.ORACLE_POLICY,
            "full_commit_oid": base_commit,
            "plumbing_observations": {k: list(v) for k, v in self.PLUMBING_OBSERVATIONS.items()},
            "target_test_ids": [],
            "protected_files": list(self.PROTECTED_FILES),
            "platform_requirements": dict(self.PLATFORM_REQUIREMENTS),
            "execution_isolation": dict(self.EXECUTION_ISOLATION),
        }


# tiny registry: Caddy (test-dialect) + Gin (command-oracle) prove both dispatch paths; the two
# files-read adapters are the FIRST replication -- one shared oracle policy, two INDEPENDENT bindings;
# Vue (js_ts) + Scrapy (python) are the second and third proven test dialects, manifest-authoritative.
CASE_ADAPTERS = {
    CaddyGoTestAdapter.case_id: CaddyGoTestAdapter(),
    GinGoVetAdapter.case_id: GinGoVetAdapter(),
    PreactReadAdapter.case_id: PreactReadAdapter(),
    LombokReadAdapter.case_id: LombokReadAdapter(),
    VueVitestAdapter.case_id: VueVitestAdapter(),
    ScrapyPytestAdapter.case_id: ScrapyPytestAdapter(),
    LuceneGradleAdapter.case_id: LuceneGradleAdapter(),
    LoghubHdfsAdapter.case_id: LoghubHdfsAdapter(),
    RubocopGitShowAdapter.case_id: RubocopGitShowAdapter(),
}


def adapter_for(case_id: str) -> CaseAdapter:
    a = CASE_ADAPTERS.get(case_id)
    if a is None:
        raise AdapterBindingError(f"no registered acceptance adapter for {case_id} "
                                  f"(the harness runs ONLY pre-registered adapters)")
    return a
