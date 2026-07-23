"""Immutable execution-control policies for frameworks with intrinsic randomization.

lucene-randomized-seed-v1: Lucene's tests use the RandomizedTesting framework, which
picks a RANDOM master seed each run unless one is supplied, so 3 faithful reps of the
publisher command diverge. This policy MECHANICALLY derives one fixed seed (never
chosen after observing outcomes) and supplies it to BOTH the RAW and RTK arms via the
gradle property the framework already exposes (`-Ptests.seed=<16-hex>`), the exact
syntax the pinned Lucene build prints in its own reproduce line. It changes NO test
membership and hides no semantic difference: if the faithful, fixed-seed execution is
still byte-nondeterministic, that is genuine DISQUALIFIED_INTRINSIC_NONDETERMINISM.

The seed is derived deterministically and recorded in the execution contract; the
verifier recomputes it and rejects any mutation.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import n2e_common as c

LUCENE_SEED_POLICY_ID = "lucene-randomized-seed-v1"
GRADLE_OFFLINE_POLICY_ID = "gradle-offline-isolation-v1"
_SEL = Path(__file__).resolve().parent.parent / "n2e-selection-result-v1.json"

# case_id -> (policy_id, gradle property flag). Only the frozen lucene test case.
_SEED_CASES = {
    "apache__lucene-13704::jvm::test::buggy": (LUCENE_SEED_POLICY_ID, "-Ptests.seed"),
}

# gradle-offline-isolation-v1: the exact flags appended (identically) to the warm
# prime AND both measured arms of every Gradle (jvm) case so each of the 3 reps runs
# fully offline, spawns NO daemon, and does NOT rely on the filesystem watcher (whose
# background rescans are a source of per-rep nondeterminism). These flags never change
# test membership. They pair with a per-repetition fresh copy of a frozen GRADLE_USER_
# HOME cache seed (no shared mutable home; no surviving daemon/journal/lock/task-history
# /test-output), so an UP-TO-DATE / FROM-CACHE short-circuit cannot mask a rep that did
# not actually execute the target class -- which, if it happened, is DISQUALIFIED_
# OFFLINE_EXECUTION, never a silent pass.
_GRADLE_OFFLINE_ARGS = ["--offline", "--no-daemon", "-Dorg.gradle.vfs.watch=false"]


def selection_seed() -> str:
    return str(c.load_record(_SEL)["seed"])


def derive_seed(case_id: str) -> str:
    """16 uppercase hex chars (64-bit), the exact width RandomizedTesting uses.
    seed_material = sha256(policy_id + frozen_selection_seed + case_id)."""
    material = (LUCENE_SEED_POLICY_ID + selection_seed() + case_id).encode()
    return hashlib.sha256(material).hexdigest()[:16].upper()


def seed_arg(case_id: str) -> str | None:
    """The exact argv token to APPEND to both arms, or None if the case has no seed
    policy. e.g. '-Ptests.seed=3F2A...'. Never filters tests / changes membership."""
    ent = _SEED_CASES.get(case_id)
    if not ent:
        return None
    _, flag = ent
    return f"{flag}={derive_seed(case_id)}"


# Lucene runs its test methods across MULTIPLE forked JVMs by default (`-Ptests.jvms`
# defaults to a CPU-derived value), so even with a fixed master seed the interleaved
# per-fork output is nondeterministic across reps. Forcing a SINGLE test JVM removes
# that interleaving without changing which tests run (same seed, same membership).
_SINGLE_JVM_ARG = "-Ptests.jvms=1"

# lucene-gradle-test-execution-v2: the fixed seed + single test JVM were already proven, but the
# residual per-rep variance sits at the GRADLE-level concurrency layer, not in randomizedtesting:
# Gradle schedules the test task across multiple WORKERS and may run projects in PARALLEL, interleaving
# task output. v2 pins the execution determinants that remove that interleaving WITHOUT changing test
# membership (same seed, same --tests target): a single Gradle worker, parallel execution disabled,
# plain console so TTY/progress rendering never enters the RAW stream. The seed is still derived by
# lucene-randomized-seed-v1 (unchanged value); daemon/offline isolation stays owned by
# gradle-offline-isolation-v1 (--no-daemon etc. applied at runtime with a fresh per-rep
# GRADLE_USER_HOME), so v2 does NOT restate those flags (no double-flag). The old seed-only run stays
# diagnostic-only. If the fixed-seed, single-worker, no-parallel, plain-console execution is STILL
# byte-nondeterministic, that is genuine DISQUALIFIED_INTRINSIC_NONDETERMINISM (diagnostic-only).
LUCENE_EXECUTION_POLICY_ID = "lucene-gradle-test-execution-v2"
_MAX_WORKERS_ARG = "--max-workers=1"              # single Gradle worker (build-level concurrency)
_NO_PARALLEL_ARG = "-Dorg.gradle.parallel=false"  # never run projects in parallel
_CONSOLE_PLAIN_ARG = "--console=plain"            # no TTY/progress rendering in the captured stream
# EXACT ordered execution-determinant flags v2 appends to the frozen argv (order frozen: the executed
# command and the evidence metadata must never diverge into separate orderings)
_LUCENE_V2_EXEC_ARGS = [_SINGLE_JVM_ARG, _MAX_WORKERS_ARG, _NO_PARALLEL_ARG, _CONSOLE_PLAIN_ARG]


def policy_for_case(case_id: str) -> dict | None:
    ent = _SEED_CASES.get(case_id)
    if not ent:
        return None
    seed_pid, flag = ent
    # seed FIRST (the reproduce-line token), then the Gradle-concurrency determinants -- an ordered
    # list, never an unordered set.
    args = [seed_arg(case_id), *_LUCENE_V2_EXEC_ARGS]
    return {"policy_id": LUCENE_EXECUTION_POLICY_ID, "flag": flag, "seed": derive_seed(case_id),
            "arg": seed_arg(case_id), "args": args, "single_jvm": _SINGLE_JVM_ARG,
            "max_workers": _MAX_WORKERS_ARG, "parallel_disabled": _NO_PARALLEL_ARG,
            "console": _CONSOLE_PLAIN_ARG,
            "seed_policy_id": seed_pid, "selection_seed": selection_seed(),
            "seed_derivation": f"sha256({seed_pid}+selection_seed+case_id)[:16].upper()",
            "daemon_offline_isolation_policy_id": GRADLE_OFFLINE_POLICY_ID,
            "execution_determinants": list(_LUCENE_V2_EXEC_ARGS),
            "supersedes": "lucene-randomized-seed-v1 (seed+jvms only; RAW-nondeterministic run stays diagnostic-only)"}


def gradle_offline_args() -> list[str]:
    """The exact argv flags appended to warm + both arms of a Gradle case."""
    return list(_GRADLE_OFFLINE_ARGS)


def gradle_offline_policy() -> dict:
    """The recorded gradle-offline-isolation-v1 policy (for the execution contract)."""
    return {
        "policy_id": GRADLE_OFFLINE_POLICY_ID,
        "args": list(_GRADLE_OFFLINE_ARGS),
        "gradle_user_home_isolation":
            "per-repetition fresh copy of a frozen GRADLE_USER_HOME cache seed at a "
            "stable per-rep path; no shared mutable home; the seed is sanitized of "
            "daemon / journal / *.lock / task-history / test-output before the reps",
        "per_rep_execution_proof":
            "each rep's output must show the target test task actually EXECUTED (not "
            "UP-TO-DATE / FROM-CACHE / NO-SOURCE / SKIPPED); otherwise the case is "
            "DISQUALIFIED_OFFLINE_EXECUTION, never a silent pass",
    }
