"""Normative typed-outcome taxonomy for N2-E canary case qualification.

A canary case receives exactly ONE terminal classification. The boundaries below
are STRICT and ordered: a case is only a candidate DISQUALIFICATION after every
harness/meter/environment-reproduction defect has been ruled out. HARNESS_DEFECT
and METER_DEFECT are NEVER terminal disqualifications -- they are corrected, then
the case is re-judged under corrected acquisition semantics.

The single source of truth for how a SWE-bench case must be acquired is the
publisher (SWE-bench Multilingual) per-instance environment recipe -- the
publisher-curated pre-install, install, and test commands plus the exact
toolchain and the exact per-instance dependency lockfile. Reproducing that recipe
faithfully is a prerequisite for ANY disqualification of a SWE-bench case.
"""
from __future__ import annotations

# ---- passing terminal outcome ------------------------------------------------
PASS = "PASS"  # RAW x3 canonically deterministic + oracle true, RTK agrees, offline

# ---- non-terminal outcomes: MUST be fixed, never disqualified ----------------
HARNESS_DEFECT = "HARNESS_DEFECT"
METER_DEFECT = "METER_DEFECT"

# ---- terminal typed disqualifications ---------------------------------------
DISQUALIFIED_INTRINSIC_NONDETERMINISM = "DISQUALIFIED_INTRINSIC_NONDETERMINISM"
DISQUALIFIED_OFFLINE_EXECUTION = "DISQUALIFIED_OFFLINE_EXECUTION"
DISQUALIFIED_RESOURCE_LIMIT = "DISQUALIFIED_RESOURCE_LIMIT"
DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE = "DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE"
DISQUALIFIED_RTK_SEMANTIC_LOSS = "DISQUALIFIED_RTK_SEMANTIC_LOSS"

TERMINAL_DISQUALIFICATIONS = frozenset({
    DISQUALIFIED_INTRINSIC_NONDETERMINISM,
    DISQUALIFIED_OFFLINE_EXECUTION,
    DISQUALIFIED_RESOURCE_LIMIT,
    DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE,
    DISQUALIFIED_RTK_SEMANTIC_LOSS,
})

# non-terminal outcomes are candidate NEITHER for the passing gate NOR the
# rejection ledger; they gate a re-run after the defect is corrected.
NON_TERMINAL = frozenset({HARNESS_DEFECT, METER_DEFECT})

# The strict, human-normative meaning of each outcome. These strings are the
# contract the rejection-ledger builder and the reviewer check against.
DEFINITIONS = {
    PASS: "RAW executed x3 network-denied under the faithfully-reproduced publisher "
          "environment, was canonically deterministic, the semantic oracle held, and "
          "the RTK arm agreed.",
    HARNESS_DEFECT:
        "Use when the acquisition did NOT faithfully reproduce the publisher recipe: "
        "the official recipe was not applied; the wrong toolchain was used; a "
        "publisher-provided lockfile was omitted; the acquisition invented its own "
        "dependency resolution; or exact recipe inputs have not yet been pinned or "
        "fetched. NOT a disqualification -- fix it, then re-judge.",
    METER_DEFECT:
        "Use when the qodec/o200k meter (not the workload) is the failure: a meter "
        "hang, crash, or timeout on otherwise deterministic canonical bytes. NOT a "
        "disqualification -- fix it, then re-judge.",
    DISQUALIFIED_INTRINSIC_NONDETERMINISM:
        "The workload was acquired faithfully and runs, but its own output is "
        "irreducibly nondeterministic across reps (e.g. a variable count / ordering "
        "of concurrently-emitted lines) that cannot be canonicalized without "
        "removing or reordering semantically meaningful content.",
    DISQUALIFIED_OFFLINE_EXECUTION:
        "The environment was successfully and reproducibly acquired; the exact "
        "effective command starts under the intended environment; but the workload "
        "genuinely cannot execute successfully with the network denied.",
    DISQUALIFIED_RESOURCE_LIMIT:
        "The faithfully-provisioned, offline effective command exceeds the frozen "
        "resource envelope (time / memory) of the scenario.",
    DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE:
        "The exact publisher-defined environment recipe and ALL of its immutable "
        "inputs were acquired and applied faithfully (recipe revision pinned; every "
        "referenced artifact pinned; exact toolchain installed; publisher lockfile "
        "installed byte-for-byte; acquisition attempted faithfully), but the "
        "environment still could not be reconstructed into a successful "
        "network-denied measurement substrate for a candidate-specific reason.",
    DISQUALIFIED_RTK_SEMANTIC_LOSS:
        "RAW fully qualifies under the faithful deterministic environment (the "
        "declared target test itself failed/passed as required), RTK runs "
        "successfully and deterministically, but the MEASURED RTK stream omits or "
        "changes a semantic identity the frozen oracle requires (e.g. a RAW failing "
        "test ID that disappears from RTK's measured output). Presence of the "
        "identity only in an unmeasured tee sidecar does NOT count -- the measured "
        "RTK stream is the artifact being qualified. Not intrinsic nondeterminism and "
        "not a harness defect: the environment is reproducible and RTK executed.",
}

# Preconditions that MUST be evidenced in a per-case record before the given
# terminal disqualification may be recorded. The rejection-ledger builder refuses
# to emit a disqualification whose preconditions are not all present + true.
PRECONDITIONS = {
    DISQUALIFIED_INTRINSIC_NONDETERMINISM: [
        "publisher_recipe_applied", "toolchain_identity_pinned",
        "raw_reps_completed", "residual_nondeterminism_is_semantic",
    ],
    DISQUALIFIED_OFFLINE_EXECUTION: [
        "publisher_recipe_applied", "toolchain_identity_pinned",
        "environment_reproduced", "command_starts_under_environment",
        "network_denied_positively_probed",
    ],
    DISQUALIFIED_RESOURCE_LIMIT: [
        "publisher_recipe_applied", "environment_reproduced",
        "exceeded_frozen_envelope",
    ],
    DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE: [
        "publisher_recipe_revision_pinned", "all_referenced_artifacts_pinned",
        "exact_toolchain_installed", "publisher_lockfile_byte_identical",
        "acquisition_attempted_faithfully", "reconstruction_failed_candidate_specific",
    ],
}


def is_terminal(outcome: str) -> bool:
    return outcome == PASS or outcome in TERMINAL_DISQUALIFICATIONS


def is_disqualification(outcome: str) -> bool:
    return outcome in TERMINAL_DISQUALIFICATIONS


def requires_fix_before_judgement(outcome: str) -> bool:
    return outcome in NON_TERMINAL


def all_outcomes() -> list[str]:
    return [PASS, HARNESS_DEFECT, METER_DEFECT, *sorted(TERMINAL_DISQUALIFICATIONS)]
