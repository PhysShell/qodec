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
VERIFIER_DEFECT = "VERIFIER_DEFECT"

# Named VERIFIER_DEFECT subtypes: the DEFECT IS IN THE VERIFIER (a classification
# harness), not in a candidate. It is corrected, then classification is re-derived.
# PROVENANCE_GATE_PRECEDENCE: a verifier wrongly placed a GLOBAL harness<->dataset
# revision-pair cross-reference gate AHEAD of, and terminal over, the instance-level
# recipe-applicability proof. The pinned harness selects a per-instance recipe purely
# from (repo, version) via MAP_REPO_VERSION_TO_SPECS -- it never consults a global
# dataset-revision cross-pin -- so the absence of a publisher document tying a harness
# commit to a dataset README revision is NOT a candidate defect and does NOT block
# classification once instance-level applicability is proven. SOURCE_PROVENANCE_DEFECT
# is therefore a VERIFIER-level, NON-TERMINAL condition for a candidate; it never
# invokes reserve fallback.
VERIFIER_DEFECT_PROVENANCE_GATE_PRECEDENCE = "VERIFIER_DEFECT_PROVENANCE_GATE_PRECEDENCE"
VERIFIER_DEFECT_SUBTYPES = frozenset({VERIFIER_DEFECT_PROVENANCE_GATE_PRECEDENCE})

# Substrate-status axis (orthogonal to the candidate outcome). Once instance-level
# recipe applicability is proven from the pinned harness's own recipe-selection
# mechanism, the substrate is PROVEN. SOURCE_PROVENANCE_DEFECT is a substrate status
# that is NEVER a terminal candidate outcome and NEVER triggers reserve fallback.
SUBSTRATE_PROVEN = "PROVEN"
SUBSTRATE_SOURCE_PROVENANCE_DEFECT = "SOURCE_PROVENANCE_DEFECT"

# Named HARNESS_DEFECT subtypes (each is corrected, then the case is re-judged).
# ORACLE_UNRECOGNIZED_RTK_TEST_GRAMMAR: the RTK agreement oracle applied the NATIVE
# tool grammar to RTK's filtered stream and so failed to recognize a failing identity
# that RTK preserves in its own bounded form (e.g. `[FAIL] X` vs `--- FAIL: X`). This
# is a parsing defect, NOT semantic loss -- fixed by a dialect-aware parser, then the
# case is re-judged (it may well PASS). This is the withdrawal basis for the previously
# proposed Caddy DISQUALIFIED_RTK_SEMANTIC_LOSS.
HARNESS_DEFECT_ORACLE_UNRECOGNIZED_RTK_TEST_GRAMMAR = \
    "HARNESS_DEFECT_ORACLE_UNRECOGNIZED_RTK_TEST_GRAMMAR"
HARNESS_DEFECT_SUBTYPES = frozenset({HARNESS_DEFECT_ORACLE_UNRECOGNIZED_RTK_TEST_GRAMMAR})

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
# rejection ledger; they gate a re-run after the defect is corrected. A
# VERIFIER_DEFECT gates a re-derivation of the classification once the verifier
# is corrected -- it is never a terminal candidate outcome.
NON_TERMINAL = frozenset({HARNESS_DEFECT, METER_DEFECT, VERIFIER_DEFECT,
                          VERIFIER_DEFECT_PROVENANCE_GATE_PRECEDENCE})

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
    # The bar is INSTANCE-LEVEL recipe applicability + faithful reproduction, NOT a
    # global harness<->dataset revision cross-pin (that precedence was a VERIFIER_DEFECT).
    DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE: [
        "instance_recipe_applicability_proven",   # pinned harness maps (repo,version)->this exact recipe
        "publisher_recipe_revision_pinned", "all_referenced_artifacts_pinned",
        "exact_toolchain_installed", "publisher_lockfile_byte_identical",
        "acquisition_attempted_faithfully", "reconstruction_failed_candidate_specific",
        "upstream_source_checkout_reproduced_identically",  # upstream == N2-E, same refusal
    ],
    DISQUALIFIED_RTK_SEMANTIC_LOSS: [
        "publisher_recipe_applied", "toolchain_identity_pinned",
        "raw_qualified_strict_target",          # corrected RAW oracle: the target test itself failed
        "rtk_executed", "rtk_deterministic",
        "rtk_outcome_count_preserved",
        "rtk_required_semantic_identity_missing",  # a RAW failing id absent from the MEASURED RTK stream
        "identity_only_in_unmeasured_sidecar",     # its sole presence is a tee sidecar, which does not count
    ],
}


def is_terminal(outcome: str) -> bool:
    return outcome == PASS or outcome in TERMINAL_DISQUALIFICATIONS


def is_disqualification(outcome: str) -> bool:
    return outcome in TERMINAL_DISQUALIFICATIONS


def requires_fix_before_judgement(outcome: str) -> bool:
    return outcome in NON_TERMINAL


def is_verifier_defect(outcome: str) -> bool:
    return outcome == VERIFIER_DEFECT or outcome in VERIFIER_DEFECT_SUBTYPES


def substrate_proven(status: str) -> bool:
    """SOURCE_PROVENANCE_DEFECT is never terminal for a candidate; only PROVEN admits
    a terminal DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE."""
    return status == SUBSTRATE_PROVEN


def all_outcomes() -> list[str]:
    return [PASS, HARNESS_DEFECT, METER_DEFECT, *sorted(TERMINAL_DISQUALIFICATIONS)]
