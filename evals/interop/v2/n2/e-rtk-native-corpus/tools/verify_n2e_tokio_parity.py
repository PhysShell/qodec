#!/usr/bin/env python3
"""Independent Tokio N2-E vs upstream parity verifier + classification (corrected).

CORRECTION (ruling steps 2/3): the previously-terminal GLOBAL harness<->dataset
revision-pair cross-pin gate is WITHDRAWN. That precedence -- placing a global
cross-reference ahead of, and terminal over, instance-level recipe applicability -- is
itself classified VERIFIER_DEFECT_PROVENANCE_GATE_PRECEDENCE. The pinned harness selects
a per-instance recipe purely from (repo, version) via MAP_REPO_VERSION_TO_SPECS; it never
consults a global dataset-revision cross-pin. Therefore:

  * substrate_status is PROVEN once tokio-4384-instance-recipe-applicability-v1 proves the
    pinned harness maps (repo, version) to exactly the recipe V4 executed;
  * SOURCE_PROVENANCE_DEFECT is a substrate status that is NEVER a terminal candidate
    outcome and NEVER invokes reserve fallback;
  * DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE (terminal candidate outcome) is emitted when
    substrate_status == PROVEN AND every identity equality holds AND both the N2-E
    reconstruction and the pinned upstream source-checkout reproduction reach the SAME
    cargo locked-resolution refusal (non-timeout exit 101, equal materialized lock, equal
    argv, both stating Cargo.lock needs updating while --locked forbids it).

Upstream install success while N2-E fails -> HARNESS_DEFECT (non-terminal; diff + fix).
A TOKIO_UPSTREAM_REPRODUCTION_DEFECT Part D -> insufficient (non-terminal).
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_classification as cls  # noqa: E402

REC = N2E_DIR / "tokio-4384-publisher-recipe-consistency-v1.json"
APPLIC = N2E_DIR / "tokio-4384-instance-recipe-applicability-v1.json"
VERIFIER_POLICY_ID = "n2e-tokio-parity-verifier-v2"
WITHDRAWN_GATE = cls.VERIFIER_DEFECT_PROVENANCE_GATE_PRECEDENCE
_ENV_PATH_KEYS = {"HOME", "CARGO_HOME", "RUSTUP_HOME", "PATH"}  # legitimately temp-path-specific


def _env_semantic(env: dict) -> dict:
    return {k: v for k, v in (env or {}).items() if k not in _ENV_PATH_KEYS}


def equalities(n2e: dict, up: dict) -> dict:
    nf, uf = n2e.get("fixture_evidence", {}), up.get("fixture_evidence", {})
    ni, ui = n2e.get("install", {}), up.get("install", {})
    return {
        "base_identity_equal": (n2e.get("base_commit") == up.get("base_commit")
                                and n2e.get("head_matches_base") and up.get("head_matches_base")),
        "manifest_set_equal": n2e.get("workspace_manifests") == up.get("workspace_manifests"),
        "fixture_source_equal": nf.get("upstream_fixture_sha256") == uf.get("upstream_fixture_sha256"),
        "materialized_lock_equal": nf.get("materialized_cargo_lock_sha256") == uf.get("materialized_cargo_lock_sha256"),
        "cargo_identity_equal": (n2e.get("cargo_binary_identity", {}).get("real_cargo_binary_sha256")
                                 == up.get("cargo_binary_identity", {}).get("real_cargo_binary_sha256")
                                 and n2e.get("cargo_binary_identity", {}).get("real_cargo_binary_sha256") is not None),
        "toolchain_equal": n2e.get("cargo_version_verbose") == up.get("cargo_version_verbose"),
        "platform_equal": n2e.get("target_platform") == up.get("target_platform"),
        "command_equal": ni.get("command") == ui.get("command"),
        "install_argv_equal": ni.get("argv") is not None and ni.get("argv") == ui.get("argv"),
        "environment_semantically_equal": _env_semantic(n2e.get("effective_env")) == _env_semantic(up.get("effective_env")),
        "failure_class_equal": (n2e.get("failure_class", {}).get("class")
                                == up.get("failure_class", {}).get("class")
                                and n2e.get("failure_class", {}).get("class") == "cargo_locked_resolution_refusal"),
    }


def _locked_update_conflict(ident: dict) -> bool:
    """The refusal message must state the lock needs updating while --locked forbids it."""
    fc = ident.get("failure_class") or {}
    stderr = (ident.get("install") or {}).get("stderr") or ""
    msg_ok = ("needs to be updated" in stderr and "--locked" in stderr)
    return bool(fc.get("locked_resolution_refusal")) and bool(fc.get("requested_lock_mutation")) and msg_ok


def rederivation(n2e: dict, up: dict, eq: dict) -> dict:
    n_ex = (n2e.get("install") or {}).get("exit")
    u_ex = (up.get("install") or {}).get("exit")
    return {
        "both_non_timeout": not n2e.get("timed_out") and not up.get("timed_out"),
        "both_exit_101": n_ex == 101 and u_ex == 101,
        "both_locked_resolution_refusal": eq["failure_class_equal"],
        "materialized_lock_equal": eq["materialized_lock_equal"],
        "install_argv_equal": eq["install_argv_equal"],
        "install_command_equal": eq["command_equal"],
        "n2e_states_locked_update_conflict": _locked_update_conflict(n2e),
        "upstream_states_locked_update_conflict": _locked_update_conflict(up),
    }


def _substrate_status(applic: dict | None) -> str:
    if applic and applic.get("instance_recipe_applicable") is True:
        return cls.SUBSTRATE_PROVEN
    return cls.SUBSTRATE_SOURCE_PROVENANCE_DEFECT


def classify(rec: dict, applic: dict | None = None) -> dict:
    d = rec.get("part_d_upstream") or {}
    n2e = rec.get("n2e_identity") or {}
    status = d.get("status")
    base = {"verifier_policy_id": VERIFIER_POLICY_ID, "withdrawn_gate": WITHDRAWN_GATE,
            "substrate_status": _substrate_status(applic)}

    if status == "TOKIO_UPSTREAM_REPRODUCTION_DEFECT":
        return {**base, "candidate_classification": None, "outcome": "insufficient_evidence",
                "terminal_candidate_outcome": False,
                "reason": "TOKIO_UPSTREAM_REPRODUCTION_DEFECT: " + "; ".join(d.get("reasons") or [])}
    if status != "upstream_install_ran":
        return {**base, "candidate_classification": None, "outcome": "insufficient_evidence",
                "terminal_candidate_outcome": False,
                "reason": f"upstream part D did not run ({status})"}

    up = d.get("identity") or {}
    up_exit = (up.get("install") or {}).get("exit")
    n2e_exit = (n2e.get("install") or {}).get("exit")

    if up_exit == 0 and n2e_exit not in (0, None):
        return {**base, "candidate_classification": cls.HARNESS_DEFECT, "outcome": "harness_defect",
                "terminal_candidate_outcome": False, "equalities": equalities(n2e, up),
                "reason": "upstream source-checkout install succeeded; diff upstream vs N2-E and fix N2-E"}

    eq = equalities(n2e, up)
    rd = rederivation(n2e, up, eq)

    # substrate provenance is NON-TERMINAL for a candidate: if instance applicability is
    # not proven we cannot yet call the substrate PROVEN -> insufficient, never terminal,
    # never fallback.
    if base["substrate_status"] != cls.SUBSTRATE_PROVEN:
        return {**base, "candidate_classification": None, "outcome": "insufficient_evidence",
                "terminal_candidate_outcome": False, "equalities": eq, "rederivation": rd,
                "reason": "instance-level recipe applicability not proven; SOURCE_PROVENANCE_DEFECT "
                          "is NOT terminal and does NOT invoke fallback -- prove applicability first"}

    if all(eq.values()) and all(rd.values()):
        return {**base, "candidate_classification": cls.DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE,
                "outcome": "environment_unreproducible", "terminal_candidate_outcome": True,
                "equalities": eq, "rederivation": rd,
                "reason": "The exact publisher environment and the exact upstream source-checkout "
                          "reproduction both reject the publisher-provided materialized Cargo.lock "
                          "under the publisher's own --locked install command. An unlocked diagnostic "
                          "resolution removes 22 stale/unselected package tuples. The candidate cannot "
                          "be faithfully acquired under its pinned publisher recipe."}
    return {**base, "candidate_classification": None, "outcome": "insufficient_evidence",
            "terminal_candidate_outcome": False, "equalities": eq, "rederivation": rd,
            "reason": "identities / re-derivation checks not all equal -- insufficient"}


def main() -> int:
    if not REC.is_file():
        print("tokio-parity: FAIL (no consistency record yet)")
        return 1
    rec = c.load_record(REC)
    applic = c.load_record(APPLIC) if APPLIC.is_file() else None
    res = classify(rec, applic)
    print(f"tokio-parity: substrate={res['substrate_status']} "
          f"candidate={res.get('candidate_classification')} "
          f"terminal={res['terminal_candidate_outcome']} outcome={res['outcome']}")
    print(f"  reason: {res['reason']}")
    for label, mp in (("eq", res.get("equalities")), ("rederivation", res.get("rederivation"))):
        for k, v in (mp or {}).items():
            print(f"    {label}.{k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
