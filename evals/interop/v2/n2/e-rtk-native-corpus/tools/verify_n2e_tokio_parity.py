#!/usr/bin/env python3
"""Independent Tokio N2-E vs upstream parity verifier + classification (items 5/7).

Reads the two primitive identity records inside tokio-4384-publisher-recipe-consistency-
v1.json (the N2-E reconstruction and the pinned upstream source-checkout reproduction)
and derives structural equalities. It emits DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE ONLY
when EVERY required equality holds AND both executions reach the SAME cargo locked-
resolution failure (parsed from the full Cargo output, not inferred from exit==101).
Missing evidence -> insufficient (never terminal). A TOKIO_UPSTREAM_REPRODUCTION_DEFECT
Part D -> insufficient. No compatible harness/dataset pair proof -> SOURCE_PROVENANCE_
DEFECT before any unreproducibility claim. Upstream success -> HARNESS_DEFECT.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

REC = N2E_DIR / "tokio-4384-publisher-recipe-consistency-v1.json"
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
        "environment_semantically_equal": _env_semantic(n2e.get("effective_env")) == _env_semantic(up.get("effective_env")),
        "failure_class_equal": (n2e.get("failure_class", {}).get("class")
                                == up.get("failure_class", {}).get("class")
                                and n2e.get("failure_class", {}).get("class") == "cargo_locked_resolution_refusal"),
    }


def classify(rec: dict) -> dict:
    d = rec.get("part_d_upstream") or {}
    prov = rec.get("harness_dataset_provenance") or {}
    n2e = rec.get("n2e_identity") or {}
    status = d.get("status")

    if status == "TOKIO_UPSTREAM_REPRODUCTION_DEFECT":
        return {"classification": None, "outcome": "insufficient_evidence",
                "reason": "TOKIO_UPSTREAM_REPRODUCTION_DEFECT: " + "; ".join(d.get("reasons", [])),
                "terminal": False}
    if status != "upstream_install_ran":
        return {"classification": None, "outcome": "insufficient_evidence",
                "reason": f"upstream part D did not run ({status})", "terminal": False}

    up = d.get("identity") or {}
    up_exit = (up.get("install") or {}).get("exit")
    n2e_exit = (n2e.get("install") or {}).get("exit")

    # upstream reproduced the environment successfully while N2-E failed -> harness defect
    if up_exit == 0 and n2e_exit not in (0, None):
        return {"classification": "HARNESS_DEFECT", "outcome": "harness_defect", "terminal": False,
                "reason": "upstream source-checkout install succeeded; diff upstream vs N2-E and fix N2-E",
                "equalities": equalities(n2e, up)}

    eq = equalities(n2e, up)
    both_locked_refusal = eq["failure_class_equal"]
    # provenance gate: a compatible published pair must be proven before unreproducibility
    if not prov.get("compatible_pair_proven"):
        return {"classification": "SOURCE_PROVENANCE_DEFECT", "outcome": "source_provenance_defect",
                "terminal": True, "equalities": eq,
                "reason": "no immutable proof that harness f7bbbb2 and the dataset revision are a "
                          "published pair; resolve provenance before any unreproducibility claim"}

    if all(eq.values()) and both_locked_refusal:
        return {"classification": "DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE",
                "outcome": "environment_unreproducible", "terminal": True, "equalities": eq,
                "reason": "every required identity equal AND both N2-E and upstream reach the same "
                          "cargo locked-resolution refusal for the pinned publisher recipe"}
    return {"classification": None, "outcome": "insufficient_evidence", "terminal": False,
            "equalities": eq, "reason": "identities/failure classes not all equal -- insufficient"}


def main() -> int:
    if not REC.is_file():
        print("tokio-parity: FAIL (no consistency record yet)")
        return 1
    rec = c.load_record(REC)
    res = classify(rec)
    print(f"tokio-parity: outcome={res['outcome']} classification={res.get('classification')} "
          f"terminal={res['terminal']}")
    print(f"  reason: {res['reason']}")
    for k, v in (res.get("equalities") or {}).items():
        print(f"    {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
