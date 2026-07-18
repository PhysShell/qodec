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
_SEL = Path(__file__).resolve().parent.parent / "n2e-selection-result-v1.json"

# case_id -> (policy_id, gradle property flag). Only the frozen lucene test case.
_SEED_CASES = {
    "apache__lucene-13704::jvm::test::buggy": (LUCENE_SEED_POLICY_ID, "-Ptests.seed"),
}


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


def policy_for_case(case_id: str) -> dict | None:
    ent = _SEED_CASES.get(case_id)
    if not ent:
        return None
    pid, flag = ent
    return {"policy_id": pid, "flag": flag, "seed": derive_seed(case_id),
            "arg": seed_arg(case_id), "selection_seed": selection_seed(),
            "derivation": f"sha256({pid}+selection_seed+case_id)[:16].upper()"}
