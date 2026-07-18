#!/usr/bin/env python3
"""Build the typed, evidence-backed canary-qualification rejection ledger.

FAIL-CLOSED: every terminal disqualification is RE-DERIVED from PRIMITIVE per-case
evidence (never a producer-supplied status) and is emitted ONLY when every
precondition in n2e_classification.PRECONDITIONS is present and true. A candidate
whose preconditions are not all satisfied is recorded as `insufficient_evidence`
(NOT a terminal disqualification) so a harness/meter defect can never be laundered
into a rejection.

The primary N2-E v1 entry is Caddy = DISQUALIFIED_RTK_SEMANTIC_LOSS: RAW qualifies
under the corrected strict target-aware oracle (the declared failing test itself
failed), RTK runs deterministically, but the MEASURED RTK stream omits the RAW
failing test identity -- it survives only in RTK's unmeasured tee sidecar. Per the
frozen decision this is neither intrinsic nondeterminism nor a harness defect.

Usage: build_n2e_canary_rejection_ledger.py <case-dir> [--run-id R] [--impl-sha I]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_classification as cls  # noqa: E402
import n2e_oracles as ora  # noqa: E402

SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
CONTRACT = N2E_DIR / "n2e-canary-execution-contract-v1.json"
OUT = N2E_DIR / "n2e-canary-rejection-ledger-qualification-v1.json"
RAW_ORACLE_POLICY_ID = "n2e-raw-strict-target-oracle-v1"


def _scen_for(case_id: str) -> dict | None:
    for s in c.load_record(SCEN)["scenarios"]:
        if s["case_id"] == case_id:
            return s
    return None


def _canon_hashes(arm: dict) -> list:
    return [r.get("canonical_sha256") for r in (arm.get("runs") or [])]


def derive_rtk_semantic_loss(rec: dict) -> tuple[dict | None, list]:
    """Return (ledger_entry, unmet_preconditions). entry is only a terminal
    DISQUALIFIED_RTK_SEMANTIC_LOSS when unmet == []."""
    case_id = rec.get("case_id")
    scen = _scen_for(case_id) or {}
    raw = rec.get("raw_arm") or {}
    rtk = rec.get("rtk_arm") or {}
    raw_orc = rec.get("raw_semantic_oracle") or {}
    rtk_orc = rec.get("rtk_semantic_oracle") or {}
    acq = rec.get("acquisition") or {}
    env_id = acq.get("environment_identity") or {}
    sidecar = rtk.get("rtk_sidecar_proof") or {}

    raw_ev = raw_orc.get("evidence") or {}
    rtk_ev = rtk_orc.get("evidence") or {}
    required = set(raw_ev.get("required_targets")
                   or ora._leaf_ids(scen.get("target_test_ids") or []))
    raw_observed = set(raw_ev.get("observed_failing")
                       or ora._leaf_ids(((rtk_ev.get("raw") or {}).get("failing_ids")) or []))
    rtk_observed = set(ora._leaf_ids(((rtk_ev.get("rtk") or {}).get("failing_ids")) or []))
    missing = sorted((required & raw_observed) - rtk_observed)

    raw_failed = ((rtk_ev.get("raw") or {}).get("failed"))
    rtk_failed = ((rtk_ev.get("rtk") or {}).get("failed"))

    # precondition truth table (mirrors cls.PRECONDITIONS[RTK_SEMANTIC_LOSS])
    truth = {
        "publisher_recipe_applied": bool(acq.get("publisher_recipe")
                                         or env_id.get("publisher")),
        "toolchain_identity_pinned": bool((env_id.get("toolchain_pin") or {})),
        "raw_qualified_strict_target": raw_orc.get("verdict") is True and bool(required)
        and required.issubset(raw_observed),
        "rtk_executed": rtk.get("reps_completed") == 3,
        "rtk_deterministic": rtk.get("canonical_deterministic") is True,
        "rtk_outcome_count_preserved": (raw_failed is not None and rtk_failed is not None
                                        and raw_failed == rtk_failed),
        "rtk_required_semantic_identity_missing": len(missing) > 0
        and rtk_orc.get("verdict") is not True,
        "identity_only_in_unmeasured_sidecar":
            sidecar.get("identity_only_in_unmeasured_sidecar") is True,
    }
    unmet = [k for k in cls.PRECONDITIONS[cls.DISQUALIFIED_RTK_SEMANTIC_LOSS]
             if not truth.get(k)]

    entry = {
        "case_id": case_id,
        "canary_slot": scen.get("canary_slot"),
        "classification": cls.DISQUALIFIED_RTK_SEMANTIC_LOSS,
        "terminal": unmet == [],
        "outcome_flags": {
            "source_environment_reproducible": truth["publisher_recipe_applied"],
            "raw_qualified": truth["raw_qualified_strict_target"],
            "rtk_executed": truth["rtk_executed"],
            "rtk_deterministic": truth["rtk_deterministic"],
            "rtk_outcome_count_preserved": truth["rtk_outcome_count_preserved"],
            "rtk_required_semantic_identity_preserved": len(missing) == 0,
        },
        "implementation_sha": rec.get("_impl_sha"),
        "run_id": rec.get("_run_id"),
        "raw_canonical_sha256_reps": _canon_hashes(raw),
        "rtk_canonical_sha256_reps": _canon_hashes(rtk),
        "raw_exit_code": raw.get("exit_code"), "rtk_exit_code": rtk.get("exit_code"),
        "raw_failed_count": raw_failed, "rtk_failed_count": rtk_failed,
        "required_failing_ids": sorted(required),
        "raw_observed_failing_ids": sorted(raw_observed),
        "rtk_observed_failing_ids": sorted(rtk_observed),
        "missing_identity_set": missing,
        "sidecar_only_proof": sidecar,
        "raw_oracle_policy_id": RAW_ORACLE_POLICY_ID,
        "rtk_oracle": rtk_orc.get("oracle"),
        "execution_contract_sha256": c.sha256_json_file(CONTRACT) if CONTRACT.exists() else None,
        "precondition_truth": truth,
        "unmet_preconditions": unmet,
        "record_sha256_ref": rec.get("record_sha256"),
        "note": "RTK semantic-preservation failure only; Caddy itself is reproducible. "
                "A tee-sidecar path does not make omitted content present in the "
                "measured stream (no sidecar-aware recoverability in N2-E v1).",
    }
    return (entry if unmet == [] else None), unmet


def _looks_like_semantic_loss(rec: dict) -> bool:
    """A candidate: RAW passed its arm, the RTK arm ran, and the RTK test-agreement
    oracle failed (a failing id disappeared) -- exactly the RTK_REJECTED shape."""
    raw_orc = rec.get("raw_semantic_oracle") or {}
    rtk_orc = rec.get("rtk_semantic_oracle") or {}
    return (raw_orc.get("verdict") is True and rtk_orc.get("oracle") == "test_agreement"
            and rtk_orc.get("verdict") is not True)


def load_cases(case_dir: Path, run_id, impl_sha) -> list:
    recs = []
    for p in sorted(case_dir.rglob("n2e-canary-case-*.json")):
        rec = c.load_record(p)
        ok, msg = c.verify_self_hash(rec)
        if not ok:
            raise SystemExit(f"{p.name}: self-hash {msg}")
        rec["_impl_sha"], rec["_run_id"] = impl_sha, run_id
        recs.append(rec)
    return recs


def build(case_dir: Path, args) -> dict:
    cases = load_cases(case_dir, args.run_id, args.impl_sha)
    entries, insufficient = [], []
    for rec in sorted(cases, key=lambda r: r["case_id"]):
        if not _looks_like_semantic_loss(rec):
            continue
        entry, unmet = derive_rtk_semantic_loss(rec)
        if entry is not None:
            entries.append(entry)
        else:
            insufficient.append({"case_id": rec["case_id"],
                                 "candidate": cls.DISQUALIFIED_RTK_SEMANTIC_LOSS,
                                 "unmet_preconditions": unmet})
    return c.envelope(
        record_type="n2e-canary-rejection-ledger-qualification",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_canary_rejection_ledger.py",
        purpose="Typed, evidence-backed terminal rejections for the qualification canary, "
                "re-derived fail-closed from primitive per-case evidence (§7/§19).",
        run_id=args.run_id, implementation_sha=args.impl_sha,
        classification_taxonomy_outcomes=cls.all_outcomes(),
        raw_oracle_policy_id=RAW_ORACLE_POLICY_ID,
        execution_contract_sha256=c.sha256_json_file(CONTRACT) if CONTRACT.exists() else None,
        scenario_sha256=c.sha256_json_file(SCEN),
        terminal_rejections=entries,
        insufficient_evidence=insufficient,
        terminal_rejection_count=len(entries),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("case_dir")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--impl-sha", default=None)
    args = ap.parse_args()
    body = build(Path(args.case_dir), args)
    c.write_record(OUT, body)
    print(f"wrote {OUT.name}: {body['terminal_rejection_count']} terminal rejection(s); "
          f"{len(body['insufficient_evidence'])} insufficient-evidence candidate(s)")
    for e in body["terminal_rejections"]:
        print(f"  TERMINAL {e['classification']}: {e['case_id']} missing={e['missing_identity_set']}")
    for e in body["insufficient_evidence"]:
        print(f"  INSUFFICIENT {e['case_id']}: unmet={e['unmet_preconditions']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
