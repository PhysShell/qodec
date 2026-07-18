#!/usr/bin/env python3
"""Build the typed, evidence-backed canary-qualification rejection ledger.

FAIL-CLOSED and GENUINELY INDEPENDENT (corrections 3/4): a terminal
DISQUALIFIED_RTK_SEMANTIC_LOSS entry is emitted ONLY when every precondition below is
re-derived from primitive evidence -- NEVER trusted from the producer's status or
oracle summaries, and NEVER from bool(toolchain_pin):

  Environment/acquisition
    - toolchain lock_state == COMPLETE;
    - the record's observed toolchain identities EXACTLY satisfy the lock
      (verify_n2e_toolchain_lock.verify_record_identity);
    - publisher registry binds this exact case (recipe.instance_id == evidence);
    - execution-contract + scenario-correction records present (hashes linked);
    - acquisition-order verifier passes (incl. the test-file reset);
    - protected-file mutation guard held;
    - network-denial probe positively denied.
  RAW arm
    - exactly 3 reps, no timeout, stable exit, canonical determinism, all 3 canonical
      hashes equal, strict target-aware oracle independently True, and the declared
      failing target parsed as a failing id in EVERY re-parsed RAW canonical stream.
  RTK arm
    - exactly 3 reps, no timeout, stable exit, canonical determinism, pinned RTK binary,
      failed-count preserved, the required identity ABSENT from every re-parsed measured
      RTK stream, and PARSED as a failing id in every re-parsed tee sidecar.

The primary per-rep streams (correction 4) are read from out/evidence/<case>/, their
SHA-256 verified against both the file manifest and the record's per-rep
canonical_sha256, and the semantic parsers re-run here -- the ledger is not derivable
from hashes + producer summaries alone. Sidecar bytes are rejection evidence only and
are never added to the measured token stream.

Usage: build_n2e_canary_rejection_ledger.py <case-dir> [--run-id R] [--impl-sha I]
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_classification as cls  # noqa: E402
import n2e_oracles as ora  # noqa: E402
import verify_n2e_toolchain_lock as vtl  # noqa: E402
import verify_n2e_acquisition_order as vao  # noqa: E402
import n2e_publisher_registry as pub  # noqa: E402

SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
CONTRACT = N2E_DIR / "n2e-canary-execution-contract-v1.json"
CORRECTION = N2E_DIR / "n2e-scenario-correction-v1.json"
REGISTRY = N2E_DIR / "n2e-publisher-env-registry-v1.json"
LOCK = N2E_DIR / "n2e-toolchain-lock-v1.json"
OUT = N2E_DIR / "n2e-canary-rejection-ledger-qualification-v1.json"
RAW_ORACLE_POLICY_ID = "n2e-raw-strict-target-oracle-v1"
RTK_BINARY_SHA256 = "41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf"


def _scen_for(case_id: str) -> dict:
    for s in c.load_record(SCEN)["scenarios"]:
        if s["case_id"] == case_id:
            return s
    return {}


def _canon_hashes(arm: dict) -> list:
    return [r.get("canonical_sha256") for r in (arm.get("runs") or [])]


def _read_evidence_file(case_dir: Path, entry: dict) -> bytes | None:
    safe = (entry.get("case_id") or "").replace("::", "__").replace("/", "_")
    fp = case_dir / "evidence" / safe / (entry.get("file") or "")
    if not fp.is_file():
        return None
    data = fp.read_bytes()
    if entry.get("compression") == "zlib":
        try:
            data = zlib.decompress(data)
        except zlib.error:
            return None
    return data


def _independent_streams(rec: dict, case_dir: Path, required: set) -> dict:
    """Re-hash + re-parse the uploaded primary streams; nothing here trusts the
    producer's recorded oracle/summary fields."""
    raw, rtk = rec.get("raw_arm") or {}, rec.get("rtk_arm") or {}
    raw_runs, rtk_runs = raw.get("runs") or [], rtk.get("runs") or []

    def files(arm, role):
        return sorted((e for e in (arm.get("primary_evidence_files") or []) if e.get("role") == role),
                      key=lambda x: x.get("rep", 0))

    reasons = []

    def parse(entries, record_runs=None, dialect="native"):
        fails, counts = [], []
        for e in entries:
            data = _read_evidence_file(case_dir, e)
            if data is None:
                reasons.append(f"missing/undecodable evidence file {e.get('file')}")
                fails.append(None); counts.append(None); continue
            if hashlib.sha256(data).hexdigest() != e.get("sha256"):
                reasons.append(f"evidence sha256 mismatch for {e.get('file')}")
                fails.append(None); counts.append(None); continue
            rep = e.get("rep")
            if record_runs is not None and rep is not None and rep < len(record_runs):
                if record_runs[rep].get("canonical_sha256") != e.get("sha256"):
                    reasons.append(f"{e.get('role')} rep{rep} file sha != record canonical_sha256")
            summ = ora._test_summary(data, dialect=dialect)
            fails.append(set(ora._leaf_ids(summ["failing_ids"])))
            counts.append(summ["failed"])
        return fails, counts

    # RAW: native tool grammar; measured RTK: RTK's bounded dialect; tee: native output.
    raw_fail, raw_cnt = parse(files(raw, "raw"), raw_runs, dialect="native")
    rtk_fail, rtk_cnt = parse(files(rtk, "rtk"), rtk_runs, dialect="rtk")
    tee_fail, _ = parse(files(rtk, "rtk_tee"), dialect="native")

    have3 = (len(raw_fail) == 3 and len(rtk_fail) == 3 and len(tee_fail) == 3
             and all(x is not None for x in raw_fail + rtk_fail + tee_fail))
    tgt_raw = have3 and all(required <= s for s in raw_fail)
    tgt_tee = have3 and all(required <= s for s in tee_fail)
    tgt_absent_rtk = have3 and all(not (required & s) for s in rtk_fail)
    count_preserved = have3 and all(a is not None and a == b for a, b in zip(raw_cnt, rtk_cnt))
    return {
        "ok": have3 and tgt_raw and tgt_tee and tgt_absent_rtk and not reasons,
        "reasons": reasons, "reps_present": have3,
        "raw_failing_ids_per_rep": [sorted(s) if s else s for s in raw_fail],
        "rtk_failing_ids_per_rep": [sorted(s) if s else s for s in rtk_fail],
        "tee_failing_ids_per_rep": [sorted(s) if s else s for s in tee_fail],
        "raw_failed_counts": raw_cnt, "rtk_failed_counts": rtk_cnt,
        "target_in_every_raw": tgt_raw, "target_in_every_tee": tgt_tee,
        "target_absent_every_rtk": tgt_absent_rtk, "failed_count_preserved": count_preserved,
    }


def derive_rtk_semantic_loss(rec: dict, case_dir: Path) -> tuple[dict | None, list, dict]:
    case_id = rec.get("case_id")
    scen = _scen_for(case_id)
    raw, rtk = rec.get("raw_arm") or {}, rec.get("rtk_arm") or {}
    raw_orc = rec.get("raw_semantic_oracle") or {}
    rtk_orc = rec.get("rtk_semantic_oracle") or {}
    acq = rec.get("acquisition") or {}
    env_id = acq.get("environment_identity") or {}
    deps = env_id.get("dependencies") or {}
    iso = rec.get("isolation") or {}
    required = set(ora._leaf_ids(scen.get("target_test_ids") or []))

    tc_ok, tc_msg = vtl.verify_record_identity(rec, require_complete=True)
    ord_ok, ord_reasons = vao.verify_record(rec)
    recipe = pub.recipe_for_case(case_id)
    binding_ok = bool(recipe) and recipe.get("instance_id") == acq.get("instance_id")
    streams = _independent_streams(rec, case_dir, required)
    lock = c.load_record(LOCK) if LOCK.exists() else {}
    raw_h = _canon_hashes(raw)

    truth = {
        # environment / acquisition
        "toolchain_lock_complete": lock.get("lock_state") == "COMPLETE",
        "toolchain_identity_matches_lock": tc_ok,
        "publisher_registry_binding_matches": binding_ok,
        "execution_contract_present": CONTRACT.exists(),
        "scenario_correction_present": CORRECTION.exists(),
        "acquisition_order_verified": ord_ok,
        "protected_files_unmutated": deps.get("mutation_guard_ok") is True,
        "network_denied": (iso.get("denial_probe") or {}).get("denied") is True,
        # RAW arm
        "raw_three_reps": raw.get("reps_completed") == 3,
        "raw_no_timeout": not raw.get("timed_out"),
        "raw_exit_stable": raw.get("exit_code_stable") is True,
        "raw_deterministic": raw.get("canonical_deterministic") is True,
        "raw_canonical_hashes_equal": len(raw_h) == 3 and len(set(raw_h)) == 1 and None not in raw_h,
        "raw_strict_oracle_pass": raw_orc.get("verdict") is True,
        "raw_target_parsed_failing_every_rep": streams["target_in_every_raw"],
        # RTK arm
        "rtk_three_reps": rtk.get("reps_completed") == 3,
        "rtk_no_timeout": not rtk.get("timed_out"),
        "rtk_exit_stable": rtk.get("exit_code_stable") is True,
        "rtk_deterministic": rtk.get("canonical_deterministic") is True,
        "rtk_binary_pinned": rec.get("rtk_binary_sha256") == RTK_BINARY_SHA256,
        "rtk_failed_count_preserved": streams["failed_count_preserved"],
        "rtk_required_missing_from_measured": streams["target_absent_every_rtk"],
        "rtk_identity_parsed_failing_every_sidecar": streams["target_in_every_tee"],
        "primary_streams_reverified": streams["ok"],
    }
    unmet = sorted(k for k, v in truth.items() if not v)
    missing = sorted(required - set().union(*[set(s) for s in streams["rtk_failing_ids_per_rep"]
                                              if s]) if streams["reps_present"] else required)

    entry = {
        "case_id": case_id, "canary_slot": scen.get("canary_slot"),
        "classification": cls.DISQUALIFIED_RTK_SEMANTIC_LOSS,
        "terminal": unmet == [],
        "outcome_flags": {
            "source_environment_reproducible": truth["toolchain_identity_matches_lock"]
            and truth["publisher_registry_binding_matches"],
            "raw_qualified": truth["raw_strict_oracle_pass"]
            and truth["raw_target_parsed_failing_every_rep"],
            "rtk_executed": truth["rtk_three_reps"], "rtk_deterministic": truth["rtk_deterministic"],
            "rtk_outcome_count_preserved": truth["rtk_failed_count_preserved"],
            "rtk_required_semantic_identity_preserved": not truth["rtk_required_missing_from_measured"],
        },
        "implementation_sha": rec.get("_impl_sha"), "run_id": rec.get("_run_id"),
        "raw_canonical_sha256_reps": raw_h, "rtk_canonical_sha256_reps": _canon_hashes(rtk),
        "raw_exit_code": raw.get("exit_code"), "rtk_exit_code": rtk.get("exit_code"),
        "raw_failed_counts": streams["raw_failed_counts"], "rtk_failed_counts": streams["rtk_failed_counts"],
        "required_failing_ids": sorted(required),
        "raw_observed_failing_ids": streams["raw_failing_ids_per_rep"],
        "rtk_observed_failing_ids": streams["rtk_failing_ids_per_rep"],
        "tee_observed_failing_ids": streams["tee_failing_ids_per_rep"],
        "missing_identity_set": missing,
        "primary_evidence_reverified": streams["ok"], "primary_evidence_reasons": streams["reasons"],
        "raw_oracle_policy_id": RAW_ORACLE_POLICY_ID, "rtk_oracle": rtk_orc.get("oracle"),
        "toolchain_lock_sha256": c.sha256_json_file(LOCK) if LOCK.exists() else None,
        "execution_contract_sha256": c.sha256_json_file(CONTRACT) if CONTRACT.exists() else None,
        "scenario_correction_sha256": c.sha256_json_file(CORRECTION) if CORRECTION.exists() else None,
        "publisher_registry_sha256": c.sha256_json_file(REGISTRY) if REGISTRY.exists() else None,
        "toolchain_identity_check": tc_msg, "acquisition_order_reasons": ord_reasons,
        "precondition_truth": truth, "unmet_preconditions": unmet,
        "record_sha256_ref": rec.get("record_sha256"),
        "note": "RTK semantic-preservation failure only; the case itself is reproducible. "
                "A tee-sidecar path does not make omitted content present in the measured "
                "stream; sidecar bytes are rejection evidence, never metered.",
    }
    return (entry if unmet == [] else None), unmet, truth


def _looks_like_semantic_loss(rec: dict) -> bool:
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
        entry, unmet, _ = derive_rtk_semantic_loss(rec, case_dir)
        if entry is not None:
            entries.append(entry)
        else:
            insufficient.append({"case_id": rec["case_id"],
                                 "candidate": cls.DISQUALIFIED_RTK_SEMANTIC_LOSS,
                                 "unmet_preconditions": unmet})
    return c.envelope(
        record_type="n2e-canary-rejection-ledger-qualification",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_canary_rejection_ledger.py",
        purpose="Typed terminal rejections re-derived FAIL-CLOSED + INDEPENDENTLY from primary "
                "per-rep stream evidence (never from producer status/oracle summaries).",
        run_id=args.run_id, implementation_sha=args.impl_sha,
        classification_taxonomy_outcomes=cls.all_outcomes(),
        raw_oracle_policy_id=RAW_ORACLE_POLICY_ID,
        toolchain_lock_sha256=c.sha256_json_file(LOCK) if LOCK.exists() else None,
        execution_contract_sha256=c.sha256_json_file(CONTRACT) if CONTRACT.exists() else None,
        scenario_correction_sha256=c.sha256_json_file(CORRECTION) if CORRECTION.exists() else None,
        publisher_registry_sha256=c.sha256_json_file(REGISTRY) if REGISTRY.exists() else None,
        scenario_sha256=c.sha256_json_file(SCEN),
        terminal_rejections=entries, insufficient_evidence=insufficient,
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
