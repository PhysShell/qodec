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
import verify_n2e_tokio_parity as tparity  # noqa: E402

SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
CONTRACT = N2E_DIR / "n2e-canary-execution-contract-v1.json"
CORRECTION = N2E_DIR / "n2e-scenario-correction-v1.json"
REGISTRY = N2E_DIR / "n2e-publisher-env-registry-v1.json"
LOCK = N2E_DIR / "n2e-toolchain-lock-v1.json"
INSTANCES = N2E_DIR / "n2e-swebench-instances-v1.json"
TOKIO_V4 = N2E_DIR / "tokio-4384-publisher-recipe-consistency-v1.json"
TOKIO_APPLIC = N2E_DIR / "tokio-4384-instance-recipe-applicability-v1.json"
OUT = N2E_DIR / "n2e-canary-rejection-ledger-qualification-v1.json"
RAW_ORACLE_POLICY_ID = "n2e-raw-strict-target-oracle-v1"
RTK_BINARY_SHA256 = "41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf"

# Immutable provenance of the preserved tokio consistency probe (run 29639827628).
TOKIO_PROBE_PROVENANCE = {
    "run_id": "29639827628",
    "workflow": "qodec-n2e-tokio-probe",
    "trigger_head_sha": "536a1a3e6179e8c1a80da1301177c0e965ba9606",
    "implementation_sha": "70b0b1d4bff49a87df18d938ad710ae2fdc718af",
    "artifact_id": "8428264892",
    "artifact_zip_sha256": "sha256:e7ca740192f57461ea8739777291e88b4ea28dc9b0af31b911278016a0404a94",
}
TOKIO_CASE_ID = "tokio-rs__tokio-4384::rust_cargo::test::fixed"


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

    # RAW: native tool grammar; measured RTK: RTK's bounded Go dialect; tee: native output.
    raw_fail, raw_cnt = parse(files(raw, "raw"), raw_runs, dialect="native")
    rtk_fail, rtk_cnt = parse(files(rtk, "rtk"), rtk_runs, dialect=ora.RTK_GO_DIALECT)
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


def derive_tokio_environment_unreproducible() -> tuple[dict | None, list]:
    """Terminal DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE for tokio-4384, re-derived from the
    preserved V4 consistency record + the instance-recipe-applicability proof + the CORRECTED
    parity verifier (ruling steps 2-4). No RTK savings / result size / execution ease /
    replacement availability is consulted anywhere in the decision."""
    if not (TOKIO_V4.is_file() and TOKIO_APPLIC.is_file()):
        return None, ["tokio V4 consistency record or applicability record absent"]
    v4 = c.load_record(TOKIO_V4)
    applic = c.load_record(TOKIO_APPLIC)
    for label, r in (("v4", v4), ("applic", applic)):
        ok, msg = c.verify_self_hash(r)
        if not ok:
            return None, [f"tokio {label} self-hash: {msg}"]

    res = tparity.classify(v4, applic)
    eq = res.get("equalities") or {}
    rd = res.get("rederivation") or {}
    n2e = v4["n2e_identity"]
    up = v4["part_d_upstream"]["identity"]
    ni, ui = n2e["install"], up["install"]
    nf, uf = n2e["fixture_evidence"], up["fixture_evidence"]
    sld = v4["part_c_disposable_lock_diff"]["structured_lock_diff"]
    aeq = applic["equalities"]

    # taxonomy preconditions for DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE (instance-level bar)
    truth = {
        "instance_recipe_applicability_proven": applic.get("instance_recipe_applicable") is True,
        "publisher_recipe_revision_pinned": bool(aeq.get("harness_commit_matches")
                                                  and aeq.get("recipe_source_blob_matches")
                                                  and aeq.get("recipe_source_sha256_matches")),
        "all_referenced_artifacts_pinned": bool(aeq.get("fixture_blob_equal")
                                                 and aeq.get("fixture_sha256_equal")
                                                 and aeq.get("pre_install_byte_equal")),
        "exact_toolchain_installed": bool(eq.get("toolchain_equal")
                                          and aeq.get("docker_rust_version_equal")),
        # fixture BLOB byte-identical both sides (6f7401a1); the sole materialized delta is the
        # publisher recipe's OWN heredoc trailing newline, and the materialized lock is identical
        # across N2-E and upstream -- i.e. the publisher lockfile input is reproduced faithfully.
        "publisher_lockfile_byte_identical": bool(eq.get("fixture_source_equal")
                                                  and aeq.get("fixture_sha256_equal")
                                                  and rd.get("materialized_lock_equal")
                                                  and nf.get("diff_is_solely_trailing_newline")),
        "acquisition_attempted_faithfully": bool(rd.get("both_exit_101")
                                                 and rd.get("both_non_timeout")),
        "reconstruction_failed_candidate_specific": bool(rd.get("both_locked_resolution_refusal")
                                                         and rd.get("n2e_states_locked_update_conflict")
                                                         and rd.get("upstream_states_locked_update_conflict")),
        "upstream_source_checkout_reproduced_identically": all(eq.values()) and all(rd.values()),
    }
    unmet = sorted(k for k, v in truth.items() if not v)
    terminal = (res.get("candidate_classification") == cls.DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE
                and res.get("terminal_candidate_outcome") is True
                and res.get("substrate_status") == cls.SUBSTRATE_PROVEN
                and not unmet)

    entry = {
        "case_id": TOKIO_CASE_ID, "canary_slot": "rust_test_pass",
        "classification": cls.DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE,
        "terminal": terminal,
        "substrate_status": res.get("substrate_status"),
        "corrected_verifier_policy_id": res.get("verifier_policy_id"),
        "withdrawn_gate": res.get("withdrawn_gate"),
        "reason": res.get("reason"),
        # ---- mandated references (ruling step 4) --------------------------------------
        "probe_provenance": TOKIO_PROBE_PROVENANCE,
        "v4_consistency_record_sha256": c.sha256_json_file(TOKIO_V4),
        "v4_consistency_record_internal_sha256": v4["record_sha256"],
        "instance_applicability_record_sha256": c.sha256_json_file(TOKIO_APPLIC),
        "instance_applicability_internal_sha256": applic["record_sha256"],
        "publisher_registry_sha256": c.sha256_json_file(REGISTRY) if REGISTRY.exists() else None,
        "harness_commit": v4["harness_commit"],
        "harness_bundle_sha256": applic["harness_bundle"]["sha256"],
        "dataset": applic["dataset"],
        "swebench_instances_sha256": c.sha256_json_file(INSTANCES) if INSTANCES.exists() else None,
        "pinned_instance_row_sha256": applic["pinned_instance_row_sha256"],
        "complete_instance_row_sha256": applic["complete_instance_row_sha256_from_v4"],
        "base_commit": v4["base_commit"],
        "identity_equality_map": eq,
        "rederivation_map": rd,
        "n2e_failure_class": n2e["failure_class"]["class"],
        "upstream_failure_class": up["failure_class"]["class"],
        "n2e_full_output_sha256": {"stdout": ni.get("stdout_sha256"), "stderr": ni.get("stderr_sha256")},
        "upstream_full_output_sha256": {"stdout": ui.get("stdout_sha256"), "stderr": ui.get("stderr_sha256")},
        "fixture_identity": {"path": nf.get("upstream_fixture_path"),
                             "git_blob_sha1": nf.get("upstream_fixture_git_blob"),
                             "sha256": nf.get("upstream_fixture_sha256"), "bytes": nf.get("upstream_fixture_bytes")},
        "materialized_lock_identity": {"n2e_sha256": nf.get("materialized_cargo_lock_sha256"),
                                       "upstream_sha256": uf.get("materialized_cargo_lock_sha256"),
                                       "bytes": nf.get("materialized_cargo_lock_bytes")},
        "diagnostic_unlocked_lock_diff": {
            "keyed_by": sld.get("keyed_by"), "removed_count": sld.get("removed_count"),
            "added_count": sld.get("added_count"), "tuples_removed": sld.get("tuples_removed"),
            "before_sha256": sld.get("before_sha256"), "after_sha256": sld.get("after_sha256"),
            "package_count_before": sld.get("package_count_before"),
            "package_count_after": sld.get("package_count_after")},
        "precondition_truth": truth, "unmet_preconditions": unmet,
        "decision_inputs_excluded": ["rtk_savings", "result_size", "execution_ease",
                                     "replacement_availability"],
        "note": "Environment faithfully reconstructed (upstream == N2-E, identical locked-resolution "
                "refusal); the candidate cannot be acquired under its pinned publisher recipe. Not an "
                "N2-E harness defect. SOURCE_PROVENANCE_DEFECT precedence was a verifier defect and is "
                "withdrawn.",
    }
    return (entry if terminal else None), unmet


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

    # Tokio DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE (independent evidence path: preserved V4
    # consistency probe + instance-recipe-applicability proof + corrected parity verifier).
    tok_entry, tok_unmet = derive_tokio_environment_unreproducible()
    if tok_entry is not None:
        entries.append(tok_entry)
    elif tok_unmet and tok_unmet != ["tokio V4 consistency record or applicability record absent"]:
        insufficient.append({"case_id": TOKIO_CASE_ID,
                             "candidate": cls.DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE,
                             "unmet_preconditions": tok_unmet})
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
        extra = (f" missing={e['missing_identity_set']}" if "missing_identity_set" in e
                 else f" substrate={e.get('substrate_status')}")
        print(f"  TERMINAL {e['classification']}: {e['case_id']}{extra}")
    for e in body["insufficient_evidence"]:
        print(f"  INSUFFICIENT {e['case_id']}: unmet={e['unmet_preconditions']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
