#!/usr/bin/env python3
"""Build the immutable loghub::HDFS::log qualification record through the DISPATCH-V2 path (NOT cq).

Consumes the FRESH acceptance observation (probe_loghub_acceptance) + its evidence, freezes the full
fresh RTK output as committed immutable evidence, embeds the RAW capsule summary, pins the dispatch
code identity (layer + immutable registry + oracle module + pinned RTK source, by content hash), and
emits an n2e-resolved-case-qualification record carrying a dispatch_code_identity (and NO cq
frozen_code_identity -- the two paths are mutually exclusive).

Two hard gates before case_qualification_pass=True:
  * GATE 1 (producer-side, structural): the acceptance observation must be clean -- fresh capsule
    parsed, published-authority held, both arms read the same member, severity equivalence closed on
    TOTALS ONLY, and the acceptance run must not be a barred diagnostic run/impl;
  * GATE 2 (independent): the freshly built record + frozen evidence must pass verify_dispatch_binding
    AND recompute_dispatch_v2 (re-parses the frozen RTK bytes, re-derives the RAW<->RTK severity
    equivalence from the capsule -- never a producer PASS string).

Normative equality: severity TOTALS only (errors/warnings/info). RTK unique counts are never compared
to the 46 published EventIds.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402
import n2e_qualification_dispatch as disp  # noqa: E402
import n2e_rtk_log_hdfs_oracle as orc  # noqa: E402

MANIFEST = N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"


def _require(cond: bool, msg: str):
    if not cond:
        raise SystemExit(f"REFUSING to build: {msg}")


def build(case_id: str, observation: Path, evidence: Path, name: str, run: dict) -> Path:
    obs = c.load_record(observation)

    # ---- GATE 1: the fresh acceptance observation must be clean ----
    _require(obs.get("record_kind") == "loghub_acceptance_capture" and not obs.get("barred_from_qualification"),
             "observation is not a non-barred loghub_acceptance_capture")
    _require(obs.get("outcome") == "LOGHUB_ACCEPTANCE_OBSERVED", f"observation outcome={obs.get('outcome')!r}")
    _require(run["run_id"] not in L.BARRED_DIAGNOSTIC_RUNS and run["impl_commit"] not in L.BARRED_DIAGNOSTIC_IMPLS,
             "acceptance run names a barred diagnostic run/impl")

    raw_arm = obs.get("raw_arm") or {}
    cap = raw_arm.get("capsule_summary") or {}
    _require(cap.get("outcome") == "parsed", f"capsule outcome={cap.get('outcome')!r} (not parsed)")
    _require(not cap.get("unmatched_lines") and not cap.get("ambiguous_lines"),
             "capsule has unmatched/ambiguous lines")
    _require(cap.get("occurrence_counts_match_published") is True, "published occurrence authority not held")

    sip = obs.get("same_input_proof") or {}
    _require(sip.get("raw_stdout_equals_member") and sip.get("member_unchanged_after")
             and sip.get("rtk_read_same_member_path"), "same-input proof does not hold")

    # the observation's own severity equivalence (TOTALS only) must already close
    oo = (obs.get("oracle_observation") or {}).get("equivalence") or {}
    _require(oo.get("equivalent") is True, f"observed severity equivalence not closed: {oo}")

    man = c.load_record(MANIFEST)
    entry = next(x for x in man["cases"] if x["case_id"] == case_id)
    _require(entry.get("dispatch_policy_id") == disp.DISPATCH_POLICY_ID,
             "manifest case is not routed to dispatch-v2")
    _require(entry["qualification_kind"] == "rtk_command_oracle", "manifest kind != rtk_command_oracle")

    # ---- freeze the FULL fresh RTK output as committed immutable evidence ----
    src_rtk = evidence / "raw.rtk.stdout.bin"
    _require(src_rtk.is_file(), f"missing fresh RTK evidence {src_rtk}")
    rtk_bytes = src_rtk.read_bytes()
    rtk_sha = hashlib.sha256(rtk_bytes).hexdigest()
    _require(rtk_sha == (obs.get("rtk_arm") or {}).get("stdout", {}).get("sha256"),
             "frozen RTK evidence sha256 != observed rtk_arm stdout sha256")

    qdir = N2E_DIR / "evidence" / name / "qualification"
    qdir.mkdir(parents=True, exist_ok=True)
    (qdir / "rtk.stdout.bin").write_bytes(rtk_bytes)
    rtk_evidence_rel = f"evidence/{name}/qualification/rtk.stdout.bin"

    # the RTK totals re-parsed from the frozen bytes -- the record pins them descriptively; the
    # verifier re-derives them independently.
    rtk_proj = orc.parse_rtk(rtk_bytes)
    _require(rtk_proj.get("derivable"), "frozen RTK output is not derivable")

    body = c.envelope(
        record_type="n2e-resolved-case-qualification",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_loghub_dispatch_qualification.py",
        record_version="v1",
        purpose=f"Immutable per-case qualification for {case_id} via the dispatch-v2 registry-bound "
                f"path (NOT cq). Built from a fresh acceptance run; gated by the dispatch binding + "
                f"recompute. Severity TOTALS only. Sets no promotion flag.",
        case_id=case_id,
        record_kind="loghub_acceptance_qualification",   # NOT the barred diagnostic kind
        manifest_generation=man["manifest_generation"],
        manifest_sha256=c.sha256_json_file(MANIFEST),
        case_entry_sha256=entry.get("case_entry_sha256"),
        qualification_kind=entry["qualification_kind"],
        rtk_test_dialect_policy_id=entry["rtk_test_dialect_policy_id"],           # null
        command_semantic_oracle_policy_id=entry["command_semantic_oracle_policy_id"],
        canonicalization_policy_id=entry["canonicalization_policy_id"],
        contract_generation=entry["contract_generation"],
        # ---- routing axis: the versioned registry-bound dispatch identity (NO cq frozen_code_identity) ----
        dispatch_policy_id=disp.DISPATCH_POLICY_ID,
        dispatch_code_identity=disp.dispatch_code_identity(entry),
        acceptance_run={"workflow": "qodec-n2e-loghub-acceptance", **run},
        identities={"rtk_sha256": obs.get("rtk_binary_sha256")},
        same_input_proof=sip,
        # ---- the RAW capsule the verifier replays (published-authority full-stream summary) ----
        raw_capsule_summary=cap,
        # ---- the frozen fresh RTK output the verifier re-parses ----
        rtk_output={"evidence_path": rtk_evidence_rel, "sha256": rtk_sha, "bytes": len(rtk_bytes)},
        re_derived_semantic_projection={
            "raw_projection": orc.raw_projection_from_capsule(cap),
            "rtk_projection": rtk_proj,
            "equivalence": orc.equivalence(orc.raw_projection_from_capsule(cap), rtk_proj),
            "normative_axis": "severity TOTALS only (errors/warnings/info); unique counts never "
                              "compared to the 46 published EventIds",
        },
        evidence={"dir": f"evidence/{name}/qualification"},
        verdict_authority="dispatch-v2 binding + recompute (producer records observations)",
        case_qualification_pass=True,
        resolved_canary_pass=False,
        promotion_state="held (resolved-twelve not yet 12/12)",
    )
    out = N2E_DIR / f"n2e-resolved-case-qualification-{name}-v1.json"
    c.write_record(out, body)

    # ---- GATE 2: the freshly built record must independently bind + recompute True via dispatch-v2 ----
    rec = c.load_record(out)
    disp.verify_dispatch_binding(rec, entry)
    _require(disp.recompute_dispatch_v2(rec, entry) is True,
             "freshly built record does not recompute True through dispatch-v2")
    print(f"wrote {out.name}; dispatch-v2 recomputed case_qualification_pass=True "
          f"(errors={rtk_proj['total_errors']} warnings={rtk_proj['total_warnings']} info={rtk_proj['total_info']})")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", default="loghub::HDFS::log")
    ap.add_argument("--name", default="loghub")
    ap.add_argument("--observation", required=True)
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--run-attempt", required=True)
    ap.add_argument("--impl-commit", required=True)
    ap.add_argument("--artifact-sha256", required=True)
    ap.add_argument("--artifact-bytes", required=True, type=int)
    a = ap.parse_args()
    run = {"run_id": a.run_id, "run_attempt": a.run_attempt, "impl_commit": a.impl_commit,
           "artifact_sha256": a.artifact_sha256, "artifact_bytes": a.artifact_bytes}
    build(a.case, Path(a.observation).resolve(), Path(a.evidence).resolve(), a.name, run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
