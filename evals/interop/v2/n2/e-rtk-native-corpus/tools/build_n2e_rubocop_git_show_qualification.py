#!/usr/bin/env python3
"""Build the immutable rubocop::git::show qualification record through the DISPATCH-V3 path (NOT cq).

Consumes the FRESH acceptance observation (probe_rubocop_git_show --mode acceptance) + its evidence,
freezes the fresh RAW `git show` + RTK compact output + the first-parent plumbing (rev-list parents,
numstat, shortstat, abbrev-resolve) as committed immutable evidence, and emits an
n2e-resolved-case-qualification record carrying a dispatch_code_identity (v3) and NO cq
frozen_code_identity.

Two hard gates before case_qualification_pass=True:
  * GATE 1 (producer-side, structural): the fresh acceptance observation must be clean -- outcome
    OBSERVED + not barred, RAW confirms merge, RTK mode compact, first-parent stat closes vs RTK
    (numstat+shortstat agree, show --stat cross-check matches), abbrev uniquely resolves, empty
    --name-status trap noted, and the acceptance run is not a barred diagnostic run/impl.
  * GATE 2 (independent): the freshly built record + frozen evidence must pass verify_dispatch_binding
    AND recompute_dispatch_v3 (which replays the split-authority merge equivalence with the contract
    OID taken from the pinned scenario, never the record's claim).
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
import n2e_qualification_dispatch_v3 as d3  # noqa: E402

MANIFEST = N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"
CASE_ID = "rubocop__rubocop-13687::git::show"
# acceptance-observation evidence file -> record merge_evidence key
_EVIDENCE = {
    "raw_stdout": "raw.stdout.bin", "rtk_stdout": "rtk.stdout.bin",
    "rev_list_parents": "plumb.rev_list_parents.bin",
    "first_parent_numstat": "plumb.first_parent_numstat.bin",
    "first_parent_shortstat": "plumb.first_parent_shortstat.bin",
    "abbrev_resolve": "plumb.abbrev_resolve.bin",
}


def _require(cond, msg):
    if not cond:
        raise SystemExit(f"REFUSING to build: {msg}")


def build(observation: Path, evidence: Path, name: str, run: dict, out_path: Path | None = None) -> Path:
    obs = c.load_record(observation)

    # ---- GATE 1: the fresh acceptance observation must be clean ----
    _require(obs.get("record_kind") == "rubocop_git_show_acceptance_capture"
             and not obs.get("barred_from_qualification"),
             "observation is not a non-barred rubocop_git_show_acceptance_capture")
    _require(obs.get("outcome") == "RUBOCOP_GIT_SHOW_OBSERVED", f"observation outcome={obs.get('outcome')!r}")
    _require(run["run_id"] not in L.BARRED_DIAGNOSTIC_RUNS and run["impl_commit"] not in L.BARRED_DIAGNOSTIC_IMPLS,
             "acceptance run names a barred diagnostic run/impl")
    _require((obs.get("raw_arm") or {}).get("identity", {}).get("is_merge"), "RAW does not confirm merge")
    _require((obs.get("rtk_arm") or {}).get("rtk_output_mode") == "compact", "RTK not compact")
    _require(obs.get("show_stat_matches_first_parent") is True, "show --stat != first-parent stat")
    _require((obs.get("oracle_observation") or {}).get("abbrev_uniquely_resolves") is True,
             "abbrev does not uniquely resolve")
    _require((obs.get("oracle_observation") or {}).get("equivalence", {}).get("equivalent") is True,
             "observed equivalence not closed")

    man = c.load_record(MANIFEST)
    entry = next(x for x in man["cases"] if x["case_id"] == CASE_ID)
    _require(entry.get("dispatch_policy_id") == d3.DISPATCH_POLICY_ID, "manifest not routed to dispatch-v3")

    # ---- freeze the fresh evidence as committed immutable evidence ----
    qdir = N2E_DIR / "evidence" / name / "qualification"
    qdir.mkdir(parents=True, exist_ok=True)
    merge_evidence = {}
    for key, fn in _EVIDENCE.items():
        src = evidence / fn
        _require(src.is_file(), f"missing fresh evidence {src}")
        b = src.read_bytes()
        (qdir / fn).write_bytes(b)
        merge_evidence[key] = {"evidence_path": f"evidence/{name}/qualification/{fn}",
                               "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)}

    body = c.envelope(
        record_type="n2e-resolved-case-qualification",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_rubocop_git_show_qualification.py",
        record_version="v1",
        purpose=f"Immutable per-case qualification for {CASE_ID} via the dispatch-v3 registry-bound "
                f"merge-aware path (NOT cq). Split authority: RAW=identity+topology, plumbing="
                f"first-parent delta, RTK=compact. Built from a fresh acceptance run; gated by the "
                f"dispatch binding + recompute. Sets no promotion flag.",
        case_id=CASE_ID,
        record_kind="rubocop_git_show_acceptance_qualification",   # NOT the barred diagnostic kind
        manifest_generation=man["manifest_generation"],
        manifest_sha256=c.sha256_json_file(MANIFEST),
        case_entry_sha256=entry.get("case_entry_sha256"),
        qualification_kind=entry["qualification_kind"],
        rtk_test_dialect_policy_id=entry["rtk_test_dialect_policy_id"],           # null
        command_semantic_oracle_policy_id=entry["command_semantic_oracle_policy_id"],
        canonicalization_policy_id=entry["canonicalization_policy_id"],
        contract_generation=entry["contract_generation"],
        dispatch_policy_id=d3.DISPATCH_POLICY_ID,
        dispatch_code_identity=d3.dispatch_code_identity(entry),
        acceptance_run={"workflow": "qodec-n2e-rubocop-git-show", **run},
        identities={"rtk_sha256": obs.get("rtk_binary_sha256")},
        merge_topology=obs.get("merge_first_parent"),
        merge_evidence=merge_evidence,
        re_derived={"equivalence": (obs.get("oracle_observation") or {}).get("equivalence"),
                    "normative_axis": "RAW=identity+topology, plumbing=first-parent stat, RTK=compact "
                                      "stat; %ar/patch/subject/author/second-parent excluded"},
        evidence={"dir": f"evidence/{name}/qualification"},
        verdict_authority="dispatch-v3 binding + recompute (producer records observations)",
        case_qualification_pass=True,
        resolved_canary_pass=False,
        promotion_state="held (resolved-twelve not yet 12/12)",
    )
    out = out_path or (N2E_DIR / f"n2e-resolved-case-qualification-{name}-v1.json")
    c.write_record(out, body)

    # ---- GATE 2: the freshly built record must independently bind + recompute True via dispatch-v3 ----
    rec = c.load_record(out)
    d3.verify_dispatch_binding(rec, entry)
    _require(d3.recompute_dispatch_v3(rec, entry) is True,
             "freshly built record does not recompute True through dispatch-v3")
    fp = obs.get("first_parent_stat") or {}
    print(f"wrote {out.name}; dispatch-v3 recomputed case_qualification_pass=True "
          f"(merge {obs['merge_first_parent']['merge_oid'][:12]} first_parent "
          f"{obs['merge_first_parent']['first_parent_oid'][:12]} "
          f"stat f{fp.get('files_changed')} +{fp.get('insertions')} -{fp.get('deletions')})")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="rubocop")
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
    build(Path(a.observation).resolve(), Path(a.evidence).resolve(), a.name, run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
