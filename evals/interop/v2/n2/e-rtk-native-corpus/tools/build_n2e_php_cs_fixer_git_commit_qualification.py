#!/usr/bin/env python3
"""Build the immutable php-cs-fixer::git::commit qualification record through the DISPATCH-V4 path
(NOT cq).

Consumes the FRESH acceptance observation (probe_php_cs_fixer_git_commit --mode acceptance) + its
evidence, freezes the fresh RAW `git commit` + RTK `rtk git commit` plumbing (rev-parse HEAD / HEAD^ +
the new commit's --name-status) and the RTK stdout as committed immutable evidence, and emits an
n2e-resolved-case-qualification record carrying a dispatch_code_identity (v4) and NO cq
frozen_code_identity.

The normative claim is the resulting-ref IDENTITY of the new commit, not the parser: under the pinned
git-commit-determinant-v1 policy the RAW and RTK full commit OIDs are EXACTLY equal (the commit object
reproduced; the hash is never normalized), both parents == the pinned base, and RTK's abbreviated OID
is a prefix.

Two hard gates before case_qualification_pass=True:
  * GATE 1 (producer-side, structural): the fresh acceptance observation must be clean -- outcome
    OBSERVED + not barred, both arms committed, OID reproduced (raw_commit_oid == rtk_commit_oid),
    observed equivalence closed, and the acceptance run is not a barred diagnostic run/impl.
  * GATE 2 (independent): the freshly built record + frozen evidence must pass verify_dispatch_binding
    AND recompute_dispatch_v4 (which replays the resulting-ref identity with the base OID taken from
    the pinned scenario, never the record's claim, and `created` derived purely from the plumbing).
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
import n2e_qualification_dispatch_v4 as d4  # noqa: E402

MANIFEST = N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"
CASE_ID = "php-cs-fixer__php-cs-fixer-8075::git::commit"
# acceptance-observation evidence file -> record commit_evidence key
_EVIDENCE = {
    "raw_head": "raw.plumb.head.bin", "raw_parent": "raw.plumb.parent.bin",
    "raw_name_status": "raw.plumb.name_status.bin",
    "rtk_head": "rtk.plumb.head.bin", "rtk_parent": "rtk.plumb.parent.bin",
    "rtk_name_status": "rtk.plumb.name_status.bin", "rtk_stdout": "rtk.stdout.bin",
}


def _require(cond, msg):
    if not cond:
        raise SystemExit(f"REFUSING to build: {msg}")


def build(observation: Path, evidence: Path, name: str, run: dict, out_path: Path | None = None) -> Path:
    obs = c.load_record(observation)

    # ---- GATE 1: the fresh acceptance observation must be clean ----
    _require(obs.get("record_kind") == "php_cs_fixer_git_commit_acceptance_capture"
             and not obs.get("barred_from_qualification"),
             "observation is not a non-barred php_cs_fixer_git_commit_acceptance_capture")
    _require(obs.get("outcome") == "PHP_CS_FIXER_GIT_COMMIT_OBSERVED", f"observation outcome={obs.get('outcome')!r}")
    _require(run["run_id"] not in L.BARRED_DIAGNOSTIC_RUNS and run["impl_commit"] not in L.BARRED_DIAGNOSTIC_IMPLS,
             "acceptance run names a barred diagnostic run/impl")
    oo = obs.get("oracle_observation") or {}
    _require(oo.get("oid_reproduced") is True, "commit OID did not reproduce (raw_commit_oid != rtk_commit_oid)")
    _require((oo.get("equivalence") or {}).get("equivalent") is True, "observed equivalence not closed")
    _require((obs.get("raw_arm") or {}).get("git_state", {}).get("created") is True, "RAW did not create a commit")
    _require((obs.get("rtk_arm") or {}).get("git_state", {}).get("created") is True, "RTK did not create a commit")

    man = c.load_record(MANIFEST)
    entry = next(x for x in man["cases"] if x["case_id"] == CASE_ID)
    _require(entry.get("dispatch_policy_id") == d4.DISPATCH_POLICY_ID, "manifest not routed to dispatch-v4")

    # ---- freeze the fresh evidence as committed immutable evidence ----
    qdir = N2E_DIR / "evidence" / name / "qualification"
    qdir.mkdir(parents=True, exist_ok=True)
    commit_evidence = {}
    for key, fn in _EVIDENCE.items():
        src = evidence / fn
        _require(src.is_file(), f"missing fresh evidence {src}")
        b = src.read_bytes()
        (qdir / fn).write_bytes(b)
        commit_evidence[key] = {"evidence_path": f"evidence/{name}/qualification/{fn}",
                                "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)}

    body = c.envelope(
        record_type="n2e-resolved-case-qualification",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_php_cs_fixer_git_commit_qualification.py",
        record_version="v1",
        purpose=f"Immutable per-case qualification for {CASE_ID} via the dispatch-v4 registry-bound "
                f"commit-identity path (NOT cq). The normative claim is the resulting-ref identity: "
                f"under the pinned git-commit-determinant-v1 policy the RAW and RTK full commit OIDs "
                f"are EXACTLY equal (the commit object reproduced; the hash is never normalized), both "
                f"parents == base, and RTK's abbrev is a prefix. Built from a fresh acceptance run; "
                f"gated by the dispatch binding + recompute. Sets no promotion flag.",
        case_id=CASE_ID,
        record_kind="php_cs_fixer_git_commit_acceptance_qualification",   # NOT the barred diagnostic kind
        manifest_generation=man["manifest_generation"],
        manifest_sha256=c.sha256_json_file(MANIFEST),
        case_entry_sha256=entry.get("case_entry_sha256"),
        qualification_kind=entry["qualification_kind"],
        rtk_test_dialect_policy_id=entry["rtk_test_dialect_policy_id"],           # null
        command_semantic_oracle_policy_id=entry["command_semantic_oracle_policy_id"],
        canonicalization_policy_id=entry["canonicalization_policy_id"],
        contract_generation=entry["contract_generation"],
        dispatch_policy_id=d4.DISPATCH_POLICY_ID,
        dispatch_code_identity=d4.dispatch_code_identity(entry),
        determinant_policy_id=obs.get("determinant_policy_id"),
        acceptance_run={"workflow": "qodec-n2e-php-cs-fixer-git-commit", **run},
        identities={"rtk_sha256": obs.get("rtk_binary_sha256")},
        commit_identity={"base_commit": oo.get("base_commit"), "staged_tree_oid": oo.get("staged_tree_oid"),
                         "reproduced_commit_oid": oo.get("raw_commit_oid")},
        commit_evidence=commit_evidence,
        re_derived={"equivalence": oo.get("equivalence"),
                    "normative_axis": "resulting-ref identity: RAW commit OID == RTK commit OID "
                                      "(reproducible; never normalized), both parents == base, RTK "
                                      "abbrev is a prefix; subject/author/committer/changed-paths excluded"},
        evidence={"dir": f"evidence/{name}/qualification"},
        verdict_authority="dispatch-v4 binding + recompute (producer records observations)",
        case_qualification_pass=True,
        resolved_canary_pass=False,
        promotion_state="held (resolved-twelve not yet 12/12)",
    )
    out = out_path or (N2E_DIR / f"n2e-resolved-case-qualification-{name}-v1.json")
    c.write_record(out, body)

    # ---- GATE 2: the freshly built record must independently bind + recompute True via dispatch-v4 ----
    rec = c.load_record(out)
    d4.verify_dispatch_binding(rec, entry)
    _require(d4.recompute_dispatch_v4(rec, entry) is True,
             "freshly built record does not recompute True through dispatch-v4")
    print(f"wrote {out.name}; dispatch-v4 recomputed case_qualification_pass=True "
          f"(commit OID reproduced {oo.get('raw_commit_oid', '?')[:12]} == "
          f"{oo.get('rtk_commit_oid', '?')[:12]}; parent {oo.get('base_commit', '?')[:12]})")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="php-cs-fixer")
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
