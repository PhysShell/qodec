#!/usr/bin/env python3
"""Promotion P5.4: the resolved-twelve aggregator -- the sole authority over resolved_canary_pass.

It NEVER trusts a producer-declared PASS. It loads the frozen twelve-case manifest, requires EXACTLY
one qualification record per listed case, binds every record to the manifest generation + declared
policy, rejects barred provenance / duplicate records / cross-case identity reuse / non-unique
acceptance runs, and INDEPENDENTLY RE-DERIVES each verdict through that case's materialized
recompute path. resolved_canary_pass becomes true ONLY when it counts twelve independently-derived
PASSes over twelve unique acceptance runs; any lower count holds it false.

Honesty constraint: a case can be counted only if its recompute path is materialized. Today only
coreutils-6731 has one (the frozen P1-P4 loader recomputation); the other eleven have no recompute
registered until their P5.2 dialect + P5.3 acceptance land, so a record for them cannot yet be
derived to PASS -- the aggregator holds. This is the current staged state: 1/12, held.

The pure core is aggregate(roster, records, recompute); aggregate_from_disk() wires the frozen
manifest + on-disk records + the production recompute registry.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402
import verify_n2e_resolved_twelve_manifest as VM  # noqa: E402


class AggregateError(Exception):
    pass


# roster entry keys the aggregator binds each record to
_BIND_KEYS = ("expected_qualification_record_type", "canonicalization_policy_id",
              "rtk_test_dialect_policy_id", "command_semantic_oracle_policy_id",
              "qualification_kind", "contract_generation")


def _check_kind_dispatch(cid: str, rec: dict, entry: dict) -> None:
    """The record must declare the manifest's qualification_kind and carry the SAME single active
    policy id. A test-dialect record presented for a command-oracle case (or vice versa), or one
    naming a different dialect/oracle than the manifest, is a wrong dispatch -> reject."""
    kind = entry["qualification_kind"]
    if rec.get("qualification_kind") != kind:
        raise AggregateError(f"{cid}: record qualification_kind {rec.get('qualification_kind')!r} "
                             f"!= manifest {kind!r} (wrong dispatch)")
    if kind == "rtk_test_dialect":
        if rec.get("rtk_test_dialect_policy_id") != entry["rtk_test_dialect_policy_id"]:
            raise AggregateError(f"{cid}: bound dialect != manifest")
        if rec.get("command_semantic_oracle_policy_id") is not None:
            raise AggregateError(f"{cid}: test-dialect record must not carry a command oracle")
    elif kind == "rtk_command_oracle":
        if rec.get("command_semantic_oracle_policy_id") != entry["command_semantic_oracle_policy_id"]:
            raise AggregateError(f"{cid}: bound command oracle != manifest")
        if rec.get("rtk_test_dialect_policy_id") is not None:
            raise AggregateError(f"{cid}: command-oracle record must not carry a test dialect")
    else:
        raise AggregateError(f"{cid}: unknown manifest qualification_kind {kind!r}")


def _recompute_coreutils(rec: dict, entry: dict) -> bool:
    """The materialized coreutils recompute path: the frozen P4 loader recomputation from the
    committed canonical streams. Returns the INDEPENDENTLY derived verdict (not the record's claim)."""
    return L.validate_coreutils_qualification(
        rec, c.sha256_json_file(L.RESOLVED_MEMBERSHIP), c.sha256_json_file(L.OV_CONTRACT),
        c.sha256_json_file(L.BINID), c.sha256_json_file(L.DIALECT), L.QUALIFICATION_DIR)


def _bind_coreutils(rec: dict, entry: dict) -> None:
    """The frozen P4 record predates the two-mode manifest; it binds transitively through the gen-3
    contract + resolved-membership hashes the manifest pins, and its (implicit) rtk_test_dialect kind
    is cross-checked against the manifest classification via the record's bound_dialect_policy_id."""
    b = entry["manifest_binding"]
    if rec.get("contract_generation3_sha256") != b["resolved_execution_contract_sha256"]:
        raise AggregateError(f"{entry['case_id']}: contract_generation3_sha256 != manifest's gen-3 contract")
    if rec.get("resolved_membership_sha256") != b["resolved_membership_sha256"]:
        raise AggregateError(f"{entry['case_id']}: resolved_membership_sha256 != manifest's membership")
    if entry["qualification_kind"] != "rtk_test_dialect":
        raise AggregateError(f"{entry['case_id']}: manifest kind != rtk_test_dialect for coreutils")
    if rec.get("bound_dialect_policy_id") != entry["rtk_test_dialect_policy_id"]:
        raise AggregateError(f"{entry['case_id']}: bound_dialect_policy_id != manifest dialect")


def _bind_case_generation(rec: dict, entry: dict) -> None:
    """The eleven forward records are built AFTER the manifest and bind it directly by generation +
    self-hash (a record from an earlier manifest generation is rejected), and must dispatch to the
    manifest's qualification_kind with the matching single active policy id."""
    b = entry["manifest_binding"]
    if rec.get("manifest_generation") != b["manifest_generation"]:
        raise AggregateError(f"{entry['case_id']}: manifest_generation {rec.get('manifest_generation')} "
                             f"!= roster {b['manifest_generation']}")
    if rec.get("manifest_sha256") != b["manifest_sha256"]:
        raise AggregateError(f"{entry['case_id']}: manifest_sha256 != frozen manifest")
    _check_kind_dispatch(entry["case_id"], rec, entry)


def _recompute_resolved_case(rec: dict, entry: dict) -> bool:
    """Materialized recompute for a forward per-case qualification record. Dispatches by
    qualification_kind: rtk_test_dialect re-parses the frozen streams through the proven dialect
    (P5.2A); rtk_command_oracle lands with P5.2B. The frozen evidence dir is pinned in the record."""
    import n2e_resolved_case_qualification as cq
    if entry.get("qualification_kind") == "rtk_test_dialect":
        ev = Path((rec.get("evidence") or {}).get("dir") or "")
        if not ev.is_absolute():
            ev = N2E_DIR / ev
        return cq.recompute_test_dialect_verdict(rec, entry, ev)
    raise AggregateError(f"{entry['case_id']}: no materialized recompute for kind "
                         f"{entry.get('qualification_kind')!r} (rtk_command_oracle lands in P5.2B)")


# production registries keyed by expected_qualification_record_type. ONLY materialized paths appear;
# a case counts only when its recompute path exists (test dialects via P5.2A; command oracles P5.2B).
PRODUCTION_RECOMPUTE = {"n2e-coreutils-qualification": _recompute_coreutils,
                        "n2e-resolved-case-qualification": _recompute_resolved_case}
PRODUCTION_BIND = {"n2e-coreutils-qualification": _bind_coreutils,
                   "n2e-resolved-case-qualification": _bind_case_generation}


def _one(records, case_id):
    """Return the single record for case_id, or None if absent; raise on duplicates."""
    got = records.get(case_id)
    if got is None:
        return None
    if isinstance(got, list):
        if len(got) != 1:
            raise AggregateError(f"{case_id}: expected exactly one qualification record, got {len(got)}")
        return got[0]
    return got


def aggregate(roster: list, records: dict, recompute: dict, bind: dict) -> dict:
    """Pure aggregate over a verified twelve-case roster + a case_id->record(s) map + recompute/bind
    registries. Derives resolved_canary_pass fail-closed. Never trusts a producer PASS string."""
    if len(roster) != 12:
        raise AggregateError(f"roster is not twelve ({len(roster)})")
    roster_ids = [e["case_id"] for e in roster]
    if len(set(roster_ids)) != 12:
        raise AggregateError("duplicate case ids in roster")

    per_case, run_keys, artifact_keys, passes = {}, {}, {}, 0
    for entry in roster:
        cid = entry["case_id"]
        rec = _one(records, cid)
        if rec is None:
            per_case[cid] = {"present": False, "derived_pass": False}
            continue

        # ---- the record must be for THIS case, of the manifest-declared type ----
        if rec.get("case_id") != cid and cid not in [q.get("case_id") for q in (rec.get("qualifications") or [])]:
            raise AggregateError(f"{cid}: record does not bind this case")
        etype = entry["expected_qualification_record_type"]
        if rec.get("record_type") != etype:
            raise AggregateError(f"{cid}: record_type {rec.get('record_type')!r} "
                                 f"!= manifest-declared {etype!r}")
        # ---- manifest binding (type-dispatched: frozen coreutils vs forward per-case) ----
        bind_fn = bind.get(etype)
        if bind_fn is None:
            raise AggregateError(f"{cid}: no manifest-binding check for {etype!r}")
        bind_fn(rec, entry)
        # declared policy binding (wrong dialect/canon/contract-generation -> reject)
        for k in ("canonicalization_policy_id", "rtk_test_dialect_policy_id", "contract_generation"):
            if k in rec and rec.get(k) != entry.get(k):
                raise AggregateError(f"{cid}: bound {k} {rec.get(k)!r} != manifest {entry.get(k)!r}")

        # ---- acceptance-run identity: present, not barred, and GLOBALLY UNIQUE across the twelve ----
        run = rec.get("acceptance_run") or {}
        for f in ("workflow", "run_id", "run_attempt", "impl_commit", "artifact_sha256", "artifact_bytes"):
            if run.get(f) in (None, ""):
                raise AggregateError(f"{cid}: acceptance_run.{f} missing")
        if run["run_id"] in L.BARRED_DIAGNOSTIC_RUNS or run["impl_commit"] in L.BARRED_DIAGNOSTIC_IMPLS:
            raise AggregateError(f"{cid}: acceptance_run names a barred diagnostic run/impl")
        rk = (run["run_id"], run["run_attempt"])
        if rk in run_keys:
            raise AggregateError(f"{cid}: acceptance run {rk} reused from {run_keys[rk]} "
                                 f"(twelve records must span twelve unique runs)")
        run_keys[rk] = cid
        ak = run["artifact_sha256"]
        if ak in artifact_keys:
            raise AggregateError(f"{cid}: artifact digest reused from {artifact_keys[ak]} (cross-case)")
        artifact_keys[ak] = cid

        # ---- INDEPENDENT recomputation through the case's materialized path ----
        fn = recompute.get(entry["expected_qualification_record_type"])
        if fn is None:
            raise AggregateError(f"{cid}: no materialized recompute path for "
                                 f"{entry['expected_qualification_record_type']!r} -- cannot derive PASS")
        derived = bool(fn(rec, entry))
        # the aggregator's derivation is authoritative; a producer PASS that disagrees is rejected
        claimed = rec.get("case_qualification_pass",
                          rec.get("coreutils_qualification_pass"))
        if claimed is not True:
            raise AggregateError(f"{cid}: record does not claim PASS")
        if claimed != derived:
            raise AggregateError(f"{cid}: producer PASS {claimed} != aggregator recomputation {derived}")
        if not derived:
            raise AggregateError(f"{cid}: aggregator recomputation is FAIL")
        per_case[cid] = {"present": True, "derived_pass": True, "acceptance_run": rk}
        passes += 1

    twelve = passes == 12
    return {
        "cardinality": 12,
        "derived_pass_count": passes,
        "unique_acceptance_runs": len(run_keys),
        "twelve_independently_derived": twelve,
        "per_case": per_case,
        # THE sole promotion output; false unless all twelve are independently derived
        "resolved_canary_pass": twelve,
    }


def _roster_from_manifest(man: dict, man_path: Path) -> list:
    VM.verify_manifest(man)  # fail-closed: exactly the frozen twelve, in order
    binding = {
        "manifest_generation": man["manifest_generation"],
        "manifest_sha256": c.sha256_json_file(man_path),
        "resolved_execution_contract_sha256": man["resolved_execution_contract_sha256"],
        "resolved_membership_sha256": man["resolved_membership_sha256"]}
    roster = []
    for x in man["cases"]:
        roster.append({**{k: x.get(k) for k in _BIND_KEYS}, "case_id": x["case_id"],
                       "manifest_generation": man["manifest_generation"],
                       "manifest_binding": binding})
    return roster


def aggregate_from_disk() -> dict:
    man_path = N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"
    man = c.load_record(man_path)
    roster = _roster_from_manifest(man, man_path)
    records = {}
    # only materialized records are loaded; still-pending cases are legitimately absent.
    # coreutils: the frozen P4 record.
    if L.QUALIFICATION.is_file():
        records[L.REPLACEMENT_CASE_ID] = c.load_record(L.QUALIFICATION)
    # forward per-case qualification records (n2e-resolved-case-qualification-<name>-v1.json)
    for p in sorted(N2E_DIR.glob("n2e-resolved-case-qualification-*.json")):
        rec = c.load_record(p)
        cid = rec.get("case_id")
        if cid in records:
            raise AggregateError(f"duplicate qualification record for {cid} ({p.name})")
        records[cid] = rec
    return aggregate(roster, records, PRODUCTION_RECOMPUTE, PRODUCTION_BIND)


def main() -> int:
    r = aggregate_from_disk()
    print(f"resolved-twelve-aggregate: {r['derived_pass_count']}/12 independently derived "
          f"(unique runs={r['unique_acceptance_runs']}) -> resolved_canary_pass={r['resolved_canary_pass']}")
    for cid, s in r["per_case"].items():
        print(f"  {'PASS' if s['derived_pass'] else 'ABSENT/HELD'}  {cid}")
    # exit 0 always: this is a status report, not a gate. Promotion is a separate, explicit step.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
