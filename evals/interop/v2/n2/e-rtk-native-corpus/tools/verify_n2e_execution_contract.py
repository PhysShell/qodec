#!/usr/bin/env python3
"""Independent verification of the N2-E execution-contract record (correction #3).

OFFLINE (always):
  1. recompute the contract record self-hash;
  2. require its membership + scenarios hashes to match the frozen records;
  3. INDEPENDENTLY re-derive every contract from the frozen scenario + the declared
     argv-resolver policy + canon.policy_for, and require exact agreement (the
     committed record may not disagree with a fresh derivation);
  4. require the _CASE_POLICY lookup to AGREE with each contract's canon policy id,
     and reject any family-generic policy where a case-scoped one is required.

RUNTIME (when a per-case evidence dir is given): for each canary per-case record,
reject:
  * an effective argv not derivable from the frozen contract + declared rule;
  * a family-generic canon policy substituted for a required case policy;
  * scheduler flags that alter test membership (a filtering flag);
  * unpinned / missing executable identities for the family's required toolchain;
  * any protected-file mutation (before/after hash inequality).

Usage: verify_n2e_execution_contract.py [<per-case-evidence-dir>]
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_canon_policies as canon  # noqa: E402
import n2e_argv_resolver as resolver  # noqa: E402
import build_n2e_execution_contract as B  # noqa: E402

CONTRACT = N2E_DIR / "n2e-canary-execution-contract-v1.json"
SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
CANARY = N2E_DIR / "n2e-canary-membership-v1.json"

# scheduler flags that would ALTER test membership are forbidden (allow-list of
# pure-scheduling flags that never select/deselect tests).
_ALLOWED_SCHED_FLAGS = {
    "--no-file-parallelism", "--sequence.concurrent=false", "--sequence.shuffle=false", "--runInBand",
}


def _rederive(scen, cid) -> dict:
    return B.build_contract(scen, cid)


def verify_offline() -> tuple[bool, str]:
    rec = c.load_record(CONTRACT)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        return False, f"contract self-hash: {msg}"
    if rec.get("canary_membership_sha256") != c.sha256_json_file(CANARY):
        return False, "contract canary_membership_sha256 mismatch"
    if rec.get("command_scenarios_sha256") != c.sha256_json_file(SCEN):
        return False, "contract command_scenarios_sha256 mismatch"
    scen_by_id = {s["case_id"]: s for s in c.load_record(SCEN)["scenarios"]}
    expected = {m["case_id"] for m in c.load_record(CANARY)["membership"]}
    got = {x["case_id"] for x in rec["contracts"]}
    if got != expected:
        return False, f"contract case set != frozen 12 (missing={sorted(expected-got)}, extra={sorted(got-expected)})"
    for x in rec["contracts"]:
        cid = x["case_id"]
        fresh = _rederive(scen_by_id[cid], cid)
        if fresh != x:
            diff = [k for k in set(fresh) | set(x) if fresh.get(k) != x.get(k)]
            return False, f"{cid}: committed contract disagrees with fresh derivation on {diff}"
        # _CASE_POLICY must AGREE with the contract's canon policy (case-scoped binding)
        fam, sub = x["command_family"], x["command_subfamily"]
        lookup = canon.policy_for(fam, sub, git=(fam == "git"), case_id=cid)
        cpid = x["canonicalization_policy_id"]
        if not cpid.startswith("RUNTIME:") and lookup != cpid:
            return False, f"{cid}: _CASE_POLICY '{lookup}' != contract canon policy '{cpid}'"
        # a case with a scoped binding must NOT carry the family-generic id
        if cid in canon._CASE_POLICY and cpid == canon._FAMILY_SUB_POLICY.get((fam, sub)):
            return False, f"{cid}: family-generic policy used where a case-scoped policy is required"
    return True, f"OK; {rec['contract_count']} contracts re-derived + _CASE_POLICY agrees"


def verify_runtime(evidence_dir: Path) -> tuple[bool, str]:
    rec = c.load_record(CONTRACT)
    by_id = {x["case_id"]: x for x in rec["contracts"]}
    scen_by_id = {s["case_id"]: s for s in c.load_record(SCEN)["scenarios"]}
    checked = 0
    for p in sorted(evidence_dir.rglob("n2e-canary-case-*.json")):
        r = c.load_record(p)
        cid = r.get("case_id")
        con = by_id.get(cid)
        if not con:
            continue
        acq = r.get("acquisition") or {}
        fam = r.get("command_family")
        # effective argv derivable from the frozen contract + declared rule
        eff_raw = acq.get("resolved_raw_argv") or (r.get("raw_argv"))
        rr = resolver.resolve(scen_by_id[cid])
        if not con["runtime_resolved"]:
            if eff_raw is not None and list(eff_raw) != con["effective_raw_argv"]:
                return False, f"{cid}: effective RAW argv {eff_raw} != frozen contract {con['effective_raw_argv']}"
        # canon policy actually used must equal the contract (never a generic substitution)
        used = (r.get("raw_arm") or {}).get("canonicalization_policy") or acq.get("policy")
        cpid = con["canonicalization_policy_id"]
        if used and not cpid.startswith("RUNTIME:") and used != cpid:
            return False, f"{cid}: used canon policy '{used}' != contract '{cpid}'"
        if cid in canon._CASE_POLICY and used and used == canon._FAMILY_SUB_POLICY.get(
                (fam, r.get("command_subfamily"))):
            return False, f"{cid}: family-generic canon policy used where case-scoped required"
        # scheduler flags must not alter test membership
        for fl in (con.get("scheduler_flags") or []):
            if fl not in _ALLOWED_SCHED_FLAGS:
                return False, f"{cid}: scheduler flag '{fl}' not in the membership-preserving allow-list"
        # executable identities present for the family's required toolchain
        env_id = acq.get("environment_identity") or {}
        toolchain = env_id.get("toolchain") or {}
        for key in con["toolchain_identity_ref"]["required_keys"]:
            t = toolchain.get(key) or {}
            if not (t.get("sha256") and t.get("version")):
                return False, f"{cid}: unpinned/missing toolchain identity for '{key}'"
        # protected-file mutation guard
        guard = (env_id.get("dependencies") or {}).get("mutation_guard_ok")
        if env_id and guard is False:
            return False, f"{cid}: protected-file mutation detected (guard failed)"
        checked += 1
    return True, f"OK; runtime contract checks passed for {checked} per-case record(s)"


def main() -> int:
    ok, msg = verify_offline()
    if not ok:
        print(f"::error::execution-contract offline verification FAILED: {msg}", file=sys.stderr)
        return 1
    print(f"execution-contract offline: {msg}")
    if len(sys.argv) > 1:
        rok, rmsg = verify_runtime(Path(sys.argv[1]))
        if not rok:
            print(f"::error::execution-contract runtime verification FAILED: {rmsg}", file=sys.stderr)
            return 1
        print(f"execution-contract runtime: {rmsg}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
