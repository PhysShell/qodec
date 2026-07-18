#!/usr/bin/env python3
"""One fail-closed resolved-scope loader (contract step 3).

Returns a single EFFECTIVE CASE BUNDLE for a case id under a scope:

  scope="base"     -> everything from the frozen base records (the 11 non-replacement
                      cases + the original tokio membership); overlays are never consulted.
  scope="resolved" -> the frozen base for every non-replacement case, and the resolved
                      replacement overlays for the coreutils-6731 case ONLY.

There are NO scattered `base_lookup(x) or overlay_lookup(x)` fallbacks: the loader
validates the entire resolved closure up-front and then routes each case to EXACTLY one
source. Any partial/base+overlay mixture, hash mismatch, shadow, or missing overlay fails
closed. The bundle carries the complete effective-record hash map so every emitted case
record can pin exactly what it ran under.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

# frozen base records
MEMBERSHIP = N2E_DIR / "n2e-canary-membership-v1.json"
SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
REGISTRY = N2E_DIR / "n2e-publisher-env-registry-v1.json"
CONTRACT = N2E_DIR / "n2e-canary-execution-contract-v1.json"
LOCK = N2E_DIR / "n2e-toolchain-lock-v1.json"
# resolved records
RESOLVED_MEMBERSHIP = N2E_DIR / "n2e-canary-resolved-membership-v1.json"
OV_PUBENV = N2E_DIR / "n2e-resolved-publisher-env-overlay-v1.json"
OV_TOOLCHAIN = N2E_DIR / "n2e-resolved-toolchain-overlay-v1.json"
OV_SCEN = N2E_DIR / "n2e-resolved-command-scenario-overlay-v1.json"
OV_CONTRACT = N2E_DIR / "n2e-resolved-execution-contract-v1.json"

REPLACEMENT_CASE_ID = "uutils__coreutils-6731::rust_cargo::test::fixed"
REPLACED_CASE_ID = "tokio-rs__tokio-4384::rust_cargo::test::fixed"

# overlay file -> (record key holding the base whole-file hash, the base file it must match)
_OVERLAYS = {
    "publisher_env": (OV_PUBENV, "base_publisher_registry_sha256", REGISTRY),
    "toolchain": (OV_TOOLCHAIN, "base_toolchain_lock_sha256", LOCK),
    "command_scenario": (OV_SCEN, "base_command_scenarios_sha256", SCEN),
    "execution_contract": (OV_CONTRACT, "base_execution_contract_sha256", CONTRACT),
}


class ResolvedScopeError(Exception):
    pass


def _load_ok(path: Path) -> dict:
    rec = c.load_record(path)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        raise ResolvedScopeError(f"{path.name}: self-hash {msg}")
    return rec


def validate_resolved_closure() -> dict:
    """Validate the whole resolved closure fail-closed; return the effective-record hash
    map + parsed overlays. Raises ResolvedScopeError on any violation."""
    rm = _load_ok(RESOLVED_MEMBERSHIP)
    rm_sha = c.sha256_json_file(RESOLVED_MEMBERSHIP)
    base_id_sets = {
        "registry": {r["case_id"] for r in _load_ok(REGISTRY)["recipes"]},
        "scenarios": {s["case_id"] for s in _load_ok(SCEN)["scenarios"]},
        "contracts": {x["case_id"] for x in _load_ok(CONTRACT)["contracts"]},
    }
    base_ids: set = set()
    for s in base_id_sets.values():
        base_ids |= s

    overlays, hashes = {}, {}
    for key, (path, base_key, base_path) in _OVERLAYS.items():
        rec = _load_ok(path)                                # self-hash valid
        if rec[base_key] != c.sha256_json_file(base_path):  # base whole-file hash matches
            raise ResolvedScopeError(f"{path.name}: {base_key} != current {base_path.name}")
        if rec["resolved_membership_sha256"] != rm_sha:     # same resolved-membership sha
            raise ResolvedScopeError(f"{path.name}: resolved_membership_sha256 mismatch")
        if rec["resolved_case_id"] != REPLACEMENT_CASE_ID:
            raise ResolvedScopeError(f"{path.name}: resolved_case_id != {REPLACEMENT_CASE_ID}")
        overlays[key] = rec
        hashes[f"overlay_{key}_sha256"] = c.sha256_json_file(path)

    # coreutils exactly once in every required overlay; shadows no base case id
    def _overlay_ids(rec, list_key, item_key="case_id"):
        return [x[item_key] for x in rec[list_key]]
    checks = {
        "publisher_env": _overlay_ids(overlays["publisher_env"], "overlay_recipes"),
        "command_scenario": _overlay_ids(overlays["command_scenario"], "overlay_scenarios"),
        "execution_contract": _overlay_ids(overlays["execution_contract"], "overlay_contracts"),
    }
    for key, ids in checks.items():
        if ids != [REPLACEMENT_CASE_ID]:
            raise ResolvedScopeError(f"overlay {key} must contain exactly [{REPLACEMENT_CASE_ID}], got {ids}")
        if REPLACEMENT_CASE_ID in base_ids:
            raise ResolvedScopeError(f"overlay {key} shadows a base case id")

    # effective membership: tokio absent, coreutils present exactly once
    eff_ids = [m["case_id"] for m in rm["resolved_membership"]]
    if REPLACED_CASE_ID in eff_ids:
        raise ResolvedScopeError("tokio present in effective (resolved) membership")
    if eff_ids.count(REPLACEMENT_CASE_ID) != 1:
        raise ResolvedScopeError("coreutils not present exactly once in effective membership")
    if not rm["constraints_ok"] or rm["corpus_feasibility_blocker"]:
        raise ResolvedScopeError("resolved membership constraints not ok / feasibility blocker")

    hashes.update({
        "resolved_membership_sha256": rm_sha,
        "base_publisher_registry_sha256": c.sha256_json_file(REGISTRY),
        "base_command_scenarios_sha256": c.sha256_json_file(SCEN),
        "base_execution_contract_sha256": c.sha256_json_file(CONTRACT),
        "base_toolchain_lock_sha256": c.sha256_json_file(LOCK),
        "base_membership_sha256": c.sha256_json_file(MEMBERSHIP),
    })
    return {"resolved_membership": rm, "overlays": overlays,
            "effective_ids": eff_ids, "effective_record_hash_map": hashes}


def load_case_bundle(case_id: str, scope: str = "base") -> dict:
    """Effective case bundle: membership entry, scenario, publisher recipe, toolchain
    contract, execution contract, plus the effective-record hash map. Fail-closed."""
    if scope not in ("base", "resolved"):
        raise ResolvedScopeError(f"unknown scope {scope!r}")

    if scope == "base":
        membership = _load_ok(MEMBERSHIP)["membership"]
        if case_id not in {m["case_id"] for m in membership}:
            raise ResolvedScopeError(f"{case_id} not in frozen base membership")
        scen = next(s for s in _load_ok(SCEN)["scenarios"] if s["case_id"] == case_id)
        contract = next((x for x in _load_ok(CONTRACT)["contracts"] if x["case_id"] == case_id), None)
        return {"scope": "base", "case_id": case_id, "source": "frozen_base",
                "membership_entry": next(m for m in membership if m["case_id"] == case_id),
                "scenario": scen, "publisher_recipe": None, "toolchain_contract": None,
                "execution_contract": contract,
                "effective_record_hash_map": {
                    "base_command_scenarios_sha256": c.sha256_json_file(SCEN),
                    "base_execution_contract_sha256": c.sha256_json_file(CONTRACT),
                    "base_membership_sha256": c.sha256_json_file(MEMBERSHIP)}}

    # scope == "resolved": validate the whole closure, then route this case to exactly one source
    closure = validate_resolved_closure()
    rm = closure["resolved_membership"]
    entry = next((m for m in rm["resolved_membership"] if m["case_id"] == case_id), None)
    if entry is None:
        raise ResolvedScopeError(f"{case_id} not in effective (resolved) membership")

    if case_id == REPLACEMENT_CASE_ID:
        ov = closure["overlays"]
        bundle = {
            "scope": "resolved", "case_id": case_id, "source": "replacement_overlay",
            "membership_entry": entry,
            "scenario": ov["command_scenario"]["overlay_scenarios"][0],
            "publisher_recipe": ov["publisher_env"]["overlay_recipes"][0],
            "toolchain_contract": ov["toolchain"]["resolved_rust_toolchain"],
            "execution_contract": ov["execution_contract"]["overlay_contracts"][0],
        }
    else:
        # every non-replacement case resolves EXCLUSIVELY from the frozen base
        scen = next(s for s in _load_ok(SCEN)["scenarios"] if s["case_id"] == case_id)
        contract = next((x for x in _load_ok(CONTRACT)["contracts"] if x["case_id"] == case_id), None)
        bundle = {
            "scope": "resolved", "case_id": case_id, "source": "frozen_base",
            "membership_entry": entry, "scenario": scen, "publisher_recipe": None,
            "toolchain_contract": None, "execution_contract": contract,
        }
    bundle["effective_record_hash_map"] = closure["effective_record_hash_map"]
    return bundle


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("case_id")
    ap.add_argument("--scope", choices=["base", "resolved"], default="base")
    args = ap.parse_args()
    try:
        b = load_case_bundle(args.case_id, args.scope)
    except ResolvedScopeError as e:
        print(f"resolved-loader: FAIL {e}")
        return 1
    print(f"resolved-loader: OK scope={b['scope']} case={b['case_id']} source={b['source']} "
          f"recipe={'yes' if b['publisher_recipe'] else 'no'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
