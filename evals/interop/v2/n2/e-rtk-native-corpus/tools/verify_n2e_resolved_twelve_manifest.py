#!/usr/bin/env python3
"""Promotion P5.1 verifier: the resolved-twelve manifest is EXACTLY the frozen twelve, in order,
with every per-case policy field matching the live frozen contract. Fail-closed.

Rejects: cardinality != 12, duplicate case ids, any case id not in the frozen resolved membership,
a reordered / substituted roster that preserves cardinality, a stale pin (membership / contract /
lock hash drift), a per-case policy field that disagrees with the frozen contract, and a manifest
of the wrong generation. Pure over (record, frozen files); the CLI verifies the committed manifest.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402
import build_n2e_resolved_twelve_manifest as B  # noqa: E402


class ManifestError(Exception):
    pass


# every policy field the manifest pins must be re-derivable from the frozen contract
_POLICY_KEYS = ("family", "subfamily", "canary_slot", "canonicalization_policy_id",
                "canonicalization_policy_generation", "rtk_test_dialect_policy_id",
                "semantic_oracle_policy_id", "contract_generation",
                "required_toolchain_identity_ref", "expected_qualification_record_type")


def verify_manifest(rec: dict, expected_generation: int = B.MANIFEST_GENERATION) -> dict:
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        raise ManifestError(f"manifest self-hash: {msg}")
    if rec.get("record_type") != "n2e-resolved-twelve-manifest":
        raise ManifestError("wrong record_type")
    if rec.get("record_version") != "v1":
        raise ManifestError("wrong record_version")
    if rec.get("manifest_generation") != expected_generation:
        raise ManifestError(f"manifest_generation {rec.get('manifest_generation')} "
                            f"!= expected {expected_generation}")

    # ---- pins to the frozen records ----
    for key, path in (("resolved_membership_sha256", L.RESOLVED_MEMBERSHIP),
                      ("base_execution_contract_sha256", L.CONTRACT),
                      ("resolved_execution_contract_sha256", L.OV_CONTRACT),
                      ("toolchain_lock_sha256", L.LOCK)):
        if rec.get(key) != c.sha256_json_file(path):
            raise ManifestError(f"stale pin: {key} != current {path.name}")

    cases = rec.get("cases") or []
    case_ids = rec.get("case_ids") or []
    if rec.get("cardinality") != 12 or len(cases) != 12 or len(case_ids) != 12:
        raise ManifestError(f"cardinality != 12 (card={rec.get('cardinality')} "
                            f"cases={len(cases)} ids={len(case_ids)})")
    if [x["case_id"] for x in cases] != case_ids:
        raise ManifestError("case_ids list disagrees with cases[].case_id")
    if len(set(case_ids)) != 12:
        raise ManifestError("duplicate case ids")

    # ---- membership identity + ORDER (reorder / substitution preserving cardinality -> reject) ----
    frozen_ids = [m["case_id"] for m in c.load_record(L.RESOLVED_MEMBERSHIP)["resolved_membership"]]
    if case_ids != frozen_ids:
        raise ManifestError("manifest roster != frozen resolved membership (order/identity)")

    # ---- re-derive the canonical manifest from the frozen contract; every field must match ----
    canonical = {x["case_id"]: x for x in B.build_manifest()["cases"]}
    for entry in cases:
        cid = entry["case_id"]
        ref = canonical.get(cid)
        if ref is None:
            raise ManifestError(f"case {cid} not in frozen contract-derived roster")
        for k in _POLICY_KEYS:
            if entry.get(k) != ref.get(k):
                raise ManifestError(f"case {cid}: field {k} {entry.get(k)!r} "
                                    f"!= frozen-derived {ref.get(k)!r}")
        # the single pinned corpus RTK binary
        if entry.get("required_rtk_binary_identity_ref", {}).get("sha256") != L.DIALECT_RTK_SHA:
            raise ManifestError(f"case {cid}: required RTK binary identity != pinned corpus RTK")

    return {"cardinality": 12, "case_ids": case_ids,
            "manifest_generation": rec["manifest_generation"]}


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else str(N2E_DIR / "n2e-resolved-twelve-manifest-v1.json")
    try:
        facts = verify_manifest(c.load_record(path))
    except ManifestError as e:
        print(f"resolved-twelve-manifest: FAIL {e}")
        return 1
    print(f"resolved-twelve-manifest: OK 12 cases, generation {facts['manifest_generation']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
