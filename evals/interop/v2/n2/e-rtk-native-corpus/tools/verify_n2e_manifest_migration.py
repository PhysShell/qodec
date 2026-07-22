#!/usr/bin/env python3
"""Independent verifier for the gen-2 -> gen-3 binding migration bridge. Fail-closed: re-derives every
attestation from the committed frozen gen-2 + current gen-3 artifacts and rejects any disagreement.

Checks:
  * bridge self-hash valid; record_type + one-directional direction;
  * pinned gen-2 manifest/contract SHAs match the frozen gen-2 audit copies;
  * pinned gen-3 manifest/contract SHAs match the CURRENT gen-3 artifacts;
  * for every case: independently recompute the gen-2 projection SHA + the gen-3 case_entry_sha256 and
    confirm the bridge stored exactly those, and that carried_forward == (gen2 == gen3);
  * exactly ONE non-carried case, and it is the declared_changed_case (Lucene);
  * carried_forward_case_ids is exactly the eleven carried cases.
Any tampering (declaring Lucene unchanged, hiding another case's determinant change, a wrong stored
digest) is caught here.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_manifest_binding as mb  # noqa: E402
import build_n2e_manifest_migration as B  # noqa: E402


class MigrationBridgeError(Exception):
    pass


def _proj_sha(man_entry, contract, overlay):
    cid = man_entry["case_id"]
    return mb._sha(mb.case_entry_projection(man_entry, mb.contract_entry_for(cid, contract),
                                            mb.overlay_entry_for(cid, overlay)))


def verify(rec: dict) -> dict:
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        raise MigrationBridgeError(f"self-hash: {msg}")
    if rec.get("record_type") != "n2e-manifest-gen2-to-gen3-binding-migration":
        raise MigrationBridgeError("wrong record_type")
    if not str(rec.get("direction", "")).startswith("gen2->gen3"):
        raise MigrationBridgeError("bridge is not one-directional gen2->gen3")

    g2 = rec.get("gen2") or {}
    g3 = rec.get("gen3") or {}
    if g2.get("manifest_sha256") != c.sha256_json_file(B.GEN2_MANIFEST):
        raise MigrationBridgeError("gen2 manifest sha != frozen gen-2 audit copy")
    if g2.get("base_execution_contract_sha256") != c.sha256_json_file(B.GEN2_CONTRACT):
        raise MigrationBridgeError("gen2 contract sha != frozen gen-2 audit copy")
    if g3.get("manifest_sha256") != c.sha256_json_file(B.GEN3_MANIFEST):
        raise MigrationBridgeError("gen3 manifest sha != current manifest")
    if g3.get("base_execution_contract_sha256") != c.sha256_json_file(B.GEN3_CONTRACT):
        raise MigrationBridgeError("gen3 contract sha != current contract")

    g2m = {e["case_id"]: e for e in c.load_record(B.GEN2_MANIFEST)["cases"]}
    g3m = {e["case_id"]: e for e in c.load_record(B.GEN3_MANIFEST)["cases"]}
    g2c, g3c, ov = c.load_record(B.GEN2_CONTRACT), c.load_record(B.GEN3_CONTRACT), c.load_record(B.OVERLAY)

    carry = {x["case_id"]: x for x in rec.get("case_carry_forward") or []}
    if set(carry) != set(g3m) or len(g3m) != 12:
        raise MigrationBridgeError("case_carry_forward must cover exactly the twelve cases")
    non_carried = []
    for cid in g3m:
        want_g2 = _proj_sha(g2m[cid], g2c, ov)
        want_g3 = _proj_sha(g3m[cid], g3c, ov)
        x = carry[cid]
        if x.get("gen2_projection_sha256") != want_g2:
            raise MigrationBridgeError(f"{cid}: stored gen2 projection sha != re-derivation")
        if x.get("gen3_case_entry_sha256") != want_g3:
            raise MigrationBridgeError(f"{cid}: stored gen3 case_entry_sha256 != re-derivation")
        if g3m[cid].get("case_entry_sha256") != want_g3:
            raise MigrationBridgeError(f"{cid}: gen-3 manifest case_entry_sha256 != re-derivation")
        carried_re = (want_g2 == want_g3)
        if bool(x.get("carried_forward")) != carried_re:
            raise MigrationBridgeError(f"{cid}: declared carried_forward != re-derived")
        if not carried_re:
            non_carried.append(cid)

    if non_carried != [rec.get("declared_changed_case")]:
        raise MigrationBridgeError(f"exactly one declared change required; non-carried={non_carried} "
                                   f"declared={rec.get('declared_changed_case')}")
    expected_carried = sorted(cid for cid in g3m if cid not in non_carried)
    if sorted(rec.get("carried_forward_case_ids") or []) != expected_carried:
        raise MigrationBridgeError("carried_forward_case_ids != the eleven carried cases")
    return {"declared_changed_case": non_carried[0], "carried_forward": len(expected_carried)}


def main() -> int:
    path = N2E_DIR / "n2e-manifest-gen2-to-gen3-binding-migration-v1.json"
    try:
        f = verify(c.load_record(path))
    except MigrationBridgeError as e:
        print(f"migration-bridge: FAIL {e}")
        return 1
    print(f"migration-bridge: OK {f['carried_forward']} carried; changed {f['declared_changed_case']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
