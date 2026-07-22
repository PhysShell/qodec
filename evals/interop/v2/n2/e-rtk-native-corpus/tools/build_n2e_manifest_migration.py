#!/usr/bin/env python3
"""One-time gen-2 -> gen-3 manifest binding migration bridge.

The gen-3 manifest introduces per-case binding (case_entry_sha256). The seven already-frozen
qualification PASS records were bound to the WHOLE gen-2 manifest SHA and MUST stay byte-identical
(frozen means frozen). This bridge is the ONLY thing that lets the aggregator carry those legacy
records forward under the gen-3 root, WITHOUT editing them:

  legacy gen-2 record  +  this exact bridge  +  unchanged gen-3 case entry  ->  acceptable

It is strictly ONE-DIRECTIONAL: it authorizes a gen-2 record under gen-3; it NEVER reinterprets a
gen-3 record as gen-2, and it is not a permanent universal compatibility layer -- it pins the two
exact manifest+contract digests and dies the moment either side drifts.

What it proves + freezes (fail-closed):
  * the exact gen-2 and gen-3 manifest + base-contract SHA-256 digests;
  * for every case: gen-2 canonical case projection SHA vs gen-3 stored case_entry_sha256;
  * carried_forward = (gen2_projection == gen3_case_entry_sha256), i.e. the case's determinants are
    byte-identical across the generations;
  * EXACTLY ONE declared changed case (Lucene), which MUST be the only non-carried case;
  * every other case (all eleven) carried_forward -- any unexpected diff is a hard failure.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_manifest_binding as mb  # noqa: E402

GEN2_MANIFEST = N2E_DIR / "n2e-resolved-twelve-manifest-gen2-frozen-v1.json"
GEN2_CONTRACT = N2E_DIR / "n2e-canary-execution-contract-gen2-frozen-v1.json"
GEN3_MANIFEST = N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"
GEN3_CONTRACT = N2E_DIR / "n2e-canary-execution-contract-v1.json"
OVERLAY = N2E_DIR / "n2e-resolved-execution-contract-v1.json"      # unchanged across the migration
OUT = N2E_DIR / "n2e-manifest-gen2-to-gen3-binding-migration-v1.json"

DECLARED_CHANGED_CASE = "apache__lucene-13704::jvm::test::buggy"


def _proj_sha(man_entry: dict, contract: dict, overlay: dict) -> str:
    cid = man_entry["case_id"]
    ce = mb.contract_entry_for(cid, contract)
    oe = mb.overlay_entry_for(cid, overlay)
    return mb._sha(mb.case_entry_projection(man_entry, ce, oe))


def build() -> dict:
    g2m = {e["case_id"]: e for e in c.load_record(GEN2_MANIFEST)["cases"]}
    g3m = {e["case_id"]: e for e in c.load_record(GEN3_MANIFEST)["cases"]}
    g2c = c.load_record(GEN2_CONTRACT)
    g3c = c.load_record(GEN3_CONTRACT)
    ov = c.load_record(OVERLAY)

    if set(g2m) != set(g3m) or len(g3m) != 12:
        raise SystemExit("gen-2/gen-3 manifests must carry the same twelve case ids")

    carry = []
    for cid in sorted(g3m):
        gen2_proj = _proj_sha(g2m[cid], g2c, ov)
        gen3_entry = g3m[cid].get("case_entry_sha256")
        if gen3_entry is None:
            raise SystemExit(f"gen-3 manifest entry {cid} is missing case_entry_sha256")
        # independent re-derivation of the gen-3 entry from the gen-3 sources (the manifest must not be
        # trusted to have stored a case_entry_sha256 that its own inputs do not produce)
        gen3_recomputed = _proj_sha(g3m[cid], g3c, ov)
        if gen3_recomputed != gen3_entry:
            raise SystemExit(f"gen-3 manifest case_entry_sha256 for {cid} != its own re-derivation")
        carry.append({"case_id": cid, "gen2_projection_sha256": gen2_proj,
                      "gen3_case_entry_sha256": gen3_entry,
                      "carried_forward": gen2_proj == gen3_entry})

    not_carried = [x["case_id"] for x in carry if not x["carried_forward"]]
    if not_carried != [DECLARED_CHANGED_CASE]:
        raise SystemExit(f"REFUSING: exactly one declared change ({DECLARED_CHANGED_CASE}) allowed; "
                         f"non-carried set is {not_carried}")

    return c.envelope(
        record_type="n2e-manifest-gen2-to-gen3-binding-migration",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_manifest_migration.py",
        record_version="v1",
        purpose="One-directional gen-2 -> gen-3 binding bridge: authorizes the seven frozen (byte-"
                "identical) legacy PASS records under the gen-3 per-case-binding root by proving each "
                "case's determinant projection carried forward. Not a permanent compatibility layer.",
        direction="gen2->gen3 (a gen-3 record is never reinterpreted as gen-2)",
        gen2={"manifest_sha256": c.sha256_json_file(GEN2_MANIFEST),
              "base_execution_contract_sha256": c.sha256_json_file(GEN2_CONTRACT),
              "manifest_generation": 2},
        gen3={"manifest_sha256": c.sha256_json_file(GEN3_MANIFEST),
              "base_execution_contract_sha256": c.sha256_json_file(GEN3_CONTRACT),
              "manifest_generation": 3},
        declared_changed_case=DECLARED_CHANGED_CASE,
        overlay_execution_contract_sha256=c.sha256_json_file(OVERLAY),
        case_carry_forward=carry,
        carried_forward_case_ids=[x["case_id"] for x in carry if x["carried_forward"]],
        invariant="exactly one declared changed case; all eleven others carried_forward; any other "
                  "diff is fail-closed",
    )


def main() -> int:
    c.write_record(OUT, build())
    print(f"wrote {OUT.name}: 11 carried_forward + 1 declared change ({DECLARED_CHANGED_CASE})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
