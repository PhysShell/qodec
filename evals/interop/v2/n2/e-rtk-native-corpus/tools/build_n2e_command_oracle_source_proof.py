#!/usr/bin/env python3
"""Command-oracle SOURCE-IDENTITY + CASE-SCOPE proof (P5.2B; parallel to the test-dialect proof).

Freezes, for a proven rtk_command_oracle, the exact pinned RTK source it was grounded in (commit +
source file + source FUNCTION + content sha256 + git blob sha + bytes), the semantics-module
identity, the single pinned corpus RTK binary, and the CASE-SCOPE binding to the manifest -- proven
for the LISTED cases only, never family-level. Command shapes shared across cases list every case
(e.g. rtk-files-read-oracle-v1 will list preact AND lombok as two independent bindings). This is the
proof that must exist BEFORE a command-oracle case's acceptance vertical binds real streams.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402

MANIFEST = N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"
SRC_DIR = N2E_DIR / "evidence" / "rtk-source"

# oracle policy id -> (semantics module basename, manifest case ids it is proven for -- case-scoped)
ORACLE_PROOFS = {
    "rtk-go-vet-oracle-v1": ("n2e_rtk_go_vet_oracle.py", ["gin-gonic__gin-2755::go::vet"]),
    "rtk-files-read-oracle-v1": ("n2e_rtk_files_read_oracle.py",
                                 ["preactjs__preact-3345::files_search::read",
                                  "projectlombok__lombok-3312::files_search::read"]),
}


def _git_blob_sha1(data: bytes) -> str:
    h = hashlib.sha1(); h.update(b"blob %d\0" % len(data)); h.update(data)
    return h.hexdigest()


def _freeze_source_ref(ref: dict) -> dict:
    """Freeze one pinned RTK source location (content sha256 + git blob sha + bytes)."""
    p = SRC_DIR / Path(ref["source_file"]).name
    if not p.is_file():
        raise SystemExit(f"pinned RTK source not committed: {p}")
    b = p.read_bytes()
    return {"source_file": ref["source_file"], "source_function": ref["source_function"],
            "content_sha256": c.sha256_bytes(b), "git_blob_sha1": _git_blob_sha1(b), "bytes": len(b)}


def build_proof(policy_id: str) -> dict:
    module_name, cases = ORACLE_PROOFS[policy_id]
    module_bytes = (HERE / module_name).read_bytes()
    mod = importlib.import_module(module_name[:-3])
    src_path = SRC_DIR / Path(mod.RTK_SOURCE_FILE).name
    if not src_path.is_file():
        raise SystemExit(f"pinned RTK source not committed: {src_path}")
    src_bytes = src_path.read_bytes()

    man = c.load_record(MANIFEST)
    by_case = {x["case_id"]: x for x in man["cases"]}
    for cid in cases:
        e = by_case.get(cid)
        if e is None:
            raise SystemExit(f"case {cid} not in manifest")
        if e["qualification_kind"] != "rtk_command_oracle" or e["command_semantic_oracle_policy_id"] != policy_id:
            raise SystemExit(f"case {cid} not classified rtk_command_oracle/{policy_id}")

    return c.envelope(
        record_type="n2e-command-oracle-source-proof",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_command_oracle_source_proof.py",
        record_version="v1",
        purpose=f"Source-identity + case-scope proof for {policy_id}. Pins the exact pinned RTK "
                f"source function it was grounded in, the semantics-module identity, the pinned corpus "
                f"RTK binary, and the case-scoped manifest binding. Sets no promotion flag.",
        oracle_policy_id=policy_id,
        oracle_scope="case_scoped",
        proven_case_ids=list(cases),
        rtk_source_identity={
            "commit": mod.RTK_SOURCE_COMMIT, "source_file": mod.RTK_SOURCE_FILE,
            "source_function": mod.RTK_SOURCE_FUNCTION,
            "content_sha256": c.sha256_bytes(src_bytes), "git_blob_sha1": _git_blob_sha1(src_bytes),
            "bytes": len(src_bytes)},
        additional_source_identities=[_freeze_source_ref(r) for r in getattr(mod, "RTK_SOURCE_REFS", [])],
        semantics_module={
            "path": f"tools/{module_name}", "sha256": c.sha256_bytes(module_bytes),
            "bytes": len(module_bytes), "declared_oracle_id": mod.ORACLE_ID},
        pinned_rtk_binary_identity={"sha256": L.DIALECT_RTK_SHA, "bytes": L.DIALECT_RTK_BYTES},
        manifest_binding={"manifest_generation": man["manifest_generation"],
                          "manifest_sha256": c.sha256_json_file(MANIFEST)},
        no_family_level=("this oracle is proven for the listed case ids ONLY; one case does not "
                         "establish family-level go::vet scope"),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", default="rtk-go-vet-oracle-v1", choices=sorted(ORACLE_PROOFS))
    args = ap.parse_args()
    out = N2E_DIR / f"n2e-command-oracle-source-proof-{args.policy}.json"
    c.write_record(out, build_proof(args.policy))
    print(f"wrote {out.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
