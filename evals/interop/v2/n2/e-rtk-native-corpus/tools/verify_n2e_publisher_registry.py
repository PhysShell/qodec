#!/usr/bin/env python3
"""Independent verification of the publisher environment registry AGAINST SOURCE.

Proves, without trusting the committed registry body:
  1. registry self-hash;
  2. harness commit + dataset revision pinned;
  3. every source-bundle file's git blob id + SHA-256 match the bytes on disk;
  4. each recipe RE-EXTRACTED from the pinned source bytes equals the registry
     (toolchain, pre_install, install, test command) -- a mutation to any upstream
     command fails here even if the registry + resolver were changed together;
  5. exact case-id binding: each recipe's case_id is a real scenario and its
     instance/repo/family/subfamily/snapshot_variant/slot all agree with that
     scenario (a recipe can never target a different scenario sharing an instance);
  6. the argv resolver derives exactly the publisher command for each recipe case.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_publisher_registry as pub  # noqa: E402
import n2e_argv_resolver as resolver  # noqa: E402
import n2e_swebench_extract as ex  # noqa: E402

REG = N2E_DIR / "n2e-publisher-env-registry-v1.json"
SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
SELECTION = N2E_DIR / "n2e-selection-result-v1.json"
SRC = N2E_DIR / "fixtures" / "swebench-source"


def _git_blob(p: Path) -> str:
    return subprocess.run(["git", "hash-object", str(p)], capture_output=True, text=True).stdout.strip()


def verify() -> tuple[bool, str]:
    rec = c.load_record(REG)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        return False, f"registry self-hash: {msg}"
    if not rec.get("harness", {}).get("commit") or not rec.get("dataset", {}).get("revision"):
        return False, "harness commit / dataset revision not pinned"
    # (3) source bundle integrity: blob id + sha256 of every file
    for rel, ident in rec["source_bundle"].items():
        p = SRC / rel
        if not p.is_file():
            return False, f"source-bundle file missing: {rel}"
        if _git_blob(p) != ident["git_blob_sha1"]:
            return False, f"source {rel} git blob id mismatch (source mutated)"
        if c.sha256_file(str(p)) != ident["sha256"]:
            return False, f"source {rel} sha256 mismatch"
    scen_by_id = {s["case_id"]: s for s in c.load_record(SCEN)["scenarios"]}
    slot_by_id = {s["case_id"]: s["slot"] for s in c.load_record(SELECTION)["selection"]}
    for r in rec["recipes"]:
        cid = r["case_id"]
        scen = scen_by_id.get(cid)
        if not scen:
            return False, f"recipe case_id {cid} is not a frozen scenario"
        # (4) re-extract from source and require exact agreement
        fresh = ex.extract(SRC, cid)
        if fresh["test_cmd"] != r["test_cmd"] or fresh["install"] != r["install"] \
                or fresh["pre_install"] != r["pre_install"] \
                or fresh["docker_specs"] != r["toolchain"]["docker_specs"]:
            return False, f"{cid}: registry disagrees with fresh source extraction"
        # (5) exact case binding agreement
        sii = scen.get("source_image_identity") or {}
        checks = {
            "instance_id": (r["instance_id"], sii.get("instance_id")),
            "repository": (r["repository"], sii.get("repository")),
            "command_family": (r["command_family"], scen["command_family"]),
            "command_subfamily": (r["command_subfamily"], scen["command_subfamily"]),
            "snapshot_variant": (r["snapshot_variant"], scen.get("snapshot_variant")),
            "slot": (r["slot"], slot_by_id.get(cid)),
        }
        for field, (a, b) in checks.items():
            if a != b:
                return False, f"{cid}: binding {field} disagrees ({a!r} != {b!r})"
        # (6) resolver derives the publisher command for THIS case
        rr = resolver.resolve(scen)
        if rr.get("resolution_rule") != "publisher_recipe":
            return False, f"{cid}: resolver did not select the publisher recipe"
        if rr["effective_raw_argv"] != pub.parse_command(r["test_cmd"][0]):
            return False, f"{cid}: resolver argv disagrees with registry test command"
    return True, f"OK; {rec['recipe_count']} recipes re-extracted from source; harness@{rec['harness']['commit'][:10]}"


def main() -> int:
    ok, msg = verify()
    if not ok:
        print(f"::error::publisher-registry verification FAILED: {msg}", file=sys.stderr)
        return 1
    print(f"publisher-registry: {msg}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
