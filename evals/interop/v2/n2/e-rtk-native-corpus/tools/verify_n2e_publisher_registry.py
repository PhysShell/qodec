#!/usr/bin/env python3
"""Independent verification of the publisher environment registry.

Checks: self-hash; every committed fixture's SHA-256 matches the registry; every
recipe references only present fixtures; each recipe's test/install commands parse
to a non-empty argv; the dataset + harness revisions are pinned; and every recipe
case_id is a real frozen scenario. Also asserts the argv resolver derives the
publisher command for each recipe case (the registry and the resolver agree).
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_publisher_registry as pub  # noqa: E402
import n2e_argv_resolver as resolver  # noqa: E402

REG = N2E_DIR / "n2e-publisher-env-registry-v1.json"
SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
FIX = N2E_DIR / "fixtures" / "swebench"


def verify() -> tuple[bool, str]:
    rec = c.load_record(REG)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        return False, f"registry self-hash: {msg}"
    if not rec.get("harness", {}).get("commit") or not rec.get("dataset", {}).get("revision"):
        return False, "harness commit / dataset revision not pinned"
    # committed fixtures match the declared hashes
    declared = rec["fixture_sha256"]
    for f in sorted(FIX.glob("*")):
        if declared.get(f.name) != c.sha256_file(str(f)):
            return False, f"fixture {f.name} sha256 mismatch vs registry"
    scen_by_id = {s["case_id"]: s for s in c.load_record(SCEN)["scenarios"]}
    for r in rec["recipes"]:
        cid = r["case_id"]
        if cid not in scen_by_id:
            return False, f"recipe case_id {cid} is not a frozen scenario"
        if not r["test_cmd"] or not pub.parse_command(r["test_cmd"][0]):
            return False, f"{cid}: empty/unparseable publisher test command"
        lf = r.get("lockfile")
        if lf and declared.get(lf["fixture"]) != lf["sha256"]:
            return False, f"{cid}: lockfile fixture hash disagrees with registry"
        for pa in r["pre_install"]:
            fx = pa.get("materialize_lockfile") or pa.get("shell_fixture")
            if fx and fx not in declared:
                return False, f"{cid}: pre_install references missing fixture {fx}"
        # resolver must derive exactly this publisher command
        rr = resolver.resolve(scen_by_id[cid])
        if rr.get("resolution_rule") != "publisher_recipe":
            return False, f"{cid}: resolver did not select the publisher recipe"
        if rr["effective_raw_argv"] != pub.parse_command(r["test_cmd"][0]):
            return False, f"{cid}: resolver argv disagrees with registry test command"
    return True, f"OK; {rec['recipe_count']} publisher recipes; harness@{rec['harness']['commit'][:10]}"


def main() -> int:
    ok, msg = verify()
    if not ok:
        print(f"::error::publisher-registry verification FAILED: {msg}", file=sys.stderr)
        return 1
    print(f"publisher-registry: {msg}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
