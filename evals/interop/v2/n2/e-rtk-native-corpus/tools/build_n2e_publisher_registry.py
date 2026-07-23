#!/usr/bin/env python3
"""Build the self-hash-locked publisher environment registry FROM PINNED SOURCE.

Every recipe field (toolchain, pre-install, install/warm, test command) is
extracted MECHANICALLY from the exact upstream harness source bytes committed under
fixtures/swebench-source/ (SWE-bench/SWE-bench @ the pinned commit) -- there is no
hand-transcribed command table. Each source file's git blob id + SHA-256 are
recorded, so a mutation to any upstream command changes both the extracted recipe
and the source hash and the verifier rejects it.

Recipes bind by EXACT case_id (never merely by SWE-bench instance): the binding
metadata (instance, repo, family, subfamily, snapshot variant, selection slot) is
carried so a recipe can never be applied to a different scenario that happens to
share the same instance.
"""
from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_swebench_extract as ex  # noqa: E402
import n2e_publisher_registry as pub  # noqa: E402
split_env = pub.split_env

OUT = N2E_DIR / "n2e-publisher-env-registry-v1.json"
SRC = N2E_DIR / "fixtures" / "swebench-source"
CANARY = N2E_DIR / "n2e-canary-membership-v1.json"
SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
SELECTION = N2E_DIR / "n2e-selection-result-v1.json"
INVENTORY = N2E_DIR / "n2e-candidate-inventory-v1.json"
RESERVES = N2E_DIR / "n2e-reserve-list-v1.json"

HARNESS = {
    "repo": "SWE-bench/SWE-bench",
    "commit": "f7bbbb2ccdf479001d6467c9e34af59e44a840f9",
    "constants_module": "swebench/harness/constants",
    "source_dir": "fixtures/swebench-source",
    "upstream_prefix": "swebench/harness/constants",
    # durable commit/path/blob proof: a minimal git bundle of the pinned commit,
    # so the offline verifier can prove each committed source file IS the exact blob
    # at that path in that upstream commit (not merely locally self-consistent).
    "git_bundle": "swebench-f7bbbb2.bundle",
}


def _upstream_path(rel: str) -> str:
    return f"{HARNESS['upstream_prefix']}/{rel}"
DATASET = {"id": "SWE-bench/SWE-bench_Multilingual",
           "revision": "2b7aced941b4873e9cad3e76abbae93f481d1beb"}

# docker_specs version key -> (toolchain kind, extra fields)
_TC_KIND = {"go_version": "go", "rust_version": "rust",
            "node_version": "node", "java_version": "java"}


def _git_blob(p: Path) -> str:
    return subprocess.run(["git", "hash-object", str(p)], capture_output=True, text=True).stdout.strip()


def _toolchain(docker: dict) -> dict:
    tc = {}
    for k, v in docker.items():
        if k in _TC_KIND:
            tc = {"kind": _TC_KIND[k], "version": str(v)}
    if tc.get("kind") == "node":
        tc["package_manager"] = "pnpm" if docker.get("_variant") == "js_2" else "npm"
    if tc.get("kind") == "java":
        tc["build"] = "gradle_wrapper"
    tc["docker_specs"] = docker
    return tc


def _source_bundle() -> dict:
    files = {}
    for f in sorted(SRC.rglob("*")):
        if f.is_file() or f.name.endswith(".bundle"):
            rel = str(f.relative_to(SRC))
            ent = {"git_blob_sha1": _git_blob(f), "sha256": c.sha256_file(str(f)),
                   "bytes": f.stat().st_size}
            if not rel.endswith(".bundle"):
                ent["upstream_path"] = _upstream_path(rel)  # path at the pinned commit
            files[rel] = ent
    return files


def _binding_meta(cid, scen_by_id, slot_by_id, inv, reserve_slot) -> dict:
    """Binding metadata for a recipe. Canary members come from the frozen scenario +
    selection; a resolved reserve replacement (not in the frozen scenarios) comes from
    the frozen candidate inventory + reserve-list slot -- never from parsing case_id."""
    if cid in scen_by_id:
        scen = scen_by_id[cid]
        return {"instance_id": scen["source_image_identity"]["instance_id"],
                "repository": scen["source_image_identity"]["repository"],
                "command_family": scen["command_family"],
                "command_subfamily": scen["command_subfamily"],
                "snapshot_variant": scen.get("snapshot_variant"),
                "slot": slot_by_id.get(cid)}
    m = inv[cid]
    return {"instance_id": m["instance_id"], "repository": m["repository"],
            "command_family": m["command_family"], "command_subfamily": m["command_subfamily"],
            "snapshot_variant": m.get("snapshot_variant"), "slot": reserve_slot.get(cid)}


def build() -> dict:
    scen_by_id = {s["case_id"]: s for s in c.load_record(SCEN)["scenarios"]}
    slot_by_id = {s["case_id"]: s["slot"] for s in c.load_record(SELECTION)["selection"]}
    inv = {x["candidate_id"]: x for x in c.load_record(INVENTORY)["candidates"]}
    reserve_slot = {cid: r["slot"] for r in c.load_record(RESERVES)["reserves"]
                    for cid in r["reserve_case_ids"]}
    bundle = _source_bundle()
    recipes = []
    for cid in ex.all_case_ids():
        r = ex.extract(SRC, cid)
        bm = _binding_meta(cid, scen_by_id, slot_by_id, inv, reserve_slot)
        tc = _toolchain(r["docker_specs"])
        warm_env, _ = split_env(r["install"][0]) if r["install"] else ({}, [])
        test_env, test_argv = split_env(r["test_cmd"][0])
        recipes.append({
            "case_id": cid,
            "instance_id": bm["instance_id"],
            "repository": bm["repository"],
            "command_family": bm["command_family"],
            "command_subfamily": bm["command_subfamily"],
            "snapshot_variant": bm["snapshot_variant"],
            "slot": bm["slot"],
            "language": {"go": "go", "rust": "rust_cargo", "node": "js_ts", "java": "jvm"}[tc["kind"]],
            "source": {"file": r["source_file"], "spec_dict": r["spec_dict"], "spec_key": r["spec_key"],
                       "git_blob_sha1": bundle[r["source_file"]]["git_blob_sha1"],
                       "sha256": bundle[r["source_file"]]["sha256"]},
            "toolchain": tc,
            "pre_install": r["pre_install"],           # exact shell (heredoc lockfile / sed), from source
            "install": r["install"],                   # publisher warm/compile, from source
            "install_env": warm_env,
            "test_cmd": r["test_cmd"],                 # publisher measurement, from source
            "test_argv": test_argv,
            "test_env": test_env,
            "oracle_policy_id": "n2e-oracle-test-v1",
        })
    return c.envelope(
        record_type="n2e-publisher-env-registry",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_publisher_registry.py",
        purpose="Self-hash-locked publisher environment registry, extracted MECHANICALLY from the "
                "pinned SWE-bench harness source bytes (fixtures/swebench-source). Recipes bind by "
                "exact case_id and carry binding metadata + source blob identities.",
        harness=HARNESS,
        dataset=DATASET,
        source_bundle=bundle,
        recipe_count=len(recipes),
        recipes=recipes,
    )


def main() -> int:
    c.write_record(OUT, build())
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name}: {rec['recipe_count']} recipes from {len(rec['source_bundle'])} pinned source files")
    for r in rec["recipes"]:
        print(f"  {r['case_id'].split('::')[0]:24} {r['toolchain']['kind']}{r['toolchain']['version']:>7} "
              f"| test: {' '.join(r['test_argv'])[:60]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
