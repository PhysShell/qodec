#!/usr/bin/env python3
"""Build n2e-candidate-inventory-v1.json (§8) — DETERMINISTIC, OFFLINE, OUTCOME-BLIND.

Enumerates the COMPLETE candidate pool from committed, immutable sources BEFORE
any RTK/QODEC execution. Candidates carry only metadata and RAW-outcome
expectations derived from the datasets themselves (e.g. FAIL_TO_PASS => the buggy
snapshot's target tests fail); they carry NO RTK output, NO token counts, NO
savings of any kind. Selection (§10) consumes this pool.

Families and their ACCEPTED_PRIMARY sources:
  - rust_cargo / go / js_ts / jvm test candidates  -> SWE-bench Multilingual
  - git candidates (dirty states from patches)      -> SWE-bench Multilingual instances
  - files_search (ls/tree/read) candidates          -> SWE-bench Multilingual repo snapshots
  - files_search (grep) + logs candidates           -> Loghub-2.0
  - python (pytest) candidates                       -> BugsInPy
  - containers (docker ps/images/logs) candidates    -> pinned local disposable images

Statistical unit (§5): cluster_id = external source unit (SWE-bench instance_id /
Loghub file / BugsInPy project:bug / container image). Buggy/fixed and per-command
rows share a cluster_id.

Where one source unit maps to several command subfamilies (git, files, docker),
the subfamily is assigned DETERMINISTICALLY from a stable hash of the source id so
the pool spreads across subfamilies without any outcome observation. This keeps
the pool bounded and reproducible while covering every subfamily quota.
"""
from __future__ import annotations

import hashlib
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_repo_languages as rl  # noqa: E402

OUT = N2E_DIR / "n2e-candidate-inventory-v1.json"
INSTANCES = N2E_DIR / "n2e-swebench-instances-v1.json"
BUGSINPY = N2E_DIR / "n2e-bugsinpy-bugs-v1.json"
REGISTRY = N2E_DIR / "n2e-source-registry-v1.json"
PINS = N2E_DIR / "n2e-source-pins-v1.json"

FAMILY_RAW_TEST = {
    "rust_cargo": ["cargo", "test"],
    "go": ["go", "test", "./..."],
    "js_ts": ["npm", "test"],
    "jvm": ["mvn", "test"],
}
# Build/lint subcommands per family (§6.3-§6.6): one is assigned deterministically
# per instance so the pool covers clean-build / diagnostics / warnings diversity.
# Their pass/fail/diagnostic outcome is determined at RAW qualification (still
# blind to RTK), so expected_raw_outcome is "text", not a dataset-derived verdict.
FAMILY_BUILD_LINT = {
    "rust_cargo": {"build": ["cargo", "build"], "check": ["cargo", "check"], "clippy": ["cargo", "clippy"]},
    "go": {"build": ["go", "build", "./..."], "vet": ["go", "vet", "./..."]},
    "js_ts": {"tsc": ["tsc"], "lint": ["eslint", "."]},
}
GIT_SUBFAMILIES = ["status", "diff", "log", "show", "add", "commit", "push"]
FILES_SUBFAMILIES = ["ls", "tree", "read"]
DOCKER_SUBFAMILIES = ["ps", "images", "logs"]
GIT_RAW = {
    "status": ["git", "status"], "diff": ["git", "diff"], "log": ["git", "log"],
    "show": ["git", "show"], "add": ["git", "add", "-A"],
    "commit": ["git", "commit", "-m", "n2e"], "push": ["git", "push", "n2e-local", "HEAD"],
}
FILES_RAW = {"ls": ["ls", "-la"], "tree": ["tree"], "read": ["cat", "README.md"]}


def _pick(key: str, options: list) -> str:
    h = int(hashlib.sha256(key.encode()).hexdigest(), 16)
    return options[h % len(options)]


def loghub_files() -> list[dict]:
    pins = c.load_record(PINS)
    for z in pins["zenodo_records"]:
        if z["source_id"] == "loghub-2.0":
            return z["files"]
    return []


def container_images() -> list[dict]:
    pins = c.load_record(PINS)
    return [o for o in pins["oci_images"] if o["source_id"].startswith("container-")]


def build() -> dict:
    inst = c.load_record(INSTANCES)
    candidates = []
    excluded = []

    for row in inst["instances"]:
        repo = row["repo"]
        family = rl.family_of(repo)
        language = rl.language_of(repo)
        instance_id = row["instance_id"]
        cluster_id = f"swebench:{instance_id}"
        f2p = row["fail_to_pass"]

        # test candidates (only for §6 target test-runner families with a real oracle)
        if family in FAMILY_RAW_TEST:
            if not f2p:
                excluded.append({"instance_id": instance_id, "repo": repo,
                                 "reason": "empty FAIL_TO_PASS — no failing-test identity for the oracle"})
            else:
                for variant, outcome in (("buggy", "fail"), ("fixed", "pass")):
                    candidates.append({
                        "candidate_id": f"{instance_id}::{family}::test::{variant}",
                        "cluster_id": cluster_id, "source_id": "swe-bench-multilingual",
                        "repository": repo, "language": language,
                        "command_family": family, "command_subfamily": "test",
                        "snapshot_variant": variant, "raw_command_argv": FAMILY_RAW_TEST[family],
                        "expected_raw_outcome": outcome, "target_test_ids": f2p,
                        "target_test_count": len(f2p), "base_commit": row["base_commit"],
                        "instance_id": instance_id,
                        "image_recipe": {"kind": "swebench_eval_image_recipe",
                                         "note": "harness-built per instance; digest pinned at acquisition (§5)."},
                        "outcome_blind": True,
                    })

        # build/lint candidate — one deterministically-assigned subcommand per instance
        if family in FAMILY_BUILD_LINT:
            bl = FAMILY_BUILD_LINT[family]
            bl_sub = _pick(f"buildlint:{instance_id}", sorted(bl))
            candidates.append({
                "candidate_id": f"{instance_id}::{family}::{bl_sub}",
                "cluster_id": cluster_id, "source_id": "swe-bench-multilingual",
                "repository": repo, "language": language,
                "command_family": family, "command_subfamily": bl_sub,
                "snapshot_variant": "fixed", "raw_command_argv": bl[bl_sub],
                "expected_raw_outcome": "text", "base_commit": row["base_commit"],
                "instance_id": instance_id,
                "image_recipe": {"kind": "swebench_eval_image_recipe",
                                 "note": "harness-built per instance; digest pinned at acquisition (§5)."},
                "outcome_blind": True,
            })

        # git candidate — one deterministically-assigned subfamily per instance
        git_sub = _pick(f"git:{instance_id}", GIT_SUBFAMILIES)
        candidates.append({
            "candidate_id": f"{instance_id}::git::{git_sub}",
            "cluster_id": cluster_id, "source_id": "swe-bench-multilingual",
            "repository": repo, "language": language,
            "command_family": "git", "command_subfamily": git_sub,
            "snapshot_variant": "dirty" if git_sub in ("status", "diff", "add", "commit") else "clean",
            "raw_command_argv": GIT_RAW[git_sub],
            "expected_raw_outcome": "text", "base_commit": row["base_commit"], "instance_id": instance_id,
            "dirty_state_source": "upstream patch/test_patch applied at base_commit (§6.2)",
            "outcome_blind": True,
        })

        # files_search candidate — ls/tree/read on the repo snapshot
        files_sub = _pick(f"files:{instance_id}", FILES_SUBFAMILIES)
        candidates.append({
            "candidate_id": f"{instance_id}::files_search::{files_sub}",
            "cluster_id": cluster_id, "source_id": "swe-bench-multilingual",
            "repository": repo, "language": language,
            "command_family": "files_search", "command_subfamily": files_sub,
            "snapshot_variant": "snapshot", "raw_command_argv": FILES_RAW[files_sub],
            "expected_raw_outcome": "text", "base_commit": row["base_commit"], "instance_id": instance_id,
            "outcome_blind": True,
        })

    # Loghub logs + grep (files_search)
    for f in loghub_files():
        system = f["key"].removesuffix(".zip")
        cluster_id = f"loghub:{system}"
        zf = {"key": f["key"], "size": f["size"], "checksum": f["checksum"]}
        candidates.append({
            "candidate_id": f"loghub::{system}::log", "cluster_id": cluster_id,
            "source_id": "loghub-2.0", "repository": f"loghub/{system}", "language": "log",
            "command_family": "logs", "command_subfamily": "log", "snapshot_variant": "prepared",
            "raw_command_argv": ["cat", f"{system}.log"], "expected_raw_outcome": "text",
            "zenodo_file": zf, "outcome_blind": True,
        })
        candidates.append({
            "candidate_id": f"loghub::{system}::grep", "cluster_id": cluster_id,
            "source_id": "loghub-2.0", "repository": f"loghub/{system}", "language": "log",
            "command_family": "files_search", "command_subfamily": "grep", "snapshot_variant": "prepared",
            "raw_command_argv": ["grep", "-n", "error", f"{system}.log"], "expected_raw_outcome": "text",
            "zenodo_file": zf, "outcome_blind": True,
        })

    # BugsInPy python pytest candidates
    bip = c.load_record(BUGSINPY)
    for b in bip["bugs"]:
        cluster_id = f"bugsinpy:{b['project']}:{b['bug_id']}"
        for variant, outcome in (("buggy", "fail"), ("fixed", "pass")):
            candidates.append({
                "candidate_id": f"bugsinpy::{b['project']}-{b['bug_id']}::python::pytest::{variant}",
                "cluster_id": cluster_id, "source_id": "bugsinpy",
                "repository": f"bugsinpy/{b['project']}", "language": "python",
                "command_family": "python", "command_subfamily": "pytest", "snapshot_variant": variant,
                "raw_command_argv": ["pytest", b.get("test_file") or "."],
                "expected_raw_outcome": outcome,
                "target_test_ids": [b["run_test_cmd"]] if b.get("run_test_cmd") else [],
                "python_version": b.get("python_version"),
                "buggy_commit": b.get("buggy_commit_id"), "fixed_commit": b.get("fixed_commit_id"),
                "outcome_blind": True,
            })

    # python ruff candidates — one per BugsInPy project (lint diagnostics, §6.4)
    seen_proj = set()
    for b in bip["bugs"]:
        if b["project"] in seen_proj:
            continue
        seen_proj.add(b["project"])
        candidates.append({
            "candidate_id": f"bugsinpy::{b['project']}::python::ruff",
            "cluster_id": f"bugsinpy:{b['project']}", "source_id": "bugsinpy",
            "repository": f"bugsinpy/{b['project']}", "language": "python",
            "command_family": "python", "command_subfamily": "ruff", "snapshot_variant": "fixed",
            "raw_command_argv": ["ruff", "check", "."], "expected_raw_outcome": "text",
            "python_version": b.get("python_version"), "outcome_blind": True,
        })

    # Container candidates (docker ps/images/logs) from pinned local images
    for img in container_images():
        name = img["source_id"].removeprefix("container-")
        cluster_id = f"container:{name}"
        for sub in DOCKER_SUBFAMILIES:
            candidates.append({
                "candidate_id": f"container::{name}::docker::{sub}",
                "cluster_id": cluster_id, "source_id": img["source_id"],
                "repository": img["repository"], "language": "container",
                "command_family": "containers", "command_subfamily": sub, "snapshot_variant": "running",
                "raw_command_argv": ["docker", sub] + ([] if sub != "logs" else [name]),
                "expected_raw_outcome": "text",
                "image_identity": {"repository": img["repository"], "platform": img["platform"],
                                   "index_digest": img["index_digest"], "child_digest": img["child_digest"]},
                "outcome_blind": True,
            })

    candidates.sort(key=lambda x: x["candidate_id"])
    fam_counts = dict(Counter(x["command_family"] for x in candidates))
    repo_counts = dict(Counter(x["repository"] for x in candidates))

    return c.envelope(
        record_type="n2e-candidate-inventory",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_candidate_inventory.py",
        purpose="Complete outcome-blind candidate pool (§8), enumerated before RTK execution.",
        instances_record="n2e-swebench-instances-v1.json",
        instances_sha256=c.sha256_json_file(INSTANCES),
        bugsinpy_record="n2e-bugsinpy-bugs-v1.json",
        bugsinpy_sha256=c.sha256_json_file(BUGSINPY),
        source_registry="n2e-source-registry-v1.json",
        source_registry_sha256=c.sha256_json_file(REGISTRY),
        cluster_unit="external source unit (SWE-bench instance / Loghub file / BugsInPy bug / container image)",
        subfamily_assignment="deterministic sha256(source_id) modulo subfamily list (git/files/docker)",
        excluded_at_enumeration=sorted(excluded, key=lambda e: e["instance_id"]),
        excluded_count=len(excluded),
        candidate_count=len(candidates),
        distinct_clusters=len({x["cluster_id"] for x in candidates}),
        distinct_repositories=len(repo_counts),
        family_candidate_counts=fam_counts,
        candidates=candidates,
    )


def main() -> int:
    c.write_record(OUT, build())
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name} record_sha256={rec['record_sha256']} candidates={rec['candidate_count']} "
          f"clusters={rec['distinct_clusters']} repos={rec['distinct_repositories']}")
    print("family counts:", rec["family_candidate_counts"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
