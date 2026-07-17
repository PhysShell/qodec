#!/usr/bin/env python3
"""Build n2e-candidate-inventory-v1.json (§8) — DETERMINISTIC, OFFLINE, OUTCOME-BLIND.

Enumerates the complete candidate pool from committed, immutable sources BEFORE
any RTK/QODEC execution. Candidates carry only metadata and RAW-outcome
expectations derived from the datasets themselves (e.g. FAIL_TO_PASS => the
buggy snapshot's target tests fail); they carry NO RTK output, NO token counts,
NO savings of any kind. Selection (§10) consumes this pool.

Sources used here (all ACCEPTED_PRIMARY with resolved identities):
  - SWE-bench Multilingual instances (test-runner families: rust_cargo, go,
    js_ts, jvm) via the committed instance manifest;
  - Loghub-2.0 files (logs + files_search) via the committed source pins.

Statistical unit (§5): cluster_id = external source unit. For SWE-bench that is
the instance_id; for Loghub that is the log file. Buggy/fixed and per-command
rows share a cluster_id and are never counted as independent projects.

Families not enumerable from currently ACCEPTED_PRIMARY sources (python via
BugsInPy reserve; containers via Terminal-Bench) are recorded as deferred strata
with a deterministic reason, not silently dropped.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_repo_languages as rl  # noqa: E402

OUT = N2E_DIR / "n2e-candidate-inventory-v1.json"
INSTANCES = N2E_DIR / "n2e-swebench-instances-v1.json"
PINS = N2E_DIR / "n2e-source-pins-v1.json"

# Family -> the RAW test command per language (the underlying real command the
# RAW arm runs; RTK-native equivalent lives in the claim surface / scenarios).
FAMILY_RAW_TEST = {
    "rust_cargo": ["cargo", "test"],
    "go": ["go", "test", "./..."],
    "js_ts": ["npm", "test"],
    "jvm": ["mvn", "test"],
}


def loghub_files() -> list[dict]:
    pins = c.load_record(PINS)
    for z in pins["zenodo_records"]:
        if z["source_id"] == "loghub-2.0":
            return z["files"]
    return []


def build() -> dict:
    inst = c.load_record(INSTANCES)
    candidates = []
    excluded = []

    # --- SWE-bench Multilingual test-runner candidates ---
    for row in inst["instances"]:
        repo = row["repo"]
        family = rl.family_of(repo)
        language = rl.language_of(repo)
        if family not in FAMILY_RAW_TEST:
            continue  # outside §6 target matrix (recorded via deferred_strata note)
        f2p = row["fail_to_pass"]
        if not f2p:
            # A test candidate with no failing-test identity cannot satisfy the
            # semantic oracle (§14: a failing test identity may not be omitted).
            excluded.append({"instance_id": row["instance_id"], "repo": repo,
                             "reason": "empty FAIL_TO_PASS — no failing-test identity for the oracle"})
            continue
        cluster_id = f"swebench:{row['instance_id']}"
        # Two snapshot variants per instance: buggy (target tests FAIL) and fixed
        # (target tests PASS). Outcomes are dataset-derived, not RTK-observed.
        for variant, outcome in (("buggy", "fail"), ("fixed", "pass")):
            candidates.append({
                "candidate_id": f"{row['instance_id']}::{family}::test::{variant}",
                "cluster_id": cluster_id,
                "source_id": "swe-bench-multilingual",
                "repository": repo,
                "language": language,
                "command_family": family,
                "command_subfamily": "test",
                "snapshot_variant": variant,
                "raw_command_argv": FAMILY_RAW_TEST[family],
                "expected_raw_outcome": outcome,
                "target_test_ids": f2p,
                "target_test_count": len(f2p),
                "base_commit": row["base_commit"],
                "instance_id": row["instance_id"],
                "image_recipe": {
                    "kind": "swebench_eval_image",
                    "repository_pattern": "docker.io/swebench/sweb.eval.x86_64.<instance>",
                    "note": "exact per-instance image digest resolved+pinned at selection/acquisition (§5).",
                },
                "outcome_blind": True,
            })

    # --- Loghub-2.0 log + files_search candidates ---
    for f in loghub_files():
        system = f["key"].removesuffix(".zip")
        cluster_id = f"loghub:{system}"
        candidates.append({
            "candidate_id": f"loghub::{system}::log",
            "cluster_id": cluster_id,
            "source_id": "loghub-2.0",
            "repository": f"loghub/{system}",
            "language": "log",
            "command_family": "logs",
            "command_subfamily": "log",
            "snapshot_variant": "prepared",
            "raw_command_argv": ["cat", f"{system}.log"],
            "expected_raw_outcome": "text",
            "zenodo_file": {"key": f["key"], "size": f["size"], "checksum": f["checksum"]},
            "outcome_blind": True,
        })
        candidates.append({
            "candidate_id": f"loghub::{system}::grep",
            "cluster_id": cluster_id,
            "source_id": "loghub-2.0",
            "repository": f"loghub/{system}",
            "language": "log",
            "command_family": "files_search",
            "command_subfamily": "grep",
            "snapshot_variant": "prepared",
            "raw_command_argv": ["grep", "-n", "error", f"{system}.log"],
            "expected_raw_outcome": "text",
            "zenodo_file": {"key": f["key"], "size": f["size"], "checksum": f["checksum"]},
            "outcome_blind": True,
        })

    candidates.sort(key=lambda x: x["candidate_id"])

    # Family coverage summary + deferred strata (deterministic reasons).
    from collections import Counter
    fam_counts = dict(Counter(c_["command_family"] for c_ in candidates))
    repo_counts = dict(Counter(c_["repository"] for c_ in candidates))

    deferred_strata = [
        {"command_family": "python", "reason": "SWE-bench Multilingual contains no Python; sourced from BugsInPy reserve (§2.4), enumeration pending."},
        {"command_family": "containers", "reason": "no ACCEPTED_PRIMARY source supplies local disposable containers; Terminal-Bench enumeration required (§2.6)."},
        {"command_family": "git", "reason": "git dirty-state candidates derive from SWE-bench patches/test-patches; enumerated in the scenario phase to keep cluster_id tied to the source instance (§6.2)."},
    ]

    return c.envelope(
        record_type="n2e-candidate-inventory",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_candidate_inventory.py",
        purpose="Complete outcome-blind candidate pool (§8), enumerated before RTK execution.",
        instances_record="n2e-swebench-instances-v1.json",
        instances_sha256=c.sha256_json_file(INSTANCES),
        source_registry="n2e-source-registry-v1.json",
        source_registry_sha256=c.sha256_json_file(N2E_DIR / "n2e-source-registry-v1.json"),
        cluster_unit="external source unit (SWE-bench instance_id / Loghub file)",
        excluded_at_enumeration=sorted(excluded, key=lambda e: e["instance_id"]),
        excluded_count=len(excluded),
        candidate_count=len(candidates),
        distinct_clusters=len({c_["cluster_id"] for c_ in candidates}),
        distinct_repositories=len(repo_counts),
        family_candidate_counts=fam_counts,
        deferred_strata=deferred_strata,
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
