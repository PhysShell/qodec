#!/usr/bin/env python3
"""Builds MIGRATION_PROVENANCE.json, the self-hash-locked provenance record
for QODEC's extraction from PhysShell/007 into this standalone repository.

Every identity value below (PR numbers/branches/head SHAs, filtered-history
tip, commit count, commit-map hashes) was resolved directly from the GitHub
API and this repository's own git history at migration time -- never copied
from a prompt or guessed. The source is NOT a merge commit: PR #54, #55, #56
in PhysShell/007 are all intentionally unmerged (DO NOT MERGE, by that
repository's own scope-PR research process) -- the authoritative source is
the verified tip of that stacked branch chain, with ancestry independently
confirmed via `git merge-base --is-ancestor` before any filtering began.

References Commit A (the standalone content commit), not this file's own
commit -- a record cannot embed the hash of the commit that contains it.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

OUT_PATH = Path(__file__).resolve().parents[1] / "MIGRATION_PROVENANCE.json"

SOURCE_REPOSITORY = "PhysShell/007"
TARGET_REPOSITORY = "PhysShell/qodec"

SOURCE_PULL_REQUEST_CHAIN = [
    {
        "number": 54,
        "url": "https://github.com/PhysShell/007/pull/54",
        "head_branch": "claude/qodec-benchmark-v2-source-freeze-n2c",
        "head_sha": "acb57379e2d0b9ed6fe79fd45e7540d7d00d7490",
        "base_branch": "main",
        "merged": False,
        "historical_directive": "DO NOT MERGE",
    },
    {
        "number": 55,
        "url": "https://github.com/PhysShell/007/pull/55",
        "head_branch": "claude/n2d0-durable-evidence-rescue",
        "head_sha": "4e40b6f393cbdaf1bfcc36b8c422f7e17ae41dee",
        "base_branch": "claude/qodec-benchmark-v2-source-freeze-n2c",
        "merged": False,
        "historical_directive": "DO NOT MERGE",
    },
    {
        "number": 56,
        "url": "https://github.com/PhysShell/007/pull/56",
        "head_branch": "claude/qodec-benchmark-v2-n2d-identity-lock",
        "head_sha": "662adf6ea6ba7438f1a31e9faf95554b4b14eedf",
        "base_branch": "claude/n2d0-durable-evidence-rescue",
        "merged": False,
        "historical_directive": "DO NOT MERGE",
    },
]

AUTHORITATIVE_SOURCE_PR = 56
AUTHORITATIVE_SOURCE_HEAD_SHA = "662adf6ea6ba7438f1a31e9faf95554b4b14eedf"

FILTERED_HISTORY_TIP_BEFORE_ADAPTATION = "38d98a0df50b3bcfd45bc3af885aad9e2b885a33"
FILTERED_COMMIT_COUNT = 189

MIGRATION_CONTENT_COMMIT_SHA = "78ee9380fe4b7c2f741f48e1f964be050a5c4f58"

COMMIT_MAP_PATH = "docs/migration/007-commit-map.tsv"
COMMIT_MAP_SHA256 = "c37535363dc00576279a7843e87b4ae5fb27e69d41aef80070349da19ac426b6"
REF_MAP_PATH = "docs/migration/007-ref-map.tsv"
REF_MAP_SHA256 = "278778792f21644565deba5675bc79ba6a29b533c22ffc48641aa90e5448858d"

INCLUDED_PATHS = [
    "qodec/ (whole subtree, renamed to repository root)",
    ".github/workflows/qodec*.yml",
    ".github/workflows/qodec*.yaml",
    "flake.nix",
    "flake.lock",
    "rust-toolchain.toml",
    ".gitignore",
    ".editorconfig (glob matched nothing at the source commit)",
    "LICENSE* (glob matched nothing at the source commit)",
    "NOTICE* (glob matched nothing at the source commit)",
]

EXCLUDED_COMPONENTS = [
    "o7 application source",
    "o7 invoke",
    "Codex CLI integration",
    "Demand Radar source",
    "unrelated 007 experiments",
]

INCLUDED_WORKFLOWS = [
    "qodec-n2-miner-canary.yml",
    "qodec-n2-miner-framework.yml",
    "qodec-n2-source-freeze.yml",
    "qodec-n2d0-durable-evidence-rescue.yml",
    "qodec-n2d1b-miner-pilot.yml",
    "qodec-v2.yml",
    "qodec-v2-corpus.yml",
    "qodec-v2-public-log-pilot.yml",
]

LEGACY_RELEASE_REPOSITORY = "PhysShell/007"
LEGACY_RELEASE_TAG = "n2d0-durable-evidence-v1"


def _compact_canonical_bytes(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_record() -> dict:
    body = {
        "schema_version": 1,
        "record_type": "qodec-repository-migration-v1",
        "source_repository": SOURCE_REPOSITORY,
        "source_mode": "stacked_unmerged_pr_tip",
        "source_pull_request_chain": SOURCE_PULL_REQUEST_CHAIN,
        "authoritative_source_pr": AUTHORITATIVE_SOURCE_PR,
        "authoritative_source_head_sha": AUTHORITATIVE_SOURCE_HEAD_SHA,
        "stack_ancestry_verified": True,
        "target_repository": TARGET_REPOSITORY,
        "history_transform": "git-filter-repo",
        "filtered_history_tip_before_adaptation": FILTERED_HISTORY_TIP_BEFORE_ADAPTATION,
        "filtered_commit_count": FILTERED_COMMIT_COUNT,
        "migration_content_commit_sha": MIGRATION_CONTENT_COMMIT_SHA,
        "path_rename": "qodec/ -> repository root",
        "included_paths": INCLUDED_PATHS,
        "excluded_components": EXCLUDED_COMPONENTS,
        "included_workflows": INCLUDED_WORKFLOWS,
        "commit_map_path": COMMIT_MAP_PATH,
        "commit_map_sha256": COMMIT_MAP_SHA256,
        "ref_map_path": REF_MAP_PATH,
        "ref_map_sha256": REF_MAP_SHA256,
        "legacy_prs_remain_external": True,
        "legacy_release_repository": LEGACY_RELEASE_REPOSITORY,
        "legacy_release_tag": LEGACY_RELEASE_TAG,
        "legacy_assets_remain_external": True,
        "old_evidence_paths_preserved": True,
        "record_sha256": None,
    }
    digest = hashlib.sha256(_compact_canonical_bytes(body)).hexdigest()
    body["record_sha256"] = f"sha256:{digest}"
    return body


def main() -> int:
    body = build_record()
    without_hash = dict(body)
    without_hash["record_sha256"] = None
    recomputed = f"sha256:{hashlib.sha256(_compact_canonical_bytes(without_hash)).hexdigest()}"
    assert recomputed == body["record_sha256"], "self-hash did not verify stable"
    OUT_PATH.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT_PATH} (record_sha256={body['record_sha256']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
