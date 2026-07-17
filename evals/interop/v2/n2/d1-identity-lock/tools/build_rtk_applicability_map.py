#!/usr/bin/env python3
"""Builds the self-hash-locked RTK applicability map for the 18-case N2-D set.

Selection policy (n2d1-contract.json section_3_rtk_identity, updated by
this record's own bounded determinism probes):

1. `--filter grep` only if the raw input is genuinely ripgrep/grep-match
   shaped (already verified deterministic by the N1 pilot; none of the 18
   N2-D cases are this shape).
2. `--filter log` is PROHIBITED unconditionally (N1 pilot proved 5 distinct
   outputs across 20 runs over identical input; never re-probed here,
   never used regardless of shape fit).
3. `--filter git-diff` -- newly verified deterministic by this record's own
   bounded probe (evidence/rtk-git-diff-determinism-probe-report.json,
   20/20 identical runs over corpus/git-diff.txt). Usable for any N2-D
   case whose raw input is genuinely git-diff-shaped; none of the 18
   currently are, so it is verified-available but unused.
4. `--filter cargo-test` -- newly verified deterministic by this record's
   own bounded probe (evidence/rtk-cargo-test-determinism-probe-report.json,
   20/20 identical runs over evals/interop/v2/smoke/fixtures/test-runner.txt).
   Usable for any N2-D case whose raw input is genuine `cargo test` output.
   repo-rustlings and repo-dockerfile-parser-rs both have frozen_argv
   ["cargo","test"] (per stage2-full-matrix-acceptance.json) -- their raw
   captured input IS real cargo-test output, so this filter now applies to
   both.
5. Default for every other case: `--filter passthrough` (deterministic by
   construction).

Nothing here is decided by content-shape guesswork: filter selection for
every case is driven strictly by that case's own frozen, already-committed
execution argv (stage2-full-matrix-acceptance.json / durable-input-
manifest.json), never by inspecting or reformatting the case's raw bytes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

IDENTITY_LOCK_DIR = Path(__file__).resolve().parents[1]
OUT_PATH = IDENTITY_LOCK_DIR / "rtk-applicability-map-v1.json"
GIT_DIFF_PROBE_PATH = IDENTITY_LOCK_DIR / "evidence" / "rtk-git-diff-determinism-probe-report.json"
CARGO_TEST_PROBE_PATH = IDENTITY_LOCK_DIR / "evidence" / "rtk-cargo-test-determinism-probe-report.json"
STAGE2_RECORD_PATH = IDENTITY_LOCK_DIR / "stage2-full-matrix-acceptance.json"

ALL_18_CASE_IDS = [
    "n2a-miner-canary",
    "bot-dependabot-black-5206", "bot-syzbot-do-mkdirat", "ci-log-jansson",
    "ci-log-nlog", "ci-log-spdlog", "dataset-loghub-v8",
    "dataset-rtn-traffic-ids", "research-corpus-loghub2",
    "repo-docker-java-parser", "repo-dockerfile-parser-rs", "repo-helm-values",
    "repo-hyperfine", "repo-kubeops-generator", "repo-moshi", "repo-pyflakes",
    "repo-requests", "repo-rustlings",
]

# Cases whose frozen execution argv is genuinely `cargo test` (per
# stage2-full-matrix-acceptance.json's own committed cases map) -- the
# ONLY basis for applying the newly-verified cargo-test filter.
CARGO_TEST_SHAPED_CASE_IDS = {"repo-rustlings", "repo-dockerfile-parser-rs"}

PROHIBITED_FILTERS = ["log"]


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_record() -> dict:
    git_diff_probe = json.loads(GIT_DIFF_PROBE_PATH.read_text())
    cargo_test_probe = json.loads(CARGO_TEST_PROBE_PATH.read_text())
    stage2_record = json.loads(STAGE2_RECORD_PATH.read_text())

    if not git_diff_probe["deterministic"]:
        raise RuntimeError("git-diff probe did not confirm determinism -- refusing to authorize the filter")
    if not cargo_test_probe["deterministic"]:
        raise RuntimeError("cargo-test probe did not confirm determinism -- refusing to authorize the filter")
    if git_diff_probe["repeats"] < 20 or cargo_test_probe["repeats"] < 20:
        raise RuntimeError("bounded probes must run at least 20 repetitions each")

    for case_id in CARGO_TEST_SHAPED_CASE_IDS:
        frozen_argv = stage2_record["cases"][case_id]["frozen_argv"]
        if frozen_argv != ["cargo", "test"]:
            raise RuntimeError(
                f"{case_id} was assumed cargo-test-shaped but its frozen_argv is {frozen_argv!r}, not ['cargo','test']"
            )

    per_case = {}
    for case_id in ALL_18_CASE_IDS:
        if case_id in CARGO_TEST_SHAPED_CASE_IDS:
            per_case[case_id] = {
                "rtk_argv": ["pipe", "--filter", "cargo-test"],
                "rationale": (
                    "frozen execution argv is ['cargo','test'] (stage2-full-matrix-acceptance.json); "
                    "raw captured input is genuine cargo-test output; filter newly verified deterministic "
                    "by this record's own bounded 20-repetition probe"
                ),
            }
        else:
            per_case[case_id] = {
                "rtk_argv": ["pipe", "--passthrough"],
                "rationale": (
                    "not grep-shaped (no case is), not verified-deterministic-git-diff-shaped "
                    "(no case's raw input is a git diff), and --filter log is unconditionally prohibited "
                    "regardless of shape fit -- passthrough is the only remaining deterministic-by-construction option"
                ),
            }

    body = {
        "record_type": "n2d-rtk-applicability-map-v1",
        "record_version": 1,
        "schema_version": 1,
        "selection_policy_summary": (
            "1) grep only if genuinely grep-shaped (none are). 2) log unconditionally prohibited. "
            "3) git-diff usable only for genuinely git-diff-shaped input, now verified deterministic "
            "(none of the 18 cases are this shape). 4) cargo-test usable only for genuine cargo-test "
            "output, now verified deterministic (repo-rustlings, repo-dockerfile-parser-rs). "
            "5) passthrough otherwise."
        ),
        "prohibited_filters": PROHIBITED_FILTERS,
        "newly_verified_deterministic_filters": {
            "git-diff": {
                "probe_report_path": "evals/interop/v2/n2/d1-identity-lock/evidence/rtk-git-diff-determinism-probe-report.json",
                "probe_report_sha256": _sha256_file(GIT_DIFF_PROBE_PATH),
                "fixture_path": "corpus/git-diff.txt",
                "repetitions": git_diff_probe["repeats"],
                "canonical_stdout_sha256": git_diff_probe["distinct_stdout_sha256"][0],
                "canonical_o200k_token_count": git_diff_probe["distinct_o200k_token_counts"][0],
            },
            "cargo-test": {
                "probe_report_path": "evals/interop/v2/n2/d1-identity-lock/evidence/rtk-cargo-test-determinism-probe-report.json",
                "probe_report_sha256": _sha256_file(CARGO_TEST_PROBE_PATH),
                "fixture_path": "evals/interop/v2/smoke/fixtures/test-runner.txt",
                "repetitions": cargo_test_probe["repeats"],
                "canonical_stdout_sha256": cargo_test_probe["distinct_stdout_sha256"][0],
                "canonical_o200k_token_count": cargo_test_probe["distinct_o200k_token_counts"][0],
                "cross_confirmed_against_canonical_nix_build": (
                    "the canonical Nix-built rtk-pinned binary (live-captured in workflow run "
                    "29553837144's qodec-rtk-smoke-report artifact) independently produced the exact "
                    "same stdout_sha256 (a340058ce57fbb80c37ee10ab7229b071db86363cde0d9054c001880cbb983e9) "
                    "and token count (47) for this same fixture on its own single real invocation"
                ),
            },
        },
        "probe_binary_provenance": (
            "ad hoc `cargo build --release` of rtk source commit 5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2 "
            "(the exact pinned rtk-src commit) in this sandbox, for verification only -- NOT the canonical "
            "Nix build (packages.rtk-pinned). Same provenance pattern as n2d1-contract.json's own tokenizer "
            "conformance fixtures. The one available real canonical-Nix-build data point (cargo-test filter "
            "over test-runner.txt, from the qodec-rtk-smoke-report artifact) is byte-identical to this ad hoc "
            "build's result across all 20 repetitions, cross-confirming the ad hoc build's behavior."
        ),
        "cases": per_case,
    }
    body["record_sha256"] = compute_record_sha256(body)
    return body


def main() -> None:
    record = build_record()
    OUT_PATH.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT_PATH} (record_sha256={record['record_sha256']})")


if __name__ == "__main__":
    main()
