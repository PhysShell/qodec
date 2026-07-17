#!/usr/bin/env python3
"""Independently, fail-closedly verifies rtk-applicability-map-v1.json.

Re-derives the two bounded-probe determinism claims from the actual
committed probe report files (never trusting the map's own recorded
values), re-checks each case's filter assignment against
stage2-full-matrix-acceptance.json's own frozen_argv (never trusting the
map's own stated rationale), and requires `log` remain unconditionally
absent from every case's rtk_argv.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
IDENTITY_LOCK_DIR = TOOLS_DIR.parent
RECORD_PATH = IDENTITY_LOCK_DIR / "rtk-applicability-map-v1.json"
GIT_DIFF_PROBE_PATH = IDENTITY_LOCK_DIR / "evidence" / "rtk-git-diff-determinism-probe-report.json"
CARGO_TEST_PROBE_PATH = IDENTITY_LOCK_DIR / "evidence" / "rtk-cargo-test-determinism-probe-report.json"
STAGE2_RECORD_PATH = IDENTITY_LOCK_DIR / "stage2-full-matrix-acceptance.json"

REQUIRED_18_CASE_IDS = [
    "n2a-miner-canary",
    "bot-dependabot-black-5206", "bot-syzbot-do-mkdirat", "ci-log-jansson",
    "ci-log-nlog", "ci-log-spdlog", "dataset-loghub-v8",
    "dataset-rtn-traffic-ids", "research-corpus-loghub2",
    "repo-docker-java-parser", "repo-dockerfile-parser-rs", "repo-helm-values",
    "repo-hyperfine", "repo-kubeops-generator", "repo-moshi", "repo-pyflakes",
    "repo-requests", "repo-rustlings",
]
CARGO_TEST_SHAPED_CASE_IDS = {"repo-rustlings", "repo-dockerfile-parser-rs"}


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(record_path: Path = RECORD_PATH) -> tuple[bool, str]:
    if not record_path.is_file():
        return False, f"{record_path} does not exist"
    record = json.loads(record_path.read_text())

    recorded = record.get("record_sha256")
    recomputed = compute_record_sha256(record)
    if recomputed != recorded:
        return False, f"self-hash mismatch: recorded={recorded} recomputed={recomputed}"

    if record.get("record_type") != "n2d-rtk-applicability-map-v1":
        return False, f"unexpected record_type: {record.get('record_type')!r}"
    if record.get("prohibited_filters") != ["log"]:
        return False, "prohibited_filters must be exactly ['log']"

    cases = record.get("cases", {})
    if sorted(cases.keys()) != sorted(REQUIRED_18_CASE_IDS):
        return False, "cases keys != required 18-case set"

    for case_id, entry in cases.items():
        argv = entry.get("rtk_argv", [])
        if "log" in argv:
            return False, f"cases[{case_id!r}].rtk_argv contains prohibited filter 'log': {argv!r}"
        if case_id in CARGO_TEST_SHAPED_CASE_IDS:
            if argv != ["pipe", "--filter", "cargo-test"]:
                return False, f"cases[{case_id!r}] must use cargo-test filter, got {argv!r}"
        else:
            if argv != ["pipe", "--passthrough"]:
                return False, f"cases[{case_id!r}] must use passthrough (no verified-deterministic shape match), got {argv!r}"

    # --- independently re-derive both determinism claims from the real probe files
    if not GIT_DIFF_PROBE_PATH.is_file() or not CARGO_TEST_PROBE_PATH.is_file():
        return False, "probe report files missing"
    git_diff_probe = json.loads(GIT_DIFF_PROBE_PATH.read_text())
    cargo_test_probe = json.loads(CARGO_TEST_PROBE_PATH.read_text())

    for name, probe, section in (
        ("git-diff", git_diff_probe, record["newly_verified_deterministic_filters"]["git-diff"]),
        ("cargo-test", cargo_test_probe, record["newly_verified_deterministic_filters"]["cargo-test"]),
    ):
        if probe.get("repeats", 0) < 20:
            return False, f"{name} probe ran fewer than 20 repetitions"
        if not probe.get("deterministic"):
            return False, f"{name} probe's own recorded data does not show determinism"
        if len(probe.get("distinct_stdout_sha256", [])) != 1:
            return False, f"{name} probe shows more than one distinct stdout hash across repetitions"
        if section.get("repetitions") != probe["repeats"]:
            return False, f"{name} map entry repetitions does not match the real probe report"
        if section.get("canonical_stdout_sha256") != probe["distinct_stdout_sha256"][0]:
            return False, f"{name} map entry canonical_stdout_sha256 does not match the real probe report"
        actual_report_sha256 = _sha256_file(
            GIT_DIFF_PROBE_PATH if name == "git-diff" else CARGO_TEST_PROBE_PATH
        )
        if section.get("probe_report_sha256") != actual_report_sha256:
            return False, f"{name} map entry probe_report_sha256 does not match the actual committed report file"

    # --- cross-check cargo-test filter selection against real frozen argv --
    if not STAGE2_RECORD_PATH.is_file():
        return False, f"{STAGE2_RECORD_PATH} does not exist"
    stage2_record = json.loads(STAGE2_RECORD_PATH.read_text())
    for case_id in CARGO_TEST_SHAPED_CASE_IDS:
        frozen_argv = stage2_record["cases"][case_id]["frozen_argv"]
        if frozen_argv != ["cargo", "test"]:
            return False, (
                f"{case_id} is assigned the cargo-test filter but its real frozen_argv "
                f"{frozen_argv!r} is not ['cargo','test']"
            )
    for case_id in REQUIRED_18_CASE_IDS:
        if case_id in CARGO_TEST_SHAPED_CASE_IDS or case_id not in stage2_record.get("cases", {}):
            continue
        frozen_argv = stage2_record["cases"][case_id]["frozen_argv"]
        if frozen_argv == ["cargo", "test"]:
            return False, (
                f"{case_id} has real frozen_argv ['cargo','test'] but is NOT assigned the cargo-test "
                "filter -- either it is missing from CARGO_TEST_SHAPED_CASE_IDS or was wrongly excluded"
            )

    return True, "OK"


def main() -> int:
    ok, message = verify()
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
