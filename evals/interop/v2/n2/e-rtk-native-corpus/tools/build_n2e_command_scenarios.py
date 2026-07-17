#!/usr/bin/env python3
"""Build n2e-command-scenarios-v1.json (§12) — one exact contract per selected case.

Deterministic and offline: joins the frozen selection with the candidate
inventory (for raw argv + identities) and the RTK claim surface (for the
RTK-native mapping and support classification). argv is always stored as arrays;
a shell rendering is human-readable only. RTK savings are never referenced.

RTK-native argv derivation (from the pinned binary's real rewrite behavior):
  - prepend `rtk`; tool substitutions: eslint->lint; cat->(log|read) by family.
  - js_ts test uses the project runner (jest|vitest) resolved at acquisition from
    package.json — recorded as rtk_argv_resolution, since `npm test` is an RTK
    passthrough, not the native test path.
"""
from __future__ import annotations

import shlex
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

OUT = N2E_DIR / "n2e-command-scenarios-v1.json"
SEL = N2E_DIR / "n2e-selection-result-v1.json"
INV = N2E_DIR / "n2e-candidate-inventory-v1.json"
CLAIM = N2E_DIR / "n2e-rtk-claim-surface-v1.json"

RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
RTK_BINARY_SHA256 = "41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf"

# semantic oracle per (family, subfamily-group)
ORACLE = {
    "test": ("test_oracle", ["exit_code", "total", "passed", "failed", "skipped",
                             "failed_test_ids", "failing_module_ids", "primary_error_locations"]),
    "build_lint": ("diagnostics_oracle", ["exit_code", "severity", "diagnostic_code",
                                          "file", "line", "error_count", "warning_count"]),
    "git_status": ("git_status_oracle", ["changed_paths", "status_code_per_path", "branch_ahead_behind", "untracked_paths"]),
    "git_diff": ("git_diff_oracle", ["affected_paths", "added_deleted_totals", "patch_semantic_hash", "binary_markers"]),
    "git_log": ("git_log_oracle", ["commit_sha_sequence", "subject_sequence", "requested_range"]),
    "git_state": ("git_state_oracle", ["exit_code", "resulting_ref", "changed_paths"]),
    "file_listing": ("file_listing_oracle", ["entry_set", "type_per_entry"]),
    "file_read": ("file_read_oracle", ["selected_path", "source_sha256", "requested_range", "truncation", "retained_line_coverage"]),
    "grep": ("grep_oracle", ["match_identities(path,line,text_hash)"]),
    "log": ("log_oracle", ["unique_template_ids", "occurrence_counts", "severity_counts", "first_last_occurrence"]),
    "docker": ("docker_oracle", ["container_image_identity_set", "names", "state", "exit_status", "log_event_identities"]),
}
BUILD_LINT = {"build", "check", "clippy", "vet", "tsc", "lint", "ruff"}


def oracle_for(family: str, sub: str) -> tuple[str, list]:
    if sub in ("test", "pytest"):
        return ORACLE["test"]
    if sub in BUILD_LINT:
        return ORACLE["build_lint"]
    if family == "git":
        if sub == "status":
            return ORACLE["git_status"]
        if sub in ("diff", "show"):
            return ORACLE["git_diff"]
        if sub == "log":
            return ORACLE["git_log"]
        return ORACLE["git_state"]  # add/commit/push
    if family == "files_search":
        if sub in ("ls", "tree"):
            return ORACLE["file_listing"]
        if sub == "read":
            return ORACLE["file_read"]
        if sub == "grep":
            return ORACLE["grep"]
    if family == "logs":
        return ORACLE["log"]
    if family == "containers":
        return ORACLE["docker"]
    raise SystemExit(f"no oracle for {family}/{sub}")


def rtk_native_argv(cand: dict) -> tuple[list | None, str, str]:
    """Return (explicit_rtk_argv, classification, resolution_note)."""
    fam, sub = cand["command_family"], cand["command_subfamily"]
    argv = cand["raw_command_argv"]
    if fam == "js_ts" and sub == "test":
        # npm test is an RTK passthrough; native path is rtk jest|vitest from package.json
        return (None, "RTK_NATIVE_SPECIALIZED", "acquisition:test_runner_from_package_json -> rtk jest|vitest")
    if fam == "logs":
        return (["rtk", "log"] + argv[1:], "RTK_NATIVE_SPECIALIZED", "")
    if fam == "files_search" and sub == "read":
        return (["rtk", "read"] + argv[1:], "RTK_NATIVE_SPECIALIZED", "")
    if fam == "js_ts" and sub == "lint":
        return (["rtk", "lint"] + argv[1:], "RTK_NATIVE_SPECIALIZED", "")
    # default: prepend rtk to the real tool invocation
    return (["rtk"] + argv, "RTK_NATIVE_SPECIALIZED", "")


def image_identity(cand: dict) -> dict:
    if cand.get("image_identity"):
        return {"kind": "oci_image", **cand["image_identity"]}
    if cand.get("zenodo_file"):
        return {"kind": "zenodo_file", **cand["zenodo_file"]}
    if cand.get("base_commit"):
        return {"kind": "swebench_recipe", "repository": cand["repository"],
                "base_commit": cand["base_commit"], "instance_id": cand.get("instance_id")}
    if cand.get("buggy_commit"):
        return {"kind": "bugsinpy_recipe", "repository": cand["repository"],
                "buggy_commit": cand["buggy_commit"], "fixed_commit": cand.get("fixed_commit")}
    return {"kind": "unspecified"}


def build() -> dict:
    sel = c.load_record(SEL)
    inv = {x["candidate_id"]: x for x in c.load_record(INV)["candidates"]}
    scenarios = []
    for case in sel["selection"]:
        cand = inv[case["case_id"]]
        fam, sub = cand["command_family"], cand["command_subfamily"]
        oracle_type, oracle_params = oracle_for(fam, sub)
        rtk_argv, cls, resolution = rtk_native_argv(cand)
        scenarios.append({
            "case_id": case["case_id"],
            "cluster_id": cand["cluster_id"],
            "source_id": cand["source_id"],
            "repository": cand["repository"],
            "snapshot_variant": cand.get("snapshot_variant"),
            "command_family": fam,
            "command_subfamily": sub,
            "working_directory": "/work",
            "original_argv": cand["raw_command_argv"],
            "original_command_shell_readable": shlex.join(cand["raw_command_argv"]),
            "explicit_rtk_argv": rtk_argv,
            "rtk_argv_resolution": resolution or None,
            "environment": {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
                            "TERM": "dumb", "NO_COLOR": "1", "COLUMNS": "120", "LINES": "40"},
            "locale": "C.UTF-8", "timezone": "UTC", "terminal_width": 120,
            "setup_recipe": {"acquire": "network acquisition per §5 (image build / archive / checkout)",
                             "identity": image_identity(cand)},
            "measurement_recipe": {"isolation": "network-denied (unshare -n), fresh workdir",
                                   "reps": 3, "combine_policy": "stdout_then_stderr"},
            "expected_exit_code": {"buggy": None, "fixed": 0, "fail": None, "pass": 0}.get(
                cand.get("snapshot_variant") or cand.get("expected_raw_outcome"), None),
            "timeout_seconds": 600 if sub == "test" else 120,
            "memory_limit_bytes": 10 * 1024**3,
            "stdout_stderr_policy": "capture separately; meter combined stdout_then_stderr",
            "semantic_oracle_type": oracle_type,
            "semantic_oracle_parameters": oracle_params,
            "expected_raw_outcome": cand.get("expected_raw_outcome"),
            "target_test_ids": cand.get("target_test_ids"),
            "rtk_support_classification": cls,
            "source_image_identity": image_identity(cand),
            "output_size_stratum": "unmeasured_pre_qualification",
            "license_provenance": {"source_id": cand["source_id"]},
        })
    scenarios.sort(key=lambda s: s["case_id"])
    return c.envelope(
        record_type="n2e-command-scenarios",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_command_scenarios.py",
        purpose="Exact per-case command contracts for the 70 selected cases (§12).",
        selection_sha256=c.sha256_json_file(SEL),
        inventory_sha256=c.sha256_json_file(INV),
        claim_surface_sha256=c.sha256_json_file(CLAIM),
        rtk_source_commit=RTK_SOURCE_COMMIT,
        rtk_binary_sha256=RTK_BINARY_SHA256,
        scenario_count=len(scenarios),
        scenarios=scenarios,
    )


def main() -> int:
    c.write_record(OUT, build())
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name} record_sha256={rec['record_sha256']} scenarios={rec['scenario_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
