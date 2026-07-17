#!/usr/bin/env python3
"""Independently, fail-closedly verifies the four evidence-only closure
records for CI run 29575975971 (jobs manifest, artifacts manifest, trigger
patch proof, N2-D3 leg-evidence record), and re-derives the ENTIRE committed
n2d3-primary-token-benchmark-v1.json from the raw leg-evidence rows via the
real, unmodified build_n2d3_primary_benchmark.build_benchmark(), requiring
exact equality (record_sha256) with what is already committed.

This is an evidence-only closure verifier: it never trusts any record's own
cached summary fields, only recomputes from the raw content each record
carries (or, for the trigger patch proof, from its literal embedded diff
text) and from the already-committed, real n2d3-primary-token-benchmark-v1.json.
It does not modify, rerun, or re-derive QODEC/RTK runtime, the input bundle,
the benchmark workflow, the applicability map, any measurement row, or any
canonical token count -- all of those remain exactly as accepted.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
IDENTITY_LOCK_DIR = TOOLS_DIR.parent
sys.path.insert(0, str(TOOLS_DIR))

JOBS_MANIFEST_PATH = IDENTITY_LOCK_DIR / "n2d-run-29575975971-jobs-manifest-v1.json"
ARTIFACTS_MANIFEST_PATH = IDENTITY_LOCK_DIR / "n2d-run-29575975971-artifacts-manifest-v1.json"
TRIGGER_PATCH_PROOF_PATH = IDENTITY_LOCK_DIR / "n2d-trigger-patch-proof-v1.json"
LEG_EVIDENCE_PATH = IDENTITY_LOCK_DIR / "n2d3-run-29575975971-leg-evidence-v1.json"
N2D3_BENCHMARK_PATH = IDENTITY_LOCK_DIR / "n2d3-primary-token-benchmark-v1.json"

IMPLEMENTATION_SHA = "0abdde6723574e908415835612e8f520d85c33e7"
TRIGGER_SHA = "46a7986967c1837797f5edc32e79122d839c3de3"
RUN_ID = 29575975971
TRIGGER_BRANCH = "n2d/ci-trigger-full-run"
CHANGED_WORKFLOW_FILE = ".github/workflows/qodec-n2d-canary-benchmark.yml"

REQUIRED_JOB_COUNT = 41
REQUIRED_ARTIFACT_COUNT = 41
REQUIRED_CASE_COUNT = 18
AUTHORIZED_NON_UTF8_CASE_IDS = frozenset({"dataset-loghub-v8", "research-corpus-loghub2"})

JOB_MEASURE_NAME_RE = re.compile(r"^n2d3-measure \(([a-z0-9-]+), (a|b), \d+, \d+\)$")
ARTIFACT_MEASUREMENT_NAME_RE = re.compile(r"^n2d3-measurement-(.+)-(a|b)$")

CANONICAL_BOOTSTRAP_SEED = 20260716
ORIGINALLY_REQUESTED_BOOTSTRAP_SEED = 20260717


def verify(
    jobs_manifest_path: Path = JOBS_MANIFEST_PATH,
    artifacts_manifest_path: Path = ARTIFACTS_MANIFEST_PATH,
    trigger_patch_proof_path: Path = TRIGGER_PATCH_PROOF_PATH,
    leg_evidence_path: Path = LEG_EVIDENCE_PATH,
    benchmark_path: Path = N2D3_BENCHMARK_PATH,
) -> tuple[bool, str]:
    for path in (
        jobs_manifest_path, artifacts_manifest_path, trigger_patch_proof_path,
        leg_evidence_path, benchmark_path,
    ):
        if not path.is_file():
            return False, f"{path} does not exist"

    import build_n2d_run_jobs_manifest as jobs_builder
    import build_n2d_run_artifacts_manifest as artifacts_builder
    import build_n2d_trigger_patch_proof as trigger_builder
    import build_n2d3_leg_evidence as leg_builder
    import build_n2d3_primary_benchmark as bench_builder

    jobs = json.loads(jobs_manifest_path.read_text())
    artifacts = json.loads(artifacts_manifest_path.read_text())
    trigger_proof = json.loads(trigger_patch_proof_path.read_text())
    leg_evidence = json.loads(leg_evidence_path.read_text())
    committed_benchmark = json.loads(benchmark_path.read_text())

    # --- self-hash of every evidence record, recomputed via its own builder's
    # own hash function -- never trusting the recorded value -------------
    if jobs_builder.compute_record_sha256(jobs) != jobs.get("record_sha256"):
        return False, "jobs manifest self-hash mismatch"
    if artifacts_builder.compute_record_sha256(artifacts) != artifacts.get("record_sha256"):
        return False, "artifacts manifest self-hash mismatch"
    if trigger_builder.compute_record_sha256(trigger_proof) != trigger_proof.get("record_sha256"):
        return False, "trigger patch proof self-hash mismatch"
    if leg_builder.compute_record_sha256(leg_evidence) != leg_evidence.get("record_sha256"):
        return False, "leg-evidence record self-hash mismatch"
    if bench_builder.compute_record_sha256(committed_benchmark) != committed_benchmark.get("record_sha256"):
        return False, "committed n2d3-primary-token-benchmark-v1.json self-hash mismatch"

    # --- exact job/artifact/trigger-patch manifest equality: each of these
    # three records is a pure, deterministic function of hardcoded ground-
    # truth literals in its own builder module (captured once from GitHub's
    # real API response / a real `git diff`). Recomputing each one from that
    # ground truth and requiring full dict equality with the file on disk
    # catches ANY deviation -- a swapped-but-unique job/artifact id, a
    # well-formed-but-wrong digest, a wrong run id, a wrong trigger sha --
    # not merely internal self-consistency of a tampered-then-rehashed file.
    ground_truth_jobs = jobs_builder.build_record()
    if jobs != ground_truth_jobs:
        return False, "jobs manifest does not exactly equal the ground-truth recomputation from its own builder"
    ground_truth_artifacts = artifacts_builder.build_record()
    if artifacts != ground_truth_artifacts:
        return False, "artifacts manifest does not exactly equal the ground-truth recomputation from its own builder"
    ground_truth_trigger_proof = trigger_builder.build_record()
    if trigger_proof != ground_truth_trigger_proof:
        return False, "trigger patch proof does not exactly equal the ground-truth recomputation from its own builder"

    # --- pin run_id / head_branch / head_sha across every evidence record --
    for label, rec in (("jobs manifest", jobs), ("artifacts manifest", artifacts), ("leg-evidence record", leg_evidence)):
        if rec.get("run_id") != RUN_ID:
            return False, f"{label}: run_id {rec.get('run_id')!r} != pinned {RUN_ID!r}"
        if rec.get("head_branch") != TRIGGER_BRANCH:
            return False, f"{label}: head_branch {rec.get('head_branch')!r} != pinned {TRIGGER_BRANCH!r}"
        if rec.get("head_sha") != TRIGGER_SHA:
            return False, f"{label}: head_sha {rec.get('head_sha')!r} != pinned {TRIGGER_SHA!r}"

    if trigger_proof.get("implementation_sha") != IMPLEMENTATION_SHA:
        return False, f"trigger patch proof: implementation_sha != pinned {IMPLEMENTATION_SHA!r}"
    if trigger_proof.get("trigger_sha") != TRIGGER_SHA:
        return False, f"trigger patch proof: trigger_sha != pinned {TRIGGER_SHA!r}"

    # --- jobs manifest: exact count, uniqueness, all-green -----------------
    job_list = jobs.get("jobs", [])
    if len(job_list) != REQUIRED_JOB_COUNT:
        return False, f"jobs manifest: expected {REQUIRED_JOB_COUNT} jobs, got {len(job_list)}"
    job_ids = [j["id"] for j in job_list]
    if len(job_ids) != len(set(job_ids)):
        return False, "jobs manifest: duplicate job id"
    if not all(j.get("status") == "completed" and j.get("conclusion") == "success" for j in job_list):
        return False, "jobs manifest: not every job is completed/success"

    # --- artifacts manifest: exact count, uniqueness ------------------------
    artifact_list = artifacts.get("artifacts", [])
    if len(artifact_list) != REQUIRED_ARTIFACT_COUNT:
        return False, f"artifacts manifest: expected {REQUIRED_ARTIFACT_COUNT} artifacts, got {len(artifact_list)}"
    artifact_ids = [a["id"] for a in artifact_list]
    if len(artifact_ids) != len(set(artifact_ids)):
        return False, "artifacts manifest: duplicate artifact id"
    for a in artifact_list:
        if not isinstance(a.get("digest"), str) or not a["digest"].startswith("sha256:"):
            return False, f"artifacts manifest: artifact {a.get('id')!r} has a malformed digest"
        if a.get("run_id") != RUN_ID or a.get("head_branch") != TRIGGER_BRANCH or a.get("head_sha") != TRIGGER_SHA:
            return False, f"artifacts manifest: artifact {a.get('id')!r} pins do not match the manifest-level pins"

    # --- exact job/artifact manifest equality: the 36 n2d3-measure jobs and
    # the 36 n2d3-measurement-<case>-<leg> artifacts must name the identical
    # (case_id, leg) pair set -- this is the strongest possible cross-check
    # that the two manifests describe the same real run, not two different ones.
    job_pairs = set()
    for j in job_list:
        m = JOB_MEASURE_NAME_RE.match(j["name"])
        if m:
            job_pairs.add((m.group(1), m.group(2)))
    artifact_pairs = set()
    for a in artifact_list:
        m = ARTIFACT_MEASUREMENT_NAME_RE.match(a["name"])
        if m:
            artifact_pairs.add((m.group(1), m.group(2)))
    if len(job_pairs) != 36:
        return False, f"jobs manifest: expected 36 n2d3-measure (case, leg) jobs, got {len(job_pairs)}"
    if len(artifact_pairs) != 36:
        return False, f"artifacts manifest: expected 36 n2d3-measurement-<case>-<leg> artifacts, got {len(artifact_pairs)}"
    if job_pairs != artifact_pairs:
        return False, "jobs manifest and artifacts manifest disagree on the (case_id, leg) pair set"

    # --- trigger patch proof: independently re-parse its own embedded literal
    # diff text (never trust its cached added_line_count/changed_files) -----
    diff_text = trigger_proof.get("diff_text", "")
    parsed = trigger_builder.parse_diff(diff_text)
    if parsed["changed_files"] != [CHANGED_WORKFLOW_FILE]:
        return False, f"trigger patch proof: re-parsed changed_files {parsed['changed_files']} != expected [{CHANGED_WORKFLOW_FILE!r}]"
    if parsed["removed_lines"]:
        return False, f"trigger patch proof: re-parsed diff has removed lines {parsed['removed_lines']} -- not additive-only"
    expected_added = ["  push:", "    branches:", f"      - {TRIGGER_BRANCH}"]
    if parsed["added_lines"] != expected_added:
        return False, f"trigger patch proof: re-parsed added lines {parsed['added_lines']} != expected {expected_added}"
    if trigger_proof.get("additive_only") is not True:
        return False, "trigger patch proof: additive_only must be true"
    if trigger_proof.get("removed_line_count") != 0:
        return False, "trigger patch proof: removed_line_count must be 0"
    if trigger_proof.get("added_line_count") != len(expected_added):
        return False, f"trigger patch proof: added_line_count != {len(expected_added)}"

    # --- leg-evidence record: exactly 18 cases, each with legs a and b -----
    cases = leg_evidence.get("cases", {})
    if leg_evidence.get("case_count") != REQUIRED_CASE_COUNT:
        return False, f"leg-evidence record: case_count != {REQUIRED_CASE_COUNT}"
    if sorted(cases.keys()) != sorted(leg_builder.EXPECTED_CASE_IDS):
        return False, "leg-evidence record: case set does not match the required 18-case list"
    if len(cases) != REQUIRED_CASE_COUNT:
        return False, f"leg-evidence record: expected {REQUIRED_CASE_COUNT} cases, got {len(cases)}"

    case_leg_pairs = {}
    for case_id, legs in cases.items():
        if sorted(legs.keys()) != ["a", "b"]:
            return False, f"leg-evidence record: {case_id} does not have exactly legs a and b"
        leg_a, leg_b = legs["a"], legs["b"]
        if leg_a.get("case_id") != case_id or leg_b.get("case_id") != case_id:
            return False, f"leg-evidence record: {case_id} leg row case_id mismatch"
        if leg_a.get("leg") != "a" or leg_b.get("leg") != "b":
            return False, f"leg-evidence record: {case_id} leg row leg-label mismatch"
        case_leg_pairs[case_id] = (leg_a, leg_b)

    # --- re-derive all 18 a/b leg pairs and both typed non-UTF-8 refusals,
    # via the real, unmodified combine_case_legs() -- never trusting the
    # leg-evidence record's own status fields in isolation. --------------
    combined_by_case = {}
    refusal_case_ids = set()
    for case_id, (leg_a, leg_b) in sorted(case_leg_pairs.items()):
        try:
            combined = bench_builder.combine_case_legs(leg_a, leg_b)
        except Exception as exc:  # noqa: BLE001
            return False, f"leg pair {case_id}: combine_case_legs raised: {exc}"
        if not combined["leg_agreement"]:
            return False, f"leg pair {case_id}: leg a/b disagreement on {combined['disagreements']}"
        combined_by_case[case_id] = combined
        if combined["measurement_status"] == "UNMEASURABLE_NON_UTF8":
            refusal_case_ids.add(case_id)
            if combined.get("qodec_failure_classification") != "INVALID_UTF8_INPUT":
                return False, f"{case_id}: re-derived refusal classification != 'INVALID_UTF8_INPUT'"

    if refusal_case_ids != set(AUTHORIZED_NON_UTF8_CASE_IDS):
        return False, f"re-derived non-UTF-8 refusal set {refusal_case_ids} != required {set(AUTHORIZED_NON_UTF8_CASE_IDS)}"
    measured_case_ids = set(combined_by_case) - refusal_case_ids
    if len(measured_case_ids) != REQUIRED_CASE_COUNT - len(AUTHORIZED_NON_UTF8_CASE_IDS):
        return False, f"re-derived measured case count {len(measured_case_ids)} != expected 16"

    # --- recompute the ENTIRE benchmark from raw leg-evidence rows via the
    # real, unmodified build_n2d3_primary_benchmark.build_benchmark(): every
    # per-case combined row, RAW/QODEC/RTK/hybrid totals, weighted/macro/
    # median savings, and bootstrap intervals -- then require byte-exact
    # equality (record_sha256, then full dict) with the already-accepted,
    # already-committed n2d3-primary-token-benchmark-v1.json. ---------------
    try:
        recomputed_benchmark = bench_builder.build_benchmark(case_leg_pairs)
    except Exception as exc:  # noqa: BLE001
        return False, f"recomputing the full benchmark from leg-evidence raised: {exc}"

    if recomputed_benchmark.get("record_sha256") != committed_benchmark.get("record_sha256"):
        return False, (
            f"recomputed benchmark record_sha256 {recomputed_benchmark.get('record_sha256')!r} != "
            f"committed {committed_benchmark.get('record_sha256')!r}"
        )
    if recomputed_benchmark != committed_benchmark:
        return False, "recomputed benchmark differs from the committed record despite matching record_sha256"

    # --- bootstrap seed: the canonical record's seed was committed in
    # implementation SHA before the canonical CI run, and is accepted here
    # as a predeclared deviation from the originally-requested seed. This
    # verifier pins that the canonical seed did NOT change post-run. -------
    for arm_key in ("qodec", "rtk", "rtk_plus_qodec_hybrid"):
        arm = committed_benchmark["token_aggregates_measured_text_domain_subset_n16"][arm_key]
        ci = arm["bootstrap_macro_savings_pct_ci95"]
        if ci.get("seed") != CANONICAL_BOOTSTRAP_SEED:
            return False, f"{arm_key}: committed bootstrap seed {ci.get('seed')!r} != canonical {CANONICAL_BOOTSTRAP_SEED!r}"
    if bench_builder.BOOTSTRAP_SEED != CANONICAL_BOOTSTRAP_SEED:
        return False, "build_n2d3_primary_benchmark.BOOTSTRAP_SEED no longer matches the canonical predeclared seed"

    return True, "OK"


def main() -> int:
    ok, message = verify()
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
