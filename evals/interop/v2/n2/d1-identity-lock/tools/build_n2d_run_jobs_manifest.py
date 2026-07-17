#!/usr/bin/env python3
"""Builds the self-hash-locked jobs manifest for the real canonical CI run
that produced the accepted N2-D2/N2-D3 evidence (run 29575975971, on the
disposable trigger branch n2d/ci-trigger-full-run, head 46a7986).

Every job's id/name/status/conclusion below was read directly from GitHub's
own Actions API response for this run (mcp__github__actions_list ->
list_workflow_jobs) during the session that produced the evidence; nothing
here is synthesized. This is an evidence-only closure commit -- it does not
modify QODEC/RTK runtime, the input bundle, the benchmark workflow, the
applicability map, any measurement row, or any canonical token count.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

IDENTITY_LOCK_DIR = Path(__file__).resolve().parents[1]
OUT_PATH = IDENTITY_LOCK_DIR / "n2d-run-29575975971-jobs-manifest-v1.json"

RUN_ID = 29575975971
WORKFLOW_NAME = "qodec-n2d-canary-benchmark"
HEAD_BRANCH = "n2d/ci-trigger-full-run"
HEAD_SHA = "46a7986967c1837797f5edc32e79122d839c3de3"

# (job_id, name, status, conclusion) -- sorted by job_id, exactly as returned
# by the GitHub Actions API for run 29575975971.
JOBS = [
    (87870384663, "n2d2-canary-leg-b", "completed", "success"),
    (87870384670, "rtk-determinism-probes", "completed", "success"),
    (87870384680, "n2d2-canary-leg-a", "completed", "success"),
    (87871893888, "n2d2-combine", "completed", "success"),
    (87871918169, "n2d3-measure (bot-dependabot-black-5206, a, 30, 1200)", "completed", "success"),
    (87871918196, "n2d3-measure (bot-syzbot-do-mkdirat, b, 30, 1200)", "completed", "success"),
    (87871918199, "n2d3-measure (ci-log-jansson, b, 30, 1200)", "completed", "success"),
    (87871918209, "n2d3-measure (bot-syzbot-do-mkdirat, a, 30, 1200)", "completed", "success"),
    (87871918217, "n2d3-measure (ci-log-spdlog, b, 30, 1200)", "completed", "success"),
    (87871918241, "n2d3-measure (n2a-miner-canary, b, 30, 1200)", "completed", "success"),
    (87871918245, "n2d3-measure (ci-log-jansson, a, 30, 1200)", "completed", "success"),
    (87871918250, "n2d3-measure (dataset-loghub-v8, a, 30, 1200)", "completed", "success"),
    (87871918263, "n2d3-measure (dataset-rtn-traffic-ids, a, 240, 5400)", "completed", "success"),
    (87871918264, "n2d3-measure (ci-log-nlog, a, 30, 1200)", "completed", "success"),
    (87871918276, "n2d3-measure (repo-pyflakes, a, 30, 1200)", "completed", "success"),
    (87871918282, "n2d3-measure (ci-log-nlog, b, 30, 1200)", "completed", "success"),
    (87871918288, "n2d3-measure (repo-kubeops-generator, a, 30, 1200)", "completed", "success"),
    (87871918289, "n2d3-measure (repo-docker-java-parser, b, 30, 1200)", "completed", "success"),
    (87871918295, "n2d3-measure (bot-dependabot-black-5206, b, 30, 1200)", "completed", "success"),
    (87871918300, "n2d3-measure (ci-log-spdlog, a, 30, 1200)", "completed", "success"),
    (87871918320, "n2d3-measure (dataset-rtn-traffic-ids, b, 240, 5400)", "completed", "success"),
    (87871918340, "n2d3-measure (repo-kubeops-generator, b, 30, 1200)", "completed", "success"),
    (87871918341, "n2d3-measure (repo-requests, a, 30, 1200)", "completed", "success"),
    (87871918345, "n2d3-measure (dataset-loghub-v8, b, 30, 1200)", "completed", "success"),
    (87871918351, "n2d3-measure (repo-helm-values, a, 30, 1200)", "completed", "success"),
    (87871918353, "n2d3-measure (repo-rustlings, b, 30, 1200)", "completed", "success"),
    (87871918354, "n2d3-measure (repo-rustlings, a, 30, 1200)", "completed", "success"),
    (87871918356, "n2d3-measure (repo-helm-values, b, 30, 1200)", "completed", "success"),
    (87871918358, "n2d3-measure (repo-pyflakes, b, 30, 1200)", "completed", "success"),
    (87871918361, "n2d3-measure (repo-dockerfile-parser-rs, a, 30, 1200)", "completed", "success"),
    (87871918362, "n2d3-measure (research-corpus-loghub2, b, 30, 1200)", "completed", "success"),
    (87871918386, "n2d3-measure (repo-moshi, b, 30, 1200)", "completed", "success"),
    (87871918387, "n2d3-measure (repo-requests, b, 30, 1200)", "completed", "success"),
    (87871918389, "n2d3-measure (repo-dockerfile-parser-rs, b, 30, 1200)", "completed", "success"),
    (87871918391, "n2d3-measure (repo-docker-java-parser, a, 30, 1200)", "completed", "success"),
    (87871918393, "n2d3-measure (n2a-miner-canary, a, 30, 1200)", "completed", "success"),
    (87871918397, "n2d3-measure (repo-hyperfine, a, 30, 1200)", "completed", "success"),
    (87871918415, "n2d3-measure (repo-hyperfine, b, 30, 1200)", "completed", "success"),
    (87871918442, "n2d3-measure (repo-moshi, a, 30, 1200)", "completed", "success"),
    (87871918479, "n2d3-measure (research-corpus-loghub2, a, 30, 1200)", "completed", "success"),
    (87884150234, "n2d3-aggregate", "completed", "success"),
]


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def build_record() -> dict:
    ids = [j[0] for j in JOBS]
    if len(ids) != len(set(ids)):
        raise RuntimeError("duplicate job id in JOBS")
    if len(JOBS) != 41:
        raise RuntimeError(f"expected exactly 41 jobs, got {len(JOBS)}")
    if not all(status == "completed" and conclusion == "success" for _, _, status, conclusion in JOBS):
        raise RuntimeError("not every job is completed/success -- this manifest only covers an all-green run")

    jobs = [
        {"id": jid, "name": name, "status": status, "conclusion": conclusion}
        for jid, name, status, conclusion in sorted(JOBS, key=lambda j: j[0])
    ]
    body = {
        "record_type": "n2d-run-jobs-manifest-v1",
        "record_version": 1,
        "schema_version": 1,
        "run_id": RUN_ID,
        "workflow_name": WORKFLOW_NAME,
        "head_branch": HEAD_BRANCH,
        "head_sha": HEAD_SHA,
        "job_count": len(jobs),
        "jobs": jobs,
    }
    body["record_sha256"] = compute_record_sha256(body)
    return body


def main() -> None:
    record = build_record()
    OUT_PATH.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT_PATH} (record_sha256={record['record_sha256']})")


if __name__ == "__main__":
    main()
