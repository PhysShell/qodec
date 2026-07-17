#!/usr/bin/env python3
"""Builds the immutable, self-hash-locked
pytest-requests-canonicalization-v1-rejection-record.json.

D1b remediation decision (2026-07-17): repo-requests' Stage 2 evidence
(workflow run 29544801640, accepted -- WRONGLY -- as part of
stage2-full-matrix-acceptance.json) is REJECTED. Real inspection of the
accepted repo-requests capture-a artifact (8393544251) found:

    exit_code = 1
    30 failed, 384 passed, 15 skipped, 1 xfailed, 32 warnings, 205 errors

The 205 errors all originate from pytest-httpbin's own local WSGI test
server hitting a genuine PermissionError in its own socket.bind() call --
a sandbox-confinement gap (this sandbox denied ALL network at the time,
including the loopback bind pytest-httpbin's own local fixture server
needs), never a real test-suite defect, and never something Stage 2
content acceptance should have treated as "genuine workload output" merely
because pytest reached its own final summary line and the two captures
happened to fail identically.

pytest_requests_canonicalizer.py's own three rules (object-repr address,
session-summary duration, threading.Thread-repr native ident) were built
FROM this same invalid run's captured bytes -- the object-address and
thread-ident rules in particular exist primarily to canonicalize REPEATED
TRACEBACK MATERIAL produced by the 205 fixture errors, not genuine pytest
output a successful run would ever emit. Making two identically-broken
captures compare byte-equal is not Stage 2 acceptance.

This record does not delete or modify pytest_requests_canonicalizer.py,
pytest-requests-capture-canonicalization-policy.json, or their own test
suite -- all three remain on disk, byte-for-byte, as historical evidence of
what was built and why it was wrong. They are simply no longer imported or
dispatched by generic_capture.py / verify_pilot_pair_reproducibility.py
(see those modules' own comments). A new, separately-reviewed
canonicalization identity -- if any canonicalization is even needed -- must
be built only after a genuinely successful (zero-failure, exit-0)
repo-requests capture pair is observed under the corrected content gate,
network-enforcement authorization, and toolchain identity fix.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

OUT_PATH = Path(__file__).resolve().parents[1] / "pytest-requests-canonicalization-v1-rejection-record.json"

APPROVING_DECISION_IDENTITY = "n2d1b-pytest-requests-canonicalization-v1-rejection-2026-07-17"

REJECTED_MODULE_PATH = "evals/interop/v2/n2/d1-identity-lock/tools/pytest_requests_canonicalizer.py"
REJECTED_POLICY_PATH = "evals/interop/v2/n2/d1-identity-lock/pytest-requests-capture-canonicalization-policy.json"
REJECTED_MODULE_SHA256 = "00df03b3a85be3af0c59963992152171736c71e5ac3aa18f820cd2f7aaa93933"
REJECTED_POLICY_FILE_SHA256 = "9716bd35a655fe457e1c87dc7eee2da4ae9db2a58e5138b96c32612ab6a649fe"
REJECTED_POLICY_INTERNAL_SHA256 = "8670190615b541db18e4ae2e13379f9477f38fa023ae342d30d85bbd1d78f16f"

REJECTED_FROM_WORKFLOW_RUN_ID = 29544801640
REJECTED_FROM_ARTIFACT_ID = 8393544251
REJECTED_FROM_ARTIFACT_NAME = "n2d1b-pilot-repo-requests-capture-a"

OBSERVED_FAILURE_SUMMARY = (
    "= 30 failed, 384 passed, 15 skipped, 1 xfailed, 32 warnings, 205 errors in 14.43s ="
)
OBSERVED_FAILURE_STDERR_EXCERPT = (
    "        self.socket.bind(self.server_address)\n"
    "      File \"/usr/lib/python3.12/socketserver.py\", line 473, in server_bind\n"
    "        self.socket.bind(self.server_address)\n"
    "E       PermissionError: [Errno 13] Permission denied\n"
    "/usr/lib/python3.12/socketserver.py:473: PermissionError\n"
)

PROHIBITED_WORKAROUNDS = [
    "using pytest_requests_canonicalizer.py or its policy as accepted Stage 2 evidence for repo-requests",
    "reusing run 29544801640 or any of its artifacts as final Stage 2 acceptance evidence",
    "carrying the object-address or thread-ident rules into a new policy without separate review of a "
    "genuinely successful (zero-failure, exit-0) capture pair",
    "treating a deterministic pair of two identically-broken pytest runs as evidence of genuine "
    "reproducibility",
    "loosening content_acceptance.py's now-fixed repo-requests semantic marker or exit-code requirement "
    "to re-accept a failing run",
    "deleting or modifying pytest_requests_canonicalizer.py, its policy file, or its test suite -- all "
    "three remain as historical evidence",
]

CORRECTIVE_ACTIONS_TAKEN = [
    "content_acceptance.py: repo-requests now requires exit_code == 0 (STRICT_ZERO_EXIT_CODE_REQUIRED_"
    "CASE_IDS) and a pytest final summary reporting zero failed and zero errors "
    "(_pytest_requests_semantic_marker); a new socket-bind-permission-denied infrastructure-failure "
    "signature was added to INFRASTRUCTURE_FAILURE_SIGNATURES.",
    "generic_sandbox_policy.py: repo-requests added to NETWORK_ENFORCEMENT_AUTHORIZED_CASES "
    "(outer-netns-loopback-only) -- approval identity "
    "n2d1b-repo-requests-loopback-only-authorization-2026-07-17 -- so pytest-httpbin's own local WSGI "
    "fixture server can bind loopback while external IPv4/IPv6 connectivity remains denied.",
    "run_pilot_case.py / qodec-n2d1b-miner-pilot.yml: repo-requests' python toolchain is now pinned via "
    "the same actions/setup-python identity (tag v5.6.0, commit "
    "a26af69be951a213d495a4c3e4e4022e16d87065, python-version 3.12.3) repo-pyflakes already uses, fixing "
    "toolchain_executed.classification from 'unexpected-resolution' to 'exact-match'.",
    "generic_capture.py / verify_pilot_pair_reproducibility.py: pytest_requests_canonicalizer.py is no "
    "longer imported or dispatched for repo-requests; repo-requests runs as raw-capped-stream "
    "(uncanonicalized) pending a fresh, genuinely successful capture pair.",
]


def build_record() -> dict:
    body = {
        "record_type": "n2d1b-canonicalization-policy-rejection-record-v1",
        "record_version": 1,
        "case_id": "repo-requests",
        "classification": "REJECTED_DERIVED_FROM_INVALID_RUN",
        "approving_decision_identity": APPROVING_DECISION_IDENTITY,
        "rejected_module": {
            "path": REJECTED_MODULE_PATH,
            "sha256": REJECTED_MODULE_SHA256,
            "status": "left byte-for-byte untouched on disk as historical evidence; no longer imported "
                      "by the active capture/pair-verify dispatch",
        },
        "rejected_policy": {
            "path": REJECTED_POLICY_PATH,
            "file_sha256": REJECTED_POLICY_FILE_SHA256,
            "internal_policy_sha256": REJECTED_POLICY_INTERNAL_SHA256,
            "status": "left byte-for-byte untouched on disk as historical evidence; no longer imported "
                      "by the active capture/pair-verify dispatch",
        },
        "rejected_from_evidence": {
            "workflow_run_id": REJECTED_FROM_WORKFLOW_RUN_ID,
            "artifact_id": REJECTED_FROM_ARTIFACT_ID,
            "artifact_name": REJECTED_FROM_ARTIFACT_NAME,
            "observed_exit_code": 1,
            "observed_pytest_final_summary": OBSERVED_FAILURE_SUMMARY,
            "observed_stderr_excerpt": OBSERVED_FAILURE_STDERR_EXCERPT,
        },
        "rationale": (
            "The accepted repo-requests capture genuinely FAILED (exit_code=1, 30 failed, 205 errors), "
            "not a sandbox/tooling artifact of an otherwise-successful run. All 205 errors trace to "
            "pytest-httpbin's own local WSGI test server's socket.bind() call hitting a real "
            "PermissionError under this sandbox's (at that time, blanket) network denial -- a genuine "
            "confinement gap, since fixed via an explicit outer-netns-loopback-only authorization for "
            "this exact case, never a defect in the test suite itself. The prior content-acceptance gate "
            "wrongly classified this as 'genuine-workload-output' because it only checked for the literal "
            "presence of a pytest final-summary line, never its actual failed/error counts, and only "
            "rejected exit codes 126/127, not any other nonzero exit. pytest_requests_canonicalizer.py's "
            "own three rules were then derived FROM this invalid run's captured bytes to make capture-a "
            "and capture-b compare canonically equal -- the object-repr-address and thread-repr-ident "
            "rules in particular exist mainly to canonicalize repeated traceback material the 205 fixture "
            "errors produced, which a genuinely successful run would never emit in the first place. "
            "Deterministic equality of two identically-broken runs is not Stage 2 acceptance."
        ),
        "prohibited_workarounds": PROHIBITED_WORKAROUNDS,
        "corrective_actions_taken": CORRECTIVE_ACTIONS_TAKEN,
        "next_step": (
            "Run a completely fresh full nine-case matrix (new implementation SHA, new disposable trigger "
            "branch and commit, new workflow run) under the corrected content gate, network-enforcement "
            "authorization, and toolchain identity. If repo-requests then produces a genuinely successful "
            "(exit_code=0, zero failed, zero errors) capture pair, inspect whether capture-a and capture-b "
            "are already byte-identical raw, or differ only in pytest's own final-summary duration (the "
            "only nondeterminism source expected to remain once no tracebacks are printed) -- and if so, "
            "build a NEW, separately-reviewed, case-scoped duration-only canonicalization policy with its "
            "own new policy identity and self-hash. If any OTHER raw difference appears, stop and report "
            "it rather than silently extending this or any policy to cover it."
        ),
        "superseded_case_evidence": {
            "record": "stage2-full-matrix-acceptance.json",
            "note": (
                "stage2-full-matrix-acceptance.json's own workflow_run_id 29544801640 is retired as "
                "REJECTED attempt history, not final Stage 2 acceptance evidence, pending a fresh full "
                "matrix run and a rebuilt acceptance record."
            ),
        },
    }
    text = json.dumps(body, indent=2, sort_keys=True) + "\n"
    body["record_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    return body


def main() -> int:
    body = build_record()
    without_hash = {k: v for k, v in body.items() if k != "record_sha256"}
    recomputed = hashlib.sha256((json.dumps(without_hash, indent=2, sort_keys=True) + "\n").encode()).hexdigest()
    assert recomputed == body["record_sha256"], "self-hash did not verify stable"
    OUT_PATH.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT_PATH} (record_sha256={body['record_sha256']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
