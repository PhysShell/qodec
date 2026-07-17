#!/usr/bin/env python3
"""N2-D1b: verifies the repo-requests-only timeout-sink network fixture
(generic_sandbox_policy.py's TIMEOUT_SINK_AUTHORIZED_CASES /
TIMEOUT_SINK_APPROVAL_IDENTITIES) is exactly what it claims to be, in the
same envelope (same run_confined_build.sh outer netns, same sandboy_bin,
same policy.toml, same cwd/env) the real capture uses -- run BEFORE that
capture, for every case_id gsp.TIMEOUT_SINK_AUTHORIZED_CASES names
(currently repo-requests only, whose pytest suite hardcodes 10.255.255.1
expecting a real socket.timeout -- the same address the `requests` library's
own upstream test suite hardcodes for exactly this purpose in a normal,
non-sandboxed environment; not an arbitrary test-suite artifact).

This is a SEPARATE, additional authorization layer on top of the existing
network_enforcement_mode = "outer-netns-loopback-only" exception
(network_enforcement_probe.py) -- it is never folded into that field or
approval identity. The two are recorded as distinct receipt fields
(`network_enforcement_mode` vs `test_network_fixture`); see generic_capture.
py's own receipt-building comment for why. "Do not broaden the existing
loopback-only approval into this behavior silently" (D1b remediation,
2026-07-17).

Three probes, all through the identical envelope:
  1. timeout_sink_target_probe.py -- the authorized sink target must
     produce a genuine socket.timeout at a caller-controlled deadline,
     never a synchronous OSError.
  2. canary/tools/network_probe.py -- every OTHER external target
     (unrelated to the sink) must remain unreachable -- the fixture must
     not permit arbitrary RFC1918/external connectivity.
  3. loopback_bind_probe.py -- loopback bind+connect must remain allowed.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
CANARY_TOOLS = TOOLS_DIR.parents[1] / "canary" / "tools"
for p in (CANARY_TOOLS, TOOLS_DIR):
    sys.path.insert(0, str(p))

import capture_build  # noqa: E402

NEGATIVE_PROBE_SCRIPT = CANARY_TOOLS / "network_probe.py"
POSITIVE_PROBE_SCRIPT = TOOLS_DIR / "loopback_bind_probe.py"
SINK_TARGET_PROBE_SCRIPT = TOOLS_DIR / "timeout_sink_target_probe.py"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run_probe(sandboy_bin: Path, policy_path: Path, cwd: Path, env: dict, script: Path) -> dict:
    result = capture_build.run_real_build(sandboy_bin, policy_path, cwd, ["python3", str(script)], env)
    try:
        parsed = json.loads(result["raw_stdout"].strip().splitlines()[-1]) if result["raw_stdout"].strip() else {}
    except (json.JSONDecodeError, IndexError):
        parsed = {"parse_error": True}
    return {
        "argv": result["argv"],
        "exit_code": result["exit_code"],
        "raw_stdout_sha256": sha256_bytes(result["raw_stdout"]),
        "raw_stderr_sha256": sha256_bytes(result["raw_stderr"]),
        # Diagnostic-only probe report (never the canonical benchmark
        # stream) -- the decoded text, not just its hash, is recorded
        # directly, mirroring network_enforcement_probe.py's own rationale.
        "raw_stdout_text": result["raw_stdout"].decode("utf-8", errors="replace"),
        "raw_stderr_text": result["raw_stderr"].decode("utf-8", errors="replace"),
        "parsed_result": parsed,
    }


def run_timeout_sink_checks(*, case_id: str, sink_target: str, test_network_fixture: str,
                             sandboy_bin: Path, policy_path: Path, cwd: Path, env: dict) -> dict:
    """Runs all three probes through the SAME envelope as the real capture
    that follows, for `case_id` (must be a key of generic_sandbox_policy.py's
    TIMEOUT_SINK_AUTHORIZED_CASES -- the caller is responsible for that
    gate; this function does not re-check it). `env` must already contain
    N2D1B_TIMEOUT_SINK_TARGET=sink_target (the caller sets this once and
    reuses it for both the probes and the real capture run that follows --
    see generic_capture.py). Raises nothing itself -- the caller decides how
    to fail based on `timeout_sink_verified`."""
    sink = _run_probe(sandboy_bin, policy_path, cwd, env, SINK_TARGET_PROBE_SCRIPT)
    negative = _run_probe(sandboy_bin, policy_path, cwd, env, NEGATIVE_PROBE_SCRIPT)
    positive = _run_probe(sandboy_bin, policy_path, cwd, env, POSITIVE_PROBE_SCRIPT)

    sink_is_genuine_timeout = (
        sink["parsed_result"].get("result") == "TIMEOUT"
        and sink["parsed_result"].get("elapsed_within_bounds") is True
        and sink["exit_code"] == 0
    )
    any_other_external_reachable = any(
        r.get("result") == "REACHABLE" for r in negative["parsed_result"].get("probe_results", [])
    )
    loopback_allowed = positive["parsed_result"].get("result") == "ALLOWED" and positive["exit_code"] == 0

    return {
        "report_type": "n2d1b-timeout-sink-probe-v1",
        "authorized_case_id": case_id,
        "test_network_fixture": test_network_fixture,
        "sink_target": sink_target,
        "sink_target_probe": sink,
        "other_external_connectivity_probe": negative,
        "loopback_bind_connect_probe": positive,
        "sink_target_confirmed_genuine_timeout": sink_is_genuine_timeout,
        "other_external_connectivity_confirmed_blocked": not any_other_external_reachable,
        "loopback_bind_connect_confirmed_allowed": loopback_allowed,
        "timeout_sink_verified": (
            sink_is_genuine_timeout and (not any_other_external_reachable) and loopback_allowed
        ),
    }
