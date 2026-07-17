#!/usr/bin/env python3
"""N2-D1b: in-sandbox probe script for the repo-requests-only timeout-sink
network fixture (generic_sandbox_policy.py's TIMEOUT_SINK_AUTHORIZED_CASES).
Run THROUGH run_confined_build.sh's outer network namespace (which, only
when N2D1B_TIMEOUT_SINK_TARGET is set in its preserved environment, adds a
veth-pair route for exactly that target -- see that script's own comment
block), this connects to the authorized sink target with a short,
deterministic timeout and requires exactly `socket.timeout` -- never a
synchronous OSError. An immediate ENETUNREACH/ECONNREFUSED/EHOSTUNREACH
means the route+device arrangement does not have the "genuinely dropped
traffic, no real L2 peer ever answers" semantics this fixture requires (the
D1b decision record's explicit warning against `blackhole`/`unreachable`/
`prohibit` Linux route types, which return exactly such a synchronous errno
at connect()-time instead of blocking): a route via a real (if otherwise
inert) veth peer forces genuine, never-answered ARP resolution, so the
CALLER's own socket.settimeout() is what actually fires.

Never hardcodes the target address itself -- takes it as argv[1] (the
caller, timeout_sink_probe.py, passes generic_sandbox_policy.py's own
TIMEOUT_SINK_AUTHORIZED_CASES[case_id] value), so a mismatch between the
authorized target and the probed target is impossible by construction.

argv, not an env var: real CI evidence (run 29548972173) showed Sandboy's
own env_clear() + env_allow confinement strips N2D1B_TIMEOUT_SINK_TARGET
before exec'ing this script even though run_confined_build.sh's OUTER
sudo/unshare layer correctly preserves it -- that outer env var is read by
the unconfined bash wrapper that sets up the veth-pair route (before
Sandboy ever runs), never by anything inside Sandboy's own confinement.
Command-line argv, unlike env vars, is not subject to Sandboy's env
allowlist, so it reaches this confined script intact. Falls back to the
N2D1B_TIMEOUT_SINK_TARGET env var (only) when no argv is given, to keep
ad hoc local invocation (e.g. a live probe outside the full pilot-case
plumbing) working unchanged.
"""
import json
import os
import socket
import sys
import time

# Deliberately short and different from the real workload's own eventual
# per-test timeout -- this probe only needs to prove the MECHANISM works,
# not reproduce the real test suite's exact timing.
PROBE_TIMEOUT_S = 0.2
PROBE_PORT = 80


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("N2D1B_TIMEOUT_SINK_TARGET")
    if not target:
        print(json.dumps({
            "result": "MISCONFIGURED",
            "error": "sink target not provided via argv[1] or N2D1B_TIMEOUT_SINK_TARGET",
        }))
        sys.exit(2)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(PROBE_TIMEOUT_S)
    start = time.time()
    try:
        s.connect((target, PROBE_PORT))
        elapsed = time.time() - start
        result = {"result": "CONNECTED", "target": target, "elapsed_s": elapsed}
    except socket.timeout:
        elapsed = time.time() - start
        # Generous upper bound (not a tight equality check): the requirement
        # is "bounded and consistent with the requested timeout", not
        # microsecond precision -- real CI runners are noisier than this
        # assistant's own local validation environment.
        result = {
            "result": "TIMEOUT",
            "target": target,
            "elapsed_s": elapsed,
            "elapsed_within_bounds": (PROBE_TIMEOUT_S * 0.5) <= elapsed <= (PROBE_TIMEOUT_S * 10 + 1.0),
        }
    except OSError as e:
        elapsed = time.time() - start
        result = {
            "result": "SYNCHRONOUS_ERROR",
            "target": target,
            "elapsed_s": elapsed,
            "errno": e.errno,
            "error": str(e),
        }
    finally:
        s.close()

    print(json.dumps(result))
    ok = result["result"] == "TIMEOUT" and result.get("elapsed_within_bounds") is True
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
