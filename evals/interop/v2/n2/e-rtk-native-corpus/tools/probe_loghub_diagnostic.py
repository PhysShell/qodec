#!/usr/bin/env python3
"""Loghub DIAGNOSTIC-ONLY capture -- explicitly BARRED from qualification. It exists to reveal the
real `rtk log HDFS.log` output on the pinned full stream and to VALIDATE the source-grounded parser
(n2e_rtk_log_hdfs_oracle) against it, before any qualifying run. It emits NO qualification record and
moves NO gate.

Separate from the generic in-memory run_arm: the RAW arm (`cat HDFS.log`, ~1.5 GB) is STREAMED --
its stdout is never held whole; a single streaming pass computes sha256 + byte count + line count AND
builds the bounded log-evidence-capsule (published-authority summary + the RTK-semantic severity
projection). The RTK arm (`rtk log HDFS.log`) output is small and captured whole. Both arms' stderr
are hashed + sized separately. Both arms read the SAME pinned member (proven: cat's stdout digest ==
the member digest, and the member is byte-identical before/after). The record carries a diagnostic
record_kind that the qualification verifier rejects unconditionally.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import run_canary_case as rcc  # noqa: E402
import n2e_measure as m  # noqa: E402
import n2e_case_adapters as adapters  # noqa: E402
import n2e_log_evidence_capsule as lcap  # noqa: E402
import n2e_rtk_log_hdfs_oracle as orc  # noqa: E402

CONTRACT = N2E_DIR / "n2e-canary-execution-contract-v1.json"
SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
DIAG_RECORD_KIND = "loghub_diagnostic_capture"   # qualification verifier MUST reject this


def _digest(b: bytes) -> dict:
    return {"sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)}


def _stream_isolated(argv, cwd, wrapper, feed, timeout):
    """Run argv network-denied, STREAMING stdout in 1 MiB chunks to `feed` (stdout never buffered
    whole); drain stderr in a thread. A wall-clock deadline is a first-class outcome."""
    env = m.measurement_env({"HOME": str(Path(cwd).parent / ".home")})
    full = wrapper + rcc._env_i(env) + list(argv)
    p = subprocess.Popen(full, cwd=cwd, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    err_box: list[bytes] = []
    t = threading.Thread(target=lambda: err_box.append(p.stderr.read()))
    t.start()
    timed_out = False
    start = time.monotonic()
    while True:
        if time.monotonic() - start > timeout:
            p.kill()
            timed_out = True
            break
        chunk = p.stdout.read(1 << 20)
        if not chunk:
            break
        feed(chunk)
    try:
        p.wait(timeout=30)
    except subprocess.TimeoutExpired:
        p.kill()
    t.join()
    return {"exit_code": p.returncode, "stderr": (err_box[0] if err_box else b""), "timed_out": timed_out}


def _run_isolated_split(argv, cwd, wrapper, timeout):
    """Run a SMALL command network-denied, capturing stdout + stderr separately (RTK log output)."""
    env = m.measurement_env({"HOME": str(Path(cwd).parent / ".home")})
    full = wrapper + rcc._env_i(env) + list(argv)
    try:
        r = subprocess.run(full, cwd=cwd, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return {"exit_code": r.returncode, "stdout": r.stdout, "stderr": r.stderr, "timed_out": False}
    except subprocess.TimeoutExpired as e:
        return {"exit_code": 124, "stdout": e.stdout or b"", "stderr": e.stderr or b"", "timed_out": True}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", default="loghub::HDFS::log")
    ap.add_argument("--out", required=True)
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--raw-timeout", type=int, default=3600)  # generous: streaming + full semantic pass
    a = ap.parse_args()
    out = Path(a.out).resolve()
    ev = Path(a.evidence).resolve()
    ev.mkdir(parents=True, exist_ok=True)
    case_id = a.case

    body = {"case_id": case_id, "record_kind": DIAG_RECORD_KIND,
            "barred_from_qualification": True, "qualification_pass": None,
            "note": "DIAGNOSTIC ONLY -- reveals real rtk log output + validates parse_rtk; moves no gate."}

    adapter = adapters.adapter_for(case_id)
    contract = next(e for e in c.load_record(CONTRACT)["contracts"] if e["case_id"] == case_id)
    scenario = next(s for s in c.load_record(SCEN)["scenarios"] if s["case_id"] == case_id)
    det = adapter.bind(contract, scenario)
    body["adapter_binding"] = det

    rtk_bin = os.environ.get("RTK_BIN")
    if not rtk_bin or c.sha256_file(rtk_bin) != rcc.RTK_BINARY_SHA256:
        body["outcome"] = "DIAG_REJECTED_RTK_IDENTITY"; c.write_record(out, c.envelope(
            record_type="n2e-loghub-diagnostic-capture", generated_by=str(HERE), **body))
        print("loghub diag: rtk identity gate failed"); return 0
    body["rtk_binary_sha256"] = c.sha256_file(rtk_bin)

    iso = rcc.resolve_isolation()
    if iso is None:
        body["outcome"] = "DIAG_REJECTED_NO_ISOLATION"; c.write_record(out, c.envelope(
            record_type="n2e-loghub-diagnostic-capture", generated_by=str(HERE), **body))
        print("loghub diag: no isolation"); return 0
    method, wrapper = iso
    body["isolation"] = {"method": method, "denial_probe": rcc.denial_probe(wrapper)}

    workroot = Path(tempfile.mkdtemp(prefix="n2e-loghub-diag-"))
    try:
        # acquisition (network) -- streaming download + member extraction (NO slice)
        acq = rcc.acquire_loghub(scenario, workroot)
        body["acquisition_identity"] = acq["environment_identity"]
        member_sha = acq["input_sha256"]
        frozen = workroot / acq["workdir"]
        member_path = frozen / det["input_file"]
        (frozen / ".home").mkdir(exist_ok=True)

        raw_argv = det["raw_argv"]
        rtk_argv = [rtk_bin] + det["rtk_argv"][1:]
        body["argv"] = {"raw": raw_argv, "rtk": det["rtk_argv"]}
        body["cwd"] = str(frozen)
        body["measurement_env"] = {"HOME": ".home", "network": "denied"}

        # ---- RAW arm: STREAM `cat HDFS.log` through the capsule collector (stdout never buffered) ----
        col = lcap._Collector(lcap.load_reference())
        raw_run = _stream_isolated(raw_argv, str(frozen), wrapper, col.feed, a.raw_timeout)
        col.finish()
        capsule_summary = col.summary()
        raw_stderr = raw_run["stderr"]
        body["raw_arm"] = {
            "argv": raw_argv, "exit_code": raw_run["exit_code"], "timed_out": raw_run["timed_out"],
            "stdout": {"sha256": col.stream_sha256, "bytes": col.total_bytes, "line_count": col.total_lines},
            "stderr": _digest(raw_stderr),
            "capsule_summary": capsule_summary,
        }
        (ev / "raw.stderr.bin").write_bytes(raw_stderr[:65536])

        # ---- RTK arm: `rtk log HDFS.log` -- small output captured WHOLE ----
        rtk_run = _run_isolated_split(rtk_argv, str(frozen), wrapper, contract["timeout_seconds"])
        rtk_stdout, rtk_stderr = rtk_run["stdout"], rtk_run["stderr"]
        rtk_proj = orc.parse_rtk(rtk_stdout)
        body["rtk_arm"] = {
            "argv": det["rtk_argv"], "exit_code": rtk_run["exit_code"], "timed_out": rtk_run["timed_out"],
            "stdout": {**_digest(rtk_stdout), "content": rtk_stdout.decode("utf-8", "replace")[:8192]},
            "stderr": _digest(rtk_stderr),
            "parsed_severity_projection": rtk_proj,  # diagnostic observation, NOT normative semantics
        }
        (ev / "rtk.stdout.bin").write_bytes(rtk_stdout[:65536])
        (ev / "rtk.stderr.bin").write_bytes(rtk_stderr[:65536])

        # ---- prove BOTH arms read the SAME bytes ----
        member_after = lcap.stream_digest(member_path)
        body["same_input_proof"] = {
            "input_member_sha256": member_sha,
            "raw_stdout_sha256": col.stream_sha256,
            "raw_stdout_equals_member": col.stream_sha256 == member_sha,   # cat is identity
            "member_unchanged_after": member_after["sha256"] == member_sha,  # read-only; both arms saw it
            "rtk_read_same_member_path": det["rtk_argv"][-1] == det["raw_argv"][-1] == det["input_file"],
        }

        # ---- DIAGNOSTIC oracle observation (NOT a verdict) ----
        raw_ref = orc.raw_projection_from_capsule(capsule_summary)
        body["oracle_observation"] = {
            "raw_projection": raw_ref, "rtk_projection": rtk_proj,
            "equivalence": orc.equivalence(raw_ref, rtk_proj),
            "authority_note": "published Loghub set governs the RAW capsule identity; the RTK oracle "
                              "proves only severity totals -- this is a diagnostic observation, not a gate.",
        }
        body["outcome"] = "LOGHUB_DIAGNOSTIC_OBSERVED"
        c.write_record(out, c.envelope(record_type="n2e-loghub-diagnostic-capture",
                                       generated_by="tools/probe_loghub_diagnostic.py", **body))
        eq = body["oracle_observation"]["equivalence"]
        print(f"loghub diag: OBSERVED raw_lines={col.total_lines} rtk_derivable={rtk_proj.get('derivable')} "
              f"severity_equivalent={eq.get('equivalent')} (DIAGNOSTIC; no gate moved)")
        return 0
    except Exception as e:  # noqa: BLE001
        import traceback
        body["outcome"] = "DIAG_ERROR"; body["error"] = f"{type(e).__name__}: {e}"
        body["traceback"] = traceback.format_exc()[-2000:]
        c.write_record(out, c.envelope(record_type="n2e-loghub-diagnostic-capture",
                                       generated_by="tools/probe_loghub_diagnostic.py", **body))
        print("loghub diag: ERROR", e); return 0
    finally:
        import shutil
        shutil.rmtree(workroot, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
