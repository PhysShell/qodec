#!/usr/bin/env python3
"""Loghub ACCEPTANCE capture (harness 2/3 for the dispatch-v2 path) -- OBSERVATIONS ONLY.

Unlike the diagnostic capture (which is BARRED), this probe produces the FRESH two-arm observation a
qualifying dispatch-v2 record is built from. It is NOT barred and carries no diagnostic record_kind.
It NEVER emits a verdict: it records observations, and the dispatch-v2 recompute (in the aggregator /
the standalone verifier) independently re-derives the RAW<->RTK severity equivalence.

Discipline (identical to the diagnostic capture, re-run FRESH):
  * the RAW arm (`cat HDFS.log`, ~1.5 GB) is STREAMED through the bounded log-evidence capsule -- its
    stdout is never held whole; one pass yields sha256 + byte/line counts + the published-authority
    summary + the RTK-semantic severity projection;
  * the RTK arm (`rtk log HDFS.log`) output is small and captured WHOLE, and FROZEN in full to the
    evidence dir (raw.rtk.stdout.bin) so the built record can pin it by content hash -- the dispatch
    recompute re-parses exactly those bytes;
  * both arms read the SAME pinned member (cat stdout digest == member digest; member byte-identical
    before/after); the acquisition RE-DOWNLOADS + RE-STREAMS (no reuse of any diagnostic capsule or
    the frozen rtk-log-summary fixture as the acceptance stream).

Normative equality is on SEVERITY TOTALS ONLY (errors/warnings/info); RTK's unique counts are never
compared to the 46 published EventIds.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import run_canary_case as rcc  # noqa: E402
import n2e_case_adapters as adapters  # noqa: E402
import n2e_log_evidence_capsule as lcap  # noqa: E402
import n2e_rtk_log_hdfs_oracle as orc  # noqa: E402
import probe_loghub_diagnostic as diag  # noqa: E402  (reuse the proven streaming helpers)

CONTRACT = N2E_DIR / "n2e-canary-execution-contract-v1.json"
SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
ACCEPT_RECORD_KIND = "loghub_acceptance_capture"   # NOT the barred diagnostic kind
RECORD_TYPE = "n2e-loghub-acceptance-capture"


def _write(out: Path, body: dict):
    c.write_record(out, c.envelope(record_type=RECORD_TYPE,
                                   generated_by="tools/probe_loghub_acceptance.py", **body))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", default="loghub::HDFS::log")
    ap.add_argument("--out", required=True)
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--raw-timeout", type=int, default=3600)
    a = ap.parse_args()
    out = Path(a.out).resolve()
    ev = Path(a.evidence).resolve()
    ev.mkdir(parents=True, exist_ok=True)
    case_id = a.case

    body = {"case_id": case_id, "record_kind": ACCEPT_RECORD_KIND,
            "barred_from_qualification": False, "qualification_pass": None,
            "verdict_authority": "dispatch-v2 recompute only (producer records observations)",
            "note": "FRESH two-arm acceptance capture; the RAW arm re-acquires + re-streams the full "
                    "pinned member (no diagnostic-capsule / fixture reuse). No gate moved here."}

    adapter = adapters.adapter_for(case_id)
    contract = next(e for e in c.load_record(CONTRACT)["contracts"] if e["case_id"] == case_id)
    scenario = next(s for s in c.load_record(SCEN)["scenarios"] if s["case_id"] == case_id)
    det = adapter.bind(contract, scenario)
    body["adapter_binding"] = det

    rtk_bin = os.environ.get("RTK_BIN")
    if not rtk_bin or c.sha256_file(rtk_bin) != rcc.RTK_BINARY_SHA256:
        body["outcome"] = "ACCEPT_REJECTED_RTK_IDENTITY"; _write(out, body)
        print("loghub accept: rtk identity gate failed"); return 0
    body["rtk_binary_sha256"] = c.sha256_file(rtk_bin)

    iso = rcc.resolve_isolation()
    if iso is None:
        body["outcome"] = "ACCEPT_REJECTED_NO_ISOLATION"; _write(out, body)
        print("loghub accept: no isolation"); return 0
    method, wrapper = iso
    denial = rcc.denial_probe(wrapper)
    body["isolation"] = {"method": method, "denial_probe": denial}
    if not denial["denied"]:
        body["outcome"] = "ACCEPT_REJECTED_ISOLATION_LEAK"; _write(out, body)
        print("loghub accept: isolation leak"); return 0

    workroot = Path(tempfile.mkdtemp(prefix="n2e-loghub-accept-"))
    try:
        # FRESH acquisition -- streaming download + member extraction (NO slice, NO reuse)
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
        raw_run = diag._stream_isolated(raw_argv, str(frozen), wrapper, col.feed, a.raw_timeout)
        col.finish()
        capsule_summary = col.summary()
        raw_stderr = raw_run["stderr"]
        body["raw_arm"] = {
            "argv": raw_argv, "exit_code": raw_run["exit_code"], "timed_out": raw_run["timed_out"],
            "stdout": {"sha256": col.stream_sha256, "bytes": col.total_bytes, "line_count": col.total_lines},
            "stderr": diag._digest(raw_stderr),
            "capsule_summary": capsule_summary,
        }
        (ev / "raw.stderr.bin").write_bytes(raw_stderr[:65536])

        # ---- RTK arm: `rtk log HDFS.log` -- small output captured WHOLE and FROZEN IN FULL ----
        rtk_run = diag._run_isolated_split(rtk_argv, str(frozen), wrapper, contract["timeout_seconds"])
        rtk_stdout, rtk_stderr = rtk_run["stdout"], rtk_run["stderr"]
        rtk_proj = orc.parse_rtk(rtk_stdout)
        rtk_full = ev / "raw.rtk.stdout.bin"          # the FULL fresh RTK output, pinned by the record
        rtk_full.write_bytes(rtk_stdout)
        body["rtk_arm"] = {
            "argv": det["rtk_argv"], "exit_code": rtk_run["exit_code"], "timed_out": rtk_run["timed_out"],
            "stdout": {**diag._digest(rtk_stdout), "evidence_path_basename": rtk_full.name},
            "stderr": diag._digest(rtk_stderr),
            "parsed_severity_projection": rtk_proj,    # observation; the verifier re-parses the frozen bytes
        }
        (ev / "raw.rtk.stderr.bin").write_bytes(rtk_stderr[:65536])

        # ---- prove BOTH arms read the SAME bytes (fresh) ----
        member_after = lcap.stream_digest(member_path)
        body["same_input_proof"] = {
            "input_member_sha256": member_sha,
            "raw_stdout_sha256": col.stream_sha256,
            "raw_stdout_equals_member": col.stream_sha256 == member_sha,
            "member_unchanged_after": member_after["sha256"] == member_sha,
            "rtk_read_same_member_path": det["rtk_argv"][-1] == det["raw_argv"][-1] == det["input_file"],
        }

        # ---- observation (NOT a verdict): severity equivalence on TOTALS ONLY ----
        raw_ref = orc.raw_projection_from_capsule(capsule_summary)
        body["oracle_observation"] = {
            "raw_projection": raw_ref, "rtk_projection": rtk_proj,
            "equivalence": orc.equivalence(raw_ref, rtk_proj),
            "authority_note": "published Loghub set governs the RAW capsule identity; the RTK oracle "
                              "proves only severity TOTALS. Unique counts are never compared to the 46 "
                              "published EventIds. The dispatch-v2 recompute is the sole verdict.",
        }
        body["outcome"] = "LOGHUB_ACCEPTANCE_OBSERVED"
        _write(out, body)
        eq = body["oracle_observation"]["equivalence"]
        print(f"loghub accept: OBSERVED raw_lines={col.total_lines} "
              f"capsule={capsule_summary.get('outcome')} rtk_derivable={rtk_proj.get('derivable')} "
              f"severity_equivalent={eq.get('equivalent')} (verifier decides PASS)")
        return 0
    except Exception as e:  # noqa: BLE001
        import traceback
        body["outcome"] = "ACCEPT_ERROR"; body["error"] = f"{type(e).__name__}: {e}"
        body["traceback"] = traceback.format_exc()[-2000:]
        _write(out, body)
        print("loghub accept: ERROR", e); return 0
    finally:
        import shutil
        shutil.rmtree(workroot, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
