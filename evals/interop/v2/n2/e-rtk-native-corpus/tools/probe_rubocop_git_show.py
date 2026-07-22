#!/usr/bin/env python3
"""rubocop `rtk git show` capture (harness 2/3) -- OBSERVATIONS ONLY, two modes:

  --mode diagnostic  : BARRED from qualification (record_kind rubocop_git_show_diagnostic_capture,
                       barred_from_qualification=True). Reveals RTK's real `git show` output mode
                       (compact | raw_fallback) and validates the source-grounded parser BEFORE freeze.
  --mode acceptance  : NOT barred; the fresh observation a qualifying dispatch record is built from.

Both re-acquire the pinned rubocop checkout FRESH (base commit f0ec1b58...), run RAW `git show` and
RTK `rtk git show` network-denied with an identical deterministic git env, and INDEPENDENTLY cross-
check the RAW projection against git plumbing (`rev-parse HEAD`, `git show --numstat/--name-status/
--shortstat`) on the same checkout. The plumbing outputs are VERIFIER OBSERVATIONS -- never the RAW
arm. The record decides NO verdict; the dispatch recompute is the sole authority.

Normative projection: STAT + IDENTITY core only (full_commit_oid via unambiguous abbreviated prefix,
affected_paths SET, files_changed/insertions/deletions). %ar / author / subject / dates / full patch
are non-normative.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import run_canary_case as rcc  # noqa: E402
import n2e_measure as m  # noqa: E402
import n2e_case_adapters as adapters  # noqa: E402
import n2e_rtk_git_show_oracle as orc  # noqa: E402

CONTRACT = N2E_DIR / "n2e-canary-execution-contract-v1.json"
SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
RECORD_TYPE = "n2e-rubocop-git-show-capture"
DIAG_KIND = "rubocop_git_show_diagnostic_capture"     # qualification path MUST reject this
ACCEPT_KIND = "rubocop_git_show_acceptance_capture"


def _digest(b: bytes) -> dict:
    return {"sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)}


def _git_measurement_env(scenario: dict, home: Path) -> dict:
    """Deterministic git env identical for BOTH arms (RTK shells out to git internally, so it inherits
    the same env): no pager, no user/system config, fixed identity/TZ/locale + the scenario env."""
    env = {**rcc._git_env(home), "GIT_PAGER": "cat", "PAGER": "cat"}
    env.update(scenario.get("environment") or {})
    env["HOME"] = str(home)
    return env


def _run_split(argv, cwd, wrapper, env_extra, timeout):
    """Run argv network-denied, capturing stdout + stderr SEPARATELY (small git output)."""
    env = m.measurement_env(env_extra)
    full = wrapper + rcc._env_i(env) + list(argv)
    try:
        r = subprocess.run(full, cwd=cwd, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return {"exit_code": r.returncode, "stdout": r.stdout, "stderr": r.stderr, "timed_out": False}
    except subprocess.TimeoutExpired as e:
        return {"exit_code": 124, "stdout": e.stdout or b"", "stderr": e.stderr or b"", "timed_out": True}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", default="rubocop__rubocop-13687::git::show")
    ap.add_argument("--mode", choices=["diagnostic", "acceptance"], default="diagnostic")
    ap.add_argument("--out", required=True)
    ap.add_argument("--evidence", required=True)
    a = ap.parse_args()
    out = Path(a.out).resolve()
    ev = Path(a.evidence).resolve()
    ev.mkdir(parents=True, exist_ok=True)
    case_id = a.case
    barred = a.mode == "diagnostic"

    body = {"case_id": case_id, "mode": a.mode,
            "record_kind": DIAG_KIND if barred else ACCEPT_KIND,
            "barred_from_qualification": barred, "qualification_pass": None,
            "verdict_authority": "dispatch recompute only (producer records observations)",
            "note": ("DIAGNOSTIC ONLY -- reveals RTK output mode + validates parse; moves no gate."
                     if barred else
                     "FRESH acceptance capture; re-acquires the pinned checkout. No gate moved here.")}

    adapter = adapters.adapter_for(case_id)
    contract = next(e for e in c.load_record(CONTRACT)["contracts"] if e["case_id"] == case_id)
    scenario = next(s for s in c.load_record(SCEN)["scenarios"] if s["case_id"] == case_id)
    det = adapter.bind(contract, scenario)
    body["adapter_binding"] = det
    full_oid = det["full_commit_oid"]

    def emit():
        c.write_record(out, c.envelope(record_type=RECORD_TYPE,
                       generated_by="tools/probe_rubocop_git_show.py", **body))

    rtk_bin = os.environ.get("RTK_BIN")
    if not rtk_bin or c.sha256_file(rtk_bin) != rcc.RTK_BINARY_SHA256:
        body["outcome"] = "CAPTURE_REJECTED_RTK_IDENTITY"; emit()
        print("rubocop git show: rtk identity gate failed"); return 0
    body["rtk_binary_sha256"] = c.sha256_file(rtk_bin)

    iso = rcc.resolve_isolation()
    if iso is None:
        body["outcome"] = "CAPTURE_REJECTED_NO_ISOLATION"; emit(); print("no isolation"); return 0
    method, wrapper = iso
    denial = rcc.denial_probe(wrapper)
    body["isolation"] = {"method": method, "denial_probe": denial}
    if not denial["denied"]:
        body["outcome"] = "CAPTURE_REJECTED_ISOLATION_LEAK"; emit(); print("isolation leak"); return 0

    workroot = Path(tempfile.mkdtemp(prefix="n2e-rubocop-gitshow-"))
    try:
        # FRESH acquisition -- fetch + checkout the pinned base commit (depth 2 so `git show` sees the
        # parent and emits the commit's true small diff, not the whole tree).
        acq = rcc.acquire_git(scenario, workroot)
        if not acq.get("identity_verified") or acq.get("commit") != full_oid:
            body["outcome"] = "CAPTURE_REJECTED_ACQUISITION"; body["acquisition"] = acq
            emit(); print("acquisition failed / commit mismatch"); return 0
        body["acquisition_identity"] = {"repository": acq["repository"], "commit": acq["commit"],
                                        "policy": acq["policy"]}
        frozen = workroot / acq["workdir"]
        home = workroot / ".home"
        env_extra = _git_measurement_env(scenario, home)
        body["measurement_env"] = {k: env_extra[k] for k in sorted(env_extra) if k != "PATH"}
        body["cwd"] = str(frozen)
        body["argv"] = {"raw": det["raw_argv"], "rtk": det["rtk_argv"]}

        tmo = contract["timeout_seconds"]
        # ---- RAW arm: `git show` ----
        raw_run = _run_split(det["raw_argv"], str(frozen), wrapper, env_extra, tmo)
        raw_stdout, raw_stderr = raw_run["stdout"], raw_run["stderr"]
        raw_proj = orc.parse_raw(raw_stdout)
        (ev / "raw.stdout.bin").write_bytes(raw_stdout)
        (ev / "raw.stderr.bin").write_bytes(raw_stderr[:65536])
        body["raw_arm"] = {"argv": det["raw_argv"], "exit_code": raw_run["exit_code"],
                           "timed_out": raw_run["timed_out"], "stdout": _digest(raw_stdout),
                           "stderr": _digest(raw_stderr), "projection": raw_proj}

        # ---- RTK arm: `rtk git show` (rtk wraps git internally) ----
        rtk_argv = [rtk_bin] + det["rtk_argv"][1:]
        rtk_run = _run_split(rtk_argv, str(frozen), wrapper, env_extra, tmo)
        rtk_stdout, rtk_stderr = rtk_run["stdout"], rtk_run["stderr"]
        rtk_proj = orc.parse_rtk(rtk_stdout)
        (ev / "rtk.stdout.bin").write_bytes(rtk_stdout)
        (ev / "rtk.stderr.bin").write_bytes(rtk_stderr[:65536])
        body["rtk_arm"] = {"argv": det["rtk_argv"], "exit_code": rtk_run["exit_code"],
                           "timed_out": rtk_run["timed_out"], "stdout": _digest(rtk_stdout),
                           "stderr": _digest(rtk_stderr),
                           "rtk_output_mode": rtk_proj.get("rtk_output_mode"),
                           "projection": rtk_proj}

        # ---- git plumbing OBSERVATIONS (independent authority; never the RAW arm) ----
        plumb = {}
        for name, pv in det["plumbing_observations"].items():
            pr = _run_split(pv, str(frozen), wrapper, env_extra, tmo)
            (ev / f"plumb.{name}.bin").write_bytes(pr["stdout"])
            plumb[name] = {"argv": pv, "exit_code": pr["exit_code"],
                           "stdout": {**_digest(pr["stdout"]),
                                      "text": pr["stdout"].decode("utf-8", "replace")[:4096]}}
        body["plumbing_observations"] = plumb

        # ---- cross-check the RAW projection against plumbing, on the same checkout ----
        cross = orc.plumbing_crosscheck(
            raw_proj, plumb["rev_parse_head"]["stdout"]["text"],
            (ev / "plumb.numstat.bin").read_bytes(),
            (ev / "plumb.name_status.bin").read_bytes(),
            (ev / "plumb.shortstat.bin").read_bytes(), full_oid)
        body["raw_plumbing_crosscheck"] = cross

        # ---- oracle observation (NOT a verdict): stat + identity equivalence ----
        eq = orc.equivalence(raw_proj, rtk_proj, full_oid)
        body["oracle_observation"] = {
            "full_commit_oid": full_oid,
            "rtk_abbreviated_oid": rtk_proj.get("abbreviated_oid"),
            "abbrev_is_prefix_of_full": bool(rtk_proj.get("abbreviated_oid")
                                             and full_oid.startswith((rtk_proj.get("abbreviated_oid") or "").lower())),
            "equivalence": eq,
            "authority_note": "stat + identity core only; %ar/author/subject/dates/full-patch excluded. "
                              "RAW projection independently cross-checked against git plumbing.",
        }
        body["outcome"] = "RUBOCOP_GIT_SHOW_OBSERVED"
        emit()
        print(f"rubocop git show [{a.mode}]: OBSERVED mode={rtk_proj.get('rtk_output_mode')} "
              f"raw_derivable={raw_proj.get('derivable')} rtk_derivable={rtk_proj.get('derivable')} "
              f"crosscheck={cross['consistent']} equivalent={eq.get('equivalent')} "
              f"(files={raw_proj.get('files_changed')} +{raw_proj.get('insertions')} "
              f"-{raw_proj.get('deletions')}) (verifier decides PASS)")
        return 0
    except Exception as e:  # noqa: BLE001
        import traceback
        body["outcome"] = "CAPTURE_ERROR"; body["error"] = f"{type(e).__name__}: {e}"
        body["traceback"] = traceback.format_exc()[-2000:]
        emit(); print("rubocop git show: ERROR", e); return 0
    finally:
        import shutil
        shutil.rmtree(workroot, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
