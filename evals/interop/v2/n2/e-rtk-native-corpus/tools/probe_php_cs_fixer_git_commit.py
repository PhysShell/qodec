#!/usr/bin/env python3
"""php-cs-fixer `rtk git commit` capture (harness 2/3) -- OBSERVATIONS ONLY, two modes:

  --mode diagnostic  : BARRED from qualification (record_kind php_cs_fixer_git_commit_diagnostic_capture).
  --mode acceptance  : NOT barred; the fresh observation a qualifying dispatch record is built from.

`git commit` MUTATES, so RAW and RTK cannot share a checkout: the probe prepares ONE checkout (fresh
acquisition + the deterministic staged state + the pinned commit determinants), then COPIES it to two
byte-identical checkouts and commits in each independently. Under the git-commit-determinant-v1 policy
(author/committer name+email+date, timezone, message, parent, the exact staged tree, signing off,
hooks inactive) the RAW `git commit` and RTK `rtk git commit` MUST produce the SAME full commit OID.
The hash is never normalized: if it diverges, a determinant leaked -- a real finding.

The oracle (rtk-git-commit-oracle-v1) claims ONLY outcome + the created commit's abbreviated OID; the
resulting-ref identity (RAW OID == RTK OID, parent == base, abbrev is a prefix) is proven from git
plumbing captured on each arm's own checkout.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import run_canary_case as rcc  # noqa: E402
import n2e_case_adapters as adapters  # noqa: E402
import n2e_rtk_git_commit_oracle as orc  # noqa: E402
import probe_rubocop_git_show as rgs  # noqa: E402  (reuse _git_measurement_env / _run_split / _digest)

CONTRACT = N2E_DIR / "n2e-canary-execution-contract-v1.json"
SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
RECORD_TYPE = "n2e-php-cs-fixer-git-commit-capture"
DIAG_KIND = "php_cs_fixer_git_commit_diagnostic_capture"     # qualification path MUST reject this
ACCEPT_KIND = "php_cs_fixer_git_commit_acceptance_capture"


def _apply_determinants(repo: Path, env: dict, hooks_dir: Path):
    """Pin the commit determinants on the prepared repo BEFORE copying to both arms: signing off,
    hooks inactive (empty hooksPath). Author/committer identity + dates + tz are supplied by env."""
    hooks_dir.mkdir(exist_ok=True)
    for kv in (["commit.gpgsign", "false"], ["core.hooksPath", str(hooks_dir)]):
        subprocess.run(["git", "-C", str(repo), "config", *kv], check=True, env=env)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", default="php-cs-fixer__php-cs-fixer-8075::git::commit")
    ap.add_argument("--mode", choices=["diagnostic", "acceptance"], default="diagnostic")
    ap.add_argument("--out", required=True)
    ap.add_argument("--evidence", required=True)
    a = ap.parse_args()
    out = Path(a.out).resolve(); ev = Path(a.evidence).resolve(); ev.mkdir(parents=True, exist_ok=True)
    case_id = a.case
    barred = a.mode == "diagnostic"

    body = {"case_id": case_id, "mode": a.mode,
            "record_kind": DIAG_KIND if barred else ACCEPT_KIND,
            "barred_from_qualification": barred, "qualification_pass": None,
            "verdict_authority": "dispatch recompute only (producer records observations)",
            "note": ("DIAGNOSTIC ONLY -- reveals whether the commit OID reproduces; moves no gate."
                     if barred else "FRESH acceptance capture; re-acquires + re-commits. No gate moved here.")}

    adapter = adapters.adapter_for(case_id)
    contract = next(e for e in c.load_record(CONTRACT)["contracts"] if e["case_id"] == case_id)
    scenario = next(s for s in c.load_record(SCEN)["scenarios"] if s["case_id"] == case_id)
    det = adapter.bind(contract, scenario)
    body["adapter_binding"] = det
    base_commit = det["base_commit"]

    def emit():
        c.write_record(out, c.envelope(record_type=RECORD_TYPE,
                       generated_by="tools/probe_php_cs_fixer_git_commit.py", **body))

    rtk_bin = os.environ.get("RTK_BIN")
    if not rtk_bin or c.sha256_file(rtk_bin) != rcc.RTK_BINARY_SHA256:
        body["outcome"] = "CAPTURE_REJECTED_RTK_IDENTITY"; emit()
        print("php-cs-fixer commit: rtk identity gate failed"); return 0
    body["rtk_binary_sha256"] = c.sha256_file(rtk_bin)

    iso = rcc.resolve_isolation()
    if iso is None:
        body["outcome"] = "CAPTURE_REJECTED_NO_ISOLATION"; emit(); print("no isolation"); return 0
    method, wrapper = iso
    denial = rcc.denial_probe(wrapper)
    body["isolation"] = {"method": method, "denial_probe": denial}
    if not denial["denied"]:
        body["outcome"] = "CAPTURE_REJECTED_ISOLATION_LEAK"; emit(); print("isolation leak"); return 0

    workroot = Path(tempfile.mkdtemp(prefix="n2e-phpcs-commit-"))
    try:
        # FRESH acquisition -> a repo at workroot/repo with N2E_DIRTY.txt staged (the commit subfamily's
        # deterministic dirty state, built by run_canary_case._construct_git_state).
        acq = rcc.acquire_git(scenario, workroot)
        if not acq.get("identity_verified") or acq.get("commit") != base_commit:
            body["outcome"] = "CAPTURE_REJECTED_ACQUISITION"; body["acquisition"] = acq
            emit(); print("acquisition failed / base commit mismatch"); return 0
        body["acquisition_identity"] = {"repository": acq["repository"], "commit": acq["commit"],
                                        "policy": acq["policy"], "git_state": acq.get("git_state")}
        prepared = workroot / acq["workdir"]
        home = workroot / ".home"
        env_extra = rgs._git_measurement_env(scenario, home)
        cfg_env = {**rcc._git_env(home), "GIT_PAGER": "cat", "PAGER": "cat"}
        _apply_determinants(prepared, cfg_env, workroot / "empty-hooks")
        body["determinant_policy_id"] = det["determinant_policy_id"]
        body["measurement_env"] = {k: env_extra[k] for k in sorted(env_extra) if k != "PATH"}
        body["argv"] = {"raw": det["raw_argv"], "rtk": det["rtk_argv"]}

        # prove the two prepared checkouts stage an IDENTICAL tree (write-tree on the shared source)
        wt = subprocess.run(["git", "-C", str(prepared), "write-tree"], capture_output=True, text=True, env=cfg_env)
        body["staged_tree_oid"] = wt.stdout.strip()

        # COPY to two byte-identical checkouts (each arm commits independently; git commit mutates HEAD)
        raw_dir, rtk_dir = workroot / "raw", workroot / "rtk"
        shutil.copytree(prepared, raw_dir); shutil.copytree(prepared, rtk_dir)

        tmo = contract["timeout_seconds"]

        def _arm(role, wd, argv):
            run = rgs._run_split(argv, str(wd), wrapper, env_extra, tmo)
            (ev / f"{role}.stdout.bin").write_bytes(run["stdout"])
            (ev / f"{role}.stderr.bin").write_bytes(run["stderr"][:65536])
            plumb = {}
            for name, pv in det["post_commit_observations"].items():
                pr = rgs._run_split(pv, str(wd), wrapper, env_extra, tmo)
                (ev / f"{role}.plumb.{name}.bin").write_bytes(pr["stdout"])
                plumb[name] = {"argv": pv, "exit_code": pr["exit_code"],
                               "stdout": {**rgs._digest(pr["stdout"]),
                                          "text": pr["stdout"].decode("utf-8", "replace")[:4096]}}
            return run, plumb

        # RAW arm: `git commit -m n2e`
        raw_run, raw_plumb = _arm("raw", raw_dir, det["raw_argv"])
        raw_state = orc.parse_git_state(raw_run["exit_code"],
                                        raw_plumb["head"]["stdout"]["text"],
                                        raw_plumb["parent"]["stdout"]["text"],
                                        (ev / "raw.plumb.name_status.bin").read_bytes(), base_commit)
        body["raw_arm"] = {"argv": det["raw_argv"], "exit_code": raw_run["exit_code"],
                           "stdout": {**rgs._digest(raw_run["stdout"]),
                                      "text": raw_run["stdout"].decode("utf-8", "replace")[:2048]},
                           "plumbing": raw_plumb, "git_state": raw_state}

        # RTK arm: `rtk git commit -m n2e`
        rtk_argv = [rtk_bin] + det["rtk_argv"][1:]
        rtk_run, rtk_plumb = _arm("rtk", rtk_dir, rtk_argv)
        rtk_parsed = orc.parse_rtk(rtk_run["stdout"])
        rtk_state = orc.parse_git_state(rtk_run["exit_code"],
                                        rtk_plumb["head"]["stdout"]["text"],
                                        rtk_plumb["parent"]["stdout"]["text"],
                                        (ev / "rtk.plumb.name_status.bin").read_bytes(), base_commit)
        body["rtk_arm"] = {"argv": det["rtk_argv"], "exit_code": rtk_run["exit_code"],
                           "stdout": {**rgs._digest(rtk_run["stdout"]),
                                      "text": rtk_run["stdout"].decode("utf-8", "replace")[:2048]},
                           "parsed": rtk_parsed, "plumbing": rtk_plumb, "git_state": rtk_state}

        eq = orc.equivalence(raw_state, rtk_state, rtk_parsed, base_commit)
        body["oracle_observation"] = {
            "base_commit": base_commit, "staged_tree_oid": body["staged_tree_oid"],
            "raw_commit_oid": raw_state.get("full_commit_oid"),
            "rtk_commit_oid": rtk_state.get("full_commit_oid"),
            "oid_reproduced": raw_state.get("full_commit_oid") == rtk_state.get("full_commit_oid"),
            "equivalence": eq,
            "authority_note": "resulting-ref identity: RAW commit OID == RTK commit OID (never "
                              "normalized). RTK reports only outcome + abbreviated OID.",
        }
        body["outcome"] = "PHP_CS_FIXER_GIT_COMMIT_OBSERVED"
        emit()
        print(f"php-cs-fixer commit [{a.mode}]: OBSERVED raw_oid={raw_state.get('full_commit_oid','?')[:12]} "
              f"rtk_oid={rtk_state.get('full_commit_oid','?')[:12]} "
              f"reproduced={body['oracle_observation']['oid_reproduced']} "
              f"rtk_out={rtk_run['stdout'].decode('utf-8','replace').strip()[:32]!r} "
              f"equivalent={eq.get('equivalent')} mismatches={eq.get('mismatches')} (verifier decides PASS)")
        return 0
    except Exception as e:  # noqa: BLE001
        import traceback
        body["outcome"] = "CAPTURE_ERROR"; body["error"] = f"{type(e).__name__}: {e}"
        body["traceback"] = traceback.format_exc()[-2000:]
        emit(); print("php-cs-fixer commit: ERROR", e); return 0
    finally:
        shutil.rmtree(workroot, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
