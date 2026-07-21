#!/usr/bin/env python3
"""Generic per-case acceptance PROBE (harness 2/3) -- OBSERVATIONS ONLY.

Orchestration only: it selects ONE pre-registered adapter (n2e_case_adapters), DOUBLE-LOCKS its
determinants against the frozen execution contract + scenario, closes the frozen loader closure,
reuses run_canary_case's proven acquisition + isolation + run_arm (fresh network-denied copies per
rep), captures FRESH RAW/RTK streams, freezes the accepted canonical bytes, computes digests, and
records determinism -- then hands the observations to the independent verifier (harness 3/3). It
NEVER emits a qualification verdict.

Go cache isolation (adapter execution_isolation): GOCACHE is pinned INTO the per-rep work copy
(rcc._FIXEDWORK/.n2e-gocache, empty in the frozen dir), so EVERY rep of BOTH arms really compiles +
executes the target -- never one arm real, one `(cached)`. The module cache (warm-populated, offline)
persists; only the build/test cache is fresh.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402
import n2e_case_adapters as adapters  # noqa: E402
import run_canary_case as rcc  # noqa: E402

CONTRACT = L.CONTRACT
SCEN = L.SCEN
DEFAULT_CASE = adapters.CaddyGoTestAdapter.case_id


def _emit(out: Path, body: dict):
    c.write_record(out, c.envelope(record_type="n2e-resolved-case-observation",
                   generated_by="tools/probe_case_qualification.py", **body))


def _freeze_canonical(evidence: Path, role: str, data: bytes) -> dict:
    p = evidence / f"{role}.canonical.bin"
    p.write_bytes(data)
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", default=DEFAULT_CASE)
    ap.add_argument("--out", required=True)
    ap.add_argument("--evidence", required=True)
    args = ap.parse_args()
    out = Path(args.out).resolve(); evidence = Path(args.evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    case_id = args.case

    body = {"case_id": case_id, "record_kind": "resolved_case_qualification_acceptance",
            "qualification_pass": None, "acceptance_pass": False,
            "verdict_authority": "independent case-qualification verifier only (producer records observations)"}

    # STEP 1: adapter + double-lock binding against the frozen contract/scenario
    try:
        adapter = adapters.adapter_for(case_id)
        contract = next(e for e in c.load_record(CONTRACT)["contracts"] if e["case_id"] == case_id)
        scenario = next(s for s in c.load_record(SCEN)["scenarios"] if s["case_id"] == case_id)
        det = adapter.bind(contract, scenario)
    except Exception as e:  # noqa: BLE001
        body["outcome"] = "CASE_ADAPTER_BINDING_FAILURE"; body["error"] = f"{type(e).__name__}: {e}"
        _emit(out, body); print("case probe: adapter binding failure", e); return 0
    body["adapter_binding"] = det

    # STEP 2: close the frozen loader closure (corpus integrity) BEFORE running
    try:
        L.validate_resolved_closure()
    except Exception as e:  # noqa: BLE001
        body["outcome"] = "CASE_CLOSURE_FAILURE"; body["error"] = f"{type(e).__name__}: {e}"
        _emit(out, body); print("case probe: closure failure", e); return 0

    # STEP 3: rtk binary identity gate + isolation
    rtk_bin = os.environ.get("RTK_BIN")
    if not rtk_bin or c.sha256_file(rtk_bin) != rcc.RTK_BINARY_SHA256:
        body["outcome"] = "CASE_REJECTED_RTK_IDENTITY"; _emit(out, body)
        print("case probe: rtk identity gate failed"); return 0
    body["rtk_binary_sha256"] = c.sha256_file(rtk_bin)
    body["rtk_binary_bytes"] = Path(rtk_bin).stat().st_size
    resolved = rcc.resolve_isolation()
    if resolved is None:
        body["outcome"] = "CASE_REJECTED_NO_ISOLATION"; _emit(out, body); return 0
    method, wrapper = resolved
    probe = rcc.denial_probe(wrapper)
    body["isolation"] = {"method": method, "denial_probe": probe}
    if not probe["denied"]:
        body["outcome"] = "CASE_REJECTED_ISOLATION_LEAK"; _emit(out, body); return 0

    fam = contract["command_family"]
    workroot = Path(tempfile.mkdtemp(prefix="n2e-caseq-"))
    try:
        # STEP 4: acquire ONE checkout via the proven adapter
        acq = rcc.ADAPTERS[fam](scenario, workroot)
        if not acq.get("identity_verified"):
            body["outcome"] = "CASE_REJECTED_ACQUISITION"; body["acquisition"] = acq
            _emit(out, body); print("case probe: acquisition failed"); return 0
        warm = acq.get("warm")
        if warm is not None and not warm.get("ok", True):
            body["outcome"] = "CASE_REJECTED_WARM"; body["acquisition"] = acq
            _emit(out, body); print("case probe: warm failed"); return 0
        body["acquisition_identity"] = acq.get("environment_identity")
        body["toolchain_identity"] = (acq.get("environment_identity") or {}).get("toolchain")

        policy = acq["policy"]
        frozen = workroot / acq.get("workdir", ".")
        if policy != det["canonicalization_policy_id"]:
            body["outcome"] = "CASE_REJECTED_POLICY_MISMATCH"
            body["detail"] = {"acq_policy": policy, "adapter_policy": det["canonicalization_policy_id"]}
            _emit(out, body); print("case probe: canon policy mismatch"); return 0

        # the argv the harness will run MUST equal the adapter's double-locked determinants
        raw_argv = acq.get("resolved_raw_argv") or det["raw_argv"]
        rtk_argv = acq.get("resolved_rtk_argv") or det["rtk_argv"]
        body["actual_raw_argv"] = raw_argv
        body["actual_rtk_argv"] = rtk_argv
        body["raw_argv_equals_adapter"] = (raw_argv == det["raw_argv"])
        body["rtk_argv_equals_adapter"] = (rtk_argv == det["rtk_argv"])

        # STEP 5: env -- FAMILY-AWARE. HOME is always redirected into the work copy (so e.g. rtk's
        # history DB write lands there, never the host HOME). The Go build/test cache + GOPATH are set
        # ONLY for the go family (fresh per-rep GOCACHE so both arms really execute, never `(cached)`);
        # a read-only files_search command needs no toolchain env at all.
        toolchains = (det.get("platform_requirements") or {}).get("toolchain") or []
        env_extra = {"HOME": str(workroot / ".home")}
        if "go" in toolchains:
            gocache = rcc._FIXEDWORK / ".n2e-gocache"
            env_extra["GOPATH"] = str(workroot / ".home" / "go")
            env_extra["GOCACHE"] = str(gocache)
            # empty gocache seed inside the frozen dir -> each fresh per-rep copy starts cold
            (frozen / ".n2e-gocache").mkdir(exist_ok=True)
        for k in ("JAVA_HOME",):
            if os.environ.get(k):
                env_extra[k] = os.environ[k]
        env_extra.update(acq.get("offline_env") or {})   # contract GOFLAGS/GOPROXY etc. (if any)
        body["measurement_env"] = {k: v for k, v in env_extra.items() if k not in ("HOME", "GOPATH")}
        body["execution_isolation"] = det["execution_isolation"]

        # STEP 6: fresh RAW then RTK arms (identical env; rtk wraps the same go target)
        raw = rcc.run_arm(raw_argv, frozen, policy, contract["timeout_seconds"], wrapper, env_extra,
                          evidence_dir=evidence, case_id=case_id)
        rtk = rcc.run_arm([rtk_bin] + rtk_argv[1:], frozen, policy, contract["timeout_seconds"],
                          wrapper, env_extra, is_rtk=True, rtk_target_ids=det["target_test_ids"],
                          evidence_dir=evidence, case_id=case_id)

        body["raw_arm"] = rcc._arm_public(raw)
        body["rtk_arm"] = rcc._arm_public(rtk)
        body["raw_arm"]["deterministic"] = raw["canonical_deterministic"]
        body["rtk_arm"]["deterministic"] = rtk["canonical_deterministic"]

        # STEP 7: freeze the accepted canonical streams (only when deterministic)
        digests = {}
        if raw.get("_accepted_canonical") is not None:
            digests["raw.canonical"] = _freeze_canonical(evidence, "raw", raw["_accepted_canonical"])
        if rtk.get("_accepted_canonical") is not None:
            digests["rtk.canonical"] = _freeze_canonical(evidence, "rtk", rtk["_accepted_canonical"])
        body["captured_stream_digests"] = digests
        body["outcome"] = "RESOLVED_CASE_OBSERVED"
        _emit(out, body)
        print(f"case probe: OBSERVED case={case_id} raw_det={raw['canonical_deterministic']} "
              f"rtk_det={rtk['canonical_deterministic']} (verifier decides PASS)")
        return 0
    except Exception as e:  # noqa: BLE001
        import traceback
        body["outcome"] = "CASE_PROBE_ERROR"; body["error"] = f"{type(e).__name__}: {e}"
        body["traceback"] = traceback.format_exc()[-2000:]
        _emit(out, body); print("case probe: ERROR", e); return 0
    finally:
        shutil.rmtree(workroot, ignore_errors=True)
        shutil.rmtree(rcc._FIXEDWORK, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
