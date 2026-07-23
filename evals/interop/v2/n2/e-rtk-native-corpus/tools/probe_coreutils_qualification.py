#!/usr/bin/env python3
"""P4 Coreutils qualification ACCEPTANCE probe -- OBSERVATIONS ONLY.

Independently executes coreutils-6731 through the already-frozen P1-P3 chain and records raw
observations. It NEVER emits a qualification verdict: the producer records what happened (fresh
RAW + RTK streams on one checkout / one resolved environment, exit codes, argv, execution
bindings, and the exact toolchain / RTK identities), and the independent qualification verifier
(verify_coreutils_qualification.py) re-derives PASS/FAIL. A green GitHub job is not a PASS.

Distinct from the diagnostic probe: record_type=n2e-coreutils-qualification-observation,
record_kind=coreutils_qualification_acceptance -- so a diagnostic artifact can never be
substituted for an acceptance artifact. Reuses the diagnostic probe's execution machinery
(enforce_toolchain / _acquire / _finalize / _measure_arm) verbatim -- NO new measurement or
canonicalization semantics; canonicalization is cargo-test-v3 as bound by contract generation 3.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as loader  # noqa: E402
import probe_coreutils_diagnostic as diag  # noqa: E402

CASE_ID = diag.CASE_ID
FROZEN_LOCK = N2E_DIR / "evidence" / "coreutils-6731" / "resolved-dependency-snapshot" / "Cargo.lock"


def _emit(out: Path, body: dict):
    c.write_record(out, c.envelope(record_type="n2e-coreutils-qualification-observation",
                   generated_by="tools/probe_coreutils_qualification.py", **body))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(N2E_DIR / "coreutils-6731-qualification-v1.json"))
    ap.add_argument("--evidence", default=str(N2E_DIR / "out" / "evidence" / "coreutils-6731-qual"))
    args = ap.parse_args()
    out = Path(args.out).resolve(); evidence = Path(args.evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=True)

    body = {"case_id": CASE_ID, "record_kind": "coreutils_qualification_acceptance",
            # OBSERVATIONS ONLY: the producer never asserts a verdict.
            "qualification_pass": None, "acceptance_pass": False,
            "verdict_authority": "independent qualification verifier only (producer records observations)"}

    # STEP 1+2: close the P1/P2/P3 loader closure BEFORE running the test; bind contract gen 3.
    try:
        closure = loader.validate_resolved_closure()
        bundle = loader.load_case_bundle(CASE_ID, "resolved")
    except Exception as e:  # noqa: BLE001
        body["outcome"] = "COREUTILS_QUAL_CLOSURE_FAILURE"; body["error"] = f"{type(e).__name__}: {e}"
        _emit(out, body); print("qualification: CLOSURE FAILURE", e); return 0
    contract = bundle["execution_contract"]
    body["closure_effective_record_hash_map"] = closure["effective_record_hash_map"]
    body["bound_dialect_policy_id"] = contract.get("rtk_test_dialect_policy_id")
    body["canonicalization_policy_id"] = contract.get("canonicalization_policy_id")
    body["contract_generations"] = {
        "canonicalization": contract.get("canonicalization_policy_generation"),
        "rtk_dialect_binding": contract.get("rtk_dialect_binding_generation")}

    pins = closure["overlays"]["toolchain"]["resolved_rust_toolchain"]
    recipe = bundle["publisher_recipe"]; scen = bundle["scenario"]
    base = scen["base_commit"]; target_ids = scen["target_test_ids"]
    row = c.load_record(diag.ROW)
    gold = (row.get("patch") or "").encode(); test = (row.get("test_patch") or "").encode()

    # STEP 3: enforce toolchain pins + capture exact Rust/Cargo + RTK identities
    tool = diag.enforce_toolchain(pins)
    body["toolchain_enforcement"] = tool
    if not tool["ok"]:
        body["outcome"] = "COREUTILS_QUAL_TOOLCHAIN_UNVERIFIED"; _emit(out, body)
        print("qualification: toolchain unverified", tool["reasons"]); return 0
    os.environ["RUSTUP_HOME"] = os.environ.get("RUSTUP_HOME") or str(Path.home() / ".rustup")
    rustup_home = os.environ["RUSTUP_HOME"]
    rtk_bin = os.environ.get("RTK_BIN")
    body["rtk_binary_path"] = rtk_bin
    body["rtk_binary_sha256"] = (c.sha256_file(rtk_bin) if rtk_bin and Path(rtk_bin).exists() else None)
    body["rtk_binary_bytes"] = (Path(rtk_bin).stat().st_size if rtk_bin and Path(rtk_bin).exists() else None)

    iso = diag.drv.resolve_isolation()
    if iso is None:
        body["outcome"] = "REJECTED_NO_ISOLATION"; _emit(out, body); return 0
    iso_method, wrapper = iso
    body["isolation"] = {"method": iso_method, "denial_probe": diag.drv.denial_probe(wrapper)}

    workroot = Path(tempfile.mkdtemp(prefix="n2e-cu-qual-"))
    try:
        # STEP 4a: acquire ONE resolved environment (reproduces the frozen P1 substrate)
        A = diag._acquire("A", workroot / "A", recipe, base)
        cls = diag._classify_acquisitions(A, A, tool)
        body["acquisition_classification"] = cls
        acq_lock = A.get("_cargo_lock_raw")
        body["acquired_lock_matches_frozen_p1"] = (
            acq_lock is not None and FROZEN_LOCK.is_file() and acq_lock == FROZEN_LOCK.read_bytes())
        if cls["outcome"] != "publisher_install_resolved_dependency_snapshot":
            body["outcome"] = "COREUTILS_QUAL_ACQUISITION_FAILURE"; _emit(out, body)
            print("qualification: acquisition failure", cls["outcome"]); return 0

        finA = diag._finalize(A, gold, test, base)
        body["finalize"] = finA
        if not finA["all_ok"]:
            body["outcome"] = "COREUTILS_QUAL_FINALIZE_FAILURE"; _emit(out, body)
            print("qualification: finalize failure"); return 0

        # frozen env: repo + cargo-home + home + rustup (identical construction to the diagnostic)
        frozen = workroot / "frozen-env"; frozen.mkdir()
        shutil.copytree(Path(A["_repo_dir"]), frozen / "repo", symlinks=True)
        shutil.copytree(Path(A["_cargo_home"]), frozen / "cargo-home", symlinks=True)
        (frozen / "home").mkdir()
        off = {k: v for k, v in diag.CONTRACT_ENV.items()}
        rustflags = recipe.get("test_env", {}).get("RUSTFLAGS")
        if rustflags:
            off["RUSTFLAGS"] = rustflags
        _env, _test_argv = diag.drv.pub.split_env(recipe["test_cmd"][0])
        meas_env = {**off, **_env}
        body["measurement_semantic_env"] = {k: v for k, v in meas_env.items() if k not in diag._ENV_PATH_KEYS}

        # STEP 4b+5+6: RAW + RTK cargo-test as two really-run paths on the one resolved env
        # (fresh streams; canonicalization is cargo-test-v3 inside _measure_arm)
        raw = diag._measure_arm(False, frozen, list(diag.CONTRACT_RAW_ARGV), rtk_bin, wrapper,
                                meas_env, target_ids, evidence, rustup_home)
        rtk = diag._measure_arm(True, frozen, [rtk_bin, *diag.CONTRACT_RAW_ARGV], rtk_bin, wrapper,
                                meas_env, target_ids, evidence, rustup_home)
        body["raw_arm"] = raw
        body["rtk_arm"] = rtk
        body["raw_rtk_semantic_env_equal"] = raw["semantic_env"] == rtk["semantic_env"]
        # OBSERVED: streams + bindings recorded. The verifier derives the qualification verdict.
        body["outcome"] = "COREUTILS_QUALIFICATION_OBSERVED"
        body["file_manifest"] = diag._artifact_manifest(evidence, out)
        _emit(out, body)
        print(f"qualification: OBSERVED (verifier decides PASS); raw_argv_ok={raw['actual_argv_equal_contract']} "
              f"rtk_argv_ok={rtk['actual_argv_equal_contract']}")
        return 0
    except Exception as e:  # noqa: BLE001
        import traceback
        body["outcome"] = "COREUTILS_QUAL_ERROR"; body["error"] = f"{type(e).__name__}: {e}"
        body["traceback"] = traceback.format_exc()[-2000:]
        try:
            body["file_manifest"] = diag._artifact_manifest(evidence, out)
        except Exception:  # noqa: BLE001
            pass
        _emit(out, body); print("qualification: ERROR", e); return 0
    finally:
        shutil.rmtree(workroot, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
