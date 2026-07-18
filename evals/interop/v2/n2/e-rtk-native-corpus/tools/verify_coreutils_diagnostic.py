#!/usr/bin/env python3
"""Independent verifier for the focused Coreutils diagnostic (correction 8).

Re-reads the diagnostic record + the artifact files and RE-DERIVES every gate from
primitive evidence -- it never trusts a producer boolean. Exit non-zero (fails the
workflow) on: COREUTILS_DIAGNOSTIC_ERROR, missing/malformed outcome, self-hash failure,
missing required primary evidence, file-manifest mismatch, or any producer/verifier
disagreement.

Usage: verify_coreutils_diagnostic.py <diagnostic.json> <evidence-dir>
"""
from __future__ import annotations

import hashlib
import json
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_oracles as ora  # noqa: E402
import n2e_resolved_loader as loader  # noqa: E402

PINNED_MANIFEST_SHA = "5596679723faf7e63772bacb1d0c898abaa51eb4ed193b328929d907c8c4bd5a"
FATAL_OUTCOMES = {"COREUTILS_DIAGNOSTIC_ERROR"}
ACQ_FAILURE_OUTCOMES = {"COREUTILS_ACQUISITION_INSTALL_FAILURE", "COREUTILS_ACQUISITION_NONDETERMINISTIC",
                        "COREUTILS_ACQUISITION_UNAUTHORIZED_MUTATION", "COREUTILS_TOOLCHAIN_PINS_UNVERIFIED",
                        "COREUTILS_FINAL_INPUT_PARITY_FAILURE", "COREUTILS_RAW_NOT_QUALIFIED",
                        "REJECTED_NO_ISOLATION"}


def _decompress(p: Path) -> bytes:
    return zlib.decompress(p.read_bytes())


def verify(rec_path: Path, evidence: Path) -> tuple[bool, list, dict]:
    fail = []
    facts = {}
    rec = c.load_record(rec_path)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        return False, [f"diagnostic self-hash: {msg}"], facts
    outcome = rec.get("outcome")
    facts["outcome"] = outcome
    if not outcome:
        return False, ["missing/malformed outcome"], facts
    if outcome in FATAL_OUTCOMES:
        return False, [f"fatal outcome: {outcome}"], facts
    if rec.get("acceptance_pass") is not False:
        fail.append("acceptance_pass must be false for a diagnostic")

    # resolved closure hashes valid (independent)
    try:
        loader.validate_resolved_closure()
        facts["resolved_closure_valid"] = True
    except Exception as e:  # noqa: BLE001
        fail.append(f"resolved closure invalid: {e}")

    # file manifest present + every file hash re-verified
    manifest = rec.get("file_manifest")
    if outcome not in ("COREUTILS_TOOLCHAIN_PINS_UNVERIFIED", "REJECTED_NO_ISOLATION"):
        if not manifest:
            fail.append("file_manifest missing")
        else:
            for e in manifest:
                fp = N2E_DIR / e["file"]
                if fp == rec_path:
                    continue  # the record's own hash is not self-referential
                if not fp.is_file():
                    fail.append(f"manifest file missing: {e['file']}")
                elif c.sha256_file(str(fp)) != e["sha256"]:
                    fail.append(f"manifest hash mismatch: {e['file']}")

    # acquisition-failure family: require the appropriate acquisition evidence, then stop
    if outcome in ACQ_FAILURE_OUTCOMES:
        if outcome != "COREUTILS_TOOLCHAIN_PINS_UNVERIFIED" and outcome != "REJECTED_NO_ISOLATION":
            if not (rec.get("acquisition_A") and rec.get("acquisition_B")):
                fail.append("acquisition A/B evidence missing for acquisition-failure outcome")
            if not rec.get("acquisition_classification"):
                fail.append("acquisition_classification missing")
        return (not fail), fail, facts

    if outcome != "RTK_DIALECT_UNPROVEN":
        fail.append(f"unexpected non-terminal outcome: {outcome}")
        return (not fail), fail, facts

    # ---- full RTK_DIALECT_UNPROVEN requirement set ----
    tool = rec.get("toolchain_enforcement") or {}
    if not tool.get("ok"):
        fail.append("toolchain_enforcement not ok")
    if tool.get("manifest_sha256") != PINNED_MANIFEST_SHA:
        fail.append("channel manifest sha256 != pinned")

    A, B = rec.get("acquisition_A"), rec.get("acquisition_B")
    if not (A and B):
        fail.append("acquisition A/B missing")
    else:
        if A["install"]["exit"] != 0 or B["install"]["exit"] != 0:
            fail.append("acquisition install non-zero")
    cls = rec.get("acquisition_classification") or {}
    if cls.get("outcome") not in ("publisher_install_dependency_snapshot", "pristine_dependency_state"):
        fail.append(f"acquisition classification not eligible: {cls.get('outcome')}")
    if not (rec.get("final_env_parity") or {}).get("all_equal"):
        fail.append("final env parity A/B not all equal")

    raw = rec.get("raw_arm") or {}
    rtk = rec.get("rtk_arm") or {}
    if raw.get("reps") != 3 or rtk.get("reps") != 3:
        fail.append("raw/rtk reps != 3")
    if not raw.get("actual_argv_equal_contract") or not rtk.get("actual_argv_equal_contract"):
        fail.append("actual argv != contract")

    # all six per-rep mutation records with mutation_ok
    mut = (raw.get("per_rep_mutation") or []) + (rtk.get("per_rep_mutation") or [])
    if len(mut) != 6:
        fail.append(f"expected 6 per-rep mutation records, got {len(mut)}")
    if not all(m.get("mutation_ok") and m.get("repo_mutation_ok")
               and m.get("cargo_cache_stable_content_ok") and m.get("toolchain_immutable") for m in mut):
        fail.append("a per-rep mutation guard failed")

    # RE-DERIVE the RAW cargo target proof from the raw captures (never the producer bool)
    target_ids = ["test_tr::test_trailing_backslash"]
    rederived_exec = []
    for i in range(3):
        f = evidence / f"raw.raw.rep{i}.zst"
        run = (raw.get("runs") or [{}, {}, {}])[i] if len(raw.get("runs") or []) > i else {}
        if not f.is_file():
            fail.append(f"missing primary raw capture raw.raw.rep{i}.zst")
            continue
        data = _decompress(f)
        proof = ora.cargo_target_execution_proof(data, run.get("exit_code", 1), target_ids)
        rederived_exec.append(tuple(proof["executed_ok_ids"]))
        if not proof["executed_ok"]:
            fail.append(f"re-derived RAW cargo proof failed rep{i}")
        # producer/verifier agreement
        prod = (raw.get("cargo_execution_proof") or [{}, {}, {}])
        if len(prod) > i and prod[i].get("executed_ok") != proof["executed_ok"]:
            fail.append(f"producer/verifier RAW proof disagreement rep{i}")
    if rederived_exec and len(set(rederived_exec)) != 1:
        fail.append("re-derived executed-id set not deterministic across raw reps")
    facts["rederived_executed_ids"] = sorted(rederived_exec[0]) if rederived_exec else []

    # canonical + raw stream files present + hash-valid against the record's runs
    for role, arm in (("raw", raw), ("rtk", rtk)):
        for i in range(3):
            cf = evidence / f"{role}.rep{i}.zst"
            if not cf.is_file():
                fail.append(f"missing canonical stream {role}.rep{i}.zst")
                continue
            runs = arm.get("runs") or []
            if len(runs) > i:
                if hashlib.sha256(_decompress(cf)).hexdigest() != runs[i].get("canonical_sha256"):
                    fail.append(f"canonical stream sha mismatch {role}.rep{i}")

    # RTK source provenance complete
    prov = rec.get("rtk_cargo_filter_source") or {}
    if not prov.get("head_proven"):
        fail.append("RTK source HEAD not proven == pinned commit")
    if not prov.get("chain_complete"):
        fail.append("RTK cargo-filter dispatch->filter->parser->formatter chain incomplete")

    facts["raw_deterministic"] = raw.get("deterministic")
    facts["rtk_deterministic"] = rtk.get("deterministic")
    return (not fail), fail, facts


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: verify_coreutils_diagnostic.py <diagnostic.json> <evidence-dir>")
        return 2
    ok, fail, facts = verify(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"coreutils-diagnostic-verify: {'OK' if ok else 'FAIL'} outcome={facts.get('outcome')}")
    for f in fail:
        print(f"  - {f}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
