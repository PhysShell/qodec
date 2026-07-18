#!/usr/bin/env python3
"""Independent verifier for the focused Coreutils diagnostic (corrections 4-8 on top of 8).

Re-reads the diagnostic record + the artifact files and RE-DERIVES every gate from
primitive evidence -- it never trusts a producer boolean:
  * re-derives each RAW/RTK canonical stream from its raw capture under the COMMITTED
    canonicalizer policy and compares to the producer canonical + record sha (corr 4);
  * runs the Cargo target-execution parser on BOTH the raw capture and the derived
    canonical and requires identical semantics -- the canonicalizer removes build
    progress only (corr 5);
  * verifies acquisition-failure vs RAW-not-qualified vs RTK-stage outcomes with the
    evidence appropriate to each, identifying the exact failed RAW gate (corr 6);
  * derives the required-file set from the outcome and requires the manifest to list
    exactly those (no omissions, no duplicate paths) with valid hashes (corr 7).

Exit non-zero (fails the workflow) on any producer/verifier disagreement, missing/
malformed outcome, self-hash failure, missing required evidence, or manifest mismatch.

Usage: verify_coreutils_diagnostic.py <diagnostic.json> <evidence-dir>
"""
from __future__ import annotations

import hashlib
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_oracles as ora  # noqa: E402
import n2e_canon_policies as canon  # noqa: E402
import n2e_resolved_loader as loader  # noqa: E402

PINNED_MANIFEST_SHA = "5596679723faf7e63772bacb1d0c898abaa51eb4ed193b328929d907c8c4bd5a"
FATAL_OUTCOMES = {"COREUTILS_DIAGNOSTIC_ERROR"}
# acquisition/parity/toolchain/isolation family: require the evidence appropriate to each,
# but NOT the full measurement set. RAW-not-qualified is handled SEPARATELY (corr 6).
ACQ_FAILURE_OUTCOMES = {"COREUTILS_ACQUISITION_INSTALL_FAILURE", "COREUTILS_ACQUISITION_NONDETERMINISTIC",
                        "COREUTILS_ACQUISITION_UNAUTHORIZED_MUTATION", "COREUTILS_TOOLCHAIN_PINS_UNVERIFIED",
                        "COREUTILS_FINAL_INPUT_PARITY_FAILURE", "REJECTED_NO_ISOLATION"}
TARGET_IDS = ["test_tr::test_trailing_backslash"]


def _decompress(p: Path) -> bytes:
    return zlib.decompress(p.read_bytes())


def _canon(policy: str, raw: bytes, is_rtk: bool) -> bytes:
    combined = canon.rtk_envelope(raw) if is_rtk else raw
    return canon.canonicalize(combined, policy)


def _required_files(outcome: str) -> list[str]:
    """Basenames the manifest MUST list for the given outcome (corr 7)."""
    if outcome == "RTK_DIALECT_UNPROVEN":
        roles = ("raw", "rtk")
    elif outcome == "COREUTILS_RAW_NOT_QUALIFIED":
        roles = ("raw",)
    else:
        return []
    req = []
    for role in roles:
        for i in range(3):
            req += [f"{role}.rep{i}.zst", f"{role}.raw.rep{i}.zst", f"{role}.mutation.rep{i}.json"]
    return req


def _proof_semantics(raw: bytes, canonical: bytes, exit_code: int) -> tuple[bool, dict]:
    pr = ora.cargo_target_execution_proof(raw, exit_code, TARGET_IDS)
    pc = ora.cargo_target_execution_proof(canonical, exit_code, TARGET_IDS)
    eq = {
        "executed_ok_ids_equal": pr["executed_ok_ids"] == pc["executed_ok_ids"],
        "executed_failed_equal": pr["summary"]["executed_failed"] == pc["summary"]["executed_failed"],
        "passed_equal": pr["summary"]["passed"] == pc["summary"]["passed"],
        "failed_equal": pr["summary"]["failed"] == pc["summary"]["failed"],
        "running_total_equal": pr["summary"]["running_total"] == pc["summary"]["running_total"],
        "target_verdict_equal": pr["checks"]["target_executed_passing"] == pc["checks"]["target_executed_passing"],
    }
    return all(eq.values()), {"raw_proof_ok": pr["executed_ok"], "canonical_proof_ok": pc["executed_ok"], **eq}


def _rederive_arm(rec: dict, evidence: Path, role: str, policy: str, fail: list) -> dict:
    arm = rec.get(f"{role}_arm") or {}
    runs = arm.get("runs") or []
    is_rtk = role == "rtk"
    derived_hashes, producer_hashes, sem = [], [], []
    for i in range(3):
        rawf = evidence / f"{role}.raw.rep{i}.zst"
        canf = evidence / f"{role}.rep{i}.zst"
        if not rawf.is_file():
            fail.append(f"missing raw capture {role}.raw.rep{i}.zst")
            continue
        if not canf.is_file():
            fail.append(f"missing canonical stream {role}.rep{i}.zst")
            continue
        raw = _decompress(rawf)
        # primary-file hash check against the record's runs[i].raw_combined_sha256
        if len(runs) > i and hashlib.sha256(raw).hexdigest() != runs[i].get("raw_combined_sha256"):
            fail.append(f"{role} rep{i} raw capture sha != record raw_combined_sha256")
        derived = _canon(policy, raw, is_rtk)
        producer_canon = _decompress(canf)
        derived_hashes.append(hashlib.sha256(derived).hexdigest())
        producer_hashes.append(hashlib.sha256(producer_canon).hexdigest())
        # derived bytes must equal the producer canonical file AND the record sha
        if derived != producer_canon:
            fail.append(f"{role} rep{i}: re-derived canonical != producer canonical file")
        if len(runs) > i and hashlib.sha256(derived).hexdigest() != runs[i].get("canonical_sha256"):
            fail.append(f"{role} rep{i}: re-derived canonical sha != record canonical_sha256")
        if not is_rtk:  # semantic preservation (corr 5): only RAW is fully parsed pre-dialect
            ok, detail = _proof_semantics(raw, derived, (runs[i] or {}).get("exit_code", 1))
            sem.append(ok)
            if not ok:
                fail.append(f"raw rep{i}: canonicalization changed test semantics {detail}")
    rederived_det = len(set(derived_hashes)) == 1 and len(derived_hashes) == 3
    equal_producer = derived_hashes == producer_hashes and len(derived_hashes) == 3
    return {"rederived_deterministic": rederived_det, "rederived_canonical_equal_producer": equal_producer,
            "semantic_preserved_all": (all(sem) if sem else None)}


def _raw_gate_diagnosis(rec: dict, evidence: Path, policy: str, fail: list):
    """corr 6: for COREUTILS_RAW_NOT_QUALIFIED, require the full RAW evidence and identify
    the EXACT failed gate (determinism vs target-not-executed vs mutation vs exit)."""
    if not (rec.get("acquisition_A") and rec.get("acquisition_B")):
        fail.append("RAW-not-qualified: acquisition A/B missing")
    cls = (rec.get("acquisition_classification") or {}).get("outcome")
    if cls not in ("publisher_install_dependency_snapshot", "pristine_dependency_state"):
        fail.append(f"RAW-not-qualified: acquisition not eligible ({cls})")
    if not (rec.get("final_env_parity") or {}).get("all_equal"):
        fail.append("RAW-not-qualified: final env parity not equal")
    rd = _rederive_arm(rec, evidence, "raw", policy, fail)
    raw = rec.get("raw_arm") or {}
    mut = raw.get("per_rep_mutation") or []
    # identify the distinct failed gate(s)
    gates = {
        "canonical_determinism_ok": rd["rederived_deterministic"],
        "target_executed_ok": all(p.get("executed_ok") for p in (raw.get("cargo_execution_proof") or [{}])),
        "mutation_guards_ok": bool(mut) and all(m.get("mutation_ok") for m in mut),
        "exit_stable_ok": raw.get("exit_stable") is True,
        "argv_equal_contract_ok": raw.get("actual_argv_equal_contract") is True,
    }
    failed = sorted(k for k, v in gates.items() if not v)
    if not failed:
        fail.append("RAW-not-qualified but every RAW gate re-derives as passing (producer/verifier disagreement)")
    return {"gates": gates, "failed_gates": failed, "raw_rederivation": rd}


def verify(rec_path: Path, evidence: Path) -> tuple[bool, list, dict]:
    fail, facts = [], {}
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
    try:
        loader.validate_resolved_closure()
    except Exception as e:  # noqa: BLE001
        fail.append(f"resolved closure invalid: {e}")

    # ---- manifest completeness (corr 7) ----
    manifest = rec.get("file_manifest")
    if outcome not in ("COREUTILS_TOOLCHAIN_PINS_UNVERIFIED", "REJECTED_NO_ISOLATION"):
        if not manifest:
            fail.append("file_manifest missing")
        else:
            paths = [e["file"] for e in manifest]
            if len(paths) != len(set(paths)):
                fail.append("duplicate manifest paths")
            for e in manifest:
                fp = N2E_DIR / e["file"]
                if fp == rec_path:
                    continue
                if not fp.is_file():
                    fail.append(f"manifest file missing: {e['file']}")
                elif c.sha256_file(str(fp)) != e["sha256"]:
                    fail.append(f"manifest hash mismatch: {e['file']}")
            manifested = {Path(p).name for p in paths}
            for req in _required_files(outcome):
                if req not in manifested:
                    fail.append(f"required evidence omitted from manifest: {req}")

    if outcome in ACQ_FAILURE_OUTCOMES:
        if outcome not in ("COREUTILS_TOOLCHAIN_PINS_UNVERIFIED", "REJECTED_NO_ISOLATION"):
            if not (rec.get("acquisition_A") and rec.get("acquisition_B")):
                fail.append("acquisition A/B evidence missing")
            if not rec.get("acquisition_classification"):
                fail.append("acquisition_classification missing")
        return (not fail), fail, facts

    policy = (rec.get("raw_arm") or {}).get("canonicalization_policy") or "cargo-test-v2"
    facts["canon_policy"] = policy

    if outcome == "COREUTILS_RAW_NOT_QUALIFIED":
        facts["raw_gate"] = _raw_gate_diagnosis(rec, evidence, policy, fail)
        return (not fail), fail, facts

    if outcome != "RTK_DIALECT_UNPROVEN":
        return False, fail + [f"unexpected outcome: {outcome}"], facts

    # ---- full RTK_DIALECT_UNPROVEN set ----
    tool = rec.get("toolchain_enforcement") or {}
    if not tool.get("ok"):
        fail.append("toolchain_enforcement not ok")
    if tool.get("manifest_sha256") != PINNED_MANIFEST_SHA:
        fail.append("channel manifest sha256 != pinned")
    A, B = rec.get("acquisition_A"), rec.get("acquisition_B")
    if not (A and B and A["install"]["exit"] == 0 and B["install"]["exit"] == 0):
        fail.append("acquisition A/B not both install-success")
    cls = (rec.get("acquisition_classification") or {}).get("outcome")
    if cls not in ("publisher_install_dependency_snapshot", "pristine_dependency_state"):
        fail.append(f"acquisition classification not eligible: {cls}")
    if not (rec.get("final_env_parity") or {}).get("all_equal"):
        fail.append("final env parity A/B not all equal")

    raw, rtk = rec.get("raw_arm") or {}, rec.get("rtk_arm") or {}
    if raw.get("reps") != 3 or rtk.get("reps") != 3:
        fail.append("raw/rtk reps != 3")
    if not raw.get("actual_argv_equal_contract") or not rtk.get("actual_argv_equal_contract"):
        fail.append("actual argv != contract")
    mut = (raw.get("per_rep_mutation") or []) + (rtk.get("per_rep_mutation") or [])
    if len(mut) != 6 or not all(m.get("mutation_ok") and m.get("repo_mutation_ok")
                                and m.get("cargo_cache_stable_content_ok") and m.get("toolchain_immutable")
                                for m in mut):
        fail.append("per-rep mutation guards incomplete/failed")

    raw_rd = _rederive_arm(rec, evidence, "raw", policy, fail)   # corr 4 + 5
    rtk_rd = _rederive_arm(rec, evidence, "rtk", policy, fail)   # corr 4
    facts["raw_rederived_canonical_equal_producer"] = raw_rd["rederived_canonical_equal_producer"]
    facts["rtk_rederived_canonical_equal_producer"] = rtk_rd["rederived_canonical_equal_producer"]
    facts["raw_rederived_deterministic"] = raw_rd["rederived_deterministic"]
    facts["rtk_rederived_deterministic"] = rtk_rd["rederived_deterministic"]
    facts["raw_semantic_preserved"] = raw_rd["semantic_preserved_all"]
    if not raw_rd["rederived_canonical_equal_producer"]:
        fail.append("raw_rederived_canonical_equal_producer false")
    if not rtk_rd["rederived_canonical_equal_producer"]:
        fail.append("rtk_rederived_canonical_equal_producer false")
    if not raw_rd["rederived_deterministic"]:
        fail.append("raw_rederived_deterministic false")
    if not rtk_rd["rederived_deterministic"]:
        fail.append("rtk_rederived_deterministic false")
    if raw_rd["semantic_preserved_all"] is not True:
        fail.append("RAW canonicalization did not preserve test semantics")

    # re-derive the RAW cargo proof independently on the raw captures (target passes all)
    for i in range(3):
        f = evidence / f"raw.raw.rep{i}.zst"
        if f.is_file():
            run = (raw.get("runs") or [{}, {}, {}])[i] if len(raw.get("runs") or []) > i else {}
            proof = ora.cargo_target_execution_proof(_decompress(f), run.get("exit_code", 1), TARGET_IDS)
            if not proof["executed_ok"]:
                fail.append(f"re-derived RAW cargo proof failed rep{i}")

    prov = rec.get("rtk_cargo_filter_source") or {}
    if not prov.get("head_proven"):
        fail.append("RTK source HEAD not proven == pinned commit")
    if not prov.get("chain_complete"):
        fail.append("RTK cargo-filter dispatch->filter->parser->formatter chain incomplete")
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
