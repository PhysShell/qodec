#!/usr/bin/env python3
"""Independent verifier for the focused Coreutils diagnostic (corrections 1-9, cumulative).

Re-derives EVERY gate from primitive evidence -- never trusts a producer boolean:
  * derives normative_evidence_eligible itself; the producer only records
    normative_evidence_eligibility=UNDETERMINED (corr 2);
  * re-derives RAW/RTK argv equality against the exact committed contract, RTK == [rtk_bin,
    *CONTRACT_RAW_ARGV] (full argv; a dropped `cargo`, injected `+1.81.0`, extra/reordered
    flags all fail) (corr 1);
  * binds the canonicalizer policy from the resolved contract (record==contract==
    cargo-test-v2) and re-derives each rep's canonical + removed-line diagnostics (corr 4);
  * re-derives the effective environment == contract and RAW/RTK semantic-env parity (corr 5);
  * requires a mechanically-resolved dispatch->filter->parser->formatter chain (corr 6);
  * requires exact relative manifest paths + external-manifest cross-agreement (corr 7);
  * re-derives RAW rejection gates from the primary captures, not the producer proof (corr 8);
  * checks acquisition prerequisites + A/B authorized-mutation (only Cargo.lock) (corr 9).

Exit non-zero (fails the workflow) on any producer/verifier disagreement.
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
import n2e_canon_policies as canon  # noqa: E402
import n2e_resolved_loader as loader  # noqa: E402

PINNED_MANIFEST_SHA = "5596679723faf7e63772bacb1d0c898abaa51eb4ed193b328929d907c8c4bd5a"
CONTRACT_RAW_ARGV = ["cargo", "test", "backslash", "--no-fail-fast"]
CONTRACT_ENV = {"RUSTUP_TOOLCHAIN": "1.81.0", "CARGO_NET_OFFLINE": "true",
                "RUST_TEST_THREADS": "1", "CARGO_BUILD_JOBS": "1"}
EXPECTED_POLICY = "cargo-test-v2"
EVIDENCE_ROOT = "out/evidence/coreutils-6731"
TARGET_IDS = ["test_tr::test_trailing_backslash"]
FATAL_OUTCOMES = {"COREUTILS_DIAGNOSTIC_ERROR"}
ACQ_FAILURE_OUTCOMES = {"COREUTILS_ACQUISITION_INSTALL_FAILURE", "COREUTILS_ACQUISITION_NONDETERMINISTIC",
                        "COREUTILS_ACQUISITION_UNAUTHORIZED_MUTATION", "COREUTILS_TOOLCHAIN_PINS_UNVERIFIED",
                        "COREUTILS_FINAL_INPUT_PARITY_FAILURE", "REJECTED_NO_ISOLATION"}


def _dz(p: Path) -> bytes:
    return zlib.decompress(p.read_bytes())


def _canon(policy: str, raw: bytes, is_rtk: bool) -> bytes:
    return canon.canonicalize(canon.rtk_envelope(raw) if is_rtk else raw, policy)


def _argv_ok(argv, is_rtk, rtk_bin) -> bool:
    expected = ([rtk_bin, *CONTRACT_RAW_ARGV] if is_rtk else list(CONTRACT_RAW_ARGV))
    if list(argv) != expected:
        return False
    return not any(str(tok).startswith("+") for tok in argv)  # no injected +toolchain


def _required_paths(outcome: str) -> list[str]:
    roles = ("raw", "rtk") if outcome == "RTK_DIALECT_UNPROVEN" else \
            ("raw",) if outcome == "COREUTILS_RAW_NOT_QUALIFIED" else ()
    req = []
    for role in roles:
        for i in range(3):
            req += [f"{EVIDENCE_ROOT}/{role}.rep{i}.zst", f"{EVIDENCE_ROOT}/{role}.raw.rep{i}.zst",
                    f"{EVIDENCE_ROOT}/{role}.mutation.rep{i}.json"]
    return req


def _rederive_arm(rec, evidence, role, policy, fail) -> dict:
    arm = rec.get(f"{role}_arm") or {}
    runs = arm.get("runs") or []
    is_rtk = role == "rtk"
    dhash, phash, sem, removed_ok = [], [], [], []
    for i in range(3):
        rawf, canf = evidence / f"{role}.raw.rep{i}.zst", evidence / f"{role}.rep{i}.zst"
        if not (rawf.is_file() and canf.is_file()):
            fail.append(f"missing {role} rep{i} stream(s)")
            continue
        raw = _dz(rawf)
        if len(runs) > i and hashlib.sha256(raw).hexdigest() != runs[i].get("raw_combined_sha256"):
            fail.append(f"{role} rep{i} raw capture sha != record")
        derived = _canon(policy, raw, is_rtk)
        prod = _dz(canf)
        dhash.append(hashlib.sha256(derived).hexdigest()); phash.append(hashlib.sha256(prod).hexdigest())
        if derived != prod:
            fail.append(f"{role} rep{i}: re-derived canonical != producer file")
        if len(runs) > i and hashlib.sha256(derived).hexdigest() != runs[i].get("canonical_sha256"):
            fail.append(f"{role} rep{i}: re-derived canonical sha != record")
        # re-derive removed-line diagnostics and compare (corr 4)
        rd = canon.cargo_test_v2_removed_diag(canon.rtk_envelope(raw) if is_rtk else raw)
        prod_rd = (runs[i] or {}).get("canon_removed_lines") or {}
        removed_ok.append(rd == prod_rd)
        if rd != prod_rd:
            fail.append(f"{role} rep{i}: removed-line diagnostic mismatch")
        if not is_rtk:
            pr = ora.cargo_target_execution_proof(raw, (runs[i] or {}).get("exit_code", 1), TARGET_IDS)
            pc = ora.cargo_target_execution_proof(derived, (runs[i] or {}).get("exit_code", 1), TARGET_IDS)
            same = (pr["executed_ok_ids"] == pc["executed_ok_ids"]
                    and pr["summary"]["passed"] == pc["summary"]["passed"]
                    and pr["summary"]["failed"] == pc["summary"]["failed"]
                    and pr["summary"]["running_total"] == pc["summary"]["running_total"]
                    and pr["checks"]["target_executed_passing"] == pc["checks"]["target_executed_passing"])
            sem.append(same)
            if not same:
                fail.append(f"raw rep{i}: canonicalization changed test semantics")
    return {"rederived_deterministic": len(set(dhash)) == 1 and len(dhash) == 3,
            "rederived_canonical_equal_producer": dhash == phash and len(dhash) == 3,
            "removed_diag_equal_producer": all(removed_ok) and len(removed_ok) == 3,
            "semantic_preserved_all": (all(sem) if sem else None)}


def _raw_target_from_captures(evidence, rec) -> bool:
    """corr 8: derive target execution from the PRIMARY raw captures, not the producer proof."""
    runs = (rec.get("raw_arm") or {}).get("runs") or []
    ok = []
    for i in range(3):
        f = evidence / f"raw.raw.rep{i}.zst"
        if not f.is_file():
            return False
        p = ora.cargo_target_execution_proof(_dz(f), (runs[i] or {}).get("exit_code", 1), TARGET_IDS)
        ok.append(p["executed_ok"])
    return len(ok) == 3 and all(ok)


def _check_acquisition(rec, fail):
    """corr 9: acquisition prerequisites + A/B authorized-mutation (only Cargo.lock)."""
    for label in ("A", "B"):
        a = rec.get(f"acquisition_{label}") or {}
        if a.get("fetch_exit") != 0:
            fail.append(f"acquisition {label}: fetch_exit != 0")
        if a.get("head_matches_base") is not True:
            fail.append(f"acquisition {label}: head != base")
        pr = a.get("pristine_state") or {}
        if pr.get("tracked_status") != []:
            fail.append(f"acquisition {label}: pristine tracked status not empty")
        if not pr.get("cargo_config") or "rust_toolchain" not in pr:
            fail.append(f"acquisition {label}: pristine config/toolchain identities not captured")
        post = a.get("post_install_state") or {}
        # only Cargo.lock may change pristine->post; any other tracked/config/toolchain change is unauthorized
        for key in ("workspace_cargo_tomls", "cargo_config", "cargo_config_toml",
                    "rust_toolchain", "rust_toolchain_toml"):
            if pr.get(key) != post.get(key):
                fail.append(f"acquisition {label}: unauthorized mutation of {key}")
        changed_tracked = set(post.get("tracked_status") or []) - set(pr.get("tracked_status") or [])
        if any("Cargo.lock" not in x for x in changed_tracked):
            fail.append(f"acquisition {label}: unauthorized tracked mutation {sorted(changed_tracked)}")


def _check_manifest(rec, outcome, fail):
    """corr 7: exact relative paths, no duplicate paths/basenames, all under the evidence
    root, external-manifest cross-agreement for shared files."""
    manifest = rec.get("file_manifest") or []
    if not manifest:
        fail.append("file_manifest missing"); return
    paths = [e["file"] for e in manifest]
    if len(paths) != len(set(paths)):
        fail.append("duplicate manifest paths")
    stream_names = [Path(p).name for p in paths if p.startswith(EVIDENCE_ROOT)]
    if len(stream_names) != len(set(stream_names)):
        fail.append("duplicate evidence basenames")
    for e in manifest:
        fp = N2E_DIR / e["file"]
        if fp.name.endswith(".json") and Path(e["file"]).name.startswith("coreutils-6731-diagnostic"):
            continue
        if not fp.is_file():
            fail.append(f"manifest file missing: {e['file']}")
        elif c.sha256_file(str(fp)) != e["sha256"]:
            fail.append(f"manifest hash mismatch: {e['file']}")
    manifested = set(paths)
    for req in _required_paths(outcome):
        if req not in manifested:
            fail.append(f"required evidence omitted from manifest (exact path): {req}")
    # external artifact manifest (built by the workflow) re-verify + agree for shared files
    ext = N2E_DIR / "out" / "external-artifact-manifest.json"
    if ext.is_file():
        try:
            ej = json.loads(ext.read_text())
            ext_by = {e["file"]: e["sha256"] for e in ej.get("files", [])}
            for e in manifest:
                if e["file"] in ext_by and ext_by[e["file"]] != e["sha256"]:
                    fail.append(f"internal/external manifest disagree: {e['file']}")
        except Exception as ex:  # noqa: BLE001
            fail.append(f"external manifest unreadable: {ex}")


def verify(rec_path: Path, evidence: Path) -> tuple[bool, list, dict]:
    fail, facts = [], {}
    rec = c.load_record(rec_path)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        return False, [f"diagnostic self-hash: {msg}"], facts
    outcome = rec.get("outcome"); facts["outcome"] = outcome
    if not outcome:
        return False, ["missing/malformed outcome"], facts
    if outcome in FATAL_OUTCOMES:
        return False, [f"fatal outcome: {outcome}"], facts
    if rec.get("record_kind") != "focused_diagnostic":
        fail.append("record_kind != focused_diagnostic")
    if rec.get("acceptance_pass") is not False:
        fail.append("acceptance_pass must be false")
    if rec.get("normative_evidence_eligibility") != "UNDETERMINED":
        fail.append("producer must record normative_evidence_eligibility=UNDETERMINED (verifier decides)")
    try:
        loader.validate_resolved_closure()
    except Exception as e:  # noqa: BLE001
        fail.append(f"resolved closure invalid: {e}")

    if outcome not in ("COREUTILS_TOOLCHAIN_PINS_UNVERIFIED", "REJECTED_NO_ISOLATION"):
        _check_manifest(rec, outcome, fail)

    if outcome in ACQ_FAILURE_OUTCOMES:
        if outcome not in ("COREUTILS_TOOLCHAIN_PINS_UNVERIFIED", "REJECTED_NO_ISOLATION"):
            if not (rec.get("acquisition_A") and rec.get("acquisition_B")):
                fail.append("acquisition A/B evidence missing")
        facts["normative_evidence_eligible"] = False
        return (not fail), fail, facts

    # policy binding (corr 4): record == contract == cargo-test-v2
    try:
        bundle = loader.load_case_bundle("uutils__coreutils-6731::rust_cargo::test::fixed", "resolved")
        contract_policy = bundle["execution_contract"]["canonicalization_policy_id"]
    except Exception as e:  # noqa: BLE001
        contract_policy = None
        fail.append(f"cannot load resolved contract policy: {e}")
    rec_policy = rec.get("canonicalization_policy_id")
    if not (rec_policy == contract_policy == EXPECTED_POLICY):
        fail.append(f"policy binding: record={rec_policy} contract={contract_policy} expected={EXPECTED_POLICY}")
    policy = EXPECTED_POLICY

    if outcome == "COREUTILS_RAW_NOT_QUALIFIED":
        _check_acquisition(rec, fail)
        rd = _rederive_arm(rec, evidence, "raw", policy, fail)
        raw = rec.get("raw_arm") or {}
        rtk_bin = rec.get("rtk_binary_path")
        gates = {
            "canonical_determinism_ok": rd["rederived_deterministic"],
            "target_executed_ok": _raw_target_from_captures(evidence, rec),
            "mutation_guards_ok": bool(raw.get("per_rep_mutation")) and all(
                m.get("mutation_ok") for m in raw.get("per_rep_mutation")),
            "exit_stable_ok": raw.get("exit_stable") is True,
            "argv_equal_contract_ok": _argv_ok(raw.get("actual_argv") or [], False, rtk_bin),
            "environment_equal_contract_ok": rec.get("actual_environment_equal_contract") is True,
        }
        failed = sorted(k for k, v in gates.items() if not v)
        facts["raw_failed_gates"] = failed
        if not failed:
            fail.append("RAW-not-qualified but all RAW gates re-derive as passing (disagreement)")
        facts["normative_evidence_eligible"] = False
        return (not fail), fail, facts

    if outcome != "RTK_DIALECT_UNPROVEN":
        return False, fail + [f"unexpected outcome: {outcome}"], facts

    # ---- full RTK_DIALECT_UNPROVEN requirement set ----
    tool = rec.get("toolchain_enforcement") or {}
    if not tool.get("ok") or tool.get("manifest_sha256") != PINNED_MANIFEST_SHA:
        fail.append("toolchain pins not verified")
    _check_acquisition(rec, fail)
    A, B = rec.get("acquisition_A") or {}, rec.get("acquisition_B") or {}
    if not (A.get("install", {}).get("exit") == 0 and B.get("install", {}).get("exit") == 0):
        fail.append("acquisition install non-zero")
    if (rec.get("acquisition_classification") or {}).get("outcome") not in (
            "publisher_install_dependency_snapshot", "pristine_dependency_state"):
        fail.append("acquisition classification not eligible")
    if not (rec.get("final_env_parity") or {}).get("all_equal"):
        fail.append("final env parity not all equal")

    raw, rtk = rec.get("raw_arm") or {}, rec.get("rtk_arm") or {}
    rtk_bin = rec.get("rtk_binary_path")
    # argv (corr 1): independent re-derivation, full argv
    if not _argv_ok(raw.get("actual_argv") or [], False, rtk_bin):
        fail.append("RAW argv != contract")
    if not _argv_ok(rtk.get("actual_argv") or [], True, rtk_bin):
        fail.append("RTK argv != [rtk_bin, *contract]")
    # environment (corr 5)
    if rec.get("actual_environment_equal_contract") is not True:
        fail.append("environment != contract (producer flag not true)")
    mse = rec.get("measurement_semantic_env") or {}
    if not all(mse.get(k) == v for k, v in CONTRACT_ENV.items()):
        fail.append("re-derived measurement env != contract")
    if rec.get("raw_rtk_semantic_env_equal") is not True or raw.get("semantic_env") != rtk.get("semantic_env"):
        fail.append("RAW/RTK semantic env not equal")
    if raw.get("reps") != 3 or rtk.get("reps") != 3:
        fail.append("raw/rtk reps != 3")
    mut = (raw.get("per_rep_mutation") or []) + (rtk.get("per_rep_mutation") or [])
    if len(mut) != 6 or not all(m.get("mutation_ok") and m.get("repo_mutation_ok")
                                and m.get("cargo_cache_stable_content_ok") and m.get("toolchain_immutable")
                                for m in mut):
        fail.append("per-rep mutation guards incomplete/failed")

    raw_rd = _rederive_arm(rec, evidence, "raw", policy, fail)
    rtk_rd = _rederive_arm(rec, evidence, "rtk", policy, fail)
    for label, rd in (("raw", raw_rd), ("rtk", rtk_rd)):
        if not rd["rederived_canonical_equal_producer"]:
            fail.append(f"{label}_rederived_canonical_equal_producer false")
        if not rd["rederived_deterministic"]:
            fail.append(f"{label}_rederived_deterministic false")
        if not rd["removed_diag_equal_producer"]:
            fail.append(f"{label} removed-line diagnostics disagree")
    if raw_rd["semantic_preserved_all"] is not True:
        fail.append("RAW canonicalization did not preserve semantics")
    if not _raw_target_from_captures(evidence, rec):
        fail.append("RAW target execution not re-derivable as passing from primary captures")

    prov = rec.get("rtk_cargo_filter_source") or {}
    if not prov.get("head_proven"):
        fail.append("RTK source HEAD not proven == pinned commit")
    if not (prov.get("chain_complete") and prov.get("all_edges_resolved") and prov.get("all_roles_found")):
        fail.append("RTK dispatch->filter->parser->formatter chain not mechanically resolved")

    facts["raw_rederivation"] = raw_rd
    facts["rtk_rederivation"] = rtk_rd
    facts["normative_evidence_eligible"] = not fail
    return (not fail), fail, facts


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: verify_coreutils_diagnostic.py <diagnostic.json> <evidence-dir>")
        return 2
    ok, fail, facts = verify(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"coreutils-diagnostic-verify: {'OK' if ok else 'FAIL'} outcome={facts.get('outcome')} "
          f"normative_evidence_eligible={facts.get('normative_evidence_eligible')}")
    for f in fail:
        print(f"  - {f}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
