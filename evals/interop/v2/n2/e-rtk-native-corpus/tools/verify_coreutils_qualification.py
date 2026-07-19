#!/usr/bin/env python3
"""P4 independent Coreutils qualification VERIFIER -- the sole PASS authority.

The producer (probe_coreutils_qualification.py) records OBSERVATIONS ONLY. This verifier re-reads
the artifact, re-checks digests + binding, independently CLOSES the P1/P2/P3 loader closure,
re-derives the RAW/RTK semantic projections through the frozen P3 dialect, recomputes the
equivalence, and only then derives PASS/FAIL. A green GitHub job is not a PASS; this exit code is.

Usage: verify_coreutils_qualification.py <qualification.json> <evidence-dir>
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
import n2e_resolved_loader as L  # noqa: E402
import n2e_rtk_rust_cargo_dialect as rcd  # noqa: E402
import n2e_canon_policies as canon  # noqa: E402

CASE_ID = "uutils__coreutils-6731::rust_cargo::test::fixed"
EXPECTED = {"passed": 10, "filtered_out": 3205, "suites": 3}
V3 = "cargo-test-v3"


def _dz(p: Path) -> bytes:
    return zlib.decompress(p.read_bytes())


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def verify(rec_path: Path, evidence: Path) -> tuple[bool, list, dict]:
    fail, facts = [], {}
    rec = c.load_record(rec_path)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        return False, [f"qualification self-hash: {msg}"], facts

    # ---- 1. this MUST be an acceptance artifact, not a diagnostic substituted for one ----
    if rec.get("record_type") != "n2e-coreutils-qualification-observation":
        fail.append(f"record_type != qualification-observation ({rec.get('record_type')})")
    if rec.get("record_kind") != "coreutils_qualification_acceptance":
        fail.append("record_kind != coreutils_qualification_acceptance (diagnostic substituted?)")
    if rec.get("case_id") != CASE_ID:
        fail.append("case_id != coreutils-6731")
    # ---- 2. the producer must NOT have declared a verdict ----
    if rec.get("qualification_pass") is not None:
        fail.append("producer declared qualification_pass (verdict is the verifier's alone)")
    if rec.get("acceptance_pass") is not False:
        fail.append("producer acceptance_pass must be false")
    if rec.get("outcome") != "COREUTILS_QUALIFICATION_OBSERVED":
        return False, fail + [f"outcome != OBSERVED ({rec.get('outcome')})"], facts

    # ---- 3. independently CLOSE the P1/P2/P3 loader closure + bind contract gen 3 ----
    try:
        L.validate_resolved_closure()
        contract = L.load_case_bundle(CASE_ID, "resolved")["execution_contract"]
    except Exception as e:  # noqa: BLE001
        return False, fail + [f"loader closure failed: {e}"], facts
    if contract.get("rtk_test_dialect_policy_id") != L.DIALECT_ID:
        fail.append("contract does not bind the proven rust dialect")
    if contract.get("canonicalization_policy_id") != V3:
        fail.append("contract canonicalization policy != cargo-test-v3")
    if rec.get("bound_dialect_policy_id") != L.DIALECT_ID:
        fail.append("artifact bound_dialect_policy_id != proven dialect")
    if rec.get("canonicalization_policy_id") != V3:
        fail.append("artifact canonicalization_policy_id != cargo-test-v3")

    # ---- 4. exact identities (Rust, Cargo, RTK source/binary) ----
    ii = (rec.get("toolchain_enforcement") or {}).get("installed_identity") or {}
    if ii.get("cargo_binary_sha256") != L.PROVEN_BINARY_IDENTITY["cargo"]["sha256"]:
        fail.append("cargo binary identity != proven")
    if ii.get("rustc_binary_sha256") != L.PROVEN_BINARY_IDENTITY["rust"]["sha256"]:
        fail.append("rustc binary identity != proven")
    if rec.get("rtk_binary_sha256") != L.DIALECT_RTK_SHA or rec.get("rtk_binary_bytes") != L.DIALECT_RTK_BYTES:
        fail.append("RTK binary identity != proven (41f316.../9200104)")
    if rec.get("acquired_lock_matches_frozen_p1") is not True:
        fail.append("acquired Cargo.lock does not match the frozen P1 substrate")

    # ---- 5. re-derive the RAW/RTK semantic projections from the FRESH captured streams ----
    for f in ("raw.rep0.zst", "rtk.rep0.zst"):
        if not (evidence / f).is_file():
            return False, fail + [f"missing stream role: {f}"], facts
    raw_can, rtk_can = _dz(evidence / "raw.rep0.zst"), _dz(evidence / "rtk.rep0.zst")
    rp, kp = rcd.parse_raw(raw_can), rcd.parse_rtk(rtk_can)
    eq = rcd.equivalence(rp, kp)
    facts["raw_projection"] = rp
    facts["rtk_projection"] = kp
    facts["equivalence"] = eq
    if rp["outcome"] != "success":
        fail.append(f"RAW process outcome != success ({rp['outcome']})")
    if not eq["equivalent"]:
        fail.append(f"RAW<->RTK not equivalent: {eq['mismatches']}")
    for side, proj in (("raw", rp), ("rtk", kp)):
        if (proj["passed"], proj["filtered_out"], proj["suites"]) != (
                EXPECTED["passed"], EXPECTED["filtered_out"], EXPECTED["suites"]):
            fail.append(f"{side} counts != (10 passed, 3205 filtered, 3 suites): "
                        f"{(proj['passed'], proj['filtered_out'], proj['suites'])}")
        if proj["failing_ids"]:
            fail.append(f"{side} has failing identities: {proj['failing_ids']}")
        if not proj["terminal_summary_present"]:
            fail.append(f"{side} lacks a complete terminal summary")

    # ---- 6. RTK canonical reproducible across reps; raw RTK differs only by the normalized duration ----
    rtk_canon_shas = {_sha(_dz(evidence / f"rtk.rep{i}.zst")) for i in range(3) if (evidence / f"rtk.rep{i}.zst").is_file()}
    if len(rtk_canon_shas) != 1:
        fail.append("RTK canonical stream not reproducible across reps")
    raw_shas, dur_norm_shas = set(), set()
    for i in range(3):
        p = evidence / f"rtk.raw.rep{i}.zst"
        if p.is_file():
            b = _dz(p)
            raw_shas.add(_sha(b))
            dur_norm_shas.add(_sha(canon.canonicalize(canon.rtk_envelope(b), V3)))
    if len(dur_norm_shas) != 1:
        fail.append("raw RTK streams differ beyond the normalized duration field")
    facts["raw_rtk_only_duration_differs"] = (len(dur_norm_shas) == 1)

    # ---- 7. RAW arm qualified + both arms deterministic (re-checked, not trusted) ----
    raw_arm, rtk_arm = rec.get("raw_arm") or {}, rec.get("rtk_arm") or {}
    if raw_arm.get("raw_qualified") is not True:
        fail.append("RAW arm not qualified")
    if raw_arm.get("deterministic") is not True or rtk_arm.get("deterministic") is not True:
        fail.append("RAW or RTK arm not deterministic across reps")
    if raw_arm.get("actual_argv_equal_contract") is not True or rtk_arm.get("actual_argv_equal_contract") is not True:
        fail.append("RAW/RTK argv != committed contract")

    # ---- 8. re-derive canonical from raw (confirm the producer canonicalized under cargo-test-v3) ----
    for role, is_rtk in (("raw", False), ("rtk", True)):
        arm = rec.get(f"{role}_arm") or {}
        runs = arm.get("runs") or []
        for i in range(3):
            rawf, canf = evidence / f"{role}.raw.rep{i}.zst", evidence / f"{role}.rep{i}.zst"
            if not (rawf.is_file() and canf.is_file()):
                fail.append(f"missing {role} rep{i} stream(s)"); continue
            raw = _dz(rawf)
            derived = canon.canonicalize(canon.rtk_envelope(raw) if is_rtk else raw, V3)
            if derived != _dz(canf):
                fail.append(f"{role} rep{i}: re-derived cargo-test-v3 canonical != producer file")
            if len(runs) > i and _sha(derived) != runs[i].get("canonical_sha256"):
                fail.append(f"{role} rep{i}: re-derived canonical sha != recorded")

    verdict = not fail
    facts["coreutils_qualification_pass"] = verdict
    return verdict, fail, facts


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: verify_coreutils_qualification.py <qualification.json> <evidence-dir>")
        return 2
    ok, fail, facts = verify(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"coreutils-qualification-verify: {'PASS' if ok else 'FAIL'} "
          f"coreutils_qualification_pass={facts.get('coreutils_qualification_pass')}")
    for f in fail:
        print(f"  - {f}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
