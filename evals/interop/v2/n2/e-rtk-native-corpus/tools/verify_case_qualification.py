#!/usr/bin/env python3
"""Independent per-case acceptance VERIFIER (harness 3/3) -- the sole PASS authority.

The producer probe records observations only. This verifier re-reads the acceptance artifact,
re-binds the adapter against the frozen contract/scenario (double-lock), re-checks the RTK/argv
identities + RAW/RTK determinism, re-hashes the frozen canonical streams, and INDEPENDENTLY
re-derives the RAW<->RTK equivalence verdict through the case's proven dialect (from the frozen
manifest classification). A green GitHub job is not the PASS; this exit code is.

Usage: verify_case_qualification.py <observation.json> <evidence-dir>
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402
import n2e_case_adapters as adapters  # noqa: E402
import n2e_resolved_case_qualification as cq  # noqa: E402

MANIFEST = N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"


def verify(rec_path: Path, evidence: Path) -> tuple[bool, list, dict]:
    fail, facts = [], {}
    rec = c.load_record(rec_path)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        return False, [f"observation self-hash: {msg}"], facts

    # ---- 1. acceptance observation, not a verdict-declaring or diagnostic record ----
    if rec.get("record_type") != "n2e-resolved-case-observation":
        fail.append(f"record_type != observation ({rec.get('record_type')})")
    if rec.get("record_kind") != "resolved_case_qualification_acceptance":
        fail.append("record_kind != resolved_case_qualification_acceptance")
    if rec.get("qualification_pass") is not None:
        fail.append("producer declared qualification_pass (verdict is the verifier's alone)")
    if rec.get("acceptance_pass") is not False:
        fail.append("producer acceptance_pass must be false")
    if rec.get("outcome") != "RESOLVED_CASE_OBSERVED":
        return False, fail + [f"outcome != RESOLVED_CASE_OBSERVED ({rec.get('outcome')})"], facts

    case_id = rec.get("case_id")

    # ---- 2. independently close the closure + re-bind the adapter (double-lock) ----
    try:
        L.validate_resolved_closure()
        contract = next(e for e in c.load_record(L.CONTRACT)["contracts"] if e["case_id"] == case_id)
        scenario = next(s for s in c.load_record(L.SCEN)["scenarios"] if s["case_id"] == case_id)
        det = adapters.adapter_for(case_id).bind(contract, scenario)
    except Exception as e:  # noqa: BLE001
        return False, fail + [f"closure/adapter re-bind failed: {e}"], facts
    if rec.get("adapter_binding") != det:
        fail.append("recorded adapter_binding != independent re-bind")
    if rec.get("raw_argv_equals_adapter") is not True or rec.get("rtk_argv_equals_adapter") is not True:
        fail.append("actual argv != adapter determinants")

    # ---- 3. manifest classification for this case (kind + semantic policy) ----
    man = c.load_record(MANIFEST)
    entry = next((x for x in man["cases"] if x["case_id"] == case_id), None)
    if entry is None:
        return False, fail + [f"{case_id} not in frozen manifest"], facts
    kind = entry["qualification_kind"]
    if kind == "rtk_test_dialect":
        if det["rtk_test_dialect_policy_id"] != entry["rtk_test_dialect_policy_id"]:
            fail.append("adapter dialect != manifest dialect")
        mod = cq.TEST_DIALECTS[entry["rtk_test_dialect_policy_id"]]
    elif kind == "rtk_command_oracle":
        if det.get("command_semantic_oracle_policy_id") != entry["command_semantic_oracle_policy_id"]:
            fail.append("adapter oracle != manifest oracle")
        mod = cq.COMMAND_ORACLES[entry["command_semantic_oracle_policy_id"]]
    else:
        return False, fail + [f"unknown qualification_kind {kind!r}"], facts

    # ---- 4. identities + determinism ----
    if rec.get("rtk_binary_sha256") != L.DIALECT_RTK_SHA or rec.get("rtk_binary_bytes") != L.DIALECT_RTK_BYTES:
        fail.append("RTK binary identity != pinned corpus RTK")
    if (rec.get("raw_arm") or {}).get("deterministic") is not True:
        fail.append("RAW arm not deterministic across reps")
    if (rec.get("rtk_arm") or {}).get("deterministic") is not True:
        fail.append("RTK arm not deterministic across reps")

    # ---- 5. re-hash the frozen canonical streams vs recorded digests ----
    dig = rec.get("captured_stream_digests") or {}
    streams = {}
    for role in ("raw", "rtk"):
        p = evidence / f"{role}.canonical.bin"
        if not p.is_file():
            return False, fail + [f"missing frozen stream: {role}.canonical.bin"], facts
        b = p.read_bytes()
        meta = dig.get(f"{role}.canonical") or {}
        if hashlib.sha256(b).hexdigest() != meta.get("sha256") or len(b) != meta.get("bytes"):
            fail.append(f"{role}.canonical sha256/bytes != recorded")
        streams[role] = b

    # ---- 6. INDEPENDENT RAW<->RTK equivalence verdict through the kind-dispatched policy (`mod`
    #         was resolved in step 3: the test dialect OR the command oracle) ----
    rp, kp = mod.parse_raw(streams["raw"]), mod.parse_rtk(streams["rtk"])
    eq = mod.equivalence(rp, kp)
    facts["raw_projection"], facts["rtk_projection"], facts["equivalence"] = rp, kp, eq
    if not eq["equivalent"]:
        fail.append(f"RAW<->RTK not equivalent: {eq['mismatches']}")
    if rp.get("outcome") in (None, "indeterminate", "passthrough"):
        fail.append(f"RAW outcome not derivable ({rp.get('outcome')})")
    if kind == "rtk_test_dialect":
        # test dialects must carry a terminal summary on BOTH sides
        summary_ok = rp.get("terminal_summary_present") is True and kp.get("terminal_summary_present") is True
        if not summary_ok:
            fail.append("test-dialect projection lacks a terminal summary on RAW or RTK")
    else:  # rtk_command_oracle: no test-summary concept; the RTK outcome must be derivable too
        if kp.get("outcome") in (None, "indeterminate", "passthrough"):
            fail.append(f"RTK outcome not derivable ({kp.get('outcome')})")
    verdict = not fail
    facts["case_qualification_pass"] = bool(verdict)
    return bool(verdict), fail, facts


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: verify_case_qualification.py <observation.json> <evidence-dir>")
        return 2
    ok, fail, facts = verify(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"case-qualification-verify: {'PASS' if ok else 'FAIL'} "
          f"case_qualification_pass={facts.get('case_qualification_pass')}")
    for f in fail:
        print(f"  - {f}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
