#!/usr/bin/env python3
"""Build the self-hash-locked Phase-A scenario-ingestion correction record.

The frozen scenarios ingested a GENERIC command (e.g. `cargo test`, `go test ./...`)
for the SWE-bench test cases where the publisher recipe mandates a SCOPED test
command. That is a typed Phase-A defect: SCENARIO_INGESTION_WRONG_WORKLOAD. The
original n2e-command-scenarios-v1.json remains immutable historical evidence; this
record is the single normative supersession, linking each affected case's original
incorrect argv to the corrected effective argv, with exact publisher-source
evidence, and pinning the superseding execution contract + publisher registry by
hash. Final canary acceptance must reference this record + the corrected contract.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_publisher_registry as pub  # noqa: E402
import n2e_argv_resolver as resolver  # noqa: E402

SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
CONTRACT = N2E_DIR / "n2e-canary-execution-contract-v1.json"
REGISTRY = N2E_DIR / "n2e-publisher-env-registry-v1.json"
OUT = N2E_DIR / "n2e-scenario-correction-v1.json"

DEFECT = "SCENARIO_INGESTION_WRONG_WORKLOAD"


def build() -> dict:
    scen_by_id = {s["case_id"]: s for s in c.load_record(SCEN)["scenarios"]}
    corrections = []
    for r in pub.load()["recipes"]:
        cid = r["case_id"]
        scen = scen_by_id[cid]
        original = list(scen.get("original_argv") or [])
        publisher_argv = pub.parse_command(r["test_cmd"][0])
        rr = resolver.resolve(scen)
        corrected = rr["effective_raw_argv"]  # publisher argv + any execution-control
        assert corrected[:len(publisher_argv)] == publisher_argv, cid
        corrections.append({
            "case_id": cid,
            "typed_defect": DEFECT,
            "original_incorrect_argv": original,
            "publisher_test_argv": publisher_argv,
            "corrected_effective_argv": corrected,
            "corrected_effective_rtk_argv": rr["effective_rtk_argv"],
            "execution_control": rr.get("execution_control"),
            "is_wrong_workload": original != publisher_argv,
            "publisher_source_evidence": {
                "harness": pub.load()["harness"],
                "source_file": r["source"]["file"],
                "source_git_blob_sha1": r["source"]["git_blob_sha1"],
                "source_sha256": r["source"]["sha256"],
                "spec": r["source"]["spec_dict"] + "[" + r["source"]["spec_key"] + "]",
                "publisher_test_cmd": r["test_cmd"],
                "toolchain": r["toolchain"],
            },
        })
    return c.envelope(
        record_type="n2e-scenario-correction",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_scenario_correction.py",
        purpose="Immutable Phase-A scenario-ingestion supersession: corrects the generic ingested "
                "command to the publisher-scoped test command for the SWE-bench test cases. The "
                "original scenarios record stays immutable; this is the normative correction.",
        typed_defect=DEFECT,
        original_scenarios_sha256=c.sha256_json_file(SCEN),
        superseding_execution_contract_sha256=c.sha256_json_file(CONTRACT),
        publisher_registry_sha256=c.sha256_json_file(REGISTRY),
        correction_count=len(corrections),
        corrections=corrections,
    )


def main() -> int:
    c.write_record(OUT, build())
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name}: {rec['correction_count']} corrections ({DEFECT})")
    for x in rec["corrections"]:
        if x["is_wrong_workload"]:
            print(f"  {x['case_id'].split('::')[0]:24} {' '.join(x['original_incorrect_argv'])!r} "
                  f"-> {' '.join(x['corrected_effective_argv'])[:48]!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
