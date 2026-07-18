#!/usr/bin/env python3
"""Build caddy-5870-pass-evidence-v1 (ruling step 6.1: commit Caddy PASS evidence).

Preserves the caddy PASS re-judgment from run 29639560535 (strict rtk-go-test-summary-v1
grammar) as a self-hash-locked provenance record over the committed case record + streams.
It re-derives, INDEPENDENTLY of the producer's summary, that the RTK MEASURED stream
preserves the RAW failing identity TestUnsyncedConfigAccess under the strict Go dialect --
confirming the previously-alleged DISQUALIFIED_RTK_SEMANTIC_LOSS was purely an oracle
parser defect (HARNESS_DEFECT_ORACLE_UNRECOGNIZED_RTK_TEST_GRAMMAR), now withdrawn. No
Caddy rejection-ledger entry is permitted.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_classification as cls  # noqa: E402
import n2e_oracles as ora  # noqa: E402

EVID_DIR = N2E_DIR / "evidence" / "caddy-pass-run-29639560535"
CASE = EVID_DIR / "n2e-canary-case-caddyserver__caddy-5870__go__test__buggy.json"
OUT = N2E_DIR / "caddy-5870-pass-evidence-v1.json"
CASE_ID = "caddyserver__caddy-5870::go::test::buggy"
REQUIRED_ID = "TestUnsyncedConfigAccess"

PROBE_PROVENANCE = {
    "run_id": "29639560535", "workflow": "qodec-n2e-corpus-canary",
    "trigger_head_sha": "f29e958e40a357891fe27e17d7d2fc2ae3660a26",
    "implementation_sha": "9865af4ce8558e8609eaf2008da1f98f739b9484",
    "artifact_id": "8428319361",
    "artifact_zip_sha256": "sha256:48a030a84485787897643a8bd7c1e81043c2ed1822a2d138c88a4ecd4c3087c6",
}


def build() -> dict:
    rec = c.load_record(CASE)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        raise SystemExit(f"caddy case self-hash: {msg}")
    raw_orc = rec["raw_semantic_oracle"]
    rtk_orc = rec["rtk_semantic_oracle"]
    ev = rtk_orc["evidence"]
    raw_ids = ev["raw"]["failing_ids"]
    rtk_ids = ev["rtk"]["failing_ids"]

    checks = {
        "raw_oracle_true": raw_orc.get("verdict") is True,
        "raw_failing_target_present": REQUIRED_ID in raw_ids,
        "rtk_dialect_is_strict": ev.get("rtk_dialect") == ora.RTK_GO_DIALECT,
        "raw_dialect_is_native": ev.get("raw_dialect") == "go-test-native-v1",
        "rtk_aggregate_summary_present": ev["rtk"].get("aggregate_summary_present") is True,
        "rtk_no_summary_conflict": ev["rtk"].get("aggregate_summary_conflict") is False,
        "rtk_preserves_required_identity": REQUIRED_ID in rtk_ids,
        "counts_agree": ev.get("count_ok") is True and ev["raw"]["failed"] == ev["rtk"]["failed"],
        "ids_agree": ev.get("ids_ok") is True and set(raw_ids) == set(rtk_ids),
        "rtk_oracle_true": rtk_orc.get("verdict") is True,
    }
    passed = all(checks.values())

    return c.envelope(
        record_type="n2e-caddy-pass-evidence",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_caddy_pass_evidence.py",
        purpose="Preserved caddy PASS re-judgment under the strict rtk-go-test-summary-v1 grammar; "
                "RTK measured stream preserves the RAW failing identity. No rejection-ledger entry.",
        case_id=CASE_ID,
        outcome=cls.PASS if passed else None,
        withdrawn_disqualification=cls.DISQUALIFIED_RTK_SEMANTIC_LOSS,
        withdrawal_basis=cls.HARNESS_DEFECT_ORACLE_UNRECOGNIZED_RTK_TEST_GRAMMAR,
        no_rejection_ledger_entry=True,
        probe_provenance=PROBE_PROVENANCE,
        preserved_case_record="evidence/caddy-pass-run-29639560535/"
                              "n2e-canary-case-caddyserver__caddy-5870__go__test__buggy.json",
        preserved_case_record_sha256=c.sha256_json_file(CASE),
        preserved_case_internal_sha256=rec["record_sha256"],
        required_failing_identity=REQUIRED_ID,
        raw_dialect=ev.get("raw_dialect"), rtk_dialect=ev.get("rtk_dialect"),
        raw_failing_ids=raw_ids, rtk_failing_ids=rtk_ids,
        raw_canonical_sha256=[r.get("canonical_sha256") for r in (rec.get("raw_arm") or {}).get("runs", [])],
        rtk_canonical_sha256=[r.get("canonical_sha256") for r in (rec.get("rtk_arm") or {}).get("runs", [])],
        checks=checks,
        pass_confirmed=passed,
    )


def main() -> int:
    body = build()
    c.write_record(OUT, body)
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name}: pass_confirmed={rec['pass_confirmed']} outcome={rec['outcome']}")
    for k, v in rec["checks"].items():
        if not v:
            print(f"  FAILED: {k}")
    return 0 if rec["pass_confirmed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
