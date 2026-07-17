#!/usr/bin/env python3
"""Aggregate per-case canary evidence — FAIL-CLOSED, primitive re-derivation (§7/§19).

Consumes ONLY per-case evidence records, independently recomputes each self-hash,
DETECTS DUPLICATES before constructing the case set, and RE-DERIVES every verdict
from primitive fields (never trusts a producer-supplied status/verdict). A case
is PASS only if every RAW and RTK acceptance property holds. Emits the acceptance
record (+ real 12-case Markdown table) with the run/implementation identity.

Usage: build_n2e_canary_acceptance.py <case-dir> [--run-id R] [--impl-sha I]
       [--trigger-sha T] [--job-manifest J] [--artifact-manifest A]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

CANARY = N2E_DIR / "n2e-canary-membership-v1.json"
OUT = N2E_DIR / "n2e-canary-acceptance-v1.json"
MD = N2E_DIR / "n2e-canary-results-v1.md"
RTK_BINARY_SHA256 = "41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf"


def rederive_verdict(rec: dict) -> tuple[str, list]:
    """Re-derive PASS/FAIL from PRIMITIVE evidence only. Ignores producer status."""
    reasons = []
    fam = rec.get("command_family")
    raw = rec.get("raw_arm") or {}
    rtk = rec.get("rtk_arm")
    raw_orc = rec.get("raw_semantic_oracle") or {}
    rtk_orc = rec.get("rtk_semantic_oracle") or {}
    acq = rec.get("acquisition") or {}
    iso = rec.get("isolation") or {}
    if rec.get("rtk_binary_sha256") != RTK_BINARY_SHA256:
        reasons.append("rtk_binary_identity")
    if raw.get("reps_completed") != 3:
        reasons.append("raw_reps!=3")
    if not raw.get("exit_code_stable"):
        reasons.append("raw_exit_unstable")
    if not raw.get("canonical_deterministic"):
        reasons.append("raw_nondeterministic")
    if raw_orc.get("verdict") is not True:
        reasons.append("raw_oracle_fail")
    if not acq.get("identity_verified"):
        reasons.append("acquisition_unverified")
    # isolation: netns-denial required for all families except containers
    if fam == "containers":
        if not iso.get("host_side_observation", True):
            reasons.append("container_isolation")
    elif not ((iso.get("denial_probe") or {}).get("denied")):
        reasons.append("isolation_not_denied")
    if rtk is None:
        reasons.append("no_rtk_arm")
    else:
        if rtk.get("reps_completed") != 3:
            reasons.append("rtk_reps!=3")
        if not rtk.get("exit_code_stable"):
            reasons.append("rtk_exit_unstable")
        if not rtk.get("canonical_deterministic"):
            reasons.append("rtk_nondeterministic")
        if rtk_orc.get("verdict") is not True:
            reasons.append("rtk_oracle_fail")
    return ("PASS" if not reasons else "FAIL", reasons)


def load_cases(case_dir: Path) -> list[dict]:
    recs, seen = [], {}
    for p in sorted(case_dir.rglob("n2e-canary-case-*.json")):
        rec = c.load_record(p)
        ok, msg = c.verify_self_hash(rec)
        if not ok:
            raise SystemExit(f"{p.name}: self-hash {msg}")
        cid = rec.get("case_id")
        if cid in seen:
            raise SystemExit(f"duplicate per-case record for {cid} ({p.name} vs {seen[cid]})")
        seen[cid] = p.name
        recs.append(rec)
    return recs


def build(case_dir: Path, args) -> dict:
    membership = c.load_record(CANARY)
    expected = {m["case_id"] for m in membership["membership"]}
    cases = load_cases(case_dir)
    got = {r["case_id"] for r in cases}
    missing, extra = sorted(expected - got), sorted(got - expected)

    verdicts, rows = {}, []
    for rec in sorted(cases, key=lambda r: r["case_id"]):
        v, reasons = rederive_verdict(rec)
        verdicts[rec["case_id"]] = v
        raw = rec.get("raw_arm") or {}
        rtk = rec.get("rtk_arm") or {}
        rows.append({
            "case_id": rec["case_id"], "family": rec.get("command_family"),
            "subfamily": rec.get("command_subfamily"),
            "producer_status": rec.get("status"), "rederived_verdict": v,
            "reasons": reasons,
            "raw_o200k": raw.get("o200k_tokens"), "rtk_o200k": rtk.get("o200k_tokens"),
            "savings_pct": rec.get("rtk_savings_pct_reporting_only"),
            "raw_deterministic": raw.get("canonical_deterministic"),
            "rtk_deterministic": rtk.get("canonical_deterministic"),
            "raw_oracle": (rec.get("raw_semantic_oracle") or {}).get("oracle"),
            "rtk_oracle": (rec.get("rtk_semantic_oracle") or {}).get("oracle"),
            "record_sha256": rec.get("record_sha256"),
        })
    all_pass = (not missing and not extra
                and len(got) == len(expected)
                and all(v == "PASS" for v in verdicts.values()))

    return c.envelope(
        record_type="n2e-canary-acceptance",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_canary_acceptance.py",
        purpose="Fail-closed 12-case canary acceptance; verdicts re-derived from primitive per-case evidence (§7/§19).",
        run_id=args.run_id, implementation_sha=args.impl_sha, trigger_sha=args.trigger_sha,
        job_manifest_sha256=c.sha256_file(args.job_manifest) if args.job_manifest else None,
        artifact_manifest_sha256=c.sha256_file(args.artifact_manifest) if args.artifact_manifest else None,
        canary_membership_sha256=c.sha256_json_file(CANARY),
        expected_case_count=len(expected), observed_case_count=len(cases),
        missing_cases=missing, extra_cases=extra,
        verdicts=verdicts, canary_pass=all_pass,
        zero_or_negative_saving_cases=[r["case_id"] for r in rows
                                       if r["savings_pct"] is not None and r["savings_pct"] <= 0],
        table=rows,
    )


def write_md(rec: dict) -> None:
    lines = [f"# N2-E 12-case canary results (run {rec.get('run_id') or 'local'})", "",
             f"canary_pass: **{rec['canary_pass']}** | observed {rec['observed_case_count']}/{rec['expected_case_count']}"
             f" | impl `{rec.get('implementation_sha')}`", "",
             "| case | family/subfamily | producer | re-derived | RAW o200k | RTK o200k | savings | RAW det | RTK det | reasons |",
             "|---|---|---|---|---:|---:|---:|:-:|:-:|---|"]
    for r in rec["table"]:
        lines.append(f"| `{r['case_id']}` | {r['family']}/{r['subfamily']} | {r['producer_status']} | "
                     f"**{r['rederived_verdict']}** | {r['raw_o200k']} | {r['rtk_o200k']} | {r['savings_pct']} | "
                     f"{r['raw_deterministic']} | {r['rtk_deterministic']} | {','.join(r['reasons']) or '-'} |")
    if rec["zero_or_negative_saving_cases"]:
        lines += ["", "Zero/negative-saving cases (shown, not hidden): "
                  + ", ".join(f"`{x}`" for x in rec["zero_or_negative_saving_cases"])]
    MD.write_text("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("case_dir")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--impl-sha", default=None)
    ap.add_argument("--trigger-sha", default=None)
    ap.add_argument("--job-manifest", default=None)
    ap.add_argument("--artifact-manifest", default=None)
    args = ap.parse_args()
    body = build(Path(args.case_dir), args)
    c.write_record(OUT, body)
    write_md(c.load_record(OUT))
    print(f"wrote {OUT.name} canary_pass={body['canary_pass']} observed={body['observed_case_count']}/{body['expected_case_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
