#!/usr/bin/env python3
"""Aggregate per-case canary evidence into n2e-canary-acceptance-v1.json + report.

Consumes ONLY the committed/downloaded per-case evidence records (produced by
run_canary_case.py), independently recomputes each self-hash, verifies the exact
frozen 12-case set (no missing/duplicate/extra), and emits the acceptance record
plus the real 12-case Markdown table (n2e-canary-results-v1.md). RTK savings are
displayed, including zero/negative, and are never an acceptance gate (§19).

Usage: build_n2e_canary_acceptance.py <dir-of-case-records> [run_id]
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

CANARY = N2E_DIR / "n2e-canary-membership-v1.json"
OUT = N2E_DIR / "n2e-canary-acceptance-v1.json"
MD = N2E_DIR / "n2e-canary-results-v1.md"


def load_cases(case_dir: Path) -> list[dict]:
    cases = []
    for p in sorted(case_dir.glob("n2e-canary-case-*.json")):
        rec = c.load_record(p)
        ok, msg = c.verify_self_hash(rec)
        if not ok:
            raise SystemExit(f"{p.name}: {msg}")
        cases.append(rec)
    return cases


def case_verdict(rec: dict) -> str:
    if rec.get("status") != "MEASURED":
        return rec.get("status", "UNKNOWN")
    raw, rtk = rec["raw_arm"], rec.get("rtk_arm")
    if not raw.get("exit_code_stable") or not raw.get("canonical_deterministic"):
        return "FAIL_RAW_NONDETERMINISTIC"
    if rtk is None:
        return "FAIL_NO_RTK_ARM"
    if not rtk.get("canonical_deterministic"):
        return "FAIL_RTK_NONDETERMINISTIC"
    return "PASS"


def build(case_dir: Path, run_id: str | None) -> dict:
    membership = c.load_record(CANARY)
    expected = {m["case_id"] for m in membership["membership"]}
    cases = load_cases(case_dir)
    got = {rec["case_id"] for rec in cases}
    missing = sorted(expected - got)
    extra = sorted(got - expected)
    verdicts = {rec["case_id"]: case_verdict(rec) for rec in cases}
    all_pass = (not missing and not extra
                and all(v == "PASS" for v in verdicts.values()))

    rows = []
    for rec in sorted(cases, key=lambda r: r["case_id"]):
        raw = rec.get("raw_arm") or {}
        rtk = rec.get("rtk_arm") or {}
        rows.append({
            "case_id": rec["case_id"], "family": rec.get("command_family"),
            "subfamily": rec.get("command_subfamily"),
            "status": rec.get("status"), "verdict": verdicts[rec["case_id"]],
            "raw_o200k": raw.get("o200k_tokens"), "rtk_o200k": rtk.get("o200k_tokens"),
            "savings_pct": rec.get("rtk_savings_pct_reporting_only"),
            "raw_deterministic": raw.get("canonical_deterministic"),
            "rtk_deterministic": rtk.get("canonical_deterministic"),
            "oracle": (rec.get("semantic_oracle") or {}).get("oracle"),
        })

    body = c.envelope(
        record_type="n2e-canary-acceptance",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_canary_acceptance.py",
        purpose="Aggregate 12-case canary acceptance from independently self-hash-verified per-case records (§19).",
        run_id=run_id,
        canary_membership_sha256=c.sha256_json_file(CANARY),
        expected_case_count=len(expected),
        observed_case_count=len(cases),
        missing_cases=missing, extra_cases=extra,
        verdicts=verdicts,
        canary_pass=all_pass,
        zero_or_negative_saving_cases=[r["case_id"] for r in rows
                                       if r["savings_pct"] is not None and r["savings_pct"] <= 0],
        table=rows,
    )
    return body


def write_md(rec: dict) -> None:
    lines = [f"# N2-E 12-case canary results (run {rec.get('run_id') or 'local'})", "",
             f"canary_pass: **{rec['canary_pass']}** | observed {rec['observed_case_count']}/{rec['expected_case_count']}",
             "", "| case | family/subfamily | status | verdict | RAW o200k | RTK o200k | savings | RAW det | RTK det | oracle |",
             "|---|---|---|---|---:|---:|---:|:-:|:-:|---|"]
    for r in rec["table"]:
        lines.append(f"| `{r['case_id']}` | {r['family']}/{r['subfamily']} | {r['status']} | {r['verdict']} | "
                     f"{r['raw_o200k']} | {r['rtk_o200k']} | {r['savings_pct']} | "
                     f"{r['raw_deterministic']} | {r['rtk_deterministic']} | {r['oracle']} |")
    if rec["zero_or_negative_saving_cases"]:
        lines += ["", "Zero/negative-saving cases (shown, not hidden): "
                  + ", ".join(f"`{x}`" for x in rec["zero_or_negative_saving_cases"])]
    MD.write_text("\n".join(lines) + "\n")


def main() -> int:
    case_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else N2E_DIR
    run_id = sys.argv[2] if len(sys.argv) > 2 else None
    body = build(case_dir, run_id)
    c.write_record(OUT, body)
    write_md(c.load_record(OUT))
    print(f"wrote {OUT.name} canary_pass={body['canary_pass']} observed={body['observed_case_count']}/{body['expected_case_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
