#!/usr/bin/env python3
"""Build n2e-ecosystem-rtk-dialect-seed-v1: characterize the REAL per-ecosystem RTK
streams captured by the non-acceptance run 29639560535, to seed the JVM/JS/Python RTK
dialect proofs (they currently fail closed -- no proven dialect). Pure characterization
from committed streams; it proves NO dialect and admits NO case (that is the later step).

Observed in this run:
  * python (pytest): RTK emits a compact aggregate summary `Pytest: <n> passed` (and,
    on failure, `Pytest: <p> passed, <f> failed`) -- directly analogous to `Go test:`.
  * js_ts (vitest): RTK passes through vitest verbose output; failing identity markers
    `× <id>` / `FAIL  <id>` and the summary line ` Tests  <f> failed | <p> passed (<n>)`.
  * jvm (lucene): RAW_REJECTED (RAW non-deterministic, exit 1) -- the RTK arm never ran,
    so NO jvm RTK stream exists in this run; the jvm blocker here is RAW determinism, not
    only the missing dialect.
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

SEED_DIR = N2E_DIR / "evidence" / "ecosystem-rtk-seed-run-29639560535"
OUT = N2E_DIR / "n2e-ecosystem-rtk-dialect-seed-v1.json"
RUN_ID = "29639560535"
CASES = {
    "python": ("bugsinpy__scrapy-9__python__pytest__fixed", "8428318715", "case-1"),
    "js_ts": ("vuejs__core-11589__js_ts__test__buggy", "8428324270", "case-11"),
    "jvm": ("apache__lucene-13704__jvm__test__buggy", "8428364189", "case-0"),
}


def _decompress(p: Path) -> bytes:
    return zlib.decompress(p.read_bytes())


def _arm_streams(case_dir: Path, role: str) -> list[Path]:
    d = case_dir / "streams"
    return sorted(d.glob(f"{role}.rep*.zst")) if d.is_dir() else []


def _determinism(streams: list[Path]) -> dict:
    hashes = [hashlib.sha256(_decompress(p)).hexdigest() for p in streams]
    return {"reps": len(streams), "content_sha256": hashes,
            "deterministic": len(hashes) == 3 and len(set(hashes)) == 1}


def characterize(fam: str, case_stub: str) -> dict:
    case_dir = SEED_DIR / case_stub
    rec = c.load_record(case_dir / f"n2e-canary-case-{case_stub}.json")
    ok, msg = c.verify_self_hash(rec)
    rtk = _arm_streams(case_dir, "rtk")
    raw = _arm_streams(case_dir, "raw")
    out = {
        "family": fam, "case_id": rec["case_id"],
        "case_record_sha256": c.sha256_json_file(case_dir / f"n2e-canary-case-{case_stub}.json"),
        "case_record_self_hash_ok": ok,
        "overall_status": rec.get("status"),
        "raw_stream": _determinism(raw),
        "rtk_stream_present": bool(rtk),
        "rtk_stream": _determinism(rtk) if rtk else None,
        "rtk_oracle_fail_closed_reason": ((rec.get("rtk_semantic_oracle") or {})
                                          .get("evidence", {}) or {}).get("error"),
    }
    if rtk:
        head = _decompress(rtk[0]).decode("utf-8", "replace")
        # small, redaction-free grammar sample to seed the dialect (summary + fail lines)
        lines = [ln for ln in head.splitlines()
                 if any(k in ln for k in ("Pytest:", "Go test:", "Tests ", "FAIL", "×", "passed", "failed"))]
        out["observed_rtk_grammar_sample"] = lines[:8]
    return out


def build() -> dict:
    seeds = [characterize(fam, stub) for fam, (stub, _aid, _cn) in CASES.items()]
    return c.envelope(
        record_type="n2e-ecosystem-rtk-dialect-seed",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_ecosystem_rtk_seed.py",
        purpose="Characterize the real per-ecosystem RTK streams from non-acceptance run "
                "29639560535 to seed the JVM/JS/Python RTK dialect proofs. Proves NO dialect "
                "and admits NO case -- those RTK arms remain fail-closed until a dialect is "
                "proven from pinned RTK source + real fixtures.",
        run_id=RUN_ID,
        note="jvm (lucene) is RAW_REJECTED in this run (RAW non-deterministic): no jvm RTK "
             "stream captured; the jvm blocker here is RAW determinism, not only the dialect.",
        provenance={fam: {"artifact_id": aid, "artifact_name": cn}
                    for fam, (_stub, aid, cn) in CASES.items()},
        dialects_still_fail_closed=["jvm", "js_ts", "python"],
        seeds=seeds,
    )


def main() -> int:
    body = build()
    c.write_record(OUT, body)
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name}")
    for s in rec["seeds"]:
        print(f"  {s['family']:7} {s['overall_status']:14} rtk_present={s['rtk_stream_present']} "
              f"rtk_det={(s['rtk_stream'] or {}).get('deterministic')} "
              f"raw_det={s['raw_stream']['deterministic']}")
        for g in s.get("observed_rtk_grammar_sample", [])[:3]:
            print(f"        RTK> {g[:80]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
