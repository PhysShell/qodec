#!/usr/bin/env python3
"""Offline runner for the N2-E text-compression benchmark.

Reads benchmark-manifest.json, verifies every RAW/RTK input digest, then measures four arms per case:
  RAW            -- the frozen RAW authority bytes
  RTK            -- the frozen RTK output bytes
  Qodec          -- qodec encode --codec deep over the RAW bytes (lossless; roundtrip-verified)
  RTK -> Qodec   -- qodec encode --codec deep over the RTK bytes (lossless; roundtrip-verified)
under two exact BPE tokenizers (o200k primary, cl100k secondary), and writes results.json,
per-case.csv, per-family.csv, and report.md. Reporting slice only -- touches no frozen evidence.

The Qodec artifact for an arm is produced ONCE under the primary meter (o200k) and then measured under
both tokenizer profiles (its bytes are fixed; only the token count differs by profile).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import bench_lib as B  # noqa: E402

METERS = ["o200k", "cl100k"]
PRIMARY = "o200k"
ARMS = ["raw", "rtk", "qodec", "rtk_then_qodec"]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_arm_bytes(man_arm: dict) -> bytes:
    p = REPO / man_arm["source"]
    data = p.read_bytes()
    if _sha(data) != man_arm["sha256"]:
        raise SystemExit(f"digest drift for {man_arm['source']}: {_sha(data)} != {man_arm['sha256']}")
    return data


def _tok_all(q: B.Qodec, data: bytes, wd: Path) -> dict:
    """Exact token count under every meter (with a t0/t1 wall for the primary tokenize)."""
    out = {}
    for m in METERS:
        r = q.tokenize(data, m, wd)
        out[m] = r
    return out


def measure(qodec_bin: Path, manifest: dict, timeout: float) -> dict:
    q = B.Qodec(qodec_bin, timeout=timeout)
    run_started = time.time()
    results = []
    peak_overall = 0
    for case in manifest["cases"]:
        with tempfile.TemporaryDirectory(prefix="n2ebench-") as td:
            wd = Path(td)
            raw_m = case["arms"]["raw"]
            rtk_m = case["arms"]["rtk"]
            raw_avail = raw_m.get("available", False)
            raw_bytes = _load_arm_bytes(raw_m) if raw_avail else None
            rtk_bytes = _load_arm_bytes(rtk_m)

            arm_out = {}

            # ---- RAW arm (the reference) ----
            if raw_avail:
                bm = B.basic_metrics(raw_bytes)
                t0 = time.perf_counter(); toks = _tok_all(q, raw_bytes, wd); dur = time.perf_counter() - t0
                arm_out["raw"] = {**bm, "tokens": {m: toks[m]["tokens"] for m in METERS},
                                  "token_status": {m: toks[m]["status"] for m in METERS},
                                  "output_sha256": _sha(raw_bytes), "wall_s": dur,
                                  "peak_kib": None, "status": B.PASS, "semantic_check": "reference",
                                  "nature": raw_m.get("nature"), "exit_status": 0}
            else:
                # bounded capsule (loghub): RAW text not local -> tokens unsupported, report capsule facts
                arm_out["raw"] = {"bytes": None, "unicode_chars": None, "lines": raw_m.get("published_line_total"),
                                  "tokens": {m: None for m in METERS},
                                  "token_status": {m: B.UNSUPPORTED for m in METERS},
                                  "output_sha256": raw_m.get("member_sha256"), "wall_s": None,
                                  "peak_kib": None, "status": B.UNSUPPORTED, "semantic_check": "reference",
                                  "nature": raw_m.get("nature"), "exit_status": None,
                                  "unsupported_reason": raw_m.get("reason")}

            # ---- RTK arm (already qualified: semantic pass reused from the frozen corpus) ----
            bm = B.basic_metrics(rtk_bytes)
            t0 = time.perf_counter(); toks = _tok_all(q, rtk_bytes, wd); dur = time.perf_counter() - t0
            arm_out["rtk"] = {**bm, "tokens": {m: toks[m]["tokens"] for m in METERS},
                              "token_status": {m: toks[m]["status"] for m in METERS},
                              "output_sha256": _sha(rtk_bytes), "wall_s": dur, "peak_kib": None,
                              "status": B.PASS, "semantic_check": B.PASS,
                              "semantic_note": "qualified in the frozen N2-E corpus (oracle-equivalent to RAW)",
                              "nature": rtk_m.get("nature"), "exit_status": 0}

            # ---- Qodec arm (over RAW) ----
            if raw_avail:
                enc = q.encode_deep(raw_bytes, PRIMARY, wd)
                arm_out["qodec"] = _qodec_arm(q, enc, wd)
            else:
                arm_out["qodec"] = {"status": B.UNSUPPORTED,
                                    "unsupported_reason": "RAW bytes not local (bounded capsule)",
                                    "tokens": {m: None for m in METERS},
                                    "token_status": {m: B.UNSUPPORTED for m in METERS},
                                    "semantic_check": B.UNSUPPORTED}

            # ---- RTK -> Qodec arm (over RTK) ----
            enc = q.encode_deep(rtk_bytes, PRIMARY, wd)
            arm_out["rtk_then_qodec"] = _qodec_arm(q, enc, wd)

            for a in arm_out.values():
                if a.get("peak_kib"):
                    peak_overall = max(peak_overall, a["peak_kib"])

            results.append({"case": case["case"], "case_id": case["case_id"],
                            "family": case["family"], "oracle_policy_id": case.get("oracle_policy_id"),
                            "arms": arm_out})

    return {"results": results, "wall_total_s": time.time() - run_started,
            "peak_kib_overall": peak_overall or None}


def _qodec_arm(q: B.Qodec, enc: dict, wd: Path) -> dict:
    if enc.get("status") != B.PASS:
        return {"status": enc.get("status", B.FAILED), "error": enc.get("error"),
                "tokens": {m: None for m in METERS}, "token_status": {m: enc.get("status") for m in METERS},
                "semantic_check": B.FAILED if enc.get("status") == B.FAILED else B.UNSUPPORTED,
                "wall_s": enc.get("duration_s"), "peak_kib": enc.get("peak_kib")}
    content = enc["content_bytes"]
    bm = B.basic_metrics(content)
    tokens = {PRIMARY: enc["tokens_out"]}
    tstat = {PRIMARY: B.PASS}
    for m in METERS:
        if m == PRIMARY:
            continue
        r = q.tokenize(content, m, wd)
        tokens[m] = r["tokens"]; tstat[m] = r["status"]
    return {**bm, "codec": enc.get("codec"), "tokens": tokens, "token_status": tstat,
            "output_sha256": _sha(content), "wall_s": enc.get("duration_s"),
            "peak_kib": enc.get("peak_kib"), "status": B.PASS,
            "roundtrip_lossless": enc.get("roundtrip_lossless"),
            "semantic_check": B.PASS,  # lossless roundtrip verified -> stronger than oracle equivalence
            "semantic_note": "byte-lossless (decode==input verified); no semantic information lost",
            "exit_status": 0}


# ---------------------------------------------------------------------------------------------------
# derivations: per-case relative metrics, per-family, aggregates
# ---------------------------------------------------------------------------------------------------
def _mib_s(nbytes, secs):
    if not nbytes or not secs:
        return None
    return (nbytes / (1024 * 1024)) / secs


def enrich(res: dict) -> dict:
    for case in res["results"]:
        raw = case["arms"]["raw"]
        for arm_name, arm in case["arms"].items():
            arm["compression_ratio"] = {}
            arm["tokens_saved"] = {}
            arm["pct_tokens_saved"] = {}
            for m in METERS:
                at = arm.get("tokens", {}).get(m)
                rt = raw.get("tokens", {}).get(m)
                arm["compression_ratio"][m] = B.ratio(at, rt)
                arm["tokens_saved"][m] = (None if at is None or rt is None else rt - at)
                arm["pct_tokens_saved"][m] = B.saving_percent(at, rt)
            # bytes saved vs RAW
            rb = raw.get("bytes")
            ab = arm.get("bytes")
            arm["bytes_saved"] = (None if rb is None or ab is None else rb - ab)
            arm["pct_bytes_saved"] = (None if not rb or ab is None else 100.0 * (1 - ab / rb))
            arm["throughput_mib_s"] = _mib_s(arm.get("bytes"), arm.get("wall_s"))
        # per-case ranking over transform arms whose token count exists + semantic ok (primary meter)
        rankable = []
        for a in ("rtk", "qodec", "rtk_then_qodec"):
            arm = case["arms"][a]
            t = arm.get("tokens", {}).get(PRIMARY)
            sem = arm.get("semantic_check")
            if t is not None and sem in (B.PASS, "reference"):
                rankable.append((t, a))
        rankable.sort()
        case["ranking_primary"] = [a for _, a in rankable]
        case["winner"] = rankable[0][1] if rankable else None
    return res


def _family_stats(res: dict) -> list:
    fams = {}
    for case in res["results"]:
        fams.setdefault(case["family"], []).append(case)
    rows = []
    for fam, cases in sorted(fams.items()):
        def savings(arm):
            return [c["arms"][arm]["pct_tokens_saved"][PRIMARY] for c in cases
                    if c["arms"][arm]["pct_tokens_saved"].get(PRIMARY) is not None]
        rtk_s = savings("rtk"); qod_s = savings("qodec")
        sem_fail = sum(1 for c in cases for a in c["arms"].values() if a.get("semantic_check") == B.FAILED)
        sem_unsup = sum(1 for c in cases for a in c["arms"].values() if a.get("semantic_check") == B.UNSUPPORTED)
        rng = (min(qod_s), max(qod_s)) if qod_s else (None, None)
        consistent = (qod_s and (max(qod_s) - min(qod_s) <= 25.0)) if len(qod_s) > 1 else None
        rows.append({
            "family": fam, "cases": [c["case"] for c in cases], "n_cases": len(cases),
            "rtk_median_pct_saved": (statistics.median(rtk_s) if rtk_s else None),
            "qodec_median_pct_saved": (statistics.median(qod_s) if qod_s else None),
            "qodec_pct_saved_range": rng,
            "semantic_failures": sem_fail, "semantic_unsupported": sem_unsup,
            "note": ("single-case family -- not a statistical average" if len(cases) == 1
                     else ("consistent across cases" if consistent else "highly case-dependent")),
        })
    return rows


def _aggregate(res: dict, cases_subset) -> dict:
    def tok(arm, c, m=PRIMARY):
        return c["arms"][arm]["tokens"].get(m)
    def raw_tok(c, m=PRIMARY):
        return c["arms"]["raw"]["tokens"].get(m)
    out = {}
    for arm in ("rtk", "qodec", "rtk_then_qodec"):
        per = [(raw_tok(c), tok(arm, c)) for c in cases_subset
               if raw_tok(c) is not None and tok(arm, c) is not None]
        macro = [s for s in (B.saving_percent(a, r) for r, a in per) if s is not None]
        # weighted totals only over cases with a defined ratio (raw tokens > 0)
        raw_sum = sum(r for r, _ in per if r); arm_sum = sum(a for r, a in per if r)
        out[arm] = {
            "n_measured": len(per),
            "weighted_pct_tokens_saved": (None if not raw_sum else 100.0 * (1 - arm_sum / raw_sum)),
            "macro_median_pct_saved": (statistics.median(macro) if macro else None),
            "min_pct_saved": (min(macro) if macro else None),
            "max_pct_saved": (max(macro) if macro else None),
            "cases_that_increased_text": sum(1 for s in macro if s is not None and s < 0),
        }
    # winner tally over the subset
    win = {"rtk": 0, "qodec": 0, "rtk_then_qodec": 0, "none": 0}
    for c in cases_subset:
        w = c.get("winner") or "none"
        win[w] = win.get(w, 0) + 1
    out["winners"] = win
    # semantic tally
    sem = {B.PASS: 0, B.FAILED: 0, B.UNSUPPORTED: 0, "reference": 0}
    for c in cases_subset:
        for a in c["arms"].values():
            sc = a.get("semantic_check")
            if sc in sem:
                sem[sc] += 1
    out["semantic_tally"] = sem
    return out


def finalize(res: dict, manifest: dict) -> dict:
    enrich(res)
    all_cases = res["results"]
    no_log = [c for c in all_cases if c["case"] != "loghub"]
    res["families"] = _family_stats(res)
    res["aggregate_all_12"] = _aggregate(res, all_cases)
    res["aggregate_without_loghub"] = _aggregate(res, no_log)
    res["manifest_ref"] = {"qodec": manifest["qodec"]["sha256"],
                           "tokenizers": manifest["tokenizers"],
                           "case_count": manifest["case_count"]}
    return res


# ---------------------------------------------------------------------------------------------------
# emit CSVs + report
# ---------------------------------------------------------------------------------------------------
def write_per_case_csv(res: dict, path: Path):
    cols = ["case", "family", "arm", "tokenizer", "bytes", "unicode_chars", "lines", "tokens",
            "compression_ratio", "bytes_saved", "pct_bytes_saved", "tokens_saved", "pct_tokens_saved",
            "wall_s", "throughput_mib_s", "peak_kib", "output_sha256", "exit_status", "status",
            "semantic_check"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader()
        for c in res["results"]:
            for arm_name in ARMS:
                arm = c["arms"][arm_name]
                for m in METERS:
                    w.writerow({
                        "case": c["case"], "family": c["family"], "arm": arm_name, "tokenizer": m,
                        "bytes": arm.get("bytes"), "unicode_chars": arm.get("unicode_chars"),
                        "lines": arm.get("lines"), "tokens": arm.get("tokens", {}).get(m),
                        "compression_ratio": _r(arm.get("compression_ratio", {}).get(m)),
                        "bytes_saved": arm.get("bytes_saved"),
                        "pct_bytes_saved": _r(arm.get("pct_bytes_saved")),
                        "tokens_saved": arm.get("tokens_saved", {}).get(m),
                        "pct_tokens_saved": _r(arm.get("pct_tokens_saved", {}).get(m)),
                        "wall_s": _r(arm.get("wall_s"), 4), "throughput_mib_s": _r(arm.get("throughput_mib_s"), 2),
                        "peak_kib": arm.get("peak_kib"), "output_sha256": arm.get("output_sha256"),
                        "exit_status": arm.get("exit_status"), "status": arm.get("status"),
                        "semantic_check": arm.get("semantic_check")})


def write_per_family_csv(res: dict, path: Path):
    cols = ["family", "n_cases", "cases", "rtk_median_pct_saved", "qodec_median_pct_saved",
            "qodec_min_pct_saved", "qodec_max_pct_saved", "semantic_failures", "semantic_unsupported", "note"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader()
        for fr in res["families"]:
            lo, hi = fr["qodec_pct_saved_range"]
            w.writerow({"family": fr["family"], "n_cases": fr["n_cases"], "cases": ";".join(fr["cases"]),
                        "rtk_median_pct_saved": _r(fr["rtk_median_pct_saved"]),
                        "qodec_median_pct_saved": _r(fr["qodec_median_pct_saved"]),
                        "qodec_min_pct_saved": _r(lo), "qodec_max_pct_saved": _r(hi),
                        "semantic_failures": fr["semantic_failures"],
                        "semantic_unsupported": fr["semantic_unsupported"], "note": fr["note"]})


def _r(x, nd=2):
    return None if x is None else round(x, nd)


def _fmt(n):
    return "—" if n is None else (f"{n:,}" if isinstance(n, int) else f"{n:,.2f}")


def write_report(res: dict, manifest: dict, path: Path, cmd: str):
    L = []
    q = manifest["qodec"]; tk = manifest["tokenizers"]
    L.append("# N2-E text-compression benchmark — RAW vs RTK vs Qodec vs RTK→Qodec\n")
    L.append("Reporting slice over the already-qualified twelve-case N2-E corpus "
             "(`resolved_canary_pass=true`). No frozen evidence, qualification record, aggregator, "
             "dispatch, or promotion flag was touched.\n")
    L.append(f"- **Qodec**: `{q['binary']}` sha256 `{q['sha256'][:16]}…`, v{q['version']}, "
             f"config codec_arm=`deep` / tokenize=`identity`, alphabet=auto, `--json` envelope.")
    L.append(f"- **Tokenizers**: primary **{tk['primary']['vocabulary']}**, secondary "
             f"**{tk['secondary']['vocabulary']}** ({tk['primary']['provider']}). Exact BPE, no char/4.")
    L.append(f"- **Command**: `{cmd}`")
    L.append(f"- **compression_ratio = arm_tokens / raw_tokens** (smaller is better); "
             f"**saving% = 100·(1 − ratio)**. Primary meter = {PRIMARY}.\n")

    # headline table
    L.append("## Per-case headline (primary o200k tokens)\n")
    L.append("| case | family | RAW | RTK | Qodec | RTK→Qodec | winner | RTK sem | notes |")
    L.append("|---|---|--:|--:|--:|--:|:--:|:--:|---|")
    for c in res["results"]:
        a = c["arms"]
        def tok(x): return a[x]["tokens"].get(PRIMARY)
        def sv(x):
            p = a[x]["pct_tokens_saved"].get(PRIMARY)
            return "" if p is None else f" ({p:+.1f}%)"
        note = []
        if a["raw"].get("nature") == "canonicalized": note.append("RAW=canon")
        if not a["raw"].get("bytes") and a["raw"].get("status") == B.UNSUPPORTED: note.append("RAW capsule")
        if tok("rtk") is not None and tok("raw") is not None and tok("rtk") > tok("raw"): note.append("RTK↑")
        L.append(f"| {c['case']} | {c['family']} | {_fmt(tok('raw'))} | "
                 f"{_fmt(tok('rtk'))}{sv('rtk')} | {_fmt(tok('qodec'))}{sv('qodec')} | "
                 f"{_fmt(tok('rtk_then_qodec'))}{sv('rtk_then_qodec')} | {c.get('winner') or '—'} | "
                 f"{a['rtk'].get('semantic_check')} | {', '.join(note)} |")
    L.append("")

    # per-case detail
    L.append("## Per-case detail\n")
    for c in res["results"]:
        L.append(f"### {c['case']} · {c['family']}\n")
        a = c["arms"]
        for arm_name, label in (("raw", "RAW"), ("rtk", "RTK"), ("qodec", "Qodec"),
                                ("rtk_then_qodec", "RTK → Qodec")):
            arm = a[arm_name]
            if arm.get("status") == B.UNSUPPORTED and arm_name in ("raw", "qodec") and not arm.get("bytes"):
                L.append(f"- **{label}**: unsupported — {arm.get('unsupported_reason','n/a')}"
                         + (f" (published lines ≈ {_fmt(arm.get('lines'))}, member `{(arm.get('output_sha256') or '')[:12]}…`)" if arm_name == 'raw' else ""))
                continue
            if arm.get("status") not in (B.PASS,):
                L.append(f"- **{label}**: {arm.get('status')} — {arm.get('error','')}")
                continue
            po = arm["tokens"].get(PRIMARY); so = arm["tokens"].get("cl100k")
            line = (f"- **{label}**: {_fmt(arm.get('bytes'))} B, {_fmt(arm.get('lines'))} lines, "
                    f"{_fmt(po)} o200k / {_fmt(so)} cl100k tok")
            if arm_name != "raw":
                pct = arm["pct_tokens_saved"].get(PRIMARY)
                sav = arm["tokens_saved"].get(PRIMARY)
                if pct is not None:
                    line += f"; vs RAW {_fmt(sav)} tok / {pct:+.2f}%"
                # qodec vs rtk
                if arm_name in ("qodec", "rtk_then_qodec"):
                    rt = a["rtk"]["tokens"].get(PRIMARY)
                    if rt and po is not None and rt:
                        line += f"; vs RTK {rt - po:+,} tok / {100*(1-po/rt):+.2f}%"
                line += f"; semantic={arm.get('semantic_check')}"
                if arm.get("roundtrip_lossless") is not None:
                    line += f" (lossless={arm['roundtrip_lossless']})"
            if arm.get("wall_s"):
                line += f"; {arm['wall_s']*1000:.0f} ms"
                if arm.get("throughput_mib_s"):
                    line += f", {arm['throughput_mib_s']:.1f} MiB/s"
            L.append(line)
        rk = c.get("ranking_primary") or []
        L.append(f"- **ranking** (fewest o200k tokens, semantic-ok only): {' < '.join(rk) or 'n/a'}\n")

    # families
    L.append("## Family summaries\n")
    L.append("| family | cases | RTK median saving | Qodec median saving | Qodec range | sem fail | sem unsup | note |")
    L.append("|---|---|--:|--:|--:|--:|--:|---|")
    for fr in res["families"]:
        lo, hi = fr["qodec_pct_saved_range"]
        rng = "—" if lo is None else f"{lo:.1f}…{hi:.1f}%"
        L.append(f"| {fr['family']} | {', '.join(fr['cases'])} | "
                 f"{_pct(fr['rtk_median_pct_saved'])} | {_pct(fr['qodec_median_pct_saved'])} | {rng} | "
                 f"{fr['semantic_failures']} | {fr['semantic_unsupported']} | {fr['note']} |")
    L.append("")

    # aggregates
    L.append("## Aggregates (secondary — read after the per-case detail)\n")
    for label, key in (("All twelve cases", "aggregate_all_12"),
                       ("Eleven cases excluding Loghub", "aggregate_without_loghub")):
        agg = res[key]
        L.append(f"### {label}\n")
        L.append("| arm | measured | weighted saving | macro-median | min | max | increased text |")
        L.append("|---|--:|--:|--:|--:|--:|--:|")
        for arm in ("rtk", "qodec", "rtk_then_qodec"):
            g = agg[arm]
            L.append(f"| {arm} | {g['n_measured']} | {_pct(g['weighted_pct_tokens_saved'])} | "
                     f"{_pct(g['macro_median_pct_saved'])} | {_pct(g['min_pct_saved'])} | "
                     f"{_pct(g['max_pct_saved'])} | {g['cases_that_increased_text']} |")
        w = agg["winners"]; s = agg["semantic_tally"]
        L.append(f"\n- winners: RTK={w.get('rtk',0)}, Qodec={w.get('qodec',0)}, "
                 f"RTK→Qodec={w.get('rtk_then_qodec',0)}, none={w.get('none',0)}")
        L.append(f"- semantic tally (arm-instances): pass={s[B.PASS]}, fail={s[B.FAILED]}, "
                 f"unsupported={s[B.UNSUPPORTED]}, reference={s['reference']}\n")
    L.append("**Micro (weighted) vs macro (median).** The weighted aggregate is dominated by the "
             "largest inputs; the macro median treats every case equally. They can disagree sharply, "
             "so both are shown, and the without-Loghub view sits beside the all-twelve view — no "
             "single 'average saving' headline stands alone.\n")

    # limitations
    L.append("## Limitations & honesty notes\n")
    L.append("- 8 cases (coreutils, caddy, lucene, vue, scrapy, gin, preact, lombok) expose "
             "**canonicalized** bytes as their frozen RAW authority, not true raw stdout — labeled `RAW=canon`.")
    L.append("- **Loghub** RAW is a ~1.5 GB reacquirable member (bounded capsule committed); its RAW/Qodec "
             "token counts are **unsupported** here (not loaded into memory; exact streaming BPE out of scope). "
             "RTK and RTK→Qodec are exact.")
    L.append("- 4 cases (lucene, vue, preact, lombok) have **RTK ≡ RAW** (faithful preservation → 0 token saving).")
    L.append("- **caddy** and **redis** show RTK **increasing** tokens vs their frozen authority (redis RAW = the "
             "`--format` projection; the user-facing default `docker images` table lives only in the CI artifact).")
    L.append("- **gin** RAW is empty (0 tokens) → compression ratio undefined; absolute values reported.")
    L.append("- Qodec arms are **byte-lossless** (decode==input verified per arm); semantic preservation is total, "
             "so a lossy 'OK'-style output can never rank as a winner.")
    L.append("- **Qodec is UTF-8-only**: it errors on invalid UTF-8 input (documented limitation). All twelve "
             "corpus streams are valid UTF-8, so no arm hit this; an invalid-UTF-8 input would be recorded as "
             "`failed`, never approximated.")
    peak = res.get("peak_kib_overall")
    peak_s = f"{peak/1024:.1f} MiB" if peak else "not available on this host (/usr/bin/time absent)"
    L.append(f"\n_Total measured runtime {res['wall_total_s']:.1f}s; peak child RSS {peak_s}. "
             f"Inputs are ≤25 KiB (loghub RTK 1.9 KiB), so per-arm wall time is dominated by process "
             f"startup and MiB/s throughput rounds to ~0; timing is reported for completeness, not as a "
             f"performance claim._\n")
    path.write_text("\n".join(L) + "\n")


def _pct(x):
    return "—" if x is None else f"{x:+.2f}%"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default=str(HERE / "benchmark-manifest.json"))
    ap.add_argument("--qodec", default=str(REPO / "target/release/qodec"))
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--out-dir", default=str(HERE))
    a = ap.parse_args()
    manifest = json.loads(Path(a.manifest).read_text())
    res = measure(Path(a.qodec), manifest, a.timeout)
    finalize(res, manifest)
    outd = Path(a.out_dir)
    (outd / "results.json").write_text(json.dumps(res, indent=2, sort_keys=True, default=str) + "\n")
    write_per_case_csv(res, outd / "per-case.csv")
    write_per_family_csv(res, outd / "per-family.csv")
    cmd = "python3 benchmarks/n2e-text-compression/run_benchmark.py"
    write_report(res, manifest, outd / "report.md", cmd)
    agg = res["aggregate_without_loghub"]["qodec"]
    print(f"benchmark done: 12 cases; Qodec macro-median saving (o200k, ex-loghub) "
          f"{_pct(agg['macro_median_pct_saved'])}; weighted {_pct(agg['weighted_pct_tokens_saved'])}")
    print(f"  wrote results.json, per-case.csv, per-family.csv, report.md to {outd}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
