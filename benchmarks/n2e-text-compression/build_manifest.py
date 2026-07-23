#!/usr/bin/env python3
"""Build benchmark-manifest.json for the N2-E text-compression benchmark.

This is a BENCHMARK/REPORTING slice only. It reads (never writes) the already-frozen twelve-case
qualification corpus and resolves, for every case, the exact frozen RAW and RTK byte sources +
digests. It verifies each referenced digest against the on-disk bytes (rule 2) and records the NATURE
of each arm's evidence honestly (raw captured bytes vs canonicalized bytes vs bounded capsule).

It changes no frozen evidence, no qualification record, no aggregator, no promotion flag.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
N2E = REPO / "evals/interop/v2/n2/e-rtk-native-corpus"
QODEC = REPO / "target/release/qodec"

# case -> resolution. Every field is explicit so the manifest binds EXACTLY the twelve frozen cases.
#   record            : the frozen qualification record (read-only)
#   ev                : the case's evidence dir under N2E
#   raw/rtk           : (filename-in-ev, nature) or None when not locally available
#   family            : output family for grouping
CASES = [
    # ---- Test output (5) : cq/bridge cases froze CANONICAL streams, not true raw ----
    dict(case="coreutils", case_id="uutils__coreutils-6731::rust_cargo::test::fixed",
         family="Test output", record="n2e-coreutils-qualification-v1.json",
         ev="evidence/coreutils-6731/qualification",
         raw=("raw.canonical.bin", "canonicalized"), rtk=("rtk.canonical.bin", "canonicalized"),
         oracle="rtk-rust-cargo-test-summary-v1"),
    dict(case="caddy", case_id="caddyserver__caddy-5870::go::test::buggy",
         family="Test output", record="n2e-resolved-case-qualification-caddy-v1.json",
         ev="evidence/caddy/qualification",
         raw=("raw.canonical.bin", "canonicalized"), rtk=("rtk.canonical.bin", "canonicalized"),
         oracle=None),
    dict(case="lucene", case_id="apache__lucene-13704::jvm::test::buggy",
         family="Test output", record="n2e-resolved-case-qualification-lucene-jvm-v1.json",
         ev="evidence/lucene-jvm/qualification",
         raw=("raw.canonical.bin", "canonicalized"), rtk=("rtk.canonical.bin", "canonicalized"),
         oracle=None),
    dict(case="vue", case_id="vuejs__core-11589::js_ts::test::buggy",
         family="Test output", record="n2e-resolved-case-qualification-vue-vitest-v1.json",
         ev="evidence/vue-vitest/qualification",
         raw=("raw.canonical.bin", "canonicalized"), rtk=("rtk.canonical.bin", "canonicalized"),
         oracle=None),
    dict(case="scrapy", case_id="bugsinpy::scrapy-9::python::pytest::fixed",
         family="Test output", record="n2e-resolved-case-qualification-scrapy-pytest-v1.json",
         ev="evidence/scrapy-pytest/qualification",
         raw=("raw.canonical.bin", "canonicalized"), rtk=("rtk.canonical.bin", "canonicalized"),
         oracle=None),
    # ---- Diagnostics (1) ----
    dict(case="gin", case_id="gin-gonic__gin-2755::go::vet",
         family="Diagnostics", record="n2e-resolved-case-qualification-gin-v1.json",
         ev="evidence/gin/qualification",
         raw=("raw.canonical.bin", "canonicalized"), rtk=("rtk.canonical.bin", "canonicalized"),
         oracle=None),
    # ---- File content (2) ----
    dict(case="preact", case_id="preactjs__preact-3345::files_search::read",
         family="File content", record="n2e-resolved-case-qualification-preact-read-v1.json",
         ev="evidence/preact-read/qualification",
         raw=("raw.canonical.bin", "canonicalized"), rtk=("rtk.canonical.bin", "canonicalized"),
         oracle=None),
    dict(case="lombok", case_id="projectlombok__lombok-3312::files_search::read",
         family="File content", record="n2e-resolved-case-qualification-lombok-read-v1.json",
         ev="evidence/lombok-read/qualification",
         raw=("raw.canonical.bin", "canonicalized"), rtk=("rtk.canonical.bin", "canonicalized"),
         oracle=None),
    # ---- Large structured logs (1) : RTK exact; RAW is a bounded capsule + 1.5GB reacquirable ----
    dict(case="loghub", case_id="loghub::HDFS::log",
         family="Large structured logs", record="n2e-resolved-case-qualification-loghub-v1.json",
         ev="evidence/loghub/qualification",
         raw=None, rtk=("rtk.stdout.bin", "raw_captured"),
         oracle="rtk-log-hdfs-oracle-v1"),
    # ---- Git output (2) : rubocop true raw stdout; php-cs-fixer RAW from frozen diag provenance ----
    dict(case="rubocop", case_id="rubocop__rubocop-13687::git::show",
         family="Git output", record="n2e-resolved-case-qualification-rubocop-v1.json",
         ev="evidence/rubocop/qualification",
         raw=("raw.stdout.bin", "raw_captured"), rtk=("rtk.stdout.bin", "raw_captured"),
         oracle="rtk-git-show-merge-first-parent-oracle-v1"),
    dict(case="php-cs-fixer", case_id="php-cs-fixer__php-cs-fixer-8075::git::commit",
         family="Git output", record="n2e-resolved-case-qualification-php-cs-fixer-v1.json",
         ev="evidence/php-cs-fixer/qualification",
         # the acceptance record froze plumbing + rtk stdout, NOT the raw git-commit stdout; the raw
         # command output lives (digest-pinned) in the frozen barred diagnostic provenance.
         raw=("../../php-cs-fixer-git-commit-diag/raw.stdout.bin", "raw_captured_diag_provenance"),
         rtk=("rtk.stdout.bin", "raw_captured"),
         oracle="rtk-git-commit-oracle-v1"),
    # ---- Docker inventory (1) : RAW = the --format projection (the oracle's RAW authority) ----
    dict(case="redis", case_id="container::redis::docker::images",
         family="Docker inventory", record="n2e-resolved-case-qualification-redis-v1.json",
         ev="evidence/redis/qualification",
         raw=("raw.format_rows.bin", "raw_format_projection"), rtk=("rtk.stdout.bin", "raw_captured"),
         oracle="rtk-docker-images-oracle-v1"),
]


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _qodec_version() -> str:
    cargo = (REPO / "Cargo.toml").read_text()
    for ln in cargo.splitlines():
        if ln.strip().startswith("version"):
            return ln.split("=", 1)[1].strip().strip('"')
    return "unknown"


def _tiktoken_version() -> str:
    lock = (REPO / "Cargo.lock").read_text()
    lines = lock.splitlines()
    for i, ln in enumerate(lines):
        if ln.strip() == 'name = "tiktoken-rs"':
            for j in range(i + 1, min(i + 4, len(lines))):
                if lines[j].strip().startswith("version"):
                    return lines[j].split("=", 1)[1].strip().strip('"')
    return "unknown"


def _loghub_capsule() -> dict:
    rec = json.loads((N2E / "n2e-resolved-case-qualification-loghub-v1.json").read_text())
    cs = rec.get("raw_capsule_summary") or {}
    sip = rec.get("same_input_proof") or {}
    counts = cs.get("published_occurrence_counts") or {}
    return {
        "nature": "bounded_capsule",
        "available_locally": False,
        "reason": "RAW is the full ~1.5 GB HDFS.log member; not committed. Reacquisition is "
                  "impractical in the session disk allowance and exact streaming BPE tokenization is "
                  "out of scope for this slice, so RAW/Qodec-on-RAW token counts are UNSUPPORTED.",
        "member_sha256": sip.get("input_member_sha256"),
        "published_line_total": sum(counts.values()) if counts else None,
        "distinct_event_ids": len(cs.get("observed_event_ids") or []),
        "reference_sha256": cs.get("reference_sha256"),
    }


def resolve_arm(ev: Path, spec, digest_index: dict, arm: str, case: str) -> dict:
    if spec is None:
        return None
    fn, nature = spec
    p = (ev / fn).resolve()
    if not p.is_file():
        raise SystemExit(f"{case}/{arm}: frozen source missing: {p}")
    got = sha256_file(p)
    rec_digest = digest_index.get(arm)
    verified = rec_digest is None or rec_digest == got
    if rec_digest is not None and not verified:
        raise SystemExit(f"{case}/{arm}: on-disk sha256 {got} != record digest {rec_digest}")
    return {"source": str(p.relative_to(REPO)), "sha256": got, "bytes": p.stat().st_size,
            "nature": nature, "record_digest_verified": bool(rec_digest is not None),
            "available": True}


def _record_digests(rec: dict, case: str) -> dict:
    """Pull the record's own frozen sha256 for the raw/rtk arms so the manifest can cross-verify."""
    out = {}
    csd = rec.get("captured_stream_digests")
    if csd:
        if "raw.canonical" in csd:
            out["raw"] = csd["raw.canonical"]["sha256"]
        if "rtk.canonical" in csd:
            out["rtk"] = csd["rtk.canonical"]["sha256"]
    for key, rawk, rtkk in (("merge_evidence", "raw_stdout", "rtk_stdout"),
                            ("docker_evidence", "raw_format_rows", "rtk_stdout")):
        ev = rec.get(key)
        if ev:
            if rawk in ev:
                out["raw"] = ev[rawk]["sha256"]
            if rtkk in ev:
                out["rtk"] = ev[rtkk]["sha256"]
    ce = rec.get("commit_evidence")
    if ce and "rtk_stdout" in ce:
        out["rtk"] = ce["rtk_stdout"]["sha256"]
    ro = rec.get("rtk_output")
    if ro and "sha256" in ro:
        out["rtk"] = ro["sha256"]
    return out


def build() -> dict:
    if not QODEC.is_file():
        raise SystemExit(f"qodec binary not built: {QODEC} (run: cargo build --release)")
    cases = []
    for c in CASES:
        rec_path = N2E / c["record"]
        rec = json.loads(rec_path.read_text())
        ev = N2E / c["ev"]
        digest_index = _record_digests(rec, c["case"])
        # php-cs-fixer RAW comes from the barred diagnostic provenance -> cross-verify against it
        if c["case"] == "php-cs-fixer":
            prov = json.loads((N2E / "n2e-php-cs-fixer-git-commit-diagnostic-provenance-v1.json").read_text())
            digest_index = dict(digest_index)
            digest_index["raw"] = (prov.get("frozen_fixtures") or {}).get("raw.stdout.bin", {}).get("sha256")
        entry = {
            "case": c["case"], "case_id": c["case_id"], "family": c["family"],
            "record": str(rec_path.relative_to(REPO)), "record_sha256": sha256_file(rec_path),
            "oracle_policy_id": c["oracle"],
            "arms": {
                "raw": (resolve_arm(ev, c["raw"], digest_index, "raw", c["case"])
                        if c["raw"] else _loghub_capsule()),
                "rtk": resolve_arm(ev, c["rtk"], digest_index, "rtk", c["case"]),
            },
        }
        cases.append(entry)
    if len(cases) != 12:
        raise SystemExit(f"manifest must bind exactly twelve cases, got {len(cases)}")

    return {
        "benchmark": "n2e-text-compression",
        "purpose": "Offline text/token-volume comparison of RAW, RTK, Qodec, and RTK->Qodec over the "
                   "already-qualified N2-E twelve-case corpus. Reporting slice only: no promotion, no "
                   "change to frozen evidence / qualification / aggregator / dispatch / manifests.",
        "frozen_corpus_ref": "resolved_canary_pass=true at 12/12 (merged); records read-only.",
        "qodec": {
            "binary": str(QODEC.relative_to(REPO)), "sha256": sha256_file(QODEC),
            "version": _qodec_version(),
            "config": {"codec_arm": "deep", "codec_tokenize": "identity", "alphabet": "auto",
                       "json_envelope": True},
            "arm_invocations": {
                "qodec": ["encode", "--codec", "deep", "--json", "--alphabet", "auto",
                          "--meter", "<meter>", "-i", "<input>"],
                "tokenize": ["encode", "--codec", "identity", "--json", "--meter", "<meter>",
                             "-i", "<input>"],
                "decode": ["decode"],
            },
        },
        "tokenizers": {
            "primary": {"profile": "o200k", "vocabulary": "o200k_base",
                        "provider": f"tiktoken-rs {_tiktoken_version()} (embedded BPE, offline)"},
            "secondary": {"profile": "cl100k", "vocabulary": "cl100k_base",
                          "provider": f"tiktoken-rs {_tiktoken_version()} (embedded BPE, offline)"},
            "policy": "exact BPE token counts via qodec's own meter; no char/4 estimate.",
        },
        "arms": {
            "raw": "the frozen RAW authority bytes for the case",
            "rtk": "the frozen RTK output bytes for the case",
            "qodec": "qodec encode --codec deep over the RAW bytes (lossless; decode==RAW verified)",
            "rtk_then_qodec": "qodec encode --codec deep over the RTK bytes (lossless; decode==RTK verified)",
        },
        "families": sorted({c["family"] for c in CASES}),
        "case_count": len(cases),
        "cases": cases,
    }


def main() -> int:
    man = build()
    out = HERE / "benchmark-manifest.json"
    out.write_text(json.dumps(man, indent=2, sort_keys=True) + "\n")
    print(f"wrote {out.relative_to(REPO)}: {man['case_count']} cases, "
          f"qodec {man['qodec']['version']} sha {man['qodec']['sha256'][:12]}, "
          f"tokenizers {man['tokenizers']['primary']['provider']}")
    n_raw_unavail = sum(1 for c in man["cases"] if not c["arms"]["raw"].get("available"))
    print(f"  raw-unavailable (bounded capsule) cases: {n_raw_unavail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
