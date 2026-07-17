#!/usr/bin/env python3
"""N2-D2: determinism canary over all 18 primary N2-D cases.

Consumes the single committed n2d3-model-free-input-bundle-v1.tar (never
reacquires or derives its own variant of any case's input). For every
case, repeats the full three-arm pipeline (raw token count via
`qodec encode`, RTK per rtk-applicability-map-v1.json's own per-case
argv, hybrid token count via a second `qodec encode` over RTK's output)
N>=20 times and requires byte-identical stdout and identical token
counts across every repetition, for every arm, for every case. This is
the SAME bar this record's own bounded RTK filter probes already used
(N1 pilot's own log-filter-probe discipline), just applied to the full
pipeline instead of an isolated filter.

A case fails the canary the moment any repetition disagrees with the
first (byte-for-byte stdout or a different token count) -- never
averaged, never sampled, never silently retried.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
from pathlib import Path

IDENTITY_LOCK_DIR = Path(__file__).resolve().parents[1]
BUNDLE_PATH = IDENTITY_LOCK_DIR / "n2d3-model-free-input-bundle-v1.tar"
OUT_PATH = IDENTITY_LOCK_DIR / "n2d2-determinism-canary-report-v1.json"

QODEC_ENCODE_ARGV = ["encode", "--codec", "fold-grep-guarded", "--meter", "o200k", "--passthrough-on-no-gain", "--json"]
QODEC_DECODE_ARGV = ["decode"]


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run(argv: list[str], input_bytes: bytes, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(argv, input=input_bytes, capture_output=True, timeout=timeout)


def _load_bundle_inputs(bundle_path: Path) -> dict:
    inputs = {}
    manifest = None
    with tarfile.open(bundle_path, mode="r:") as tar:
        manifest = json.loads(tar.extractfile("manifest.json").read())
        for case_id, entry in manifest["cases"].items():
            inputs[case_id] = tar.extractfile(entry["bundle_member_path"]).read()
    return inputs, manifest


def run_one_repetition(qodec_bin: str, rtk_bin: str, rtk_argv: list[str], raw: bytes) -> dict:
    """Reproduces n2d1-contract.json's own uniform_measurement_mechanism
    exactly: RAW tokens = tokens_in of the first encode call over raw input;
    QODEC tokens = tokens_out of that SAME call; RTK tokens = tokens_in of a
    SECOND encode call over RTK's own output (that second call's
    tokens_out/content/encoded are the bonus "hybrid" arm -- qodec applied
    on top of RTK's already-filtered output -- tracked separately, not
    conflated with the RTK arm's own token count)."""
    enc = _run([qodec_bin, *QODEC_ENCODE_ARGV], raw)
    if enc.returncode != 0:
        return {"stage": "qodec_encode", "exit_code": enc.returncode, "ok": False}
    envelope = json.loads(enc.stdout.decode("utf-8"))

    # The --json envelope's own contract (src/adapter.rs Adapted doc comment):
    # `content` is a %q1 artifact the reader must `decode` only when
    # `encoded=true`; when `encoded=false` (passthrough_on_no_gain fired),
    # `content` IS the original text already, verbatim, and is not decodable
    # container input. Feeding the whole JSON envelope to `qodec decode` (as
    # an earlier version of this harness did) is a harness bug, not a QODEC
    # roundtrip defect -- decode never sees a `%q1` artifact in that case.
    content_bytes = envelope["content"].encode("utf-8")
    if envelope["encoded"]:
        dec = _run([qodec_bin, *QODEC_DECODE_ARGV], content_bytes)
        roundtrip_ok = dec.returncode == 0 and dec.stdout == raw
    else:
        roundtrip_ok = content_bytes == raw

    rtk = _run([rtk_bin, *rtk_argv], raw)
    rtk_ok = rtk.returncode == 0

    rtk_tokens = None
    hybrid_tokens = None
    hybrid_stdout_sha256 = None
    if rtk_ok:
        hybrid_enc = _run([qodec_bin, *QODEC_ENCODE_ARGV], rtk.stdout)
        if hybrid_enc.returncode == 0:
            hybrid_envelope = json.loads(hybrid_enc.stdout.decode("utf-8"))
            rtk_tokens = hybrid_envelope["tokens_in"]
            hybrid_tokens = hybrid_envelope["tokens_out"]
            hybrid_stdout_sha256 = _sha256(hybrid_enc.stdout)

    return {
        "ok": True,
        "qodec_encode_stdout_sha256": _sha256(enc.stdout),
        "qodec_tokens_in": envelope["tokens_in"],
        "qodec_tokens_out": envelope["tokens_out"],
        "qodec_encoded": envelope["encoded"],
        "roundtrip_ok": roundtrip_ok,
        "rtk_exit_code": rtk.returncode,
        "rtk_stdout_sha256": _sha256(rtk.stdout) if rtk_ok else None,
        "rtk_tokens": rtk_tokens,
        "hybrid_stdout_sha256": hybrid_stdout_sha256,
        "hybrid_tokens": hybrid_tokens,
    }


def run_canary(qodec_bin: str, rtk_bin: str, bundle_path: Path, repetitions: int,
               only_case_ids: set | None = None) -> dict:
    if repetitions < 20:
        raise ValueError(f"repetitions must be >= 20, got {repetitions}")
    inputs, manifest = _load_bundle_inputs(bundle_path)
    case_ids = sorted(inputs.keys()) if only_case_ids is None else sorted(only_case_ids)

    case_results = {}
    all_deterministic = True
    for case_id in case_ids:
        raw = inputs[case_id]
        rtk_argv = manifest["cases"][case_id]["rtk_argv"]
        reps = [run_one_repetition(qodec_bin, rtk_bin, rtk_argv, raw) for _ in range(repetitions)]

        if not all(r["ok"] for r in reps):
            case_results[case_id] = {"deterministic": False, "failure": "qodec_encode failed on at least one repetition", "repetitions": repetitions}
            all_deterministic = False
            continue

        distinct_qodec_stdout = {r["qodec_encode_stdout_sha256"] for r in reps}
        distinct_tokens_in = {r["qodec_tokens_in"] for r in reps}
        distinct_tokens_out = {r["qodec_tokens_out"] for r in reps}
        distinct_rtk_stdout = {r["rtk_stdout_sha256"] for r in reps}
        distinct_rtk_tokens = {r["rtk_tokens"] for r in reps}
        distinct_hybrid_stdout = {r["hybrid_stdout_sha256"] for r in reps}
        distinct_hybrid_tokens = {r["hybrid_tokens"] for r in reps}
        all_roundtrip_ok = all(r["roundtrip_ok"] for r in reps)
        all_rtk_exit_zero = all(r["rtk_exit_code"] == 0 for r in reps)

        deterministic = (
            len(distinct_qodec_stdout) == 1
            and len(distinct_tokens_in) == 1
            and len(distinct_tokens_out) == 1
            and len(distinct_rtk_stdout) == 1
            and len(distinct_rtk_tokens) == 1
            and len(distinct_hybrid_stdout) == 1
            and len(distinct_hybrid_tokens) == 1
            and all_roundtrip_ok
            and all_rtk_exit_zero
        )
        if not deterministic:
            all_deterministic = False

        case_results[case_id] = {
            "deterministic": deterministic,
            "repetitions": repetitions,
            "raw_tokens": next(iter(distinct_tokens_in)),
            "qodec_tokens": next(iter(distinct_tokens_out)),
            "rtk_tokens": next(iter(distinct_rtk_tokens)) if len(distinct_rtk_tokens) == 1 else None,
            "hybrid_tokens": next(iter(distinct_hybrid_tokens)) if len(distinct_hybrid_tokens) == 1 else None,
            "canonical_qodec_stdout_sha256": next(iter(distinct_qodec_stdout)) if len(distinct_qodec_stdout) == 1 else None,
            "canonical_rtk_stdout_sha256": next(iter(distinct_rtk_stdout)) if len(distinct_rtk_stdout) == 1 else None,
            "canonical_hybrid_stdout_sha256": next(iter(distinct_hybrid_stdout)) if len(distinct_hybrid_stdout) == 1 else None,
            "all_roundtrip_ok": all_roundtrip_ok,
            "all_rtk_exit_zero": all_rtk_exit_zero,
        }

    return {
        "record_type": "n2d2-determinism-canary-report-v1",
        "record_version": 1,
        "schema_version": 1,
        "repetitions_per_case": repetitions,
        "case_count": len(case_results),
        "all_cases_deterministic": all_deterministic,
        "cases": case_results,
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--qodec-bin", required=True)
    parser.add_argument("--rtk-bin", required=True)
    parser.add_argument("--bundle", type=Path, default=BUNDLE_PATH)
    parser.add_argument("--repetitions", type=int, default=20)
    parser.add_argument("--out", type=Path, default=OUT_PATH)
    parser.add_argument("--only-case-ids", default=None, help="comma-separated subset of case IDs to run")
    args = parser.parse_args()

    only_case_ids = set(args.only_case_ids.split(",")) if args.only_case_ids else None
    report = run_canary(args.qodec_bin, args.rtk_bin, args.bundle, args.repetitions, only_case_ids)
    report["record_sha256"] = compute_record_sha256(report)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"all_cases_deterministic={report['all_cases_deterministic']} -> wrote {args.out}")
    return 0 if report["all_cases_deterministic"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
