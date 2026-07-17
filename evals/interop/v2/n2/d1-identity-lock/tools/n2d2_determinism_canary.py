#!/usr/bin/env python3
"""N2-D2: determinism canary over exactly ONE input -- n2a-miner-canary.

Corrected scope (this record previously, incorrectly, ran all 18 primary
N2-D corpus cases through N2-D2; the other 17 cases are N2-D3 inputs, not
N2-D2 inputs -- see n2d3_measure_case.py / build_n2d3_primary_benchmark.py).

N2-D2 exists to answer one question: is the full three-arm pipeline
(raw token count via `qodec encode`, RTK per rtk-applicability-map-v1.json,
hybrid token count via a second `qodec encode` over RTK's output)
deterministic at all, on a single small, durable, always-UTF-8 canary
input? It is answered with the SAME bar this record's own bounded RTK
filter probes already used (N1 pilot's own log-filter-probe discipline):
N>=20 repetitions, byte-identical stdout and identical token counts
required across every repetition.

To rule out determinism that is an artifact of one job's specific runner/
process/thread-scheduling environment, N2-D2 runs the 20 repetitions
TWICE, independently (leg "a" and leg "b" -- two separate CI jobs), and
requires agreement within each leg AND between the two legs' canonical
values before certifying the canary as deterministic.

A leg fails the moment any repetition disagrees with the first (byte-for-
byte stdout or a different token count) -- never averaged, never sampled,
never silently retried.
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

CANARY_CASE_ID = "n2a-miner-canary"
REQUIRED_CANARY_INPUT_SHA256 = "09b023837a4a969f9bf12401595429aeefe65263a2705e8e3a3e62ee5aa437db"

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


def _load_canary_input(bundle_path: Path) -> tuple[bytes, list[str]]:
    with tarfile.open(bundle_path, mode="r:") as tar:
        manifest = json.loads(tar.extractfile("manifest.json").read())
        entry = manifest["cases"][CANARY_CASE_ID]
        raw = tar.extractfile(entry["bundle_member_path"]).read()
        rtk_argv = entry["rtk_argv"]
    actual_sha256 = _sha256(raw)
    if actual_sha256 != REQUIRED_CANARY_INPUT_SHA256:
        raise RuntimeError(
            f"n2a-miner-canary bundle bytes sha256 {actual_sha256!r} != required "
            f"{REQUIRED_CANARY_INPUT_SHA256!r}"
        )
    return raw, rtk_argv


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
    # container input.
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


def run_leg(qodec_bin: str, rtk_bin: str, bundle_path: Path, repetitions: int, leg: str) -> dict:
    if repetitions < 20:
        raise ValueError(f"repetitions must be >= 20, got {repetitions}")
    if leg not in ("a", "b"):
        raise ValueError(f"leg must be 'a' or 'b', got {leg!r}")

    raw, rtk_argv = _load_canary_input(bundle_path)
    reps = [run_one_repetition(qodec_bin, rtk_bin, rtk_argv, raw) for _ in range(repetitions)]

    if not all(r["ok"] for r in reps):
        return {
            "record_type": "n2d2-canary-leg-report-v1",
            "leg": leg,
            "case_id": CANARY_CASE_ID,
            "repetitions": repetitions,
            "deterministic": False,
            "failure": "qodec_encode failed on at least one repetition",
        }

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

    return {
        "record_type": "n2d2-canary-leg-report-v1",
        "leg": leg,
        "case_id": CANARY_CASE_ID,
        "repetitions": repetitions,
        "deterministic": deterministic,
        "raw_tokens": next(iter(distinct_tokens_in)) if len(distinct_tokens_in) == 1 else None,
        "qodec_tokens": next(iter(distinct_tokens_out)) if len(distinct_tokens_out) == 1 else None,
        "rtk_tokens": next(iter(distinct_rtk_tokens)) if len(distinct_rtk_tokens) == 1 else None,
        "hybrid_tokens": next(iter(distinct_hybrid_tokens)) if len(distinct_hybrid_tokens) == 1 else None,
        "canonical_qodec_stdout_sha256": next(iter(distinct_qodec_stdout)) if len(distinct_qodec_stdout) == 1 else None,
        "canonical_rtk_stdout_sha256": next(iter(distinct_rtk_stdout)) if len(distinct_rtk_stdout) == 1 else None,
        "canonical_hybrid_stdout_sha256": next(iter(distinct_hybrid_stdout)) if len(distinct_hybrid_stdout) == 1 else None,
        "all_roundtrip_ok": all_roundtrip_ok,
        "all_rtk_exit_zero": all_rtk_exit_zero,
    }


def combine_legs(leg_a: dict, leg_b: dict) -> dict:
    if leg_a.get("leg") != "a" or leg_b.get("leg") != "b":
        raise ValueError("combine_legs requires exactly one leg 'a' report and one leg 'b' report")
    if leg_a.get("case_id") != CANARY_CASE_ID or leg_b.get("case_id") != CANARY_CASE_ID:
        raise ValueError("both legs must report on n2a-miner-canary")

    within_leg_deterministic = bool(leg_a.get("deterministic")) and bool(leg_b.get("deterministic"))

    compare_fields = (
        "raw_tokens", "qodec_tokens", "rtk_tokens", "hybrid_tokens",
        "canonical_qodec_stdout_sha256", "canonical_rtk_stdout_sha256", "canonical_hybrid_stdout_sha256",
    )
    between_leg_agreement = within_leg_deterministic and all(
        leg_a.get(f) is not None and leg_a.get(f) == leg_b.get(f) for f in compare_fields
    )

    deterministic = within_leg_deterministic and between_leg_agreement

    body = {
        "record_type": "n2d2-determinism-canary-report-v1",
        "record_version": 2,
        "schema_version": 2,
        "case_id": CANARY_CASE_ID,
        "case_count": 1,
        "repetitions_per_leg": leg_a.get("repetitions"),
        "within_leg_a_deterministic": bool(leg_a.get("deterministic")),
        "within_leg_b_deterministic": bool(leg_b.get("deterministic")),
        "between_leg_agreement": between_leg_agreement,
        "all_cases_deterministic": deterministic,
        "leg_a": leg_a,
        "leg_b": leg_b,
    }
    if deterministic:
        body["raw_tokens"] = leg_a["raw_tokens"]
        body["qodec_tokens"] = leg_a["qodec_tokens"]
        body["rtk_tokens"] = leg_a["rtk_tokens"]
        body["hybrid_tokens"] = leg_a["hybrid_tokens"]
    return body


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)

    leg_parser = sub.add_parser("run-leg")
    leg_parser.add_argument("--qodec-bin", required=True)
    leg_parser.add_argument("--rtk-bin", required=True)
    leg_parser.add_argument("--bundle", type=Path, default=BUNDLE_PATH)
    leg_parser.add_argument("--repetitions", type=int, default=20)
    leg_parser.add_argument("--leg", required=True, choices=["a", "b"])
    leg_parser.add_argument("--out", type=Path, required=True)

    combine_parser = sub.add_parser("combine")
    combine_parser.add_argument("--leg-a", type=Path, required=True)
    combine_parser.add_argument("--leg-b", type=Path, required=True)
    combine_parser.add_argument("--out", type=Path, default=OUT_PATH)

    args = parser.parse_args()

    if args.mode == "run-leg":
        report = run_leg(args.qodec_bin, args.rtk_bin, args.bundle, args.repetitions, args.leg)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(f"leg={args.leg} deterministic={report['deterministic']} -> wrote {args.out}")
        return 0 if report["deterministic"] else 1

    if args.mode == "combine":
        leg_a = json.loads(args.leg_a.read_text())
        leg_b = json.loads(args.leg_b.read_text())
        report = combine_legs(leg_a, leg_b)
        report["record_sha256"] = compute_record_sha256(report)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(f"all_cases_deterministic={report['all_cases_deterministic']} -> wrote {args.out}")
        return 0 if report["all_cases_deterministic"] else 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
