#!/usr/bin/env python3
"""N2-D3: one full-pipeline measurement of one (case_id, leg) pair.

N2-D3 covers all 18 primary N2-D corpus cases (as opposed to N2-D2, which
covers exactly one: n2a-miner-canary -- see n2d2_determinism_canary.py).
Each case is measured independently TWICE (leg "a" and leg "b", run as
separate jobs) rather than 20 times: N2-D3 is a token-count benchmark, not
a determinism probe, and two independent full-pipeline runs are enough to
catch any nondeterminism in a benchmark measurement without paying N2-D2's
20x repetition cost on a corpus that includes a 38MB case.

The five-step pipeline, unchanged from the corrected N2-D2 canary:
  1. qodec encode over the raw input
  2. roundtrip verification of that encode
  3. the case's selected RTK invocation (rtk-applicability-map-v1.json)
  4. qodec encode over RTK's output -> RTK tokens (tokens_in of this call)
     and RTK+QODEC hybrid tokens (tokens_out of this call)
  5. roundtrip verification of the hybrid encode

Two of the 18 locked canonical benchmark inputs (dataset-loghub-v8,
research-corpus-loghub2) are not valid UTF-8 -- their normalized-source.tar
wraps a nested compressed archive member -- so step 1 hard-fails on them by
construction (qodec's --json envelope reads UTF-8 text). This is a real,
authorized, typed measurement-domain refusal for exactly those two case
IDs, not a benchmark failure: their row records real exit code and stderr
hash, contributes to the 18-case corpus count, and is excluded from the
16-case token aggregates. A qodec_encode failure on ANY OTHER case ID, or
a non-UTF-8-shaped failure even on these two, is NOT authorized and this
tool refuses to swallow it -- it raises so the caller stops on a genuine
unexpected failure instead of silently reporting a phantom refusal.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
from pathlib import Path

IDENTITY_LOCK_DIR = Path(__file__).resolve().parents[1]
BUNDLE_PATH = IDENTITY_LOCK_DIR / "n2d3-model-free-input-bundle-v1.tar"

AUTHORIZED_NON_UTF8_CASE_IDS = frozenset({"dataset-loghub-v8", "research-corpus-loghub2"})
NON_UTF8_STDERR_MARKER = "did not contain valid utf-8"

QODEC_ENCODE_ARGV = ["encode", "--codec", "fold-grep-guarded", "--meter", "o200k", "--passthrough-on-no-gain", "--json"]
QODEC_DECODE_ARGV = ["decode"]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run(argv: list[str], input_bytes: bytes, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(argv, input=input_bytes, capture_output=True, timeout=timeout)


def _load_case_input(bundle_path: Path, case_id: str) -> tuple[bytes, list[str]]:
    with tarfile.open(bundle_path, mode="r:") as tar:
        manifest = json.loads(tar.extractfile("manifest.json").read())
        entry = manifest["cases"][case_id]
        raw = tar.extractfile(entry["bundle_member_path"]).read()
        rtk_argv = entry["rtk_argv"]
    actual_sha256 = _sha256(raw)
    if actual_sha256 != entry["input_sha256"]:
        raise RuntimeError(
            f"{case_id}: bundle bytes sha256 {actual_sha256!r} != manifest-recorded {entry['input_sha256']!r}"
        )
    return raw, rtk_argv


def _encode_roundtrip(qodec_bin: str, raw: bytes, timeout: int) -> dict:
    """One encode + roundtrip-verify pass. Raises on any failure NOT
    authorized as an invalid-UTF-8 refusal (see module docstring)."""
    enc = _run([qodec_bin, *QODEC_ENCODE_ARGV], raw, timeout)
    if enc.returncode != 0:
        return {"encode_ok": False, "exit_code": enc.returncode, "stderr": enc.stderr}

    envelope = json.loads(enc.stdout.decode("utf-8"))
    content_bytes = envelope["content"].encode("utf-8")
    if envelope["encoded"]:
        dec = _run([qodec_bin, *QODEC_DECODE_ARGV], content_bytes, timeout)
        roundtrip_ok = dec.returncode == 0 and dec.stdout == raw
    else:
        roundtrip_ok = content_bytes == raw

    return {
        "encode_ok": True,
        "stdout_sha256": _sha256(enc.stdout),
        "tokens_in": envelope["tokens_in"],
        "tokens_out": envelope["tokens_out"],
        "encoded": envelope["encoded"],
        "roundtrip_ok": roundtrip_ok,
    }


def measure_case_leg(qodec_bin: str, rtk_bin: str, case_id: str, leg: str, raw: bytes, rtk_argv: list[str],
                      timeout: int) -> dict:
    if leg not in ("a", "b"):
        raise ValueError(f"leg must be 'a' or 'b', got {leg!r}")

    base = {
        "record_type": "n2d3-case-leg-measurement-v1",
        "case_id": case_id,
        "leg": leg,
        "input_sha256": _sha256(raw),
        "input_bytes": len(raw),
    }

    raw_pass = _encode_roundtrip(qodec_bin, raw, timeout)
    if not raw_pass["encode_ok"]:
        stderr_text = raw_pass["stderr"].decode("utf-8", errors="replace")
        is_non_utf8 = NON_UTF8_STDERR_MARKER in stderr_text.lower()
        if case_id not in AUTHORIZED_NON_UTF8_CASE_IDS or not is_non_utf8:
            raise RuntimeError(
                f"UNEXPECTED qodec_encode failure on case_id={case_id!r} leg={leg!r}: "
                f"exit_code={raw_pass['exit_code']} authorized_non_utf8_case={case_id in AUTHORIZED_NON_UTF8_CASE_IDS} "
                f"stderr_matches_non_utf8_marker={is_non_utf8}\nstderr:\n{stderr_text}"
            )
        return {
            **base,
            "measurement_status": "UNMEASURABLE_NON_UTF8",
            "utf8_valid": False,
            "raw_tokens": None,
            "qodec_tokens": None,
            "rtk_tokens": None,
            "rtk_plus_qodec_tokens": None,
            "qodec_exit_code": raw_pass["exit_code"],
            "qodec_stderr_sha256": _sha256(raw_pass["stderr"]),
            "qodec_failure_classification": "INVALID_UTF8_INPUT",
            "excluded_from_token_aggregates": True,
            "excluded_from_corpus_count": False,
        }

    # case_id is expected to be UTF-8-measurable; a raw encode success here
    # is required (the two authorized non-UTF-8 cases never reach this path).
    rtk = _run([rtk_bin, *rtk_argv], raw, timeout)
    if rtk.returncode != 0:
        raise RuntimeError(
            f"UNEXPECTED rtk failure on case_id={case_id!r} leg={leg!r}: exit_code={rtk.returncode}\n"
            f"stderr:\n{rtk.stderr.decode('utf-8', errors='replace')}"
        )

    hybrid_pass = _encode_roundtrip(qodec_bin, rtk.stdout, timeout)
    if not hybrid_pass["encode_ok"]:
        raise RuntimeError(
            f"UNEXPECTED hybrid qodec_encode failure (over RTK output) on case_id={case_id!r} leg={leg!r}: "
            f"exit_code={hybrid_pass['exit_code']}\nstderr:\n{hybrid_pass['stderr'].decode('utf-8', errors='replace')}"
        )

    # Roundtrip correctness is not an authorized refusal category -- a broken
    # roundtrip on a UTF-8-measurable case is a real, unexpected pipeline
    # defect and must stop the run, not be silently folded into the benchmark.
    if not raw_pass["roundtrip_ok"]:
        raise RuntimeError(f"UNEXPECTED raw roundtrip failure on case_id={case_id!r} leg={leg!r}")
    if not hybrid_pass["roundtrip_ok"]:
        raise RuntimeError(f"UNEXPECTED hybrid roundtrip failure on case_id={case_id!r} leg={leg!r}")

    return {
        **base,
        "measurement_status": "MEASURED",
        "utf8_valid": True,
        "raw_tokens": raw_pass["tokens_in"],
        "qodec_tokens": raw_pass["tokens_out"],
        "rtk_tokens": hybrid_pass["tokens_in"],
        "rtk_plus_qodec_tokens": hybrid_pass["tokens_out"],
        "qodec_encode_stdout_sha256": raw_pass["stdout_sha256"],
        "qodec_encoded": raw_pass["encoded"],
        "raw_roundtrip_ok": raw_pass["roundtrip_ok"],
        "rtk_exit_code": rtk.returncode,
        "rtk_stdout_sha256": _sha256(rtk.stdout),
        "hybrid_encode_stdout_sha256": hybrid_pass["stdout_sha256"],
        "hybrid_encoded": hybrid_pass["encoded"],
        "hybrid_roundtrip_ok": hybrid_pass["roundtrip_ok"],
        "excluded_from_token_aggregates": False,
        "excluded_from_corpus_count": False,
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--qodec-bin", required=True)
    parser.add_argument("--rtk-bin", required=True)
    parser.add_argument("--bundle", type=Path, default=BUNDLE_PATH)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--leg", required=True, choices=["a", "b"])
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    raw, rtk_argv = _load_case_input(args.bundle, args.case_id)
    row = measure_case_leg(args.qodec_bin, args.rtk_bin, args.case_id, args.leg, raw, rtk_argv, args.timeout_seconds)
    args.out.write_text(json.dumps(row, indent=2, sort_keys=True) + "\n")
    print(f"case_id={args.case_id} leg={args.leg} measurement_status={row['measurement_status']} -> wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
