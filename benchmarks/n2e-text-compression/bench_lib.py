#!/usr/bin/env python3
"""Core library for the N2-E text-compression benchmark: the narrow Qodec adapter, the exact
BPE tokenizer (Qodec's own o200k/cl100k meter), per-arm metrics, and aggregates.

Design rules honored here:
  * Qodec is invoked ONLY through its real CLI (`encode`/`decode`), one explicit frozen config.
  * measured stdout is never mixed with diagnostics (`--report` goes to stderr; we use `--json`).
  * every Qodec transform is roundtrip-verified (decode(encode(x)) == x) -- a lossy result FAILS.
  * token counts are exact BPE via the meter; NEVER char/4. A meter hang/timeout -> token unsupported.
  * binary-safe: bytes are passed via a temp file (`-i`); char count only when valid UTF-8.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

# status values
PASS, FAILED, UNSUPPORTED = "pass", "failed", "unsupported"

_HAS_GNU_TIME = shutil.which("/usr/bin/time") is not None


def _run(argv, input_bytes: bytes, timeout: float, workdir: Path):
    """Run qodec over input_bytes (written to a temp file, passed via -i). Returns
    (exit, stdout_bytes, stderr_text, duration_s, peak_kib_or_None)."""
    inp = workdir / "in.bin"
    inp.write_bytes(input_bytes)
    full = list(argv) + ["-i", str(inp)]
    if _HAS_GNU_TIME:
        rss_f = workdir / "rss.txt"
        full = ["/usr/bin/time", "-v", "-o", str(rss_f)] + full
    t0 = time.perf_counter()
    try:
        p = subprocess.run(full, capture_output=True, timeout=timeout, cwd=str(workdir))
    except subprocess.TimeoutExpired as e:
        return ("timeout", e.stdout or b"", "TIMEOUT", timeout, None)
    except OSError as e:  # missing/unexecutable binary -> graceful failure, never a crash
        return (127, b"", f"cannot exec: {e}", time.perf_counter() - t0, None)
    dur = time.perf_counter() - t0
    peak = None
    if _HAS_GNU_TIME:
        try:
            for ln in (workdir / "rss.txt").read_text().splitlines():
                if "Maximum resident set size" in ln:
                    peak = int(ln.rsplit(":", 1)[1].strip())
        except Exception:  # noqa: BLE001
            peak = None
    return (p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")[:4096], dur, peak)


class Qodec:
    def __init__(self, binary: Path, timeout: float = 120.0):
        self.binary = str(binary)
        self.timeout = timeout

    def _json(self, argv, data: bytes, workdir: Path):
        code, out, err, dur, peak = _run([self.binary, *argv], data, self.timeout, workdir)
        if code == "timeout":
            return {"ok": False, "status": UNSUPPORTED, "error": "meter/codec timeout",
                    "duration_s": dur, "peak_kib": peak}
        if code != 0:
            return {"ok": False, "status": FAILED, "error": f"exit {code}: {err.strip()[:200]}",
                    "duration_s": dur, "peak_kib": peak, "exit_code": code}
        try:
            env = json.loads(out.decode("utf-8", "replace"))
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "status": FAILED, "error": f"bad json envelope: {e}",
                    "duration_s": dur, "peak_kib": peak}
        env["ok"] = True
        env["duration_s"] = dur
        env["peak_kib"] = peak
        return env

    def tokenize(self, data: bytes, meter: str, workdir: Path) -> dict:
        """Exact BPE token count of `data` under `meter` via the identity codec (tokens_in is the
        count of the ORIGINAL input, before the container wrap)."""
        r = self._json(["encode", "--codec", "identity", "--json", "--meter", meter], data, workdir)
        if not r.get("ok"):
            return {"tokens": None, "status": r["status"], "error": r.get("error")}
        return {"tokens": r.get("tokens_in"), "status": PASS, "error": None}

    def encode_deep(self, data: bytes, meter: str, workdir: Path) -> dict:
        """The Qodec arm: `encode --codec deep`. Returns the artifact bytes + its exact token count
        (tokens_out) + timing/mem, then roundtrip-verifies losslessness (decode == data)."""
        r = self._json(["encode", "--codec", "deep", "--json", "--alphabet", "auto",
                        "--meter", meter], data, workdir)
        if not r.get("ok"):
            return {"status": r["status"], "error": r.get("error"),
                    "duration_s": r.get("duration_s"), "peak_kib": r.get("peak_kib")}
        content = (r.get("content") or "").encode("utf-8")
        # losslessness gate: decode the emitted artifact and require byte-identity with the input.
        dec = self._json_decode(content, workdir)
        lossless = dec is not None and dec == data
        return {
            "status": PASS if lossless else FAILED,
            "error": None if lossless else "roundtrip NOT byte-identical (lossy) -- rejected",
            "codec": r.get("codec"), "content_bytes": content,
            "tokens_out": r.get("tokens_out"), "tokens_in": r.get("tokens_in"),
            "duration_s": r.get("duration_s"), "peak_kib": r.get("peak_kib"),
            "roundtrip_lossless": lossless,
        }

    def _json_decode(self, artifact: bytes, workdir: Path):
        code, out, err, dur, peak = _run([self.binary, "decode"], artifact, self.timeout, workdir)
        if code != 0:
            return None
        return out


# ---------------------------------------------------------------------------------------------------
# metrics
# ---------------------------------------------------------------------------------------------------
def basic_metrics(data: bytes) -> dict:
    try:
        text = data.decode("utf-8")
        chars = len(text)
        valid_utf8 = True
    except UnicodeDecodeError:
        chars = None
        valid_utf8 = False
    lines = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
    return {"bytes": len(data), "unicode_chars": chars, "valid_utf8": valid_utf8, "lines": lines}


def ratio(arm_tokens, raw_tokens):
    """compression_ratio = arm/raw (smaller better); None when raw is 0/None/arm None."""
    if raw_tokens in (None, 0) or arm_tokens is None:
        return None
    return arm_tokens / raw_tokens


def saving_percent(arm_tokens, raw_tokens):
    r = ratio(arm_tokens, raw_tokens)
    return None if r is None else 100.0 * (1.0 - r)
