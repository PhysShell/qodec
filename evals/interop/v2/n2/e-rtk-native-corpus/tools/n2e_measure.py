"""RAW / RTK execution + measurement harness (§4, §13, §15).

Runs a scenario's real command under the mandated network-denied-friendly,
deterministic environment and captures stdout and stderr SEPARATELY plus the
exact combined byte stream fed to the token meter (§13). Repetition support (§15)
runs a command N times in fresh working directories and reports byte-determinism.

Token counting uses the canonical QODEC o200k meter (§0): `qodec encode --json
--meter o200k` reports tokens_in for the exact captured bytes. Binaries are taken
from the environment (RTK_BIN, QODEC_BIN) — never hard-coded transient paths.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile

# §4 mandated measurement environment (applied where compatible with the tool).
MANDATED_ENV = {
    "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC", "TERM": "dumb",
    "NO_COLOR": "1", "COLUMNS": "120", "LINES": "40",
}


def measurement_env(extra: dict | None = None) -> dict:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    env.update(MANDATED_ENV)
    if extra:
        env.update(extra)
    return env


def combine(stdout: bytes, stderr: bytes, policy: str = "stdout_then_stderr") -> bytes:
    """Predeclared, identical-for-RAW-and-RTK combination policy (§13)."""
    if policy == "stdout_then_stderr":
        return stdout + stderr
    if policy == "stdout_only":
        return stdout
    raise ValueError(f"unknown combine policy {policy!r}")


def run_once(argv: list[str], cwd: str, timeout: int, env_extra: dict | None = None,
             stdin_path: str | None = None) -> dict:
    stdin = open(stdin_path, "rb") if stdin_path else subprocess.DEVNULL
    try:
        p = subprocess.run(argv, cwd=cwd, env=measurement_env(env_extra),
                           stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout)
    finally:
        if stdin_path:
            stdin.close()
    combined = combine(p.stdout, p.stderr)
    return {
        "exit_code": p.returncode,
        "stdout_sha256": hashlib.sha256(p.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(p.stderr).hexdigest(),
        "combined_sha256": hashlib.sha256(combined).hexdigest(),
        "stdout_bytes": len(p.stdout),
        "combined_bytes": len(combined),
        "_stdout": p.stdout,
        "_stderr": p.stderr,
        "_combined": combined,
    }


def run_repeated(argv: list[str], reps: int, timeout: int, setup=None,
                 env_extra: dict | None = None, stdin_path: str | None = None) -> dict:
    """Run `reps` times in FRESH workdirs; report byte-determinism (§15)."""
    runs = []
    for _ in range(reps):
        with tempfile.TemporaryDirectory(prefix="n2e-") as td:
            if setup:
                setup(td)
            runs.append(run_once(argv, td, timeout, env_extra, stdin_path))
    exit_codes = {r["exit_code"] for r in runs}
    combined_hashes = {r["combined_sha256"] for r in runs}
    return {
        "reps": reps,
        "exit_code_stable": len(exit_codes) == 1,
        "byte_deterministic": len(combined_hashes) == 1,
        "exit_code": runs[0]["exit_code"] if exit_codes else None,
        "combined_sha256": runs[0]["combined_sha256"],
        "combined_bytes": runs[0]["combined_bytes"],
        "runs": [{k: v for k, v in r.items() if not k.startswith("_")} for r in runs],
        "_last": runs[-1],
    }


def o200k_tokens(data: bytes, qodec_bin: str | None = None) -> int:
    """Exact o200k token count of `data` via the canonical qodec meter."""
    qodec_bin = qodec_bin or os.environ.get("QODEC_BIN")
    if not qodec_bin:
        raise RuntimeError("QODEC_BIN not set")
    with tempfile.NamedTemporaryFile() as tf:
        tf.write(data)
        tf.flush()
        p = subprocess.run([qodec_bin, "encode", "--json", "--meter", "o200k", "-i", tf.name],
                           capture_output=True, timeout=300)
    env = json.loads(p.stdout.decode())
    return int(env["tokens_in"])


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
