"""Loader for the self-hash-locked publisher environment registry.

The registry is the NORMATIVE source of each SWE-bench case's effective commands
+ toolchain + fixtures. The driver, the argv resolver, and the execution-contract
builder all derive from here rather than guessing per-repository.
"""
from __future__ import annotations

import shlex
from pathlib import Path

import n2e_common as c

N2E_DIR = Path(__file__).resolve().parent.parent
REGISTRY = N2E_DIR / "n2e-publisher-env-registry-v1.json"
FIX = N2E_DIR / "fixtures" / "swebench"

_CACHE: dict | None = None


def load() -> dict:
    global _CACHE
    if _CACHE is None:
        _CACHE = c.load_record(REGISTRY)
    return _CACHE


def recipe_for(instance_id: str) -> dict | None:
    for r in load()["recipes"]:
        if r["instance_id"] == instance_id:
            return r
    return None


def recipe_for_case(case_id: str) -> dict | None:
    for r in load()["recipes"]:
        if r["case_id"] == case_id:
            return r
    return None


def parse_command(cmd: str) -> list[str]:
    """Split a publisher command string into argv (POSIX). Leading VAR=val env
    assignments (if any survive in a string) are NOT expected here -- recipe env
    lives in recipe['env'] -- but we still strip any that appear, defensively."""
    parts = shlex.split(cmd)
    argv = []
    seen_cmd = False
    for p in parts:
        if not seen_cmd and "=" in p and p.split("=", 1)[0].isupper() and " " not in p:
            continue  # a leading ENV=val assignment; env is carried in recipe['env']
        seen_cmd = True
        argv.append(p)
    return argv


def fixture_path(name: str) -> Path:
    return FIX / name


def registry_sha256() -> str:
    return c.sha256_json_file(REGISTRY)
