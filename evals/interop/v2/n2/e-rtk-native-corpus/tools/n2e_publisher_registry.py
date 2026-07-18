"""Loader for the self-hash-locked publisher environment registry.

The registry is the NORMATIVE source of each SWE-bench case's effective commands +
toolchain + fixtures, extracted mechanically from pinned upstream source. Recipes
bind by EXACT case_id. The driver, argv resolver, and execution-contract builder
all derive from here rather than guessing per-repository.
"""
from __future__ import annotations

import shlex
from pathlib import Path

import n2e_common as c

N2E_DIR = Path(__file__).resolve().parent.parent
REGISTRY = N2E_DIR / "n2e-publisher-env-registry-v1.json"
SRC = N2E_DIR / "fixtures" / "swebench-source"

_CACHE: dict | None = None


def load() -> dict:
    global _CACHE
    if _CACHE is None:
        _CACHE = c.load_record(REGISTRY)
    return _CACHE


def recipe_for_case(case_id: str) -> dict | None:
    """EXACT case-id binding: a recipe is applied only to the scenario it registers,
    never to another scenario that merely shares the same SWE-bench instance."""
    for r in load()["recipes"]:
        if r["case_id"] == case_id:
            return r
    return None


def recipe_for_instance_debug(instance_id: str) -> list:
    return [r["case_id"] for r in load()["recipes"] if r["instance_id"] == instance_id]


def split_env(cmd: str) -> tuple[dict, list]:
    """({ENV:val...}, argv) from a publisher command string. Leading upper-case
    VAR=val tokens are environment assignments; the rest is argv."""
    parts = shlex.split(cmd)
    env, argv, in_argv = {}, [], False
    for p in parts:
        if not in_argv and "=" in p and p.split("=", 1)[0].isupper() and "/" not in p.split("=", 1)[0]:
            k, v = p.split("=", 1)
            env[k] = v
        else:
            in_argv = True
            argv.append(p)
    return env, argv


def parse_command(cmd: str) -> list[str]:
    return split_env(cmd)[1]


def source_path(rel: str) -> Path:
    return SRC / rel


def registry_sha256() -> str:
    return c.sha256_json_file(REGISTRY)
