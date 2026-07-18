"""Mechanical extraction of SWE-bench per-instance recipes from PINNED source bytes.

The publisher recipe (toolchain + pre-install/install/test commands) is NOT
transcribed by hand -- it is parsed out of the exact upstream harness source files
committed under fixtures/swebench-source/ (SWE-bench/SWE-bench @ the pinned commit).
A mutation to any upstream command string changes both the extracted recipe AND the
source file hash, so the verifier can prove the registry is faithful to source.

Only the ADDRESSING of a recipe (which source file + repo + PR key + which frozen
case it binds to) is declared here; every command/toolchain field is read from the
source. Resolution is: instance repo + PR key -> MAP_REPO_VERSION_TO_SPECS_* ->
spec dict -> entry.
"""
from __future__ import annotations

import ast
from pathlib import Path

# case_id -> addressing (source file, repo, PR key). NOT recipe content.
SELECTORS = {
    "caddyserver__caddy-5870::go::test::buggy":
        {"file": "go.py", "map": "MAP_REPO_VERSION_TO_SPECS_GO", "repo": "caddyserver/caddy", "pr": "5870"},
    "tokio-rs__tokio-4384::rust_cargo::test::fixed":
        {"file": "rust.py", "map": "MAP_REPO_VERSION_TO_SPECS_RUST", "repo": "tokio-rs/tokio", "pr": "4384"},
    "vuejs__core-11589::js_ts::test::buggy":
        {"file": "javascript.py", "map": "MAP_REPO_VERSION_TO_SPECS_JS", "repo": "vuejs/core", "pr": "11589"},
    "apache__lucene-13704::jvm::test::buggy":
        {"file": "java.py", "map": "MAP_REPO_VERSION_TO_SPECS_JAVA", "repo": "apache/lucene", "pr": "13704"},
}

# Resolved-scope reserve replacements (NOT part of the frozen canary registry / toolchain
# lock). Extracted from the SAME pinned harness source bytes when a slot is terminally
# disqualified and resolved via the frozen reserve order.
RESERVE_SELECTORS = {
    # frozen-order replacement for the DISQUALIFIED_ENVIRONMENT_UNREPRODUCIBLE tokio-4384
    # rust_test_pass slot (uutils/coreutils-6731: rust 1.81, no --locked, no Cargo.lock fixture).
    "uutils__coreutils-6731::rust_cargo::test::fixed":
        {"file": "rust.py", "map": "MAP_REPO_VERSION_TO_SPECS_RUST", "repo": "uutils/coreutils", "pr": "6731"},
}

# family -> pinned harness source file + rust/go/js/java repo->spec map name
FAMILY_SOURCE = {
    "rust_cargo": ("rust.py", "MAP_REPO_VERSION_TO_SPECS_RUST"),
    "go": ("go.py", "MAP_REPO_VERSION_TO_SPECS_GO"),
    "js_ts": ("javascript.py", "MAP_REPO_VERSION_TO_SPECS_JS"),
    "jvm": ("java.py", "MAP_REPO_VERSION_TO_SPECS_JAVA"),
}


def spec_resolves(src_dir: Path, family: str, repo: str, version: str) -> bool:
    """True iff the pinned harness source maps (repo, version) to a concrete spec entry
    for the given command family -- the source-driven extractability of a publisher
    recipe, independent of what is currently materialized in any registry."""
    fs = FAMILY_SOURCE.get(family)
    if not fs:
        return False
    fname, map_name = fs
    p = src_dir / fname
    if not p.is_file():
        return False
    try:
        mod, _ = _module(src_dir, fname)
        spec_name = _map_repo_to_specname(mod, map_name, repo)
        _spec_entry(mod, spec_name, version)
        return True
    except (KeyError, ValueError):
        return False


def _module(src_dir: Path, fname: str) -> tuple[ast.Module, str]:
    text = (src_dir / fname).read_text()
    return ast.parse(text), text


def _map_repo_to_specname(mod: ast.Module, map_name: str, repo: str) -> str:
    for node in mod.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == map_name for t in node.targets):
            for k, v in zip(node.value.keys, node.value.values):
                if isinstance(k, ast.Constant) and k.value == repo:
                    if not isinstance(v, ast.Name):
                        raise ValueError(f"{map_name}[{repo}] is not a spec-dict name")
                    return v.id
    raise KeyError(f"{repo} not in {map_name}")


def _spec_entry(mod: ast.Module, spec_name: str, pr: str) -> ast.Dict:
    for node in mod.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == spec_name for t in node.targets):
            for k, v in zip(node.value.keys, node.value.values):
                if isinstance(k, ast.Constant) and k.value == pr:
                    if not isinstance(v, ast.Dict):
                        raise ValueError(f"{spec_name}[{pr}] is not a dict")
                    return v
    raise KeyError(f"{pr} not in {spec_name}")


def _funcdef_src(text: str, mod: ast.Module, name: str) -> str:
    for node in mod.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(text, node)
    raise KeyError(f"function {name} not found in source")


def _eval_call(call: ast.Call, text: str, mod: ast.Module, src_dir: Path, fname: str) -> list[str]:
    """Evaluate a pre_install helper CALL by exec'ing its source-defined function
    with __file__ pointed at the pinned source file (so committed upstream fixtures
    resolve). Returns the exact list[str] of shell commands the publisher emits."""
    fname_called = call.func.id
    args = [ast.literal_eval(a) for a in call.args]
    ns: dict = {"__file__": str(src_dir / fname)}
    exec("from pathlib import Path\nfrom typing import List\nimport shlex\n"
         + _funcdef_src(text, mod, fname_called), ns)
    out = ns[fname_called](*args)
    if not isinstance(out, list) or not all(isinstance(x, str) for x in out):
        raise ValueError(f"{fname_called} did not return list[str]")
    return out


def _field(entry: ast.Dict, key: str):
    for k, v in zip(entry.keys, entry.values):
        if isinstance(k, ast.Constant) and k.value == key:
            return v
    return None


def extract(src_dir: Path, case_id: str) -> dict:
    sel = SELECTORS.get(case_id) or RESERVE_SELECTORS[case_id]
    mod, text = _module(src_dir, sel["file"])
    spec_name = _map_repo_to_specname(mod, sel["map"], sel["repo"])
    entry = _spec_entry(mod, spec_name, sel["pr"])
    docker = _field(entry, "docker_specs")
    install = _field(entry, "install")
    test_cmd = _field(entry, "test_cmd")
    pre = _field(entry, "pre_install")
    pre_cmds: list[str] = []
    if pre is not None:
        if isinstance(pre, ast.Call):
            pre_cmds = _eval_call(pre, text, mod, src_dir, sel["file"])
        else:
            pre_cmds = ast.literal_eval(pre)
    return {
        "case_id": case_id,
        "source_file": sel["file"], "spec_dict": spec_name, "spec_key": sel["pr"],
        "repo": sel["repo"],
        "docker_specs": ast.literal_eval(docker) if docker is not None else {},
        "pre_install": pre_cmds,
        "install": ast.literal_eval(install) if install is not None else [],
        "test_cmd": ast.literal_eval(test_cmd) if test_cmd is not None else [],
    }


def all_case_ids() -> list[str]:
    return sorted(SELECTORS)
