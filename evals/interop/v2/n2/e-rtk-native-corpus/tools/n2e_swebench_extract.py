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


import hashlib as _hashlib

# recognized publisher toolchain kinds per docker_specs key, and the family each maps to
_DOCKER_KIND = {"go_version": ("go", "go"), "rust_version": ("rust", "rust_cargo"),
                "node_version": ("node", "js_ts"), "java_version": ("java", "jvm")}


def _git_blob_sha1(data: bytes) -> str:
    return _hashlib.sha1(b"blob " + str(len(data)).encode() + b"\x00" + data).hexdigest()


def spec_resolves(src_dir: Path, family: str, repo: str, version: str) -> bool:
    """Back-compat thin wrapper -> structural verifier's `extractable` verdict."""
    return verify_recipe_extractable(src_dir, family, repo, version)["extractable"]


def verify_recipe_extractable(src_dir: Path, family: str, repo: str, version: str) -> dict:
    """STRUCTURAL source-only extractability verifier for a recipe-required reserve
    candidate. Proves, purely from the pinned harness source bytes, that (repo, version)
    resolves to a concrete, fully-parseable publisher recipe for the candidate's family.
    No registry membership, benchmark result, savings, or runtime state is consulted.

    Returns a dict of structural checks + `extractable` (all checks true) + the source
    file identity (path / git blob sha1 / sha256) + the resolved recipe commands.
    """
    checks = {
        "family_has_source_binding": False, "source_file_present": False,
        "exact_repository_mapping": False, "concrete_recipe_key_entry": False,
        "toolchain_kind_recognized": False, "toolchain_version_nonempty": False,
        "family_matches_toolchain": False, "test_cmd_nonempty": False,
        "test_commands_parseable": False, "install_commands_parseable": False,
        "pre_install_mechanically_extractable": False,
    }
    out = {"family": family, "repo": repo, "recipe_key": version, "checks": checks,
           "source": None, "resolved": None, "extractable": False, "reason": None}

    fs = FAMILY_SOURCE.get(family)
    if not fs:
        out["reason"] = f"no source binding for family {family}"
        return out
    checks["family_has_source_binding"] = True
    fname, map_name = fs
    p = src_dir / fname
    if not p.is_file():
        out["reason"] = f"source file {fname} absent"
        return out
    checks["source_file_present"] = True
    data = p.read_bytes()
    out["source"] = {"file": fname, "path": str(p), "map": map_name,
                     "git_blob_sha1": _git_blob_sha1(data),
                     "sha256": _hashlib.sha256(data).hexdigest()}
    try:
        mod, text = _module(src_dir, fname)
        spec_name = _map_repo_to_specname(mod, map_name, repo)   # exact repository mapping
        checks["exact_repository_mapping"] = True
        entry = _spec_entry(mod, spec_name, version)             # concrete dict entry @ exact key
        checks["concrete_recipe_key_entry"] = True
        out["source"]["spec_dict"] = spec_name
    except (KeyError, ValueError) as e:
        out["reason"] = f"repo/key not resolvable: {e}"
        return out

    docker = _field(entry, "docker_specs")
    docker_d = ast.literal_eval(docker) if docker is not None else {}
    kind = ver = None
    for dk, (k, fam) in _DOCKER_KIND.items():
        if dk in docker_d:
            kind, ver, mapped_fam = k, str(docker_d[dk]), fam
            checks["toolchain_kind_recognized"] = True
            checks["toolchain_version_nonempty"] = bool(ver.strip())
            checks["family_matches_toolchain"] = (mapped_fam == family)
            break

    install = _field(entry, "install")
    test_cmd = _field(entry, "test_cmd")
    pre = _field(entry, "pre_install")
    install_l = ast.literal_eval(install) if install is not None else []
    test_l = ast.literal_eval(test_cmd) if test_cmd is not None else []
    checks["test_cmd_nonempty"] = bool(test_l) and all(isinstance(x, str) and x.strip() for x in test_l)

    def _parseable(cmds):
        ok = True
        for cmd in cmds:
            _env, argv = _split_env(cmd)
            if not argv:
                ok = False
        return ok

    checks["test_commands_parseable"] = bool(test_l) and _parseable(test_l)
    checks["install_commands_parseable"] = _parseable(install_l) if install_l else True
    try:
        if pre is None:
            checks["pre_install_mechanically_extractable"] = True
        elif isinstance(pre, ast.Call):
            _eval_call(pre, text, mod, src_dir, fname)
            checks["pre_install_mechanically_extractable"] = True
        else:
            ast.literal_eval(pre)
            checks["pre_install_mechanically_extractable"] = True
    except Exception as e:  # noqa: BLE001 - any extraction failure => not extractable
        out["reason"] = f"pre_install not extractable: {e}"

    out["resolved"] = {"toolchain_kind": kind, "toolchain_version": ver,
                       "install": install_l, "test_cmd": test_l}
    out["extractable"] = all(checks.values())
    if out["extractable"]:
        out["reason"] = "structurally extractable"
    return out


def _split_env(cmd: str):
    """Local minimal (env, argv) split -- leading UPPER=val tokens are env assignments."""
    import shlex
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
