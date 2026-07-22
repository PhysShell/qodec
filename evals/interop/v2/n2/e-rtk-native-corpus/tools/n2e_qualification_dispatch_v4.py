#!/usr/bin/env python3
"""n2e-qualification-dispatch-v4: a NEW versioned, immutable, case-scoped dispatch generation for the
php-cs-fixer commit-identity oracle (rtk-git-commit-oracle-v1). dispatch-v2 froze after Loghub and
dispatch-v3 after the rubocop merge oracle; a new grounded oracle gets a new generation rather than
reopening a frozen one.

Strictly separated from cq AND from dispatch-v2/v3: a v4 record carries a dispatch_code_identity naming
v4 (and NO cq frozen_code_identity, and NOT v2/v3). No plugin discovery, no import path from the
artifact, no generic-oracle fallback. Registry is checksum-pinned + case-scoped (exact-one-match to
php-cs-fixer only -- Redis gets its own future generation).

recompute replays the resulting-ref identity from the FROZEN record evidence: RAW `git commit` and RTK
`rtk git commit` plumbing (rev-parse HEAD / HEAD^ + the new commit's --name-status) plus RTK's stdout,
run through the oracle. The commit hash is NEVER normalized: the RAW and RTK full commit OIDs must be
EXACTLY equal (the commit object reproduced under the pinned determinants), both parents == the pinned
base, and RTK's abbreviated OID a prefix. `created` is derived purely from the frozen plumbing (HEAD
advanced off base, first parent IS base) -- a producer PASS string is never trusted. The base OID
authority is the pinned scenario base_commit, not the record's claim.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_rtk_git_commit_oracle as _commit_oracle  # noqa: E402
import n2e_rtk_git_show_oracle as _parser_lib  # noqa: E402  (the commit oracle's parse_name_status dep)

DISPATCH_POLICY_ID = "n2e-qualification-dispatch-v4"
REGISTRY = N2E_DIR / "n2e-qualification-dispatch-registry-v4.json"
SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"

# the ONLY oracle modules this generation may bind -- a static, closed table (no discovery, no fallback)
_ORACLE_MODULES = {"rtk-git-commit-oracle-v1": _commit_oracle}

# frozen-evidence key -> the plumbing/stdout blob it pins
_EVIDENCE_KEYS = ("raw_head", "raw_parent", "raw_name_status",
                  "rtk_head", "rtk_parent", "rtk_name_status", "rtk_stdout")


class DispatchError(Exception):
    pass


def _module_sha256(mod) -> str:
    return hashlib.sha256(Path(mod.__file__).read_bytes()).hexdigest()


def dispatch_module_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def load_registry() -> dict:
    rec = c.load_record(REGISTRY)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        raise DispatchError(f"registry self-hash: {msg}")
    if rec.get("record_type") != "n2e-qualification-dispatch-registry":
        raise DispatchError("registry wrong record_type")
    if rec.get("dispatch_policy_id") != DISPATCH_POLICY_ID:
        raise DispatchError("registry dispatch_policy_id != v4")
    return rec


def registry_sha256() -> str:
    return c.sha256_json_file(REGISTRY).split(":", 1)[-1]


def _registry_entry(registry: dict, policy_id: str, case_id: str) -> dict:
    hits = [e for e in (registry.get("entries") or [])
            if e.get("policy_id") == policy_id and case_id in (e.get("allowed_case_ids") or [])]
    if len(hits) != 1:
        raise DispatchError(f"registry match for ({policy_id}, {case_id}) is not exactly one: {len(hits)}")
    e = hits[0]
    for cid in e.get("allowed_case_ids") or []:
        if "::" not in cid:
            raise DispatchError(f"registry entry has a non-case-scoped (family-level) binding: {cid!r}")
    if e.get("dispatch_policy_id") != DISPATCH_POLICY_ID:
        raise DispatchError("registry entry dispatch_policy_id != v4")
    return e


def dispatch_code_identity(entry: dict) -> dict:
    """Pins the exact code + data that produce/check a dispatch-v4 verdict: the dispatch layer, the
    immutable registry, the oracle module AND its parser-library dependency, and the pinned RTK source
    identity. A frozen record pins this; later drift is DETECTED."""
    policy = entry.get("command_semantic_oracle_policy_id")
    registry = load_registry()
    re = _registry_entry(registry, policy, entry["case_id"])
    mod = _ORACLE_MODULES.get(policy)
    if mod is None:
        raise DispatchError(f"no registry-bound oracle module for {policy!r} (no discovery, no fallback)")
    return {
        "dispatch_policy_id": DISPATCH_POLICY_ID,
        "dispatch_module_sha256": dispatch_module_sha256(),
        "registry_sha256": registry_sha256(),
        "oracle_policy_id": policy,
        "oracle_module_sha256": _module_sha256(mod),
        "parser_library_sha256": _module_sha256(_parser_lib),
        "rtk_source_identity_sha256": re["rtk_source_identity_sha256"],
        "canonicalization_policy_id": re["canonicalization_policy_id"],
    }


def verify_dispatch_binding(rec: dict, entry: dict) -> None:
    if entry.get("dispatch_policy_id") != DISPATCH_POLICY_ID:
        raise DispatchError(f"{entry['case_id']}: manifest not routed to dispatch-v4")
    if rec.get("dispatch_policy_id") != DISPATCH_POLICY_ID:
        raise DispatchError("record dispatch_policy_id != v4 (wrong-generation record on the registry path?)")
    # MUTUAL EXCLUSION: a v4 record carries dispatch_code_identity and NEVER a cq frozen_code_identity
    if rec.get("frozen_code_identity") is not None:
        raise DispatchError("record carries a cq frozen_code_identity -- legacy record on the dispatch path")
    if rec.get("dispatch_code_identity") is None:
        raise DispatchError("record carries no dispatch_code_identity")
    kind = entry.get("qualification_kind")
    if kind != "rtk_command_oracle":
        raise DispatchError("dispatch-v4 binds rtk_command_oracle only")
    if entry.get("rtk_test_dialect_policy_id") is not None:
        raise DispatchError("both test dialect and command oracle specified")
    if not entry.get("command_semantic_oracle_policy_id"):
        raise DispatchError("no command_semantic_oracle_policy_id (both semantic ids absent)")
    for k in ("oracle_module_path", "oracle_import", "module_path", "import_path", "entry_point"):
        if k in rec:
            raise DispatchError(f"artifact carries a dynamic import path ({k}) -- barred")
    want = dispatch_code_identity(entry)
    got = rec.get("dispatch_code_identity")
    if got != want:
        raise DispatchError(f"dispatch_code_identity DRIFT:\n  record: {got}\n  current: {want}")


def _scenario_base_commit(case_id: str) -> str:
    """The authoritative base commit OID (the parent the new commit must have): the pinned scenario
    base_commit (NOT the record's claim)."""
    scen = next(s for s in c.load_record(SCEN)["scenarios"] if s["case_id"] == case_id)
    oid = (((scen.get("setup_recipe") or {}).get("identity") or {}).get("base_commit")
           or (scen.get("source_image_identity") or {}).get("base_commit"))
    if not oid:
        raise DispatchError(f"{case_id}: scenario has no base_commit")
    return oid.lower()


def _frozen_bytes(rec: dict, key: str) -> bytes:
    """Read + integrity-check one committed evidence blob the record pins under `key`."""
    ev = (rec.get("commit_evidence") or {}).get(key)
    if not ev or not ev.get("evidence_path"):
        raise DispatchError(f"record pins no commit_evidence.{key}.evidence_path")
    fp = N2E_DIR / ev["evidence_path"]
    b = fp.read_bytes()
    if hashlib.sha256(b).hexdigest() != ev.get("sha256") or len(b) != ev.get("bytes"):
        raise DispatchError(f"frozen evidence {key} sha256/bytes != recorded")
    return b


def recompute_dispatch_v4(rec: dict, entry: dict) -> bool:
    """Registry-bound recompute for a dispatch-v4 commit-identity record. Replays the resulting-ref
    identity from the frozen plumbing + RTK stdout; diagnostic provenance is rejected. `created` is
    derived purely from the frozen HEAD/HEAD^/--name-status (a commit that failed leaves HEAD at base
    -> created False), so no producer exit-code/PASS string is trusted; the base OID authority is the
    pinned scenario base_commit."""
    verify_dispatch_binding(rec, entry)
    if rec.get("record_kind") == "php_cs_fixer_git_commit_diagnostic_capture" or rec.get("barred_from_qualification"):
        raise DispatchError("diagnostic provenance cannot be recomputed as acceptance")
    mod = _ORACLE_MODULES[entry["command_semantic_oracle_policy_id"]]

    base_commit = _scenario_base_commit(entry["case_id"])
    raw_state = mod.parse_git_state(0,
                                    _frozen_bytes(rec, "raw_head").decode("utf-8", "replace"),
                                    _frozen_bytes(rec, "raw_parent").decode("utf-8", "replace"),
                                    _frozen_bytes(rec, "raw_name_status"), base_commit)
    rtk_state = mod.parse_git_state(0,
                                    _frozen_bytes(rec, "rtk_head").decode("utf-8", "replace"),
                                    _frozen_bytes(rec, "rtk_parent").decode("utf-8", "replace"),
                                    _frozen_bytes(rec, "rtk_name_status"), base_commit)
    rtk_parsed = mod.parse_rtk(_frozen_bytes(rec, "rtk_stdout"))
    eq = mod.equivalence(raw_state, rtk_state, rtk_parsed, base_commit)
    return bool(eq.get("equivalent"))


def bind_dispatch_v4(rec: dict, entry: dict) -> None:
    if rec.get("case_id") != entry["case_id"]:
        raise DispatchError("record does not bind this case")
    verify_dispatch_binding(rec, entry)
