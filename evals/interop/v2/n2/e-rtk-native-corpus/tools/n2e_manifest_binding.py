#!/usr/bin/env python3
"""Per-case manifest binding (gen-3): decouple a case's QUALIFICATION evidence from the SHA of the
whole twelve-case manifest.

The gen-2 model bound each qualification record to the SHA of the ENTIRE manifest, so changing ONE
case's determinants (e.g. Lucene's execution policy) made the OTHER eleven cases' frozen evidence
"stale" even though their bytes + semantics were unchanged -- a real over-coupling defect. This module
computes a canonical, CASE-LOCAL digest (`case_entry_sha256`) over ONLY that case's determinants:

  * case_id + qualification_kind + expected_qualification_record_type
  * execution-policy id + digest        (from the case's execution contract entry; None if no policy)
  * canonicalization-policy id + digest (the policy DEFINITION bytes, not just the id string)
  * dialect/oracle id + digest          (the proven semantics-module bytes; None until materialized)
  * required identity references        (rtk binary + toolchain)
  * the case's contract entry digest    (+ overlay entry digest when the case is resolved-overlaid)

Membership stays GLOBAL (the manifest still fixes exactly twelve cases + a root hash); only the
qualification evidence becomes case-local. A later case-local policy upgrade (Lucene v2 today; the
git/docker/log oracles tomorrow) then changes ONLY its own entry -- no mass re-freeze of the others.

Digests of not-yet-materialized components (an oracle whose module is not registered, a canon policy
not yet in the registry) are None; when that component is built, only THAT case's digest changes.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import n2e_canon_policies as canon  # noqa: E402
import n2e_resolved_case_qualification as cq  # noqa: E402


def _canon_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha(obj) -> str:
    return "sha256:" + hashlib.sha256(_canon_json(obj)).hexdigest()


def _sha_bytes(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def _canon_policy_digest(canon_id: str):
    """Digest of the canonicalization policy DEFINITION. Handles the RUNTIME:a|b form (jvm test, where
    the concrete policy is resolved at runtime) by digesting each component definition in order. None
    if a component policy is not (yet) materialized in the registry."""
    if not canon_id:
        return None
    try:
        if canon_id.startswith("RUNTIME:"):
            comps = canon_id[len("RUNTIME:"):].split("|")
            return _sha({"runtime_components": {c: canon.policy_definition_sha256(c) for c in comps}})
        return "sha256:" + canon.policy_definition_sha256(canon_id)
    except KeyError:
        return None  # policy not yet materialized


def _module_digest(mod) -> str | None:
    try:
        return _sha_bytes(Path(mod.__file__).read_bytes())
    except Exception:  # noqa: BLE001
        return None


def _dialect_or_oracle(kind: str, entry: dict):
    """(id, module-digest) for the case's proven semantics module, or (id, None) when the module is
    not yet registered (the four not-yet-built command oracles)."""
    if kind == "rtk_test_dialect":
        pid = entry.get("rtk_test_dialect_policy_id")
        mod = cq.TEST_DIALECTS.get(pid)
    elif kind == "rtk_command_oracle":
        pid = entry.get("command_semantic_oracle_policy_id")
        mod = cq.COMMAND_ORACLES.get(pid)
    else:
        return (None, None)
    return (pid, _module_digest(mod) if mod is not None else None)


def case_entry_projection(manifest_entry: dict, contract_entry: dict,
                          overlay_entry: dict | None = None) -> dict:
    """The canonical determinant projection for ONE case. Deterministic; independent of the other
    eleven cases. Its `_canon_json` is what `case_entry_sha256` hashes."""
    kind = manifest_entry["qualification_kind"]
    ec = (contract_entry or {}).get("execution_control")
    exec_policy = None if not ec else {"id": ec.get("policy_id"), "digest": _sha(ec)}
    canon_id = manifest_entry.get("canonicalization_policy_id")
    do_id, do_digest = _dialect_or_oracle(kind, manifest_entry)
    return {
        "case_id": manifest_entry["case_id"],
        "qualification_kind": kind,
        "expected_qualification_record_type": manifest_entry.get("expected_qualification_record_type"),
        "execution_policy": exec_policy,
        "canonicalization_policy": {"id": canon_id, "digest": _canon_policy_digest(canon_id)},
        "dialect_or_oracle": {"id": do_id, "digest": do_digest},
        "identity_refs": {
            "rtk_binary": manifest_entry.get("required_rtk_binary_identity_ref"),
            "toolchain": manifest_entry.get("required_toolchain_identity_ref"),
        },
        "contract_entry_digest": _sha(contract_entry) if contract_entry is not None else None,
        "overlay_entry_digest": _sha(overlay_entry) if overlay_entry is not None else None,
    }


def case_entry_sha256(manifest_entry: dict, contract_entry: dict,
                      overlay_entry: dict | None = None) -> str:
    """'sha256:<hex>' over the canonical case-entry projection. This is the case-local binding key a
    qualification record pins instead of the whole-manifest SHA."""
    return _sha(case_entry_projection(manifest_entry, contract_entry, overlay_entry))


def contract_entry_for(case_id: str, contract_record: dict) -> dict | None:
    return next((e for e in contract_record.get("contracts", []) if e["case_id"] == case_id), None)


def overlay_entry_for(case_id: str, overlay_record: dict | None) -> dict | None:
    if not overlay_record:
        return None
    return next((e for e in overlay_record.get("overlay_contracts", []) if e.get("case_id") == case_id), None)
