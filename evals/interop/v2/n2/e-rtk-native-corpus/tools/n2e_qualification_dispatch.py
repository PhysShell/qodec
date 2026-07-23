#!/usr/bin/env python3
"""n2e-qualification-dispatch-v2: a versioned, immutable dispatch layer for registry-bound
command-oracle qualification records. It exists so a NEW command oracle (Loghub's
rtk-log-hdfs-oracle-v1) can be dispatched WITHOUT editing the frozen cq implementation -- the eight
legacy records pin cq's identity, so cq is sealed.

Two STRICTLY separated paths, never crossing:
  * legacy qualification record  -> frozen cq implementation (exact pinned cq hash) -- NOT here;
  * registry-bound command-oracle record -> THIS dispatch-v2 + exact registry entry + exact oracle
    implementation, pinned by module sha256.

Hard prohibitions (there is no code path for any of these):
  * no module discovery by directory / entry points / import path taken from the artifact;
  * no "unknown policy -> try a generic oracle" fallback;
  * no reinterpreting a legacy record through this path, nor a dispatch record through cq.

Future command oracles get a NEW immutable dispatch generation (v3, v4); v2 is frozen after Loghub.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_log_evidence_capsule as lcap  # noqa: E402
import n2e_rtk_log_hdfs_oracle as _log_oracle  # noqa: E402

DISPATCH_POLICY_ID = "n2e-qualification-dispatch-v2"
REGISTRY = N2E_DIR / "n2e-qualification-dispatch-registry-v2.json"

# the ONLY oracle modules this generation may bind, by policy id. NOT discovered -- a static, closed
# table; a policy not here has no path (no fallback). Each is cross-checked against the registry hash.
_ORACLE_MODULES = {"rtk-log-hdfs-oracle-v1": _log_oracle}


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
        raise DispatchError("registry dispatch_policy_id != v2")
    return rec


def registry_sha256() -> str:
    return c.sha256_json_file(REGISTRY).split(":", 1)[-1]


def _registry_entry(registry: dict, policy_id: str, case_id: str) -> dict:
    """EXACTLY-ONE-MATCH by (policy_id, case_id). Zero or more than one is a hard reject. The match is
    CASE-SCOPED to an exact case id in allowed_case_ids -- never a family-level ('logs') binding."""
    hits = [e for e in (registry.get("entries") or [])
            if e.get("policy_id") == policy_id and case_id in (e.get("allowed_case_ids") or [])]
    if len(hits) != 1:
        raise DispatchError(f"registry match for ({policy_id}, {case_id}) is not exactly one: {len(hits)}")
    e = hits[0]
    # a family-level token in allowed_case_ids is barred: every entry must be an exact '::'-scoped case id
    for cid in e.get("allowed_case_ids") or []:
        if "::" not in cid:
            raise DispatchError(f"registry entry has a non-case-scoped (family-level) binding: {cid!r}")
    if e.get("dispatch_policy_id") != DISPATCH_POLICY_ID:
        raise DispatchError("registry entry dispatch_policy_id != v2")
    return e


def dispatch_code_identity(entry: dict) -> dict:
    """The exact code that produces + checks a dispatch-v2 case's verdict, pinned by content hash: the
    dispatch layer, the immutable registry, and the registry-bound oracle module + its pinned RTK
    source identity. A frozen record pins this; a later change is DETECTED (not silently absorbed)."""
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
        "rtk_source_identity_sha256": re["rtk_source_identity_sha256"],
        "canonicalization_policy_id": re["canonicalization_policy_id"],
    }


def verify_dispatch_binding(rec: dict, entry: dict) -> None:
    """Fail-closed dispatch binding. Rejects: a non-dispatch record on this path; both/neither semantic
    policy id; a manifest not routed to v2; an unknown dispatch policy; a registry/module/source drift;
    a wrong-case or family-level binding; and any dynamic import path smuggled in the artifact."""
    if entry.get("dispatch_policy_id") != DISPATCH_POLICY_ID:
        raise DispatchError(f"{entry['case_id']}: manifest not routed to dispatch-v2")
    if rec.get("dispatch_policy_id") != DISPATCH_POLICY_ID:
        raise DispatchError("record dispatch_policy_id != v2 (legacy record on the registry path?)")
    # MUTUAL EXCLUSION: a dispatch record carries dispatch_code_identity and NEVER a cq
    # frozen_code_identity; a legacy record is the converse. This bars a legacy record here and a
    # dispatch record through cq -- the two frozen paths can never launder each other's evidence.
    if rec.get("frozen_code_identity") is not None:
        raise DispatchError("record carries a cq frozen_code_identity -- legacy record on the dispatch path")
    if rec.get("dispatch_code_identity") is None:
        raise DispatchError("record carries no dispatch_code_identity")
    # exactly one active semantic policy id: command oracle present, test dialect absent
    kind = entry.get("qualification_kind")
    if kind != "rtk_command_oracle":
        raise DispatchError("dispatch-v2 binds rtk_command_oracle only")
    if entry.get("rtk_test_dialect_policy_id") is not None:
        raise DispatchError("both test dialect and command oracle specified")
    oracle_pid = entry.get("command_semantic_oracle_policy_id")
    if not oracle_pid:
        raise DispatchError("no command_semantic_oracle_policy_id (both semantic ids absent)")
    # NO dynamic module/import path may be honored from the artifact
    for k in ("oracle_module_path", "oracle_import", "module_path", "import_path", "entry_point"):
        if k in rec:
            raise DispatchError(f"artifact carries a dynamic import path ({k}) -- barred")
    # frozen dispatch-code-identity drift is fail-closed
    want = dispatch_code_identity(entry)
    got = rec.get("dispatch_code_identity")
    if got != want:
        raise DispatchError(f"dispatch_code_identity DRIFT:\n  record: {got}\n  current: {want}")


def recompute_dispatch_v2(rec: dict, entry: dict) -> bool:
    """Registry-bound recompute for a dispatch-v2 command-oracle record. Re-derives the RAW<->RTK
    severity equivalence from the FROZEN capsule summary + the frozen RTK output through the
    registry-pinned oracle. Never trusts a producer PASS string. Diagnostic provenance is rejected."""
    verify_dispatch_binding(rec, entry)
    if rec.get("record_kind") == "loghub_diagnostic_capture" or rec.get("barred_from_qualification"):
        raise DispatchError("diagnostic provenance cannot be recomputed as acceptance")
    policy = entry["command_semantic_oracle_policy_id"]
    mod = _ORACLE_MODULES[policy]

    cap_summary = rec.get("raw_capsule_summary")
    if not cap_summary:
        raise DispatchError("record carries no raw_capsule_summary")
    # the RAW capsule must have PASSED the published-authority model on the full stream
    if cap_summary.get("outcome") != "parsed":
        return False
    if cap_summary.get("unmatched_lines") or cap_summary.get("ambiguous_lines"):
        return False
    if cap_summary.get("occurrence_counts_match_published") is not True:
        return False

    rtk_bytes = _frozen_rtk_output(rec)
    rtk_proj = mod.parse_rtk(rtk_bytes)
    raw_ref = mod.raw_projection_from_capsule(cap_summary)
    eq = mod.equivalence(raw_ref, rtk_proj)
    return bool(eq.get("equivalent"))


def _frozen_rtk_output(rec: dict) -> bytes:
    """Read + integrity-check the committed RTK output the record pins."""
    ro = rec.get("rtk_output") or {}
    p = ro.get("evidence_path")
    if not p:
        raise DispatchError("record pins no rtk_output evidence_path")
    fp = (N2E_DIR / p)
    b = fp.read_bytes()
    if hashlib.sha256(b).hexdigest() != ro.get("sha256") or len(b) != ro.get("bytes"):
        raise DispatchError("frozen RTK output sha256/bytes != recorded")
    return b


def bind_dispatch_v2(rec: dict, entry: dict) -> None:
    """Aggregator bind hook: the dispatch-v2 record must bind THIS case through the registry path."""
    if rec.get("case_id") != entry["case_id"]:
        raise DispatchError("record does not bind this case")
    verify_dispatch_binding(rec, entry)
