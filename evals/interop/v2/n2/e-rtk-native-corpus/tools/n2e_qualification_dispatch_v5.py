#!/usr/bin/env python3
"""n2e-qualification-dispatch-v5: a NEW versioned, immutable, case-scoped dispatch generation for the
redis docker-images oracle (rtk-docker-images-oracle-v1). v2 froze after Loghub, v3 after the rubocop
merge oracle, v4 after the php-cs-fixer commit oracle; a new grounded oracle gets a new generation.

Strictly separated from cq AND from dispatch-v2/v3/v4: a v5 record carries a dispatch_code_identity
naming v5 (and NO cq frozen_code_identity, and NOT v2/v3/v4). No plugin discovery, no import path from
the artifact, no generic-oracle fallback. Registry is checksum-pinned + case-scoped (exact-one-match
to redis only).

recompute replays TWO authorities from the FROZEN record evidence:
  * the RTK PROJECTION -- RTK's compact `docker images` output vs the RAW `--format` projection: the
    (repository:tag, size) multiset + count must match, RTK must be COMPACT (not never_worse
    passthrough), and its header count/total must be faithful. This is all the oracle claims.
  * the IMAGE IDENTITY -- from the frozen `docker image inspect` of BOTH isolated daemons: the config
    Id and RepoDigest must equal the pinned redis-docker-images-execution-v1 determinants (config Id +
    RepoDigest == the pinned index digest, platform amd64/linux), and the two daemons' inspects must
    agree. RTK never reports identity; it is proven here as an execution determinant, re-asserted at
    aggregation time. The execution policy is hash-pinned into the dispatch identity.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_rtk_docker_images_oracle as _docker_oracle  # noqa: E402

DISPATCH_POLICY_ID = "n2e-qualification-dispatch-v5"
REGISTRY = N2E_DIR / "n2e-qualification-dispatch-registry-v5.json"
EXECUTION_POLICY = N2E_DIR / "n2e-redis-docker-images-execution-policy-v1.json"

# the ONLY oracle modules this generation may bind -- a static, closed table (no discovery, no fallback)
_ORACLE_MODULES = {"rtk-docker-images-oracle-v1": _docker_oracle}


class DispatchError(Exception):
    pass


def _module_sha256(mod) -> str:
    return hashlib.sha256(Path(mod.__file__).read_bytes()).hexdigest()


def dispatch_module_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _execution_policy_sha256() -> str:
    return c.sha256_json_file(EXECUTION_POLICY).split(":", 1)[-1]


def load_execution_policy() -> dict:
    rec = c.load_record(EXECUTION_POLICY)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        raise DispatchError(f"execution policy self-hash: {msg}")
    if rec.get("policy_id") != "redis-docker-images-execution-v1":
        raise DispatchError("execution policy policy_id mismatch")
    return rec


def load_registry() -> dict:
    rec = c.load_record(REGISTRY)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        raise DispatchError(f"registry self-hash: {msg}")
    if rec.get("record_type") != "n2e-qualification-dispatch-registry":
        raise DispatchError("registry wrong record_type")
    if rec.get("dispatch_policy_id") != DISPATCH_POLICY_ID:
        raise DispatchError("registry dispatch_policy_id != v5")
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
        raise DispatchError("registry entry dispatch_policy_id != v5")
    return e


def dispatch_code_identity(entry: dict) -> dict:
    """Pins the exact code + data that produce/check a dispatch-v5 verdict: the dispatch layer, the
    immutable registry, the oracle module, the pinned RTK source identity, AND the execution policy
    (the isolated-daemon + image determinants). A frozen record pins this; later drift is DETECTED."""
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
        "execution_policy_sha256": _execution_policy_sha256(),
        "canonicalization_policy_id": re["canonicalization_policy_id"],
    }


def verify_dispatch_binding(rec: dict, entry: dict) -> None:
    if entry.get("dispatch_policy_id") != DISPATCH_POLICY_ID:
        raise DispatchError(f"{entry['case_id']}: manifest not routed to dispatch-v5")
    if rec.get("dispatch_policy_id") != DISPATCH_POLICY_ID:
        raise DispatchError("record dispatch_policy_id != v5 (wrong-generation record on the registry path?)")
    # MUTUAL EXCLUSION: a v5 record carries dispatch_code_identity and NEVER a cq frozen_code_identity
    if rec.get("frozen_code_identity") is not None:
        raise DispatchError("record carries a cq frozen_code_identity -- legacy record on the dispatch path")
    if rec.get("dispatch_code_identity") is None:
        raise DispatchError("record carries no dispatch_code_identity")
    kind = entry.get("qualification_kind")
    if kind != "rtk_command_oracle":
        raise DispatchError("dispatch-v5 binds rtk_command_oracle only")
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


def _frozen_bytes(rec: dict, key: str) -> bytes:
    """Read + integrity-check one committed evidence blob the record pins under `key`."""
    ev = (rec.get("docker_evidence") or {}).get(key)
    if not ev or not ev.get("evidence_path"):
        raise DispatchError(f"record pins no docker_evidence.{key}.evidence_path")
    fp = N2E_DIR / ev["evidence_path"]
    b = fp.read_bytes()
    if hashlib.sha256(b).hexdigest() != ev.get("sha256") or len(b) != ev.get("bytes"):
        raise DispatchError(f"frozen evidence {key} sha256/bytes != recorded")
    return b


def _assert_identity(insp: dict, pol_img: dict, who: str) -> list:
    m = []
    if not insp.get("derivable"):
        return [f"{who}_inspect_not_derivable"]
    if insp.get("id") != pol_img["expected_config_id"]:
        m.append(f"{who}_config_id != pinned")
    if pol_img["expected_repo_digest"] not in (insp.get("repo_digests") or []):
        m.append(f"{who}_repo_digest missing pinned index digest")
    if insp.get("architecture") != pol_img["expected_arch"] or insp.get("os") != pol_img["expected_os"]:
        m.append(f"{who}_platform != pinned amd64/linux")
    return m


def recompute_dispatch_v5(rec: dict, entry: dict) -> bool:
    """Registry-bound recompute for a dispatch-v5 docker-images record. Replays the RTK projection
    equivalence (compact, multiset+count faithful) AND the image identity (config Id + RepoDigest ==
    the pinned execution-policy determinants, both daemons agreeing) from the frozen evidence.
    Diagnostic provenance is rejected. A producer PASS string is never trusted."""
    verify_dispatch_binding(rec, entry)
    if rec.get("record_kind") == "redis_docker_images_diagnostic_capture" or rec.get("barred_from_qualification"):
        raise DispatchError("diagnostic provenance cannot be recomputed as acceptance")
    mod = _ORACLE_MODULES[entry["command_semantic_oracle_policy_id"]]
    pol = load_execution_policy()
    pol_img = pol["image"]

    # ---- authority 1: RTK projection vs RAW --format projection (compact, faithful, equal multiset) ----
    raw_fmt = mod.parse_format_rows(_frozen_bytes(rec, "raw_format_rows"))
    rtk = mod.parse_rtk(_frozen_bytes(rec, "rtk_stdout"))
    eq = mod.equivalence(raw_fmt, rtk, allow_passthrough=False)
    if not eq.get("equivalent"):
        return False
    if eq.get("output_mode") != pol["measurement"]["output_mode_required"]:
        return False

    # ---- authority 2: image identity from BOTH isolated daemons' inspect (execution determinant) ----
    raw_insp = mod.parse_inspect(_frozen_bytes(rec, "raw_inspect"))
    rtk_insp = mod.parse_inspect(_frozen_bytes(rec, "rtk_inspect"))
    m = _assert_identity(raw_insp, pol_img, "raw") + _assert_identity(rtk_insp, pol_img, "rtk")
    if raw_insp.get("id") != rtk_insp.get("id") or raw_insp.get("repo_digests") != rtk_insp.get("repo_digests"):
        m.append("raw_rtk_inspect_identity_disagree")
    return not m


def bind_dispatch_v5(rec: dict, entry: dict) -> None:
    if rec.get("case_id") != entry["case_id"]:
        raise DispatchError("record does not bind this case")
    verify_dispatch_binding(rec, entry)
