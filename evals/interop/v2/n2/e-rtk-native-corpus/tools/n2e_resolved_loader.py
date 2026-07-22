#!/usr/bin/env python3
"""One fail-closed resolved-scope loader (contract step 3).

Returns a single EFFECTIVE CASE BUNDLE for a case id under a scope:

  scope="base"     -> everything from the frozen base records (the 11 non-replacement
                      cases + the original tokio membership); overlays are never consulted.
  scope="resolved" -> the frozen base for every non-replacement case, and the resolved
                      replacement overlays for the coreutils-6731 case ONLY.

There are NO scattered `base_lookup(x) or overlay_lookup(x)` fallbacks: the loader
validates the entire resolved closure up-front and then routes each case to EXACTLY one
source. Any partial/base+overlay mixture, hash mismatch, shadow, or missing overlay fails
closed. The bundle carries the complete effective-record hash map so every emitted case
record can pin exactly what it ran under.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

# frozen base records
MEMBERSHIP = N2E_DIR / "n2e-canary-membership-v1.json"
SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
REGISTRY = N2E_DIR / "n2e-publisher-env-registry-v1.json"
CONTRACT = N2E_DIR / "n2e-canary-execution-contract-v1.json"
LOCK = N2E_DIR / "n2e-toolchain-lock-v1.json"
# resolved records
RESOLVED_MEMBERSHIP = N2E_DIR / "n2e-canary-resolved-membership-v1.json"
OV_PUBENV = N2E_DIR / "n2e-resolved-publisher-env-overlay-v1.json"
OV_TOOLCHAIN = N2E_DIR / "n2e-resolved-toolchain-overlay-v1.json"
OV_SCEN = N2E_DIR / "n2e-resolved-command-scenario-overlay-v1.json"
OV_CONTRACT = N2E_DIR / "n2e-resolved-execution-contract-v1.json"
MIGRATION_BRIDGE = N2E_DIR / "n2e-manifest-gen2-to-gen3-binding-migration-v1.json"
# additive resolved-ENVIRONMENT overlay (Model B frozen dependency snapshot) + its committed
# immutable evidence
OV_DEPSNAP = N2E_DIR / "n2e-resolved-dependency-snapshot-overlay-v1.json"
DEPSNAP_DIR = N2E_DIR / "evidence" / "coreutils-6731" / "resolved-dependency-snapshot"
# P2: executed-binary identity record + its committed frozen installed-identity evidence
BINID = N2E_DIR / "n2e-resolved-toolchain-binary-identity-v1.json"
BINID_DIR = N2E_DIR / "evidence" / "coreutils-6731" / "toolchain-binary-identity"
# P3: case-scoped Rust cargo-test RTK dialect record + its committed frozen streams
DIALECT = N2E_DIR / "n2e-resolved-rtk-rust-cargo-dialect-v1.json"
DIALECT_DIR = N2E_DIR / "evidence" / "coreutils-6731" / "rtk-rust-cargo-dialect"
# P4: Coreutils qualification record + its committed frozen canonical streams (predicate carrier)
QUALIFICATION = N2E_DIR / "n2e-coreutils-qualification-v1.json"
QUALIFICATION_DIR = N2E_DIR / "evidence" / "coreutils-6731" / "qualification"

REPLACEMENT_CASE_ID = "uutils__coreutils-6731::rust_cargo::test::fixed"
REPLACED_CASE_ID = "tokio-rs__tokio-4384::rust_cargo::test::fixed"

# The proven-promotable Model B run + implementation. Diagnostic-only runs/impls must satisfy NO
# provenance or promotion predicate (fail-closed). Eligibility itself is NEVER derived from
# provenance -- it comes only from the corrected normative verifier replay; these sets exist only
# to REJECT mis-provenanced overlays.
PROMOTABLE_RUN = "29654373144"
BARRED_DIAGNOSTIC_RUNS = frozenset({"29651849616", "29652684349",
                                    "29900168290"})                     # ...; 2c1a523 loghub diag
BARRED_DIAGNOSTIC_IMPLS = frozenset({"bcd4164", "3dbbf2b", "2ddd731", "8eefa97",
                                     "4ceaa11", "ab416ce", "186ade9",
                                     "2c1a523"})                         # loghub diagnostic capture
DEPSNAP_SCOPE = "full cross-platform resolution"
DEPSNAP_PROVEN_COUNT = 346

# P2 proven executed-binary identities. rust 1.81.0 is a pinned/immutable channel, so the on-disk
# cargo/rustc/rustup binaries are deterministic -> these measured identities are the anchor the
# committed record + frozen evidence must both match. The identity record's provenance names the
# determinant-neutral capture run (29656538775 / impl 1157bb8), whose Cargo.lock + resolved graph
# are byte-identical to the frozen Phase 1 evidence.
BINID_RUN = "29656538775"
BINID_IMPL = "1157bb8"
PROVEN_BINARY_IDENTITY = {
    "rust": {"binary_name": "rustc",
             "sha256": "91f9ba0819d622cbb0f4f3298580d939173eb3258d95f7755b301a394eeb2ae0",
             "bytes": 2642592},
    "cargo": {"binary_name": "cargo",
              "sha256": "0e654dccd3501e5feb68aa570e5f780d5f7921c820e558ac5d3ef60016b5c0a7",
              "bytes": 33654096},
}
PROVEN_WRAPPER = {"name": "rustup",
                  "sha256": "4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10",
                  "bytes": 20838840}
BINID_CHANNEL = "1.81.0"
BINID_HOST = "x86_64-unknown-linux-gnu"

# P3 proven Rust cargo-test dialect identity anchors (case-scoped: coreutils-6731 only).
DIALECT_ID = "rtk-rust-cargo-test-summary-v1"
DIALECT_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
DIALECT_SOURCE_TREE = "8ef9e912286858c2caf5b066c1121327a072be79"
DIALECT_RTK_SHA = "41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf"
DIALECT_RTK_BYTES = 9200104
DIALECT_RUN = "29667956749"

# P4 qualification expected semantics (the single proven Coreutils case).
QUAL_EXPECTED = {"passed": 10, "filtered_out": 3205, "suites": 3}
QUAL_WORKFLOW = "qodec-n2e-coreutils-qualification"

# overlay file -> (record key holding the base whole-file hash, the base file it must match)
_OVERLAYS = {
    "publisher_env": (OV_PUBENV, "base_publisher_registry_sha256", REGISTRY),
    "toolchain": (OV_TOOLCHAIN, "base_toolchain_lock_sha256", LOCK),
    "command_scenario": (OV_SCEN, "base_command_scenarios_sha256", SCEN),
    "execution_contract": (OV_CONTRACT, "base_execution_contract_sha256", CONTRACT),
}


class ResolvedScopeError(Exception):
    pass


def _load_ok(path: Path) -> dict:
    rec = c.load_record(path)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        raise ResolvedScopeError(f"{path.name}: self-hash {msg}")
    return rec


def acceptable_base_contract_shas() -> set:
    """The base-contract SHA(s) a coreutils FROZEN artifact (its resolved execution overlay, dependency
    snapshot, rust-dialect binding) may legitimately pin: the CURRENT base contract, plus -- when a
    valid ONE-DIRECTIONAL gen2->gen3 migration bridge attests the base contract advanced with coreutils'
    entry unchanged -- the frozen gen-2 predecessor. This is the base-contract sibling of per-case
    manifest binding: a case-local base-contract change (Lucene v2) must NOT invalidate coreutils'
    byte-identical frozen provenance. The bridge is required, pins the CURRENT contract as its gen-3
    side, and must list coreutils among the carried-forward cases; otherwise only the current sha is
    accepted (fail-closed)."""
    cur = c.sha256_json_file(CONTRACT)
    acc = {cur}
    if MIGRATION_BRIDGE.is_file():
        br = _load_ok(MIGRATION_BRIDGE)
        if (br.get("record_type") == "n2e-manifest-gen2-to-gen3-binding-migration"
                and (br.get("gen3") or {}).get("base_execution_contract_sha256") == cur
                and REPLACEMENT_CASE_ID in (br.get("carried_forward_case_ids") or [])):
            acc.add((br.get("gen2") or {}).get("base_execution_contract_sha256"))
    return acc - {None}


def _base_contract_sha_ok(pinned: str) -> bool:
    return pinned in acceptable_base_contract_shas()


def _manifest_hash(obj) -> str:
    """sha256 over sort-keyed JSON with DEFAULT separators -- matches the producer/verifier's
    host-graph + full-packages digest exactly (NOT the compact sha256_json_file)."""
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def _reachable(hg: dict) -> list:
    """Independently recompute reachable package ids: BFS from resolve_roots over resolve_nodes
    (same semantics as the producer/verifier). Used to re-derive the closure size from the
    committed frozen graph, not to trust a recorded count."""
    by = {n.get("id"): n for n in hg.get("resolve_nodes", [])}
    seen, stack = set(), list(hg.get("resolve_roots", []))
    while stack:
        nid = stack.pop()
        if nid in seen:
            continue
        seen.add(nid)
        for d in by.get(nid, {}).get("deps", []):
            pk = d.get("pkg")
            if pk:
                stack.append(pk)
    return sorted(i for i in seen if i in by)


def _load_snapshot_overlay(path: Path) -> dict:
    if not Path(path).is_file():
        raise ResolvedScopeError("required resolved dependency-snapshot overlay missing")
    return _load_ok(path)


def validate_dependency_snapshot_overlay(ds: dict, dep_ref, rm_sha: str, base_contract_sha: str,
                                         evidence_dir: Path) -> dict:
    """Fail-closed validation of the additive resolved-ENVIRONMENT overlay (Model B frozen
    dependency snapshot). Pure over its inputs so RED cases can exercise it without mutating the
    committed corpus. Validates EVERY pinned determinant against the referenced frozen artifacts
    (not schema shape); requires exactly one snapshot for the replacement case; re-derives the
    closure size from the committed graph and requires it to be the proven 346-node closure; bars
    diagnostic-only provenance. Returns the validated snapshot entry or raises."""
    if ds.get("record_type") != "n2e-resolved-dependency-snapshot-overlay":
        raise ResolvedScopeError("dependency-snapshot overlay wrong record_type")
    if ds.get("record_version") != "v1":
        raise ResolvedScopeError("dependency-snapshot overlay wrong record_version")
    if ds.get("resolved_case_id") != REPLACEMENT_CASE_ID:
        raise ResolvedScopeError("dependency-snapshot overlay resolved_case_id != replacement case")
    if not _base_contract_sha_ok(ds.get("base_execution_contract_sha256")):
        raise ResolvedScopeError("dependency-snapshot overlay base_execution_contract_sha256 mismatch "
                                 "(overlay attached to the wrong execution contract)")
    if ds.get("resolved_membership_sha256") != rm_sha:
        raise ResolvedScopeError("dependency-snapshot overlay resolved_membership_sha256 mismatch")
    # materializes the contract's stable-logical dependency_environment_identity_ref (one-way ref)
    if ds.get("materializes_dependency_environment_identity_ref") != dep_ref:
        raise ResolvedScopeError("dependency-snapshot overlay does not materialize the contract's "
                                 "dependency_environment_identity_ref")
    # EXACTLY ONE snapshot, for the replacement case only (duplicate / wrong-case -> reject)
    snaps = ds.get("overlay_dependency_snapshots") or []
    if [s.get("case_id") for s in snaps] != [REPLACEMENT_CASE_ID]:
        raise ResolvedScopeError("dependency-snapshot overlay must contain exactly one snapshot for "
                                 f"[{REPLACEMENT_CASE_ID}]")
    snap = snaps[0]

    # ---- validate every pinned determinant against the committed frozen artifacts ----
    lock_path = Path(evidence_dir) / "Cargo.lock"
    graph_path = Path(evidence_dir) / "resolved-graph.json"
    if not lock_path.is_file() or not graph_path.is_file():
        raise ResolvedScopeError("dependency-snapshot frozen evidence (Cargo.lock/resolved-graph.json) missing")
    lock = lock_path.read_bytes()
    if c.sha256_bytes(lock) != snap.get("cargo_lock_sha256"):
        raise ResolvedScopeError("frozen Cargo.lock sha256 != pinned cargo_lock_sha256")
    if len(lock) != snap.get("cargo_lock_bytes"):
        raise ResolvedScopeError("frozen Cargo.lock byte count != pinned cargo_lock_bytes")
    if snap.get("cargo_lock_scope") != DEPSNAP_SCOPE:
        raise ResolvedScopeError(f"dependency-snapshot cargo_lock_scope != {DEPSNAP_SCOPE!r}")
    graph = c.load_record(graph_path)
    hg = graph.get("host_resolve_graph") or {}
    if _manifest_hash(hg) != snap.get("host_resolve_graph_sha256"):
        raise ResolvedScopeError("frozen host_resolve_graph sha256 != pinned host_resolve_graph_sha256")
    if _manifest_hash(graph.get("full_packages_metadata")) != snap.get("full_packages_metadata_sha256"):
        raise ResolvedScopeError("frozen full_packages_metadata sha256 != pinned full_packages_metadata_sha256")
    # tie the frozen graph's own lock reference to the frozen lock (closure self-consistency)
    if graph.get("cargo_lock_sha256") != snap.get("cargo_lock_sha256"):
        raise ResolvedScopeError("frozen graph cargo_lock_sha256 != frozen Cargo.lock sha256")
    # requirement 4: the pinned count must resolve to the SAME 346-node closure -- recompute it
    reach = _reachable(hg)
    node_ids = {n.get("id") for n in hg.get("resolve_nodes", [])}
    if len(reach) != snap.get("host_resolved_package_count"):
        raise ResolvedScopeError(f"pinned host_resolved_package_count {snap.get('host_resolved_package_count')} "
                                 f"!= recomputed reachable {len(reach)}")
    if set(reach) != node_ids:
        raise ResolvedScopeError("frozen host graph has nodes disconnected from resolve_roots")
    if snap.get("host_resolved_package_count") != DEPSNAP_PROVEN_COUNT:
        raise ResolvedScopeError(f"dependency-snapshot closure is not the proven {DEPSNAP_PROVEN_COUNT}-node closure")

    # ---- provenance is DESCRIPTIVE; bar diagnostic-only runs/impls from satisfying it ----
    prov = snap.get("provenance") or {}
    if prov.get("run_id") in BARRED_DIAGNOSTIC_RUNS:
        raise ResolvedScopeError("dependency-snapshot provenance names a barred diagnostic-only run")
    if (prov.get("producer_implementation") in BARRED_DIAGNOSTIC_IMPLS
            or prov.get("verifier_implementation") in BARRED_DIAGNOSTIC_IMPLS):
        raise ResolvedScopeError("dependency-snapshot provenance names a barred diagnostic-only implementation")
    return snap


def _load_binid(path: Path) -> dict:
    if not Path(path).is_file():
        raise ResolvedScopeError("required executed-binary identity record missing")
    return _load_ok(path)


def _is_sha256(s) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(ch in "0123456789abcdef" for ch in s)


def validate_toolchain_binary_identity(rec: dict, ref, rm_sha: str, base_lock_sha: str,
                                       overlay_sha: str, evidence_dir: Path) -> dict:
    """Fail-closed validation of the P2 executed-binary identity record. Pure over its inputs so
    RED cases exercise it without mutating the committed corpus. Ties the record to the frozen
    toolchain overlay's stable-logical exact_binary_identity_ref (one-way); validates each measured
    identity against BOTH the committed frozen installed-identity evidence AND the proven immutable
    anchor; resolves wrappers explicitly (invoked path vs measured target); rejects
    missing/duplicate/internally-inconsistent/cross-case/metadata-only identities; keeps Rust and
    Cargo separate. Sets no promotion flag."""
    if rec.get("record_type") != "n2e-resolved-toolchain-binary-identity":
        raise ResolvedScopeError("binary-identity record wrong record_type")
    if rec.get("record_version") != "v1":
        raise ResolvedScopeError("binary-identity record wrong record_version")
    if rec.get("resolved_case_id") != REPLACEMENT_CASE_ID:
        raise ResolvedScopeError("binary-identity resolved_case_id != replacement case")
    if rec.get("resolved_membership_sha256") != rm_sha:
        raise ResolvedScopeError("binary-identity resolved_membership_sha256 mismatch")
    if rec.get("base_toolchain_lock_sha256") != base_lock_sha:
        raise ResolvedScopeError("binary-identity base_toolchain_lock_sha256 mismatch")
    if rec.get("resolved_toolchain_overlay_sha256") != overlay_sha:
        raise ResolvedScopeError("binary-identity resolved_toolchain_overlay_sha256 mismatch")
    if rec.get("materializes_exact_binary_identity_ref") != ref:
        raise ResolvedScopeError("binary-identity does not materialize the toolchain overlay's "
                                 "exact_binary_identity_ref")
    if rec.get("requested_toolchain") != BINID_CHANNEL or rec.get("channel") != BINID_CHANNEL:
        raise ResolvedScopeError("binary-identity requested_toolchain/channel != pinned")
    if rec.get("host_target") != BINID_HOST:
        raise ResolvedScopeError("binary-identity host_target != pinned")

    frozen_path = Path(evidence_dir) / "installed-identity.json"
    if not frozen_path.is_file():
        raise ResolvedScopeError("frozen installed-identity evidence missing")
    ii = c.load_record(frozen_path).get("installed_identity") or {}
    _ROLE_FROZEN = {
        "rust": ("rustc", "rustc_binary_path", "rustc_binary_sha256", "rustc_binary_bytes",
                 "rustc_shim_path", "rustc_shim_realpath", "rustc_version_verbose"),
        "cargo": ("cargo", "cargo_binary_path", "cargo_binary_sha256", "cargo_binary_bytes",
                  "cargo_shim_path", "cargo_shim_realpath", "cargo_version_verbose"),
    }

    roles = rec.get("role_identities") or []
    seen_roles = [r.get("role") for r in roles]
    if sorted(seen_roles) != ["cargo", "rust"]:
        raise ResolvedScopeError(f"binary-identity role_identities must be exactly rust+cargo (once each), "
                                 f"got {seen_roles}")
    run_ids, case_ids = set(), set()
    for r in roles:
        role = r["role"]
        proven = PROVEN_BINARY_IDENTITY[role]
        binname, f_path, f_sha, f_bytes, f_inv, f_invreal, f_vv = _ROLE_FROZEN[role]
        if r.get("binary_name") != binname:
            raise ResolvedScopeError(f"binary-identity {role}: binary_name != {binname}")
        # metadata-only guard: a measured executable digest MUST be present + well-formed
        if not _is_sha256(r.get("measured_sha256")):
            raise ResolvedScopeError(f"binary-identity {role}: measured_sha256 missing/invalid (metadata-only)")
        if not isinstance(r.get("measured_bytes"), int) or r["measured_bytes"] <= 0:
            raise ResolvedScopeError(f"binary-identity {role}: measured_bytes missing/invalid")
        # anchor: the measured identity must equal the proven immutable binary (changed byte -> reject)
        if r["measured_sha256"] != proven["sha256"] or r["measured_bytes"] != proven["bytes"]:
            raise ResolvedScopeError(f"binary-identity {role}: measured identity != proven {binname} binary")
        # referenced-artifact cross-check: the record must equal the committed frozen evidence
        if (r["measured_sha256"] != ii.get(f_sha) or r.get("measured_bytes") != ii.get(f_bytes)
                or r.get("measured_path") != ii.get(f_path) or r.get("invoked_path") != ii.get(f_inv)
                or r.get("invoked_realpath") != ii.get(f_invreal)
                or r.get("version_verbose") != ii.get(f_vv)):
            raise ResolvedScopeError(f"binary-identity {role}: record disagrees with frozen installed-identity evidence")
        # version text must attest the role binary + the resolved channel (disagreement -> reject)
        first = (r.get("version_verbose") or "").splitlines()[0] if r.get("version_verbose") else ""
        if not first.startswith(f"{binname} {BINID_CHANNEL}"):
            raise ResolvedScopeError(f"binary-identity {role}: version text does not attest {binname} {BINID_CHANNEL}")
        # resolve wrappers explicitly: invoked proxy + measured target must be the SAME role binary,
        # invoked must resolve to the rustup wrapper, and invoked must differ from measured.
        if Path(r.get("invoked_path", "")).name != binname:
            raise ResolvedScopeError(f"binary-identity {role}: invoked_path is not the {binname} proxy")
        if Path(r.get("measured_path", "")).name != binname:
            raise ResolvedScopeError(f"binary-identity {role}: measured_path is not a {binname} binary")
        if Path(r.get("invoked_realpath", "")).name != PROVEN_WRAPPER["name"]:
            raise ResolvedScopeError(f"binary-identity {role}: invoked_realpath is not the {PROVEN_WRAPPER['name']} wrapper")
        if r.get("invoked_path") == r.get("measured_path") or r.get("invoked_differs_from_measured") is not True:
            raise ResolvedScopeError(f"binary-identity {role}: invoked path must differ from measured target")
        if r.get("case_id") != REPLACEMENT_CASE_ID:
            raise ResolvedScopeError(f"binary-identity {role}: case_id != replacement case")
        run_ids.add(r.get("run_id"))
        case_ids.add(r.get("case_id"))
    # cross-role coherence: a single coherent measurement -- both roles from the SAME run + case
    # (rust identity from run A paired with cargo identity from run B -> reject)
    if len(run_ids) != 1 or len(case_ids) != 1:
        raise ResolvedScopeError("binary-identity roles are cross-paired (different run_id/case_id)")
    if run_ids != {BINID_RUN}:
        raise ResolvedScopeError("binary-identity role run_id != the capture run")

    # invoked wrapper identity
    w = rec.get("invoked_wrapper") or {}
    if w.get("name") != PROVEN_WRAPPER["name"] or w.get("sha256") != PROVEN_WRAPPER["sha256"] \
            or w.get("bytes") != PROVEN_WRAPPER["bytes"]:
        raise ResolvedScopeError("binary-identity invoked_wrapper identity != proven rustup wrapper")
    if w.get("sha256") != ii.get("rustup_executable_sha256"):
        raise ResolvedScopeError("binary-identity invoked_wrapper sha != frozen installed-identity")

    # provenance is DESCRIPTIVE; bar diagnostic-only runs/impls
    prov = rec.get("provenance") or {}
    if prov.get("run_id") in BARRED_DIAGNOSTIC_RUNS or prov.get("producer_implementation") in BARRED_DIAGNOSTIC_IMPLS:
        raise ResolvedScopeError("binary-identity provenance names a barred diagnostic-only run/impl")
    if prov.get("run_id") != BINID_RUN or prov.get("producer_implementation") != BINID_IMPL:
        raise ResolvedScopeError("binary-identity provenance run/impl != the capture run")
    return rec


def _load_dialect(path: Path) -> dict:
    if not Path(path).is_file():
        raise ResolvedScopeError("required RTK dialect record missing (contract binds a dialect)")
    return _load_ok(path)


def validate_rtk_rust_cargo_dialect(rec: dict, bound_dialect_id, rm_sha: str, base_contract_sha: str,
                                    resolved_contract_sha: str, p2_sha: str, evidence_dir: Path) -> dict:
    """Fail-closed validation of the case-scoped Rust cargo-test RTK dialect record. Pure over its
    inputs. Ties the dialect to the exact pinned RTK source + executable identity + the P2
    binary-identity record; re-derives the semantic projection + equivalence from the frozen
    streams; enforces the CASE-scoped binding (proven for coreutils-6731 only -- a family-level
    binding, a different/tokio case, a missing/changed case_id, or a duplicate binding all reject).
    No floating branch/tag/HEAD/PATH; provenance descriptive; diagnostic-only runs barred."""
    import n2e_oracles as ora
    import n2e_rtk_rust_cargo_dialect as rcd

    if rec.get("record_type") != "n2e-resolved-rtk-rust-cargo-dialect":
        raise ResolvedScopeError("dialect record wrong record_type")
    if rec.get("record_version") != "v1":
        raise ResolvedScopeError("dialect record wrong record_version")
    if rec.get("dialect_policy_id") != DIALECT_ID:
        raise ResolvedScopeError("dialect record dialect_policy_id != pinned")
    if rec.get("dialect_scope") != "case_scoped":
        raise ResolvedScopeError("dialect record is not case_scoped")
    if rec.get("materializes_rtk_test_dialect_policy_id") != bound_dialect_id:
        raise ResolvedScopeError("dialect record does not materialize the contract's rtk_test_dialect_policy_id")
    if rec.get("resolved_case_id") != REPLACEMENT_CASE_ID:
        raise ResolvedScopeError("dialect resolved_case_id != replacement case")
    if rec.get("resolved_membership_sha256") != rm_sha:
        raise ResolvedScopeError("dialect resolved_membership_sha256 mismatch")
    if not _base_contract_sha_ok(rec.get("base_execution_contract_sha256")):
        raise ResolvedScopeError("dialect base_execution_contract_sha256 mismatch")
    if rec.get("resolved_execution_contract_sha256") != resolved_contract_sha:
        raise ResolvedScopeError("dialect resolved_execution_contract_sha256 mismatch")

    # CASE-scoped binding correctness: the case must resolve to THIS dialect case-scoped, and the
    # FAMILY must stay unproven (a family-level binding / duplicate binding is rejected).
    if ora.rtk_dialect_for_case("rust_cargo", REPLACEMENT_CASE_ID) != DIALECT_ID:
        raise ResolvedScopeError("dialect is not the proven case-scoped binding for the replacement case")
    if ora.rtk_dialect_for("rust_cargo") is not None:
        raise ResolvedScopeError("rust_cargo has a FAMILY-level dialect binding (only case-scoped proven) "
                                 "-- duplicate/over-broad binding rejected")
    # a different (e.g. tokio) case must NOT resolve to this dialect
    if ora.rtk_dialect_for_case("rust_cargo", REPLACED_CASE_ID) is not None:
        raise ResolvedScopeError("dialect leaks to a non-proven case (e.g. tokio)")

    # ---- identity chain (no floating ref) ----
    src = rec.get("rtk_source_identity") or {}
    if src.get("commit") != DIALECT_SOURCE_COMMIT or src.get("source_tree") != DIALECT_SOURCE_TREE:
        raise ResolvedScopeError("dialect RTK source commit/tree != pinned 5d32d07")
    exe = rec.get("rtk_executable_identity") or {}
    if exe.get("sha256") != DIALECT_RTK_SHA or exe.get("bytes") != DIALECT_RTK_BYTES:
        raise ResolvedScopeError("dialect built RTK executable sha256/bytes != proven")
    if rec.get("p2_binary_identity_ref", {}).get("sha256") != p2_sha:
        raise ResolvedScopeError("dialect p2_binary_identity_ref sha != current P2 record")

    # ---- layer 1: captured bytes -- re-hash every frozen stream ----
    cap = rec.get("captured_bytes") or {}
    streams = cap.get("streams") or {}
    if not streams:
        raise ResolvedScopeError("dialect captured_bytes has no streams (metadata-only)")
    if cap.get("streams_manifest_sha256") != c.sha256_json_file(evidence_dir / "streams-manifest.json"):
        raise ResolvedScopeError("dialect streams_manifest_sha256 mismatch")
    for name, meta in streams.items():
        p = evidence_dir / "streams" / name
        if not p.is_file():
            raise ResolvedScopeError(f"dialect frozen stream missing: {name}")
        raw = p.read_bytes()
        if c.sha256_bytes(raw) != meta.get("sha256") or len(raw) != meta.get("bytes"):
            raise ResolvedScopeError(f"dialect frozen stream {name}: sha256/bytes != recorded")

    # ---- layer 3: semantic projection -- re-derive from the frozen v3-canonical streams ----
    raw_can = (evidence_dir / "streams" / "raw.canonical.rep0.bin").read_bytes()
    rtk_can = (evidence_dir / "streams" / "rtk.canonical.rep0.bin").read_bytes()
    rp, kp = rcd.parse_raw(raw_can), rcd.parse_rtk(rtk_can)
    sp = rec.get("semantic_projection") or {}
    if sp.get("raw_projection") != rp or sp.get("rtk_projection") != kp:
        raise ResolvedScopeError("dialect recorded projection != re-derived from frozen streams")
    eq = rcd.equivalence(rp, kp)
    if not eq["equivalent"] or sp.get("equivalence", {}).get("equivalent") is not True:
        raise ResolvedScopeError("dialect RAW<->RTK equivalence does not hold on the frozen streams")

    # provenance descriptive; bar diagnostic-only runs/impls
    prov = rec.get("provenance") or {}
    if prov.get("run_id") in BARRED_DIAGNOSTIC_RUNS or prov.get("producer_implementation") in BARRED_DIAGNOSTIC_IMPLS:
        raise ResolvedScopeError("dialect provenance names a barred diagnostic-only run/impl")
    if prov.get("run_id") != DIALECT_RUN:
        raise ResolvedScopeError("dialect provenance run_id != the capture run")
    return rec


def _load_qualification(path: Path) -> dict:
    if not Path(path).is_file():
        raise ResolvedScopeError("required Coreutils qualification record missing (predicate active)")
    return _load_ok(path)


def validate_coreutils_qualification(rec: dict, rm_sha: str, resolved_contract_sha: str, p2_sha: str,
                                     p3_sha: str, evidence_dir: Path) -> bool:
    """Fail-closed validation of the Coreutils qualification record + INDEPENDENT recomputation of
    the verdict. Pure over its inputs. Re-parses the committed frozen canonical streams through the
    frozen P3 dialect, recomputes the equivalence + required semantics, and requires the record's
    claimed coreutils_qualification_pass to MATCH the recomputed verdict (a record claiming PASS
    while the recomputation yields FAIL is rejected). Ties the record to contract generation 3, the
    seven overlays, and the P2/P3 identity records; bars diagnostic runs. Returns the verdict."""
    import n2e_rtk_rust_cargo_dialect as rcd

    if rec.get("record_type") != "n2e-coreutils-qualification":
        raise ResolvedScopeError("qualification record wrong record_type")
    if rec.get("record_version") != "v1":
        raise ResolvedScopeError("qualification record wrong record_version")
    # EXACTLY ONE qualification, for the replacement case (duplicate / wrong-case -> reject)
    quals = rec.get("qualifications") or []
    if [q.get("case_id") for q in quals] != [REPLACEMENT_CASE_ID]:
        raise ResolvedScopeError(f"qualification record must contain exactly one qualification for "
                                 f"[{REPLACEMENT_CASE_ID}]")
    q = quals[0]

    # ---- bindings: gen-3 contract + membership + P2/P3 identity records ----
    if rec.get("resolved_membership_sha256") != rm_sha:
        raise ResolvedScopeError("qualification resolved_membership_sha256 mismatch")
    if rec.get("contract_generation3_sha256") != resolved_contract_sha:
        raise ResolvedScopeError("qualification contract_generation3_sha256 != current resolved contract")
    if rec.get("p2_binary_identity_ref", {}).get("sha256") != p2_sha:
        raise ResolvedScopeError("qualification p2_binary_identity_ref sha != current P2 record")
    if rec.get("p3_dialect_ref", {}).get("sha256") != p3_sha:
        raise ResolvedScopeError("qualification p3_dialect_ref sha != current P3 dialect record")
    # the qualification is bound to the SAME proven dialect + versioned canon policy as the contract
    if rec.get("bound_dialect_policy_id") != DIALECT_ID:
        raise ResolvedScopeError("qualification bound_dialect_policy_id != proven dialect")
    if rec.get("canonicalization_policy_id") != "cargo-test-v3":
        raise ResolvedScopeError("qualification canonicalization_policy_id != cargo-test-v3")

    # ---- acceptance-run identity (a diagnostic run cannot be substituted) ----
    run = rec.get("acceptance_run") or {}
    if run.get("workflow") != QUAL_WORKFLOW:
        raise ResolvedScopeError("qualification acceptance_run.workflow != the qualification workflow "
                                 "(diagnostic run substituted?)")
    for k in ("run_id", "run_attempt", "impl_commit", "artifact_sha256", "artifact_bytes"):
        if run.get(k) in (None, ""):
            raise ResolvedScopeError(f"qualification acceptance_run.{k} missing")
    if run.get("run_id") in BARRED_DIAGNOSTIC_RUNS or run.get("impl_commit") in BARRED_DIAGNOSTIC_IMPLS:
        raise ResolvedScopeError("qualification acceptance_run names a barred diagnostic-only run/impl")

    # ---- exact identities (Rust, Cargo, RTK) ----
    ident = rec.get("identities") or {}
    if ident.get("cargo_sha256") != PROVEN_BINARY_IDENTITY["cargo"]["sha256"]:
        raise ResolvedScopeError("qualification cargo identity != proven")
    if ident.get("rustc_sha256") != PROVEN_BINARY_IDENTITY["rust"]["sha256"]:
        raise ResolvedScopeError("qualification rustc identity != proven")
    if ident.get("rtk_sha256") != DIALECT_RTK_SHA or ident.get("rtk_bytes") != DIALECT_RTK_BYTES:
        raise ResolvedScopeError("qualification RTK identity != proven (41f316.../9200104)")

    # ---- captured-bytes layer: re-hash the committed frozen canonical streams ----
    dig = rec.get("captured_stream_digests") or {}
    if not dig:
        raise ResolvedScopeError("qualification has no captured_stream_digests (metadata-only)")
    for role in ("raw", "rtk"):
        p = Path(evidence_dir) / f"{role}.canonical.bin"
        if not p.is_file():
            raise ResolvedScopeError(f"qualification frozen canonical stream missing: {role}")
        raw = p.read_bytes()
        meta = dig.get(f"{role}.canonical") or {}
        if c.sha256_bytes(raw) != meta.get("sha256") or len(raw) != meta.get("bytes"):
            raise ResolvedScopeError(f"qualification frozen {role}.canonical sha256/bytes != recorded")

    # ---- INDEPENDENT verdict recomputation from the frozen streams ----
    rp = rcd.parse_raw((Path(evidence_dir) / "raw.canonical.bin").read_bytes())
    kp = rcd.parse_rtk((Path(evidence_dir) / "rtk.canonical.bin").read_bytes())
    eq = rcd.equivalence(rp, kp)
    recomputed = (rp["outcome"] == "success" and eq["equivalent"]
                  and (rp["passed"], rp["filtered_out"], rp["suites"]) == (
                      QUAL_EXPECTED["passed"], QUAL_EXPECTED["filtered_out"], QUAL_EXPECTED["suites"])
                  and (kp["passed"], kp["filtered_out"], kp["suites"]) == (
                      QUAL_EXPECTED["passed"], QUAL_EXPECTED["filtered_out"], QUAL_EXPECTED["suites"])
                  and not rp["failing_ids"] and not kp["failing_ids"]
                  and rp["terminal_summary_present"] and kp["terminal_summary_present"])
    # the record's re-derived projection must agree with the loader's independent parse
    sp = rec.get("re_derived_semantic_projection") or {}
    if sp.get("raw_projection") != rp or sp.get("rtk_projection") != kp:
        raise ResolvedScopeError("qualification recorded projection != loader re-derivation from frozen streams")
    # the record's claimed verdict MUST equal the loader recomputation
    claimed = rec.get("coreutils_qualification_pass")
    if claimed is not True:
        raise ResolvedScopeError("qualification record does not claim PASS")
    if claimed != recomputed:
        raise ResolvedScopeError(f"qualification verdict {claimed} != loader recomputation {recomputed}")
    if not recomputed:
        raise ResolvedScopeError("qualification loader recomputation is FAIL")
    return True


def validate_resolved_closure() -> dict:
    """Validate the whole resolved closure fail-closed; return the effective-record hash
    map + parsed overlays. Raises ResolvedScopeError on any violation."""
    rm = _load_ok(RESOLVED_MEMBERSHIP)
    rm_sha = c.sha256_json_file(RESOLVED_MEMBERSHIP)
    base_id_sets = {
        "registry": {r["case_id"] for r in _load_ok(REGISTRY)["recipes"]},
        "scenarios": {s["case_id"] for s in _load_ok(SCEN)["scenarios"]},
        "contracts": {x["case_id"] for x in _load_ok(CONTRACT)["contracts"]},
    }
    base_ids: set = set()
    for s in base_id_sets.values():
        base_ids |= s

    overlays, hashes = {}, {}
    for key, (path, base_key, base_path) in _OVERLAYS.items():
        rec = _load_ok(path)                                # self-hash valid
        # the execution-contract overlay pins the BASE CONTRACT it was resolved from: a case-local
        # base-contract advance (Lucene v2) is accepted only through a valid gen2->gen3 bridge that
        # attests coreutils' entry is unchanged. Every other overlay pins its own (unchanged) base.
        base_ok = (_base_contract_sha_ok(rec[base_key]) if base_path == CONTRACT
                   else rec[base_key] == c.sha256_json_file(base_path))
        if not base_ok:
            raise ResolvedScopeError(f"{path.name}: {base_key} != current {base_path.name}")
        if rec["resolved_membership_sha256"] != rm_sha:     # same resolved-membership sha
            raise ResolvedScopeError(f"{path.name}: resolved_membership_sha256 mismatch")
        if rec["resolved_case_id"] != REPLACEMENT_CASE_ID:
            raise ResolvedScopeError(f"{path.name}: resolved_case_id != {REPLACEMENT_CASE_ID}")
        overlays[key] = rec
        hashes[f"overlay_{key}_sha256"] = c.sha256_json_file(path)

    # coreutils exactly once in every required overlay; shadows no base case id
    def _overlay_ids(rec, list_key, item_key="case_id"):
        return [x[item_key] for x in rec[list_key]]
    checks = {
        "publisher_env": _overlay_ids(overlays["publisher_env"], "overlay_recipes"),
        "command_scenario": _overlay_ids(overlays["command_scenario"], "overlay_scenarios"),
        "execution_contract": _overlay_ids(overlays["execution_contract"], "overlay_contracts"),
    }
    for key, ids in checks.items():
        if ids != [REPLACEMENT_CASE_ID]:
            raise ResolvedScopeError(f"overlay {key} must contain exactly [{REPLACEMENT_CASE_ID}], got {ids}")
        if REPLACEMENT_CASE_ID in base_ids:
            raise ResolvedScopeError(f"overlay {key} shadows a base case id")

    # effective membership: tokio absent, coreutils present exactly once
    eff_ids = [m["case_id"] for m in rm["resolved_membership"]]
    if REPLACED_CASE_ID in eff_ids:
        raise ResolvedScopeError("tokio present in effective (resolved) membership")
    if eff_ids.count(REPLACEMENT_CASE_ID) != 1:
        raise ResolvedScopeError("coreutils not present exactly once in effective membership")
    if not rm["constraints_ok"] or rm["corpus_feasibility_blocker"]:
        raise ResolvedScopeError("resolved membership constraints not ok / feasibility blocker")

    # ---- additive resolved-ENVIRONMENT overlay: Model B frozen dependency snapshot ----
    # REQUIRED (exactly one) whenever the resolved execution contract carries a
    # dependency_environment_identity_ref -- so the contract can never be validated while the
    # resolved snapshot is omitted, mismatched, or substituted.
    contract = overlays["execution_contract"]["overlay_contracts"][0]
    dep_ref = contract.get("dependency_environment_identity_ref")
    if dep_ref is not None:
        ds = _load_snapshot_overlay(OV_DEPSNAP)
        snap = validate_dependency_snapshot_overlay(
            ds, dep_ref, rm_sha, c.sha256_json_file(CONTRACT), DEPSNAP_DIR)
        overlays["dependency_snapshot"] = ds
        hashes["overlay_dependency_snapshot_sha256"] = c.sha256_json_file(OV_DEPSNAP)
        hashes["frozen_dependency_snapshot"] = {
            "cargo_lock_sha256": snap["cargo_lock_sha256"],
            "host_resolve_graph_sha256": snap["host_resolve_graph_sha256"],
            "full_packages_metadata_sha256": snap["full_packages_metadata_sha256"],
            "host_resolved_package_count": snap["host_resolved_package_count"],
        }

    # ---- P2: executed-binary identity ----
    # REQUIRED whenever the frozen toolchain overlay carries an exact_binary_identity_ref, so the
    # toolchain can never be validated while the identity of the binaries that actually executed is
    # omitted, mismatched, or substituted.
    tc = overlays["toolchain"]["resolved_rust_toolchain"]
    binid_ref = tc.get("exact_binary_identity_ref")
    if binid_ref is not None:
        rec = _load_binid(BINID)
        validate_toolchain_binary_identity(
            rec, binid_ref, rm_sha, c.sha256_json_file(LOCK),
            c.sha256_json_file(OV_TOOLCHAIN), BINID_DIR)
        overlays["toolchain_binary_identity"] = rec
        hashes["toolchain_binary_identity_sha256"] = c.sha256_json_file(BINID)

    # ---- P3: case-scoped Rust cargo-test RTK dialect ----
    # REQUIRED whenever the resolved execution contract BINDS a test dialect, so the contract can
    # never reference a dialect whose identity/streams/equivalence are unmaterialized.
    bound_dialect = contract.get("rtk_test_dialect_policy_id")
    if bound_dialect is not None:
        drec = _load_dialect(DIALECT)
        validate_rtk_rust_cargo_dialect(
            drec, bound_dialect, rm_sha, c.sha256_json_file(CONTRACT),
            c.sha256_json_file(OV_CONTRACT), c.sha256_json_file(BINID), DIALECT_DIR)
        overlays["rtk_rust_cargo_dialect"] = drec
        hashes["rtk_rust_cargo_dialect_sha256"] = c.sha256_json_file(DIALECT)

    # ---- P4: Coreutils qualification predicate (standalone record; OPTIONAL until produced) ----
    # This predicate lives ONLY in the standalone qualification record -- never in resolved
    # membership. Until the acceptance run + independent verifier produce the frozen record, the
    # predicate is HELD (coreutils_qualification_pass=False) and the closure stays green. Once the
    # record is present it is validated fail-closed and its verdict is INDEPENDENTLY recomputed
    # from the frozen canonical streams; a passing record flips the predicate to True. This flag is
    # NOT resolved_canary_pass -- promotion stays held until the resolved-twelve reach 12/12.
    coreutils_qualification_pass = False
    if QUALIFICATION.is_file():
        qrec = _load_qualification(QUALIFICATION)
        coreutils_qualification_pass = validate_coreutils_qualification(
            qrec, rm_sha, c.sha256_json_file(OV_CONTRACT), c.sha256_json_file(BINID),
            c.sha256_json_file(DIALECT), QUALIFICATION_DIR)
        overlays["coreutils_qualification"] = qrec
        hashes["coreutils_qualification_sha256"] = c.sha256_json_file(QUALIFICATION)
    hashes["coreutils_qualification_pass"] = coreutils_qualification_pass

    hashes.update({
        "resolved_membership_sha256": rm_sha,
        "base_publisher_registry_sha256": c.sha256_json_file(REGISTRY),
        "base_command_scenarios_sha256": c.sha256_json_file(SCEN),
        "base_execution_contract_sha256": c.sha256_json_file(CONTRACT),
        "base_toolchain_lock_sha256": c.sha256_json_file(LOCK),
        "base_membership_sha256": c.sha256_json_file(MEMBERSHIP),
    })
    return {"resolved_membership": rm, "overlays": overlays,
            "effective_ids": eff_ids, "effective_record_hash_map": hashes,
            "coreutils_qualification_pass": coreutils_qualification_pass}


def load_case_bundle(case_id: str, scope: str = "base") -> dict:
    """Effective case bundle: membership entry, scenario, publisher recipe, toolchain
    contract, execution contract, plus the effective-record hash map. Fail-closed."""
    if scope not in ("base", "resolved"):
        raise ResolvedScopeError(f"unknown scope {scope!r}")

    if scope == "base":
        membership = _load_ok(MEMBERSHIP)["membership"]
        if case_id not in {m["case_id"] for m in membership}:
            raise ResolvedScopeError(f"{case_id} not in frozen base membership")
        scen = next(s for s in _load_ok(SCEN)["scenarios"] if s["case_id"] == case_id)
        contract = next((x for x in _load_ok(CONTRACT)["contracts"] if x["case_id"] == case_id), None)
        return {"scope": "base", "case_id": case_id, "source": "frozen_base",
                "membership_entry": next(m for m in membership if m["case_id"] == case_id),
                "scenario": scen, "publisher_recipe": None, "toolchain_contract": None,
                "execution_contract": contract,
                "effective_record_hash_map": {
                    "base_command_scenarios_sha256": c.sha256_json_file(SCEN),
                    "base_execution_contract_sha256": c.sha256_json_file(CONTRACT),
                    "base_membership_sha256": c.sha256_json_file(MEMBERSHIP)}}

    # scope == "resolved": validate the whole closure, then route this case to exactly one source
    closure = validate_resolved_closure()
    rm = closure["resolved_membership"]
    entry = next((m for m in rm["resolved_membership"] if m["case_id"] == case_id), None)
    if entry is None:
        raise ResolvedScopeError(f"{case_id} not in effective (resolved) membership")

    if case_id == REPLACEMENT_CASE_ID:
        ov = closure["overlays"]
        bundle = {
            "scope": "resolved", "case_id": case_id, "source": "replacement_overlay",
            "membership_entry": entry,
            "scenario": ov["command_scenario"]["overlay_scenarios"][0],
            "publisher_recipe": ov["publisher_env"]["overlay_recipes"][0],
            "toolchain_contract": ov["toolchain"]["resolved_rust_toolchain"],
            "execution_contract": ov["execution_contract"]["overlay_contracts"][0],
            # additive resolved environment: the frozen Model B dependency snapshot (validated
            # fail-closed by validate_resolved_closure above)
            "resolved_dependency_snapshot": (
                ov["dependency_snapshot"]["overlay_dependency_snapshots"][0]
                if "dependency_snapshot" in ov else None),
        }
    else:
        # every non-replacement case resolves EXCLUSIVELY from the frozen base
        scen = next(s for s in _load_ok(SCEN)["scenarios"] if s["case_id"] == case_id)
        contract = next((x for x in _load_ok(CONTRACT)["contracts"] if x["case_id"] == case_id), None)
        bundle = {
            "scope": "resolved", "case_id": case_id, "source": "frozen_base",
            "membership_entry": entry, "scenario": scen, "publisher_recipe": None,
            "toolchain_contract": None, "execution_contract": contract,
        }
    bundle["effective_record_hash_map"] = closure["effective_record_hash_map"]
    return bundle


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("case_id")
    ap.add_argument("--scope", choices=["base", "resolved"], default="base")
    args = ap.parse_args()
    try:
        b = load_case_bundle(args.case_id, args.scope)
    except ResolvedScopeError as e:
        print(f"resolved-loader: FAIL {e}")
        return 1
    print(f"resolved-loader: OK scope={b['scope']} case={b['case_id']} source={b['source']} "
          f"recipe={'yes' if b['publisher_recipe'] else 'no'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
