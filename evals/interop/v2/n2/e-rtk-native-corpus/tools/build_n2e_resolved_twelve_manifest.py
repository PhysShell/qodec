#!/usr/bin/env python3
"""Promotion P5.1: freeze the resolved-twelve manifest.

ONE immutable manifest naming EXACTLY the twelve cases that constitute the resolved_canary_pass
claim, in the frozen resolved-membership order. Every per-case policy field is DERIVED from the
frozen base/overlay execution contract (never hand-copied), so a drift in any policy id is caught
by the manifest verifier. No dynamic discovery, no "all records in this directory": the aggregator
(P5.4) will require exactly one qualification record for each of these twelve, of the declared type,
binding the declared contract generation. Sets no promotion flag.

Field provenance (all read live from the frozen contract):
  canonicalization_policy_id / _generation, rtk_test_dialect_policy_id, semantic_oracle_policy_id,
  command_family / _subfamily, toolchain_identity_ref  -> per-case execution contract entry.
  contract_generation                                  -> 3 for the coreutils overlay (its
                                                          rtk_dialect_binding_generation.generation),
                                                          1 (implicit original) for every base case.
  required_rtk_binary_identity_ref                     -> the single pinned corpus RTK binary.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402
import n2e_manifest_binding as mb  # noqa: E402

OUT = N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"
MANIFEST_GENERATION = 3  # gen 3: per-case binding (case_entry_sha256) + Lucene execution policy v2;
#                          gen 2 added the explicit two-mode qualification_kind discriminator

# the one case that is already frozen-qualified (P4) carries its concrete record type; every other
# case declares the uniform per-case qualification type its P5.3 acceptance run must emit.
COREUTILS_QUAL_TYPE = "n2e-coreutils-qualification"
PENDING_QUAL_TYPE = "n2e-resolved-case-qualification"

# The two proof modes are an EXPLICIT classification, not inferred from rtk_test_dialect_policy_id
# being null (lucene/vue/scrapy currently bind no dialect in the frozen contract but WILL, once
# their P5.2A dialect is proven -- so the kind cannot be read off the current contract). Each entry:
#   case_id -> (qualification_kind, rtk_test_dialect_policy_id, command_semantic_oracle_policy_id)
# Invariant enforced by build + verifier: exactly one policy id set, matching the kind. The listed
# policy ids are the EXPECTED (forward) ids each P5.2 proof must materialize; coreutils' rust dialect
# and caddy's go dialect already exist and must be PROVEN (source identity + scope), not re-authored.
# Command shapes that are identical share one oracle id (preact & lombok are both files_search::read).
RTK_TEST_DIALECT = "rtk_test_dialect"
RTK_COMMAND_ORACLE = "rtk_command_oracle"

# case_id -> dispatch_policy_id: a case routed through a versioned registry-bound dispatch layer
# (instead of the frozen cq). Only cases whose oracle is grounded + registered belong here -- future
# Rubocop/Redis/PHP oracles are NOT pre-registered; they enter via a NEW dispatch generation once
# grounded. NOT part of the case_entry_sha256 projection (routing, bound by manifest root + registry).
_DISPATCH_POLICY = {
    "loghub::HDFS::log": "n2e-qualification-dispatch-v2",
    "rubocop__rubocop-13687::git::show": "n2e-qualification-dispatch-v3",
    "php-cs-fixer__php-cs-fixer-8075::git::commit": "n2e-qualification-dispatch-v4",
    "container::redis::docker::images": "n2e-qualification-dispatch-v5",
}
QUALIFICATION_MODEL = {
    "uutils__coreutils-6731::rust_cargo::test::fixed": (RTK_TEST_DIALECT, "rtk-rust-cargo-test-summary-v1", None),
    "apache__lucene-13704::jvm::test::buggy":           (RTK_TEST_DIALECT, "rtk-jvm-test-summary-v1", None),
    "vuejs__core-11589::js_ts::test::buggy":            (RTK_TEST_DIALECT, "rtk-js-vitest-summary-v1", None),
    "bugsinpy::scrapy-9::python::pytest::fixed":        (RTK_TEST_DIALECT, "rtk-python-pytest-summary-v1", None),
    "caddyserver__caddy-5870::go::test::buggy":         (RTK_TEST_DIALECT, "rtk-go-test-summary-v1", None),
    "container::redis::docker::images":                 (RTK_COMMAND_ORACLE, None, "rtk-docker-images-oracle-v1"),
    "gin-gonic__gin-2755::go::vet":                     (RTK_COMMAND_ORACLE, None, "rtk-go-vet-oracle-v1"),
    "loghub::HDFS::log":                                (RTK_COMMAND_ORACLE, None, "rtk-log-hdfs-oracle-v1"),
    "php-cs-fixer__php-cs-fixer-8075::git::commit":     (RTK_COMMAND_ORACLE, None, "rtk-git-commit-oracle-v1"),
    "preactjs__preact-3345::files_search::read":        (RTK_COMMAND_ORACLE, None, "rtk-files-read-oracle-v1"),
    "projectlombok__lombok-3312::files_search::read":   (RTK_COMMAND_ORACLE, None, "rtk-files-read-oracle-v1"),
    "rubocop__rubocop-13687::git::show":                (RTK_COMMAND_ORACLE, None, "rtk-git-show-merge-first-parent-oracle-v1"),
}


def _qualification_mode(case_id: str) -> tuple:
    if case_id not in QUALIFICATION_MODEL:
        raise SystemExit(f"case {case_id} has no qualification-mode classification")
    kind, dialect, oracle = QUALIFICATION_MODEL[case_id]
    # exactly-one-of invariant, enforced at build time
    if kind == RTK_TEST_DIALECT and (dialect is None or oracle is not None):
        raise SystemExit(f"{case_id}: rtk_test_dialect requires dialect set + oracle null")
    if kind == RTK_COMMAND_ORACLE and (oracle is None or dialect is not None):
        raise SystemExit(f"{case_id}: rtk_command_oracle requires oracle set + dialect null")
    if kind not in (RTK_TEST_DIALECT, RTK_COMMAND_ORACLE):
        raise SystemExit(f"{case_id}: unknown qualification_kind {kind!r}")
    return kind, dialect, oracle


def _contract_generation(entry: dict) -> int:
    g = entry.get("rtk_dialect_binding_generation")
    if isinstance(g, dict) and isinstance(g.get("generation"), int):
        return g["generation"]
    return 1  # base cases: implicit original generation


def _canon_generation(entry: dict):
    g = entry.get("canonicalization_policy_generation")
    if isinstance(g, dict):
        return g.get("generation")
    return None


def build_manifest() -> dict:
    rm = c.load_record(L.RESOLVED_MEMBERSHIP)
    membership = rm["resolved_membership"]
    base = c.load_record(L.CONTRACT)
    by_base = {x["case_id"]: x for x in base["contracts"]}
    ov = c.load_record(L.OV_CONTRACT)["overlay_contracts"][0]

    if len(membership) != 12:
        raise SystemExit(f"resolved membership is not twelve ({len(membership)})")

    pinned_rtk = {"sha256": L.DIALECT_RTK_SHA, "bytes": L.DIALECT_RTK_BYTES,
                  "note": "single pinned corpus RTK binary (all twelve cases execute under it)"}

    cases = []
    for m in membership:  # frozen order preserved -> reordering is detectable
        cid = m["case_id"]
        is_coreutils = cid == L.REPLACEMENT_CASE_ID
        x = ov if is_coreutils else by_base.get(cid)
        if x is None:
            raise SystemExit(f"no execution contract for manifest case {cid}")
        kind, dialect, oracle = _qualification_mode(cid)
        entry = {
            "case_id": cid,
            "family": x.get("command_family"),
            "subfamily": x.get("command_subfamily"),
            "canary_slot": m.get("canary_slot"),
            # ---- byte-normalization axis (kept SEPARATE from the semantic proof) ----
            "canonicalization_policy_id": x.get("canonicalization_policy_id"),
            "canonicalization_policy_generation": _canon_generation(x),
            # ---- semantic-proof axis: the two-mode discriminator + exactly one active policy ----
            "qualification_kind": kind,
            "rtk_test_dialect_policy_id": dialect,             # set iff rtk_test_dialect
            "command_semantic_oracle_policy_id": oracle,       # set iff rtk_command_oracle
            "base_semantic_oracle_policy_id": x.get("semantic_oracle_policy_id"),  # descriptive
            "contract_generation": _contract_generation(x),
            "required_toolchain_identity_ref": x.get("toolchain_identity_ref"),
            "required_rtk_binary_identity_ref": pinned_rtk,
            "expected_qualification_record_type":
                COREUTILS_QUAL_TYPE if is_coreutils else PENDING_QUAL_TYPE,
            # ---- routing axis (NOT in case_entry_sha256; bound by the manifest root + the immutable
            # registry): a case with a dispatch_policy_id qualifies through that versioned dispatch
            # layer + its checksum-pinned oracle registry, NOT through the frozen cq. All others route
            # legacy (cq). Loghub is the first; future oracles enter via NEW dispatch generations. ----
            "dispatch_policy_id": _DISPATCH_POLICY.get(cid),
            # descriptive: which cases are already frozen-qualified vs pending an acceptance run.
            # NOT a promotion input -- the aggregator derives PASS/absence from the actual records.
            "qualification_status": "frozen" if is_coreutils else "pending",
        }
        # gen-3 CASE-LOCAL binding: the canonical digest of ONLY this case's determinants (pulls the
        # case's BASE contract entry + the overlay entry when resolved-overlaid). A qualification record
        # binds to case_id + case_entry_sha256, NOT the whole-manifest SHA, so a later case-local policy
        # change advances only its own entry. Computed from the determinant fields above (the projection
        # never reads case_entry_sha256 itself, so adding it here does not alter the digest).
        entry["case_entry_sha256"] = mb.case_entry_sha256(
            entry, by_base.get(cid), ov if is_coreutils else None)
        cases.append(entry)

    case_ids = [x["case_id"] for x in cases]
    if len(set(case_ids)) != 12:
        raise SystemExit("duplicate case ids in manifest")

    return c.envelope(
        record_type="n2e-resolved-twelve-manifest",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_resolved_twelve_manifest.py",
        record_version="v1",
        purpose="Immutable roster of the exact twelve cases constituting the resolved_canary_pass "
                "claim. Per-case policy derived from the frozen contract. Sets no promotion flag; "
                "resolved_canary_pass stays false until the P5.4 aggregator independently derives "
                "twelve PASSes.",
        manifest_generation=MANIFEST_GENERATION,
        # gen-3 binding model: qualification records bind by case_id + per-entry case_entry_sha256
        # (case-local), NOT the whole-manifest SHA. Membership + ordering still fixed by the root.
        case_entry_binding_model="per-case-v1",
        cardinality=12,
        resolved_membership_sha256=c.sha256_json_file(L.RESOLVED_MEMBERSHIP),
        base_execution_contract_sha256=c.sha256_json_file(L.CONTRACT),
        resolved_execution_contract_sha256=c.sha256_json_file(L.OV_CONTRACT),
        toolchain_lock_sha256=c.sha256_json_file(L.LOCK),
        pinned_rtk_binary_identity=pinned_rtk,
        case_ids=case_ids,
        cases=cases,
        # held-flag reminder carried in the record itself
        resolved_canary_pass=False,
        promotion_state="held (twelve-case aggregation not yet closed)",
    )


def main() -> int:
    c.write_record(OUT, build_manifest())
    print(f"wrote {OUT.name} (12 cases, generation {MANIFEST_GENERATION})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
