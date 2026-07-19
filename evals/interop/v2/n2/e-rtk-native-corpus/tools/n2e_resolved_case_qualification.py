#!/usr/bin/env python3
"""Generic per-case qualification recompute for the resolved-twelve (the eleven non-coreutils cases).

The qualification CRITERION is RAW<->RTK semantic EQUIVALENCE through the case's frozen dialect (RTK
faithfully projects the raw result -- pass OR fail), plus RAW determinism -- NOT "the tests pass".
Most resolved cases are `::buggy` (the test is expected to fail); a `::buggy` case qualifies when RTK
correctly reflects that failure, matching RAW. This is the same invariant coreutils satisfied (its
specific counts were just the concrete evidence).

This module is the SINGLE recompute authority shared by the independent verifier and the aggregator,
dispatched by qualification_kind + the frozen dialect/oracle policy id. It re-parses the committed
frozen canonical streams through the proven dialect and INDEPENDENTLY derives the verdict; it never
trusts a producer-declared PASS. Command-oracle recompute (rtk_command_oracle) lands with P5.2B.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_rtk_rust_cargo_dialect as rust  # noqa: E402
import n2e_rtk_jvm_test_dialect as jvm  # noqa: E402
import n2e_rtk_js_vitest_dialect as js  # noqa: E402
import n2e_rtk_python_pytest_dialect as py  # noqa: E402
import n2e_rtk_go_test_dialect as go  # noqa: E402
import n2e_rtk_go_vet_oracle as go_vet  # noqa: E402


class CaseQualificationError(Exception):
    pass


# frozen test-dialect modules, keyed by the proven dialect policy id
TEST_DIALECTS = {
    "rtk-rust-cargo-test-summary-v1": rust,
    "rtk-jvm-test-summary-v1": jvm,
    "rtk-js-vitest-summary-v1": js,
    "rtk-python-pytest-summary-v1": py,
    "rtk-go-test-summary-v1": go,
}

# frozen command-oracle modules, keyed by the proven oracle policy id
COMMAND_ORACLES = {
    "rtk-go-vet-oracle-v1": go_vet,
}


def _dialect_for(entry: dict):
    pid = entry.get("rtk_test_dialect_policy_id")
    mod = TEST_DIALECTS.get(pid)
    if mod is None:
        raise CaseQualificationError(f"no proven test dialect module for {pid!r}")
    return mod


def _oracle_for(entry: dict):
    pid = entry.get("command_semantic_oracle_policy_id")
    mod = COMMAND_ORACLES.get(pid)
    if mod is None:
        raise CaseQualificationError(f"no proven command oracle module for {pid!r}")
    return mod


def recompute_test_dialect_verdict(rec: dict, entry: dict, evidence_dir: Path) -> bool:
    """Re-derive an rtk_test_dialect case's verdict from its committed frozen canonical streams.

    Requires: the frozen raw/rtk streams re-hash to the recorded digests; RAW parses deterministically
    (the record must attest RAW determinism across reps); RAW<->RTK equivalence holds through the
    proven dialect; and the record's re_derived_semantic_projection equals the loader's independent
    parse. Returns the INDEPENDENTLY derived verdict (True/False), never the producer's claim."""
    if entry.get("qualification_kind") != "rtk_test_dialect":
        raise CaseQualificationError("recompute_test_dialect_verdict on a non-test-dialect case")
    mod = _dialect_for(entry)

    # captured-bytes layer: re-hash the frozen streams
    dig = rec.get("captured_stream_digests") or {}
    streams = {}
    for role in ("raw", "rtk"):
        p = Path(evidence_dir) / f"{role}.canonical.bin"
        if not p.is_file():
            raise CaseQualificationError(f"missing frozen stream: {role}.canonical.bin")
        b = p.read_bytes()
        meta = dig.get(f"{role}.canonical") or {}
        if c.sha256_bytes(b) != meta.get("sha256") or len(b) != meta.get("bytes"):
            raise CaseQualificationError(f"{role}.canonical sha256/bytes != recorded")
        streams[role] = b

    # RAW determinism must be attested by the producer (checked against reps in the verifier)
    if (rec.get("raw_arm") or {}).get("deterministic") is not True:
        raise CaseQualificationError("record does not attest RAW determinism")

    # semantic-projection layer: independent re-derivation through the proven dialect
    rp = mod.parse_raw(streams["raw"])
    kp = mod.parse_rtk(streams["rtk"])
    eq = mod.equivalence(rp, kp)

    sp = rec.get("re_derived_semantic_projection") or {}
    if sp.get("raw_projection") != rp or sp.get("rtk_projection") != kp:
        raise CaseQualificationError("recorded projection != loader re-derivation from frozen streams")

    # QUALIFICATION = faithful RAW<->RTK equivalence (pass OR fail); a non-indeterminate RAW outcome
    # with a terminal summary present on both sides. The test PASSING is not required (::buggy cases).
    verdict = (eq["equivalent"]
               and rp.get("outcome") not in (None, "indeterminate", "passthrough")
               and rp.get("terminal_summary_present") is True
               and kp.get("terminal_summary_present") is True)
    return bool(verdict)


def _load_frozen_streams(rec: dict, evidence_dir: Path) -> dict:
    dig = rec.get("captured_stream_digests") or {}
    streams = {}
    for role in ("raw", "rtk"):
        p = Path(evidence_dir) / f"{role}.canonical.bin"
        if not p.is_file():
            raise CaseQualificationError(f"missing frozen stream: {role}.canonical.bin")
        b = p.read_bytes()
        meta = dig.get(f"{role}.canonical") or {}
        if c.sha256_bytes(b) != meta.get("sha256") or len(b) != meta.get("bytes"):
            raise CaseQualificationError(f"{role}.canonical sha256/bytes != recorded")
        streams[role] = b
    return streams


def recompute_command_oracle_verdict(rec: dict, entry: dict, evidence_dir: Path) -> bool:
    """Re-derive a rtk_command_oracle case's verdict from its committed frozen streams through the
    proven command oracle. QUALIFICATION = faithful RAW<->RTK equivalence + a non-indeterminate RAW
    outcome (clean OR issues); the command SUCCEEDING is not required. Never trusts a producer PASS."""
    if entry.get("qualification_kind") != "rtk_command_oracle":
        raise CaseQualificationError("recompute_command_oracle_verdict on a non-command-oracle case")
    mod = _oracle_for(entry)
    streams = _load_frozen_streams(rec, evidence_dir)
    if (rec.get("raw_arm") or {}).get("deterministic") is not True:
        raise CaseQualificationError("record does not attest RAW determinism")
    rp = mod.parse_raw(streams["raw"])
    kp = mod.parse_rtk(streams["rtk"])
    eq = mod.equivalence(rp, kp)
    sp = rec.get("re_derived_semantic_projection") or {}
    if sp.get("raw_projection") != rp or sp.get("rtk_projection") != kp:
        raise CaseQualificationError("recorded projection != loader re-derivation from frozen streams")
    verdict = (eq["equivalent"]
               and rp.get("outcome") not in (None, "indeterminate")
               and kp.get("outcome") not in (None, "indeterminate"))
    return bool(verdict)


def recompute_case_verdict(rec: dict, entry: dict, evidence_dir: Path) -> bool:
    """Dispatch to the right recompute path by the manifest qualification_kind."""
    kind = entry.get("qualification_kind")
    if kind == "rtk_test_dialect":
        return recompute_test_dialect_verdict(rec, entry, evidence_dir)
    if kind == "rtk_command_oracle":
        return recompute_command_oracle_verdict(rec, entry, evidence_dir)
    raise CaseQualificationError(f"unknown qualification_kind {kind!r}")
