#!/usr/bin/env python3
"""Promotion P4: build the Coreutils qualification record from a REAL acceptance artifact.

Consumes the acceptance run's observation record + downloaded evidence streams, RE-RUNS the
independent qualification verifier (verify_coreutils_qualification) as a hard gate, FREEZES the
rep0 cargo-test-v3 canonical RAW/RTK streams as committed immutable evidence, and emits the
standalone predicate-carrier record n2e-coreutils-qualification-v1.json. The verdict is not
trusted from the producer: the record embeds the loader-reproducible re-derived projection and
coreutils_qualification_pass=True ONLY when the independent verifier passes AND the freshly built
record closes through validate_coreutils_qualification. Sets no resolved_canary_pass; promotion
stays held. The acceptance-run identity (run_id/attempt/impl/artifact digest) is supplied from CI
metadata so a diagnostic run can never be substituted.
"""
from __future__ import annotations

import argparse
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402
import n2e_rtk_rust_cargo_dialect as rcd  # noqa: E402
import verify_coreutils_qualification as vq  # noqa: E402

OV_CONTRACT = L.OV_CONTRACT
RESOLVED_MEMBERSHIP = L.RESOLVED_MEMBERSHIP
BINID = L.BINID
DIALECT = L.DIALECT
OUT = N2E_DIR / "n2e-coreutils-qualification-v1.json"
QUAL_DIR = L.QUALIFICATION_DIR


def _dz(p: Path) -> bytes:
    return zlib.decompress(p.read_bytes())


def build(observation: Path, evidence: Path, run: dict) -> dict:
    obs = c.load_record(observation)

    # HARD GATE 1: the independent verifier must PASS on the downloaded artifact before we freeze
    ok, fail, facts = vq.verify(observation, evidence)
    if not ok:
        raise SystemExit("REFUSING to build: independent qualification verifier FAILED:\n  - "
                         + "\n  - ".join(fail))

    # freeze the rep0 cargo-test-v3 canonical RAW/RTK streams as committed immutable evidence
    QUAL_DIR.mkdir(parents=True, exist_ok=True)
    raw_can = _dz(evidence / "raw.rep0.zst")
    rtk_can = _dz(evidence / "rtk.rep0.zst")
    (QUAL_DIR / "raw.canonical.bin").write_bytes(raw_can)
    (QUAL_DIR / "rtk.canonical.bin").write_bytes(rtk_can)

    # the loader re-parses the FROZEN files; embed exactly what it will re-derive
    rp = rcd.parse_raw(raw_can)
    kp = rcd.parse_rtk(rtk_can)

    ii = (obs.get("toolchain_enforcement") or {}).get("installed_identity") or {}
    body = c.envelope(
        record_type="n2e-coreutils-qualification",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_coreutils_qualification.py",
        record_version="v1",
        purpose="Standalone Coreutils-6731 qualification predicate carrier. Built from a real "
                "acceptance run, gated by the independent verifier, verdict INDEPENDENTLY "
                "recomputed by the loader from the frozen canonical streams. Sets no "
                "resolved_canary_pass -- promotion stays held until the resolved-twelve reach 12/12.",
        # ---- exactly one qualification, for the replacement case ----
        qualifications=[{
            "case_id": L.REPLACEMENT_CASE_ID,
            "passed": L.QUAL_EXPECTED["passed"], "filtered_out": L.QUAL_EXPECTED["filtered_out"],
            "suites": L.QUAL_EXPECTED["suites"]}],
        # ---- bindings: gen-3 contract + membership + P2/P3 identity records ----
        resolved_membership_sha256=c.sha256_json_file(RESOLVED_MEMBERSHIP),
        contract_generation3_sha256=c.sha256_json_file(OV_CONTRACT),
        p2_binary_identity_ref={"record": "n2e-resolved-toolchain-binary-identity-v1.json",
                                "sha256": c.sha256_json_file(BINID)},
        p3_dialect_ref={"record": "n2e-resolved-rtk-rust-cargo-dialect-v1.json",
                        "sha256": c.sha256_json_file(DIALECT)},
        bound_dialect_policy_id=L.DIALECT_ID,
        canonicalization_policy_id="cargo-test-v3",
        # ---- acceptance-run identity (from CI metadata; diagnostic runs barred by the loader) ----
        acceptance_run={"workflow": L.QUAL_WORKFLOW, **run},
        # ---- exact identities re-affirmed by the record ----
        identities={
            "cargo_sha256": ii.get("cargo_binary_sha256"),
            "rustc_sha256": ii.get("rustc_binary_sha256"),
            "rtk_sha256": obs.get("rtk_binary_sha256"), "rtk_bytes": obs.get("rtk_binary_bytes")},
        # ---- captured-bytes layer: digests of the committed frozen canonical streams ----
        captured_stream_digests={
            "raw.canonical": {"sha256": c.sha256_bytes(raw_can), "bytes": len(raw_can),
                              "path": "evidence/coreutils-6731/qualification/raw.canonical.bin"},
            "rtk.canonical": {"sha256": c.sha256_bytes(rtk_can), "bytes": len(rtk_can),
                              "path": "evidence/coreutils-6731/qualification/rtk.canonical.bin"}},
        # ---- semantic-projection layer (loader RE-derives this from the frozen files) ----
        re_derived_semantic_projection={
            "raw_projection": rp, "rtk_projection": kp,
            "equivalence": rcd.equivalence(rp, kp)},
        verdict_authority="independent qualification verifier + loader recomputation "
                          "(producer records observations only)",
        # ---- the verdict, INDEPENDENTLY recomputed by the loader; a lie here fails closed ----
        coreutils_qualification_pass=True,
        # explicit reminder that this predicate is NOT resolved_canary_pass
        resolved_canary_pass=False,
        promotion_state="held (resolved-twelve not yet 12/12)",
    )
    return body


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--observation", required=True)
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--run-attempt", required=True)
    ap.add_argument("--impl-commit", required=True)
    ap.add_argument("--artifact-sha256", required=True)
    ap.add_argument("--artifact-bytes", required=True, type=int)
    args = ap.parse_args()
    run = {"run_id": args.run_id, "run_attempt": args.run_attempt, "impl_commit": args.impl_commit,
           "artifact_sha256": args.artifact_sha256, "artifact_bytes": args.artifact_bytes}
    body = build(Path(args.observation).resolve(), Path(args.evidence).resolve(), run)
    c.write_record(OUT, body)

    # HARD GATE 2: the freshly built record + frozen evidence must close through the loader
    rec = c.load_record(OUT)
    verdict = L.validate_coreutils_qualification(
        rec, c.sha256_json_file(RESOLVED_MEMBERSHIP), c.sha256_json_file(OV_CONTRACT),
        c.sha256_json_file(BINID), c.sha256_json_file(DIALECT), QUAL_DIR)
    if verdict is not True:
        raise SystemExit("REFUSING: freshly built record does not close through the loader")
    print(f"wrote {OUT.name}; loader recomputed coreutils_qualification_pass=True")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
