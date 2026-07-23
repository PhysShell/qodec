#!/usr/bin/env python3
"""Build an immutable per-case qualification record (n2e-resolved-case-qualification) from a REAL
acceptance artifact. Generic across the rtk_test_dialect cases (Caddy first).

Consumes the acceptance observation + downloaded evidence, RE-RUNS the independent verifier
(verify_case_qualification) as a hard gate, FREEZES the rep0 canonical RAW/RTK streams as committed
immutable evidence under evidence/<name>/qualification/, re-derives the projections through the
proven dialect, and emits the record binding the manifest generation + case classification +
acceptance-run identity. Then the aggregator's own recompute (recompute_test_dialect_verdict) must
independently agree. case_qualification_pass=True only when BOTH gates pass. Sets no promotion flag.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402
import n2e_case_adapters as adapters  # noqa: E402
import n2e_resolved_case_qualification as cq  # noqa: E402
import verify_case_qualification as vq  # noqa: E402

MANIFEST = N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"


def build(case_id: str, observation: Path, evidence: Path, name: str, run: dict) -> Path:
    obs = c.load_record(observation)

    # HARD GATE 1: the independent verifier must PASS on the downloaded artifact before we freeze
    ok, fail, facts = vq.verify(observation, evidence)
    if not ok:
        raise SystemExit("REFUSING to build: independent case verifier FAILED:\n  - " + "\n  - ".join(fail))

    man = c.load_record(MANIFEST)
    entry = next(x for x in man["cases"] if x["case_id"] == case_id)
    # projection module dispatched by qualification_kind (test dialect OR command oracle)
    if entry["qualification_kind"] == "rtk_test_dialect":
        mod = cq.TEST_DIALECTS[entry["rtk_test_dialect_policy_id"]]
    elif entry["qualification_kind"] == "rtk_command_oracle":
        mod = cq.COMMAND_ORACLES[entry["command_semantic_oracle_policy_id"]]
    else:
        raise SystemExit(f"unknown qualification_kind {entry['qualification_kind']!r}")

    # freeze the accepted canonical RAW/RTK streams as committed immutable evidence
    qdir = N2E_DIR / "evidence" / name / "qualification"
    qdir.mkdir(parents=True, exist_ok=True)
    raw = (evidence / "raw.canonical.bin").read_bytes()
    rtk = (evidence / "rtk.canonical.bin").read_bytes()
    (qdir / "raw.canonical.bin").write_bytes(raw)
    (qdir / "rtk.canonical.bin").write_bytes(rtk)
    rp, kp = mod.parse_raw(raw), mod.parse_rtk(rtk)

    body = c.envelope(
        record_type="n2e-resolved-case-qualification",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_resolved_case_qualification.py",
        record_version="v1",
        purpose=f"Immutable per-case qualification for {case_id}. Built from a real acceptance run, "
                f"gated by the independent verifier + aggregator recomputation. Sets no promotion flag.",
        case_id=case_id,
        manifest_generation=man["manifest_generation"],
        manifest_sha256=c.sha256_json_file(MANIFEST),
        # gen-3 NATIVE per-case binding: the record binds to its case by the case-LOCAL
        # case_entry_sha256, not the whole-manifest sha. The aggregator INDEPENDENTLY re-derives the
        # gen-3 entry hash from the manifest's own inputs and rejects any disagreement, so copying the
        # manifest's stored value here is only a claim the aggregator re-proves.
        case_entry_sha256=entry.get("case_entry_sha256"),
        qualification_kind=entry["qualification_kind"],
        rtk_test_dialect_policy_id=entry["rtk_test_dialect_policy_id"],
        command_semantic_oracle_policy_id=entry["command_semantic_oracle_policy_id"],
        canonicalization_policy_id=entry["canonicalization_policy_id"],
        contract_generation=entry["contract_generation"],
        acceptance_run={"workflow": "qodec-n2e-case-qualification", **run},
        identities={"rtk_sha256": obs.get("rtk_binary_sha256"), "rtk_bytes": obs.get("rtk_binary_bytes")},
        raw_arm={"deterministic": (obs.get("raw_arm") or {}).get("deterministic")},
        rtk_arm={"deterministic": (obs.get("rtk_arm") or {}).get("deterministic")},
        captured_stream_digests={
            "raw.canonical": {"sha256": c.sha256_bytes(raw), "bytes": len(raw)},
            "rtk.canonical": {"sha256": c.sha256_bytes(rtk), "bytes": len(rtk)}},
        re_derived_semantic_projection={"raw_projection": rp, "rtk_projection": kp,
                                        "equivalence": mod.equivalence(rp, kp)},
        frozen_code_identity=cq.frozen_code_identity({**entry, "case_id": case_id}),
        evidence={"dir": f"evidence/{name}/qualification"},
        verdict_authority="independent case verifier + aggregator recomputation (producer records observations)",
        case_qualification_pass=True,
        resolved_canary_pass=False,
        promotion_state="held (resolved-twelve not yet 12/12)",
    )
    out = N2E_DIR / f"n2e-resolved-case-qualification-{name}-v1.json"
    c.write_record(out, body)

    # HARD GATE 2: the freshly built record + frozen evidence must recompute True in the aggregator
    rec = c.load_record(out)
    verdict = cq.recompute_case_verdict(rec, {**entry, "case_id": case_id}, qdir)
    if verdict is not True:
        raise SystemExit("REFUSING: freshly built record does not recompute True in the aggregator")
    print(f"wrote {out.name}; aggregator recomputed case_qualification_pass=True")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True)
    ap.add_argument("--name", required=True, help="short evidence dir name, e.g. caddy")
    ap.add_argument("--observation", required=True)
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--run-attempt", required=True)
    ap.add_argument("--impl-commit", required=True)
    ap.add_argument("--artifact-sha256", required=True)
    ap.add_argument("--artifact-bytes", required=True, type=int)
    a = ap.parse_args()
    run = {"run_id": a.run_id, "run_attempt": a.run_attempt, "impl_commit": a.impl_commit,
           "artifact_sha256": a.artifact_sha256, "artifact_bytes": a.artifact_bytes}
    build(a.case, Path(a.observation).resolve(), Path(a.evidence).resolve(), a.name, run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
