#!/usr/bin/env python3
"""Build the immutable redis::docker::images qualification record through the DISPATCH-V5 path (NOT cq).

Consumes the FRESH acceptance observation (probe_redis_docker_images --mode acceptance) + its evidence,
freezes the fresh RAW `--format` projection + RTK compact `docker images` output + BOTH isolated
daemons' `docker image inspect` as committed immutable evidence, and emits an
n2e-resolved-case-qualification record carrying a dispatch_code_identity (v5) and NO cq
frozen_code_identity.

Two authorities, both proven at build time and re-proven by the dispatch-v5 recompute:
  * the RTK PROJECTION (all the oracle claims): RTK compacts and its (repository:tag, size) multiset +
    count equal the RAW `--format` projection (never_worse passthrough rejected).
  * the image IDENTITY (an execution determinant, NOT an oracle claim): the config Id + RepoDigest +
    platform from inspect equal the pinned redis-docker-images-execution-v1 determinants, on two
    independent isolated daemons that agree.

Two hard gates before case_qualification_pass=True:
  * GATE 1 (producer-side, structural): the fresh observation is clean -- outcome OBSERVED + not
    barred, output_mode compact, equivalence closed, both daemons vfs + empty-start + net-denied +
    pinned image identity, DinD image digest == pinned, and the run is not a barred diagnostic run/impl.
  * GATE 2 (independent): the freshly built record + frozen evidence pass verify_dispatch_binding AND
    recompute_dispatch_v5.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_resolved_loader as L  # noqa: E402
import n2e_qualification_dispatch_v5 as d5  # noqa: E402

MANIFEST = N2E_DIR / "n2e-resolved-twelve-manifest-v1.json"
EXECUTION_POLICY = N2E_DIR / "n2e-redis-docker-images-execution-policy-v1.json"
CASE_ID = "container::redis::docker::images"
# acceptance-observation evidence file -> record docker_evidence key
_EVIDENCE = {
    "raw_format_rows": "raw.format_rows.bin", "rtk_stdout": "rtk.images.rep0.bin",
    "raw_inspect": "raw.inspect.json", "rtk_inspect": "rtk.inspect.json",
}


def _require(cond, msg):
    if not cond:
        raise SystemExit(f"REFUSING to build: {msg}")


def build(observation: Path, evidence: Path, name: str, run: dict, out_path: Path | None = None) -> Path:
    obs = c.load_record(observation)
    pol = c.load_record(EXECUTION_POLICY)
    pol_img = pol["image"]

    # ---- GATE 1: the fresh acceptance observation must be clean ----
    _require(obs.get("record_kind") == "redis_docker_images_acceptance_capture"
             and not obs.get("barred_from_qualification"),
             "observation is not a non-barred redis_docker_images_acceptance_capture")
    _require(obs.get("outcome") == "REDIS_DOCKER_IMAGES_OBSERVED", f"observation outcome={obs.get('outcome')!r}")
    _require(run["run_id"] not in L.BARRED_DIAGNOSTIC_RUNS and run["impl_commit"] not in L.BARRED_DIAGNOSTIC_IMPLS,
             "acceptance run names a barred diagnostic run/impl")
    oo = obs.get("oracle_observation") or {}
    _require(oo.get("output_mode") == "compact", "RTK did not compact (never_worse passthrough)")
    _require((oo.get("equivalence") or {}).get("equivalent") is True, "observed equivalence not closed")
    dind = (obs.get("dind_daemon_image") or {})
    _require(pol["daemon"]["image_digest"] in (dind.get("repo_digests") or []),
             "DinD daemon image digest != pinned execution policy")
    for role in ("raw", "rtk"):
        arm = (obs.get("arms") or {}).get(role) or {}
        dm = arm.get("daemon") or {}
        _require(dm.get("storage_driver") == pol["daemon"]["storage_driver"], f"{role} daemon storage driver != pinned")
        _require(dm.get("images_at_start") == pol["daemon"]["preloaded_images"], f"{role} daemon had preloaded images")
        insp = arm.get("inspect") or {}
        _require(insp.get("id") == pol_img["expected_config_id"], f"{role} image config Id != pinned")
        _require(pol_img["expected_repo_digest"] in (insp.get("repo_digests") or []), f"{role} RepoDigest != pinned index digest")
        _require(insp.get("architecture") == pol_img["expected_arch"] and insp.get("os") == pol_img["expected_os"],
                 f"{role} platform != pinned amd64/linux")
        _require((arm.get("network_denied") or {}).get("disconnect", {}).get("exit_code") == 0,
                 f"{role} measurement not network-denied")

    man = c.load_record(MANIFEST)
    entry = next(x for x in man["cases"] if x["case_id"] == CASE_ID)
    _require(entry.get("dispatch_policy_id") == d5.DISPATCH_POLICY_ID, "manifest not routed to dispatch-v5")

    # ---- freeze the fresh evidence as committed immutable evidence ----
    qdir = N2E_DIR / "evidence" / name / "qualification"
    qdir.mkdir(parents=True, exist_ok=True)
    docker_evidence = {}
    for key, fn in _EVIDENCE.items():
        src = evidence / fn
        _require(src.is_file(), f"missing fresh evidence {src}")
        b = src.read_bytes()
        # store under a stable committed name (rtk stdout normalized to rtk.stdout.bin)
        dest_name = "rtk.stdout.bin" if key == "rtk_stdout" else fn
        (qdir / dest_name).write_bytes(b)
        docker_evidence[key] = {"evidence_path": f"evidence/{name}/qualification/{dest_name}",
                                "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)}

    body = c.envelope(
        record_type="n2e-resolved-case-qualification",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_redis_docker_images_qualification.py",
        record_version="v1",
        purpose=f"Immutable per-case qualification for {CASE_ID} via the dispatch-v5 registry-bound "
                f"docker-images path (NOT cq). RTK claims ONLY outcome + (repository:tag, size) "
                f"multiset + count (compact); the image identity (config Id + RepoDigest == the pinned "
                f"index digest, platform amd64/linux) is proven as an execution determinant from "
                f"docker image inspect on two independent isolated pinned daemons. Built from a fresh "
                f"acceptance run; gated by the dispatch binding + recompute. Sets no promotion flag.",
        case_id=CASE_ID,
        record_kind="redis_docker_images_acceptance_qualification",   # NOT the barred diagnostic kind
        manifest_generation=man["manifest_generation"],
        manifest_sha256=c.sha256_json_file(MANIFEST),
        case_entry_sha256=entry.get("case_entry_sha256"),
        qualification_kind=entry["qualification_kind"],
        rtk_test_dialect_policy_id=entry["rtk_test_dialect_policy_id"],           # null
        command_semantic_oracle_policy_id=entry["command_semantic_oracle_policy_id"],
        canonicalization_policy_id=entry["canonicalization_policy_id"],
        contract_generation=entry["contract_generation"],
        dispatch_policy_id=d5.DISPATCH_POLICY_ID,
        dispatch_code_identity=d5.dispatch_code_identity(entry),
        execution_policy_id=pol["policy_id"],
        acceptance_run={"workflow": "qodec-n2e-redis-docker-images", **run},
        identities={"rtk_sha256": obs.get("rtk_binary_sha256"),
                    "dind_image_digest": pol["daemon"]["image_digest"],
                    "host_docker_client": obs.get("host_docker_client_identity")},
        image_identity={"config_id": pol_img["expected_config_id"],
                        "repo_digest": pol_img["expected_repo_digest"],
                        "index_digest": pol_img["index_digest"], "child_digest": pol_img["child_digest"],
                        "platform": pol_img["platform"]},
        docker_evidence=docker_evidence,
        re_derived={"equivalence": oo.get("equivalence"), "output_mode": oo.get("output_mode"),
                    "normative_axis": "RTK preserves outcome + (repository:tag, size) multiset + count "
                                      "(compact); image ID / digest / CREATED NOT emitted by RTK; "
                                      "identity proven from inspect as an execution determinant"},
        evidence={"dir": f"evidence/{name}/qualification"},
        verdict_authority="dispatch-v5 binding + recompute (producer records observations)",
        case_qualification_pass=True,
        resolved_canary_pass=False,
        promotion_state="held until top-level policy (resolved_canary_pass flips to true at 12/12; "
                        "original_canary_pass stays false; promotion is a separate step)",
    )
    out = out_path or (N2E_DIR / f"n2e-resolved-case-qualification-{name}-v1.json")
    c.write_record(out, body)

    # ---- GATE 2: the freshly built record must independently bind + recompute True via dispatch-v5 ----
    rec = c.load_record(out)
    d5.verify_dispatch_binding(rec, entry)
    _require(d5.recompute_dispatch_v5(rec, entry) is True,
             "freshly built record does not recompute True through dispatch-v5")
    print(f"wrote {out.name}; dispatch-v5 recomputed case_qualification_pass=True "
          f"(mode={oo.get('output_mode')}; config Id {pol_img['expected_config_id'][:19]}...; "
          f"RepoDigest == pinned index {pol_img['index_digest'][:19]}...)")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="redis")
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
    build(Path(a.observation).resolve(), Path(a.evidence).resolve(), a.name, run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
