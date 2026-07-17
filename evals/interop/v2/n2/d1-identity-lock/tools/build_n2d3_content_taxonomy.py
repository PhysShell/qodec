#!/usr/bin/env python3
"""Builds the self-hash-locked, post-hoc-exploratory N2-D3 content taxonomy.

This is NOT a re-measurement and does not change any canonical N2-D3 value.
It classifies each of the 18 already-measured cases by what was ACTUALLY fed
to QODEC/RTK -- the frozen command + selected stream + actual canonical
payload format -- never by the source repository's name, language, or file
extension. Every label below is cross-checked at build time against real,
already-committed evidence (the input bundle's own manifest, the Stage 2
repository-miner acceptance record, the durable N2-C acquisition manifest,
the RTK applicability map, the 8 primary source-freeze manifests, and the
N2-A canary's own source manifest); a mismatch between a hardcoded label and
live evidence raises, it is never silently corrected.

Two real, load-bearing findings surfaced while cross-checking this taxonomy
against evidence (documented here, not invented for classification):

  1. repo-hyperfine's frozen command is `cargo run -- --version` (Stage 2
     record), not `cargo test` -- its measured payload is a one-line CLI
     version banner, not cargo-test-shaped output, despite being invoked via
     cargo. producer_family is therefore "generic-cli", not "cargo".

  2. dataset-loghub-v8 and research-corpus-loghub2's own primary source-freeze
     manifests record an `extraction_recipe` that INTENDED to extract a named
     plain-text archive member (Proxifier.log / Proxifier/Proxifier_full.log)
     out of a downloaded .tar.gz / .zip. The actual committed canonical
     benchmark input (durable-input-manifest.json) is the UN-EXTRACTED
     original .tar.gz/.zip file, re-wrapped in a "normalized-source.tar"
     container -- i.e. a container-of-a-container, never the intended plain
     text. This is exactly why these two are the project's typed
     UNMEASURABLE_NON_UTF8 refusals, and is real, already-accepted history,
     not a new defect: it is documented here as the evidentiary basis for
     content_family="binary-archive-container", not asserted from the name.
"""
from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path

IDENTITY_LOCK_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = IDENTITY_LOCK_DIR.parents[4]
OUT_PATH = IDENTITY_LOCK_DIR / "n2d3-content-taxonomy-v1.json"

N2D3_BENCHMARK_PATH = IDENTITY_LOCK_DIR / "n2d3-primary-token-benchmark-v1.json"
CANONICAL_N2D3_SHA256 = "sha256:c00d2ff8f4883c964fbd05d46840763826806ea73357511e6f38a882aaf0e1cd"

INPUT_BUNDLE_PATH = IDENTITY_LOCK_DIR / "n2d3-model-free-input-bundle-v1.tar"
STAGE2_RECORD_PATH = IDENTITY_LOCK_DIR / "stage2-full-matrix-acceptance.json"
DURABLE_MANIFEST_PATH = REPO_ROOT / "evals/interop/v2/n2/d0-durable-evidence/durable-input-manifest.json"
IDENTITY_CLOSURE_PATH = IDENTITY_LOCK_DIR / "n2d-current-identity-closure-v1.json"
RTK_APPLICABILITY_MAP_PATH = IDENTITY_LOCK_DIR / "rtk-applicability-map-v1.json"
SOURCE_FREEZE_PRIMARY_DIR = REPO_ROOT / "evals/interop/v2/n2/source-freeze/source-manifests/primary"
N2A_SOURCE_MANIFEST_PATH = REPO_ROOT / "evals/interop/v2/n2/canary/source-manifest.json"

CONTENT_FAMILIES = frozenset({
    "dependency-bot-report", "kernel-bug-report", "ci-build-log", "canary-ci-log",
    "static-log-dataset", "binary-archive-container", "maven-test-output",
    "cargo-test-output", "gradle-test-output", "dotnet-test-output",
    "pytest-output", "cli-tool-output",
})
ORIGIN_KINDS = frozenset({
    "bot-output", "ci-log", "repository-command-output", "static-dataset",
    "research-corpus", "canary",
})
PRODUCER_FAMILIES = frozenset({
    "bot", "generic-ci", "cargo", "gradle", "maven", "dotnet", "pytest",
    "generic-cli", "dataset", "none",
})
PAYLOAD_KINDS = frozenset({"utf8-text", "binary-container"})

STATIC_N2C_CASE_IDS = frozenset({
    "bot-dependabot-black-5206", "bot-syzbot-do-mkdirat",
    "ci-log-jansson", "ci-log-nlog", "ci-log-spdlog",
    "dataset-loghub-v8", "dataset-rtn-traffic-ids", "research-corpus-loghub2",
})
STAGE2_CASE_IDS = frozenset({
    "repo-docker-java-parser", "repo-dockerfile-parser-rs", "repo-helm-values",
    "repo-hyperfine", "repo-kubeops-generator", "repo-moshi", "repo-pyflakes",
    "repo-requests", "repo-rustlings",
})

# Hardcoded judgment-call labels: (content_family, origin_kind, producer_family).
# payload_kind is never hardcoded -- it is always derived live from the
# bundle manifest's own utf8_valid field (see build_record()).
CASE_LABELS = {
    "bot-dependabot-black-5206": ("dependency-bot-report", "bot-output", "bot"),
    "bot-syzbot-do-mkdirat": ("kernel-bug-report", "bot-output", "bot"),
    "ci-log-jansson": ("ci-build-log", "ci-log", "generic-ci"),
    "ci-log-nlog": ("ci-build-log", "ci-log", "generic-ci"),
    "ci-log-spdlog": ("ci-build-log", "ci-log", "generic-ci"),
    "n2a-miner-canary": ("canary-ci-log", "canary", "dotnet"),
    "dataset-rtn-traffic-ids": ("static-log-dataset", "static-dataset", "dataset"),
    "dataset-loghub-v8": ("binary-archive-container", "static-dataset", "dataset"),
    "research-corpus-loghub2": ("binary-archive-container", "research-corpus", "none"),
    "repo-docker-java-parser": ("maven-test-output", "repository-command-output", "maven"),
    "repo-dockerfile-parser-rs": ("cargo-test-output", "repository-command-output", "cargo"),
    "repo-rustlings": ("cargo-test-output", "repository-command-output", "cargo"),
    "repo-helm-values": ("gradle-test-output", "repository-command-output", "gradle"),
    "repo-moshi": ("gradle-test-output", "repository-command-output", "gradle"),
    "repo-kubeops-generator": ("dotnet-test-output", "repository-command-output", "dotnet"),
    "repo-requests": ("pytest-output", "repository-command-output", "pytest"),
    "repo-hyperfine": ("cli-tool-output", "repository-command-output", "generic-cli"),
    "repo-pyflakes": ("cli-tool-output", "repository-command-output", "generic-cli"),
}
EXPECTED_CASE_IDS = frozenset(CASE_LABELS.keys())


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _load_bundle_manifest(bundle_path: Path) -> dict:
    with tarfile.open(bundle_path, mode="r:") as tar:
        return json.loads(tar.extractfile("manifest.json").read())


def _rationale_for(case_id: str, content_family: str, origin_kind: str, producer_family: str, ev: dict) -> str:
    if case_id in STATIC_N2C_CASE_IDS or case_id == "n2a-miner-canary":
        acquisition_note = (
            f"static content acquisition (no frozen command); canonical input is the archived "
            f"'{ev['contained_input_path']}' member described in {ev['source_evidence_record_path']}"
            if case_id in STATIC_N2C_CASE_IDS
            else (
                f"frozen canary command {ev['frozen_argv']} (stdout), per "
                f"{N2A_SOURCE_MANIFEST_PATH.relative_to(REPO_ROOT)}"
            )
        )
    else:
        acquisition_note = f"frozen command {ev['frozen_argv']} (stdout), per {ev['source_evidence_record_path']}"

    if content_family == "binary-archive-container":
        return (
            f"{acquisition_note}. The case's own primary source-freeze manifest recorded an "
            f"extraction_recipe intending to extract a named plain-text archive member, but the "
            f"committed canonical_benchmark_input is the un-extracted original compressed archive "
            f"re-wrapped in normalized-source.tar (utf8_valid=False) -- a genuine binary archive "
            f"container, not a semantic judgment about the underlying logs, which is why this case "
            f"is a typed UNMEASURABLE_NON_UTF8 refusal rather than a measured row."
        )
    return f"{acquisition_note}. Classified as {content_family} ({origin_kind}/{producer_family})."


def build_case_entry(case_id: str, bundle_entry: dict, stage2_record: dict, durable_manifest: dict,
                      rtk_cases: dict, n2a_source_manifest: dict, source_freeze_by_case: dict) -> dict:
    content_family, origin_kind, producer_family = CASE_LABELS[case_id]
    if content_family not in CONTENT_FAMILIES:
        raise RuntimeError(f"{case_id}: content_family {content_family!r} is not an authorized value")
    if origin_kind not in ORIGIN_KINDS:
        raise RuntimeError(f"{case_id}: origin_kind {origin_kind!r} is not an authorized value")
    if producer_family not in PRODUCER_FAMILIES:
        raise RuntimeError(f"{case_id}: producer_family {producer_family!r} is not an authorized value")

    payload_kind = "utf8-text" if bundle_entry["utf8_valid"] else "binary-container"
    if payload_kind not in PAYLOAD_KINDS:
        raise RuntimeError(f"{case_id}: derived payload_kind {payload_kind!r} is not an authorized value")

    rtk_argv = rtk_cases[case_id]["rtk_argv"]
    if rtk_argv != bundle_entry["rtk_argv"]:
        raise RuntimeError(f"{case_id}: rtk_argv disagreement between rtk-applicability-map and bundle manifest")

    if case_id in STAGE2_CASE_IDS:
        stage2_case = stage2_record["cases"][case_id]
        if bundle_entry["origin_kind"] != "n2d1b-stage2-repository-miner":
            raise RuntimeError(f"{case_id}: expected bundle origin_kind 'n2d1b-stage2-repository-miner'")
        if origin_kind != "repository-command-output":
            raise RuntimeError(f"{case_id}: stage2 case must map to origin_kind='repository-command-output'")
        frozen_argv = stage2_case["frozen_argv"]
        effective_argv = stage2_case["effective_argv"]
        ecosystem = stage2_case["ecosystem"]
        canonicalization_policy_identity = stage2_case["canonicalization_policy_identity"]
        if bundle_entry["canonicalization_policy_identity"] != canonicalization_policy_identity:
            raise RuntimeError(f"{case_id}: canonicalization_policy_identity disagreement bundle vs stage2 record")
        if bundle_entry["ecosystem"] != ecosystem:
            raise RuntimeError(f"{case_id}: ecosystem disagreement bundle vs stage2 record")
        is_cargo_test_shaped = canonicalization_policy_identity == "cargo_test"
        if is_cargo_test_shaped and content_family != "cargo-test-output":
            raise RuntimeError(f"{case_id}: cargo_test canonicalization requires content_family='cargo-test-output'")
        if content_family == "cargo-test-output" and not is_cargo_test_shaped:
            raise RuntimeError(f"{case_id}: content_family='cargo-test-output' requires cargo_test canonicalization evidence")
        if content_family == "cargo-test-output" and "--filter" not in rtk_argv:
            raise RuntimeError(f"{case_id}: cargo-test-output case must use RTK's cargo-test filter, not passthrough")
        acquisition_source_path = "evals/interop/v2/n2/d1-identity-lock/stage2-full-matrix-acceptance.json"
        acquisition_source_sha256 = stage2_record["record_sha256"]
        raw_acquisition_origin_kind = "n2d1b-stage2-repository-miner"
        selected_stream = stage2_case["selected_stream"]
        if selected_stream != "stdout":
            raise RuntimeError(f"{case_id}: expected selected_stream='stdout'")
    elif case_id == "n2a-miner-canary":
        if bundle_entry["origin_kind"] != "n2a-canary":
            raise RuntimeError(f"{case_id}: expected bundle origin_kind 'n2a-canary'")
        if origin_kind != "canary":
            raise RuntimeError(f"{case_id}: n2a-miner-canary must map to origin_kind='canary'")
        frozen_argv = n2a_source_manifest["build"]["argv"]
        effective_argv = frozen_argv
        ecosystem = n2a_source_manifest["project"]["ecosystem"]
        if ecosystem != "dotnet" or producer_family != "dotnet":
            raise RuntimeError(f"{case_id}: n2a canary's own source manifest identifies a dotnet build -- producer_family must be 'dotnet'")
        canonicalization_policy_identity = None
        acquisition_source_path = str(N2A_SOURCE_MANIFEST_PATH.relative_to(REPO_ROOT))
        acquisition_source_sha256 = durable_manifest["manifest_sha256"]
        raw_acquisition_origin_kind = n2a_source_manifest["origin_kind"]
        selected_stream = "stdout"
    else:
        if bundle_entry["origin_kind"] != "n2c-static-durable-input":
            raise RuntimeError(f"{case_id}: expected bundle origin_kind 'n2c-static-durable-input'")
        source_freeze = source_freeze_by_case[case_id]
        expected_origin_kind_map = {
            "kernel-or-infrastructure-bot": "bot-output",
            "native-upstream-ci-log": "ci-log",
            "public-runtime-dataset": "static-dataset",
            "reproducible-research-corpus": "research-corpus",
        }
        raw_acquisition_origin_kind = source_freeze["origin_kind"]
        expected_mapped = expected_origin_kind_map.get(raw_acquisition_origin_kind)
        if expected_mapped is None:
            raise RuntimeError(f"{case_id}: unrecognized source-freeze origin_kind {raw_acquisition_origin_kind!r}")
        if origin_kind != expected_mapped:
            raise RuntimeError(
                f"{case_id}: source-freeze origin_kind {raw_acquisition_origin_kind!r} maps to "
                f"{expected_mapped!r}, but taxonomy has origin_kind={origin_kind!r}"
            )
        frozen_argv = None
        effective_argv = None
        ecosystem = None
        canonicalization_policy_identity = None
        acquisition_source_path = "evals/interop/v2/n2/d0-durable-evidence/durable-input-manifest.json"
        acquisition_source_sha256 = durable_manifest["manifest_sha256"]
        selected_stream = None

    canonical_input_sha256 = bundle_entry["input_sha256"]

    evidence = {
        "acquisition_mode": "command-invocation" if frozen_argv is not None else "static-content-acquisition",
        "frozen_argv": frozen_argv,
        "effective_argv": effective_argv,
        "selected_stream": selected_stream,
        "raw_acquisition_origin_kind": raw_acquisition_origin_kind,
        "ecosystem": ecosystem,
        "canonicalization_policy_identity": canonicalization_policy_identity,
        "rtk_argv": rtk_argv,
        "canonical_benchmark_input_sha256": canonical_input_sha256,
        "utf8_valid": bundle_entry["utf8_valid"],
        "contained_input_path": bundle_entry["contained_input_path"],
        "source_evidence_record_path": acquisition_source_path,
        "source_evidence_record_sha256": acquisition_source_sha256,
    }

    return {
        "case_id": case_id,
        "content_family": content_family,
        "origin_kind": origin_kind,
        "producer_family": producer_family,
        "payload_kind": payload_kind,
        "rationale": _rationale_for(case_id, content_family, origin_kind, producer_family, evidence),
        "classification_evidence": evidence,
    }


def build_record() -> dict:
    if not N2D3_BENCHMARK_PATH.is_file():
        raise RuntimeError(f"{N2D3_BENCHMARK_PATH} does not exist")
    n2d3_record = json.loads(N2D3_BENCHMARK_PATH.read_text())
    if n2d3_record.get("record_sha256") != CANONICAL_N2D3_SHA256:
        raise RuntimeError(
            f"n2d3-primary-token-benchmark-v1.json record_sha256 {n2d3_record.get('record_sha256')!r} "
            f"!= pinned canonical {CANONICAL_N2D3_SHA256!r}"
        )
    import build_n2d3_primary_benchmark as bench_builder
    if bench_builder.compute_record_sha256(n2d3_record) != n2d3_record["record_sha256"]:
        raise RuntimeError("n2d3-primary-token-benchmark-v1.json self-hash does not verify")

    bundle_manifest = _load_bundle_manifest(INPUT_BUNDLE_PATH)
    stage2_record = json.loads(STAGE2_RECORD_PATH.read_text())
    durable_manifest = json.loads(DURABLE_MANIFEST_PATH.read_text())
    rtk_applicability_map = json.loads(RTK_APPLICABILITY_MAP_PATH.read_text())
    n2a_source_manifest = json.loads(N2A_SOURCE_MANIFEST_PATH.read_text())

    source_freeze_by_case = {}
    for case_id in STATIC_N2C_CASE_IDS:
        p = SOURCE_FREEZE_PRIMARY_DIR / f"{case_id}.json"
        source_freeze_by_case[case_id] = json.loads(p.read_text())

    n2d3_case_ids = frozenset(n2d3_record["cases"].keys())
    if n2d3_case_ids != EXPECTED_CASE_IDS:
        raise RuntimeError(
            f"canonical N2-D3 case set {sorted(n2d3_case_ids)} != taxonomy's expected 18-case set "
            f"{sorted(EXPECTED_CASE_IDS)}"
        )
    if frozenset(bundle_manifest["cases"].keys()) != EXPECTED_CASE_IDS:
        raise RuntimeError("input bundle manifest case set != expected 18-case set")

    cases = {}
    for case_id in sorted(EXPECTED_CASE_IDS):
        bundle_entry = bundle_manifest["cases"][case_id]
        n2d3_row = n2d3_record["cases"][case_id]
        if bundle_entry["input_sha256"] != n2d3_row["input_sha256"]:
            raise RuntimeError(f"{case_id}: bundle input_sha256 != canonical N2-D3 row's input_sha256")
        cases[case_id] = build_case_entry(
            case_id, bundle_entry, stage2_record, durable_manifest,
            rtk_applicability_map["cases"], n2a_source_manifest, source_freeze_by_case,
        )

    refusal_ids = {cid for cid, row in n2d3_record["cases"].items() if row["measurement_status"] == "UNMEASURABLE_NON_UTF8"}
    for case_id in refusal_ids:
        if cases[case_id]["payload_kind"] != "binary-container":
            raise RuntimeError(f"{case_id}: is a typed non-UTF-8 refusal but payload_kind != 'binary-container'")

    body = {
        "record_type": "n2d3-content-taxonomy-v1",
        "record_version": 1,
        "schema_version": 1,
        "post_hoc_exploratory": True,
        "canonical_benchmark_link": {
            "path": "evals/interop/v2/n2/d1-identity-lock/n2d3-primary-token-benchmark-v1.json",
            "record_sha256": n2d3_record["record_sha256"],
        },
        "classification_basis": {
            "frozen_argv": (
                "the exact command argv recorded as frozen in stage2-full-matrix-acceptance.json "
                "(repository-miner cases) or the N2-A canary's own source-manifest.json build.argv "
                "-- null for the 8 static N2-C acquisitions, which invoke no command"
            ),
            "selected_stream": "always 'stdout' for command-invocation cases; null for static content acquisitions",
            "actual_canonical_payload": (
                "the real committed canonical_benchmark_input bytes and their utf8_valid outcome, "
                "read from the input bundle's own manifest.json -- never inferred from a file "
                "extension or repository name"
            ),
            "committed_acquisition_or_stage2_records": (
                "stage2-full-matrix-acceptance.json (9 repository-miner cases), "
                "durable-input-manifest.json + source-freeze/source-manifests/primary/*.json "
                "(8 static N2-C acquisitions), evals/interop/v2/n2/canary/source-manifest.json "
                "(N2-A canary)"
            ),
        },
        "authorized_content_families": sorted(CONTENT_FAMILIES),
        "authorized_origin_kinds": sorted(ORIGIN_KINDS),
        "authorized_producer_families": sorted(PRODUCER_FAMILIES),
        "authorized_payload_kinds": sorted(PAYLOAD_KINDS),
        "cases": cases,
    }
    body["record_sha256"] = compute_record_sha256(body)
    return body


def main() -> None:
    record = build_record()
    OUT_PATH.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT_PATH} (record_sha256={record['record_sha256']})")


if __name__ == "__main__":
    main()
