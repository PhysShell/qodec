#!/usr/bin/env python3
"""Build n2e-source-registry-v1.json (§2 step 2) — DETERMINISTIC, OFFLINE.

Constructs the canonical registry purely from the committed explicit pins
(n2e-source-pins-v1.json) plus the static reserve/deferred source declarations.
NO network. Rebuilding tomorrow produces byte-identical output even if the
publishers add new revisions or move tags — because the pins are fixed and no
mutable state is read.

A network refresh is a separate, explicit command (acquire_n2e_source_pins.py);
it never runs here.

Classification vocabulary (§2.7): ACCEPTED_PRIMARY | ACCEPTED_RESERVE |
REJECTED | DEFERRED — each with a typed reason.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

OUT = N2E_DIR / "n2e-source-registry-v1.json"
PINS = N2E_DIR / "n2e-source-pins-v1.json"

ACCEPTED_PRIMARY = "ACCEPTED_PRIMARY"
ACCEPTED_RESERVE = "ACCEPTED_RESERVE"
REJECTED = "REJECTED"
DEFERRED = "DEFERRED"


def _pin(pins: dict, section: str, source_id: str) -> dict:
    for p in pins[section]:
        if p["source_id"] == source_id:
            return p
    raise SystemExit(f"pin {source_id!r} missing from {section} in {PINS.name}")


def build() -> dict:
    pins = c.load_record(PINS)
    ok, msg = c.verify_self_hash(pins)
    if not ok:
        raise SystemExit(f"pins self-hash invalid: {msg}")

    hf = _pin(pins, "hf_datasets", "swe-bench-multilingual")
    zen = _pin(pins, "zenodo_records", "loghub-2.0")
    oci = _pin(pins, "oci_images", "swe-bench-eval-image-sample")
    bugsinpy = _pin(pins, "git_repos", "bugsinpy")
    container_ids = ["container-redis", "container-nginx", "container-busybox", "container-postgres"]
    containers = [_pin(pins, "oci_images", cid) for cid in container_ids]

    sources = [
        {
            "source_id": "swe-bench-multilingual",
            "spec_section": "2.2",
            "classification": ACCEPTED_PRIMARY,
            "typed_reason": "immutable HF revision pinned; reproducible per-instance Docker environments; native RTK ecosystems (Rust/Go/JS/TS/Java).",
            "primary_for": ["rust_cargo", "go", "js_ts", "jvm"],
            "license_note": "per-instance upstream repository licenses; dataset card on HF.",
            "identity": {
                "kind": "huggingface_dataset",
                "dataset_id": hf["dataset_id"],
                "immutable_revision": hf["revision"],
                "source_url": hf["source_url"],
            },
        },
        {
            "source_id": "swe-bench-eval-image-sample",
            "spec_section": "2.2",
            "classification": ACCEPTED_PRIMARY,
            "typed_reason": "real SWE-bench eval image pinned by immutable manifest digest; validates the per-instance OCI-by-digest lock path the corpus relies on.",
            "primary_for": [],
            "license_note": "image derived from upstream project + SWE-bench harness.",
            "identity": {
                "kind": "oci_image",
                "registry": oci["registry"],
                "repository": oci["repository"],
                "platform": oci["platform"],
                "index_digest": oci["index_digest"],
                "child_digest": oci["child_digest"],
                "media_type": oci["media_type"],
            },
        },
        *[{
            "source_id": ci["source_id"],
            "spec_section": "6.9",
            "classification": ACCEPTED_PRIMARY,
            "typed_reason": "local disposable container image pinned by immutable manifest digest; run locally on the session daemon for docker ps/images/logs states (§6.9).",
            "primary_for": ["containers"],
            "license_note": "upstream official image license.",
            "identity": {
                "kind": "oci_image",
                "registry": ci["registry"],
                "repository": ci["repository"],
                "platform": ci["platform"],
                "index_digest": ci["index_digest"],
                "child_digest": ci["child_digest"],
                "media_type": ci["media_type"],
            },
        } for ci in containers],
        {
            "source_id": "loghub-2.0",
            "spec_section": "2.5",
            "classification": ACCEPTED_PRIMARY,
            "typed_reason": "immutable Zenodo version record with publisher file checksums; static log files for deterministic slices.",
            "primary_for": ["logs", "files_search"],
            "license_note": zen.get("license"),
            "identity": {
                "kind": "zenodo_record",
                "record_id": zen["record_id"],
                "version_doi": zen["version_doi"],
                "concept_doi": zen.get("concept_doi"),
                "title": zen.get("title"),
                "license": zen.get("license"),
                "files": zen["files"],
            },
        },
        {
            "source_id": "bugswarm-1.3.1",
            "spec_section": "2.1",
            "classification": DEFERRED,
            "typed_reason": "reachable (metadata via raw.githubusercontent, images on docker.io resolvable via the OCI resolver), but per-artifact reproducible-image digest enumeration and reproducible-only filtering not completed; no per-artifact hashes are recorded until resolved. Required only if SWE-bench Multilingual cannot fill the Maven/Gradle quota.",
            "intended_primary_for": ["jvm", "python"],
            "metadata_source": "https://raw.githubusercontent.com/BugSwarm/BugSwarm/master/",
            "image_namespace": "docker.io/bugswarm/images",
            "license_note": "BugSwarm project license (to be recorded at enumeration).",
        },
        {
            "source_id": "terminal-bench-2.0",
            "spec_section": "2.6",
            "classification": DEFERRED,
            "typed_reason": "environment-only use (no agent, no task success). Task image OCI digests resolvable via the resolver, but the exact task-id -> image-digest table is not enumerated yet; required to populate the mandatory container stratum if no accepted source provides local disposable containers.",
            "intended_primary_for": ["containers"],
            "license_note": "Terminal-Bench task license (to be recorded at enumeration).",
        },
        {
            "source_id": "bugsjs",
            "spec_section": "2.3",
            "classification": ACCEPTED_RESERVE,
            "typed_reason": "independent JS/Mocha stratum; framework repo + metadata reachable via raw.githubusercontent. Reserve behind SWE-bench Multilingual JS/TS.",
            "reserve_for": ["js_ts"],
            "metadata_source": "https://raw.githubusercontent.com/BugsJS/",
            "license_note": "BugsJS project license (to be recorded at selection).",
        },
        {
            "source_id": "bugsinpy",
            "spec_section": "2.4",
            "classification": ACCEPTED_PRIMARY,
            "typed_reason": "SWE-bench Multilingual has no Python; BugsInPy is the Python/pytest primary source. Pinned by exact commit over the git transport; per-bug metadata manifest committed (n2e-bugsinpy-bugs-v1.json).",
            "primary_for": ["python"],
            "license_note": "BugsInPy project license (recorded at bug-manifest acquisition).",
            "identity": {
                "kind": "git_repo",
                "repository": bugsinpy["repository"],
                "commit": bugsinpy["commit"],
                "transport": bugsinpy["transport"],
                "bugs_manifest": "n2e-bugsinpy-bugs-v1.json",
            },
        },
    ]
    for sid, reason in [
        ("gobench", "reserve only; concurrency failures may be flaky; not needed while SWE-bench Multilingual supplies reproducible Go."),
        ("panic4r", "research candidate only; no independently verified durable executable artifact source confirmed."),
        ("defects4j", "reserve Java source if BugSwarm cannot fill a declared Maven/Gradle stratum."),
        ("gitbug-java", "reserve source for later freshness expansion."),
    ]:
        sources.append({"source_id": sid, "spec_section": "2.7", "classification": DEFERRED, "typed_reason": reason})

    body = c.envelope(
        record_type="n2e-source-registry",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_source_registry.py",
        purpose=(
            "External source registry (§2), built deterministically and offline from the "
            "committed immutable pins (n2e-source-pins-v1.json). Rebuilds byte-identically "
            "regardless of upstream movement. Incomplete acquisitions are DEFERRED with "
            "typed reasons and never carry fabricated hashes."
        ),
        classification_vocabulary=[ACCEPTED_PRIMARY, ACCEPTED_RESERVE, REJECTED, DEFERRED],
        pins_record="n2e-source-pins-v1.json",
        pins_sha256=c.sha256_json_file(PINS),
        source_count=len(sources),
        sources=sources,
    )
    return body


def main() -> int:
    c.write_record(OUT, build())
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name} record_sha256={rec['record_sha256']} sources={rec['source_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
