#!/usr/bin/env python3
"""Build n2e-source-registry-v1.json (§2).

Pins the external source registry. Every immutable identity is RESOLVED LIVE at
build time from its publisher (HuggingFace dataset revision, Zenodo record,
OCI registry digest via the daemonless resolver) so the committed record
contains only real, content-addressed values — never placeholders or inferred
hashes. Sources whose full artifact-level enumeration is not completed in this
bootstrap are recorded with an honest DEFERRED status and a typed reason; no
fabricated per-artifact hashes are ever written.

Classification vocabulary (§2.7): ACCEPTED_PRIMARY | ACCEPTED_RESERVE |
REJECTED | DEFERRED — each with a typed reason.

Requires outbound network to the publishers (acquisition phase, §4). Run with
--offline to skip resolution (used only for schema/self-hash checks; will refuse
to write unless every source already carries resolved identities).
"""
from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import oci_resolve  # noqa: E402

OUT = N2E_DIR / "n2e-source-registry-v1.json"

ACCEPTED_PRIMARY = "ACCEPTED_PRIMARY"
ACCEPTED_RESERVE = "ACCEPTED_RESERVE"
REJECTED = "REJECTED"
DEFERRED = "DEFERRED"


def _ctx():
    ca = "/root/.ccr/ca-bundle.crt"
    if Path(ca).exists():
        return ssl.create_default_context(cafile=ca)
    return ssl.create_default_context()


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, context=_ctx(), timeout=60) as r:
        return json.loads(r.read())


def hf_dataset_revision(dataset_id: str) -> dict:
    d = _get_json(f"https://huggingface.co/api/datasets/{dataset_id}")
    return {
        "kind": "huggingface_dataset",
        "dataset_id": d["id"],
        "immutable_revision": d["sha"],
        "last_modified": d.get("lastModified"),
        "gated": d.get("gated", False),
        "source_url": f"https://huggingface.co/datasets/{dataset_id}",
        "resolved_via": "huggingface_api",
    }


def zenodo_record(recid: str) -> dict:
    d = _get_json(f"https://zenodo.org/api/records/{recid}")
    files = []
    for f in d.get("files", []):
        files.append({
            "key": f.get("key"),
            "checksum": f.get("checksum"),  # e.g. "md5:..." — publisher checksum
            "size": f.get("size"),
        })
    meta = d.get("metadata", {})
    return {
        "kind": "zenodo_record",
        "record_id": str(d.get("id", recid)),
        "concept_doi": d.get("conceptdoi"),
        "version_doi": d.get("doi"),
        "title": meta.get("title"),
        "license": (meta.get("license") or {}).get("id") if isinstance(meta.get("license"), dict) else meta.get("license"),
        "files": files,
        "source_url": f"https://zenodo.org/records/{recid}",
        "resolved_via": "zenodo_api",
    }


def oci_digest(image: str, arch: str = "amd64") -> dict:
    repo, _, ref = image.partition(":")
    ref = ref or "latest"
    if "/" not in repo:
        repo = "library/" + repo
    ev = oci_resolve.resolve(oci_resolve.DEFAULT_REGISTRY, repo, ref, arch=arch)
    return {
        "kind": "oci_image",
        "repository": ev["repository"],
        "reference": ev["reference"],
        "immutable_digest": ev.get("pinned_digest"),
        "media_type": ev.get("child_media_type") or ev.get("top_media_type"),
        "platform": ev.get("platform_requested"),
        "digest_verified": ev.get("child_digest_verified", ev.get("top_digest_verified")),
        "resolved_via": "oci_registry_http_api",
    }


def build(offline: bool) -> dict:
    sources = []

    # 2.2 SWE-bench Multilingual — PRIMARY (Rust/Go/JS/TS + extra Java).
    swebench = {
        "source_id": "swe-bench-multilingual",
        "spec_section": "2.2",
        "classification": ACCEPTED_PRIMARY,
        "typed_reason": "immutable HF revision resolved; reproducible per-instance Docker environments; native RTK ecosystems (Rust/Go/JS/TS/Java).",
        "primary_for": ["rust_cargo", "go", "js_ts", "jvm"],
        "license_note": "per-instance upstream repository licenses; dataset card on HF.",
        "identity": hf_dataset_revision("SWE-bench/SWE-bench_Multilingual") if not offline else None,
        "oci_digest_example": oci_digest("swebench/sweb.eval.x86_64.astropy_1776_astropy-12907:latest") if not offline else None,
    }
    sources.append(swebench)

    # 2.5 Loghub-2.0 — PRIMARY for logs (rtk log / grep / rg).
    sources.append({
        "source_id": "loghub-2.0",
        "spec_section": "2.5",
        "classification": ACCEPTED_PRIMARY,
        "typed_reason": "immutable Zenodo record with publisher checksums; static log files for deterministic slices.",
        "primary_for": ["logs", "files_search"],
        "license_note": "see Zenodo record metadata.",
        "identity": zenodo_record("8275861") if not offline else None,
    })

    # 2.1 BugSwarm 1.3.1 — PRIMARY for Maven/Gradle + Python CI output.
    # Release metadata + per-artifact reproducible image digests require the
    # per-artifact enumeration pass; recorded honestly as DEFERRED until done.
    sources.append({
        "source_id": "bugswarm-1.3.1",
        "spec_section": "2.1",
        "classification": DEFERRED,
        "typed_reason": "reachable (metadata via raw.githubusercontent, images on docker.io resolvable via the OCI resolver), but per-artifact reproducible-image digest enumeration and reproducible-only filtering not completed in the bootstrap session; no per-artifact hashes are recorded until resolved.",
        "intended_primary_for": ["jvm", "python"],
        "metadata_source": "https://raw.githubusercontent.com/BugSwarm/BugSwarm/master/",
        "image_namespace": "docker.io/bugswarm/images",
        "license_note": "BugSwarm project license (to be recorded at enumeration).",
    })

    # 2.6 Terminal-Bench 2.0 — PRIMARY for containers (docker ps/images/logs).
    sources.append({
        "source_id": "terminal-bench-2.0",
        "spec_section": "2.6",
        "classification": DEFERRED,
        "typed_reason": "environment-only use (no agent, no task success). Task image OCI digests resolvable via the resolver, but the exact task-id -> image-digest table is not enumerated in the bootstrap session; no digests recorded until resolved.",
        "intended_primary_for": ["containers"],
        "license_note": "Terminal-Bench task license (to be recorded at enumeration).",
    })

    # 2.3 BugsJS — RESERVE (independent JS/Mocha stratum).
    sources.append({
        "source_id": "bugsjs",
        "spec_section": "2.3",
        "classification": ACCEPTED_RESERVE,
        "typed_reason": "independent JS/Mocha stratum; framework repo + metadata reachable via raw.githubusercontent. Held as reserve behind SWE-bench Multilingual JS/TS.",
        "reserve_for": ["js_ts"],
        "metadata_source": "https://raw.githubusercontent.com/BugsJS/",
        "license_note": "BugsJS project license (to be recorded at selection).",
    })

    # 2.4 BugsInPy — RESERVE / independent Python stratum.
    sources.append({
        "source_id": "bugsinpy",
        "spec_section": "2.4",
        "classification": ACCEPTED_RESERVE,
        "typed_reason": "independent Python/pytest stratum; repo + per-bug metadata reachable via raw.githubusercontent. Reserve behind SWE-bench/BugSwarm Python.",
        "reserve_for": ["python"],
        "metadata_source": "https://raw.githubusercontent.com/soarsmu/BugsInPy/",
        "license_note": "BugsInPy project license (to be recorded at selection).",
    })

    # 2.7 Explicitly deferred / reserve sources.
    for sid, section, reason in [
        ("gobench", "2.7", "reserve only; concurrency failures may be flaky; not needed while SWE-bench Multilingual supplies reproducible Go."),
        ("panic4r", "2.7", "research candidate only; no independently verified durable executable artifact source confirmed in bootstrap."),
        ("defects4j", "2.7", "reserve Java source if BugSwarm cannot fill a declared Maven/Gradle stratum."),
        ("gitbug-java", "2.7", "reserve source for later freshness expansion."),
    ]:
        sources.append({
            "source_id": sid,
            "spec_section": section,
            "classification": DEFERRED if sid != "panic4r" else DEFERRED,
            "typed_reason": reason,
        })

    body = c.envelope(
        record_type="n2e-source-registry",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_source_registry.py",
        purpose=(
            "External source registry (§2). Immutable identities are resolved live "
            "from publishers (HF revision, Zenodo record, OCI digest) so only real "
            "content-addressed values are committed; incomplete acquisitions are "
            "DEFERRED with typed reasons and never carry fabricated hashes."
        ),
        classification_vocabulary=[ACCEPTED_PRIMARY, ACCEPTED_RESERVE, REJECTED, DEFERRED],
        resolution_mode="offline" if offline else "live",
        source_count=len(sources),
        sources=sources,
    )
    return body


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    args = ap.parse_args()
    body = build(args.offline)
    if args.offline:
        print("offline mode: not writing (resolution skipped)", file=sys.stderr)
        return 0
    c.write_record(OUT, body)
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name} record_sha256={rec['record_sha256']} sources={rec['source_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
