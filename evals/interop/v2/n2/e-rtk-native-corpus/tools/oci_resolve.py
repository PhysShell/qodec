#!/usr/bin/env python3
"""Minimal daemonless OCI/Docker registry client.

Resolves a repository:tag to an immutable, content-addressed digest using only
the registry HTTP API (Bearer token auth + manifest Accept headers +
Docker-Content-Digest), verifies the locally computed sha256 of the exact
manifest bytes against the registry-reported digest, and for multi-platform
indexes pins the platform-specific child manifest.

Stdlib only (urllib) so it runs under the bare Python 3.11 already present.
Honors HTTPS_PROXY / the agent proxy CA bundle via the standard env vars.
"""
import argparse
import hashlib
import json
import os
import ssl
import urllib.request
import urllib.error

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
ACCEPT = ",".join([OCI_INDEX, OCI_MANIFEST, DOCKER_LIST, DOCKER_MANIFEST])

DEFAULT_REGISTRY = "registry-1.docker.io"


def _ctx():
    """TLS context honoring standard CA env vars, else the platform trust store.

    No session-specific CA path is baked in; supply one via SSL_CERT_FILE /
    REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE / NIX_SSL_CERT_FILE if a proxy re-terminates TLS.
    """
    for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NIX_SSL_CERT_FILE"):
        ca = os.environ.get(var)
        if ca and os.path.exists(ca):
            return ssl.create_default_context(cafile=ca)
    return ssl.create_default_context()


def _open(url, headers, method="GET"):
    req = urllib.request.Request(url, headers=headers, method=method)
    # urllib honors HTTPS_PROXY via ProxyHandler default opener
    return urllib.request.urlopen(req, context=_ctx(), timeout=60)


def get_token(registry, repo):
    """Perform the standard 401 auth-challenge dance."""
    url = f"https://{registry}/v2/"
    try:
        _open(url, {})
        return None  # no auth needed
    except urllib.error.HTTPError as e:
        if e.code != 401:
            raise
        chal = e.headers.get("WWW-Authenticate", "")
    # Bearer realm="...",service="...",scope="..."
    if not chal.lower().startswith("bearer"):
        return None
    parts = {}
    for kv in chal[len("Bearer "):].split(","):
        k, _, v = kv.strip().partition("=")
        parts[k] = v.strip('"')
    realm = parts.get("realm")
    service = parts.get("service", "")
    scope = parts.get("scope", f"repository:{repo}:pull")
    tok_url = f"{realm}?service={urllib.parse.quote(service)}&scope={urllib.parse.quote(scope)}"
    with _open(tok_url, {}) as r:
        body = json.loads(r.read())
    return body.get("token") or body.get("access_token")


def fetch_manifest(registry, repo, reference, token):
    url = f"https://{registry}/v2/{repo}/manifests/{reference}"
    headers = {"Accept": ACCEPT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with _open(url, headers) as r:
        raw = r.read()
        dcd = r.headers.get("Docker-Content-Digest")
        ctype = r.headers.get("Content-Type")
    return raw, dcd, ctype


def sha256_digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def resolve(registry, repo, reference, arch="amd64", os_name="linux"):
    token = get_token(registry, repo)
    raw, dcd, ctype = fetch_manifest(registry, repo, reference, token)
    local = sha256_digest(raw)
    ev = {
        "registry": registry,
        "repository": repo,
        "reference": reference,
        "top_media_type": ctype,
        "top_registry_digest": dcd,
        "top_local_sha256": local,
        "top_digest_verified": (dcd == local) if dcd else None,
        "platform_requested": f"{os_name}/{arch}",
    }
    if ctype in (OCI_INDEX, DOCKER_LIST):
        idx = json.loads(raw)
        child = None
        for m in idx.get("manifests", []):
            p = m.get("platform", {})
            if p.get("architecture") == arch and p.get("os") == os_name:
                child = m
                break
        if not child:
            ev["error"] = "no matching platform in index"
            ev["available_platforms"] = [
                f"{m.get('platform', {}).get('os')}/{m.get('platform', {}).get('architecture')}"
                for m in idx.get("manifests", [])
            ]
            return ev
        ev["index_digest"] = dcd or local
        ev["child_digest_from_index"] = child["digest"]
        craw, cdcd, cctype = fetch_manifest(registry, repo, child["digest"], token)
        clocal = sha256_digest(craw)
        ev["child_media_type"] = cctype
        ev["child_registry_digest"] = cdcd
        ev["child_local_sha256"] = clocal
        ev["child_digest_verified"] = (child["digest"] == clocal == (cdcd or clocal))
        ev["pinned_digest"] = child["digest"]
    else:
        ev["pinned_digest"] = dcd or local
    return ev


def verify_by_digest(registry, repo, index_digest, child_digest, arch="amd64", os_name="linux"):
    """Verify an immutable pin: fetch repo@index_digest and repo@child_digest,
    confirm the manifest bytes hash to the claimed digests, and that the child is
    the requested platform inside the index. Never resolves a mutable tag.
    """
    token = get_token(registry, repo)
    ev = {
        "registry": registry, "repository": repo,
        "index_digest": index_digest, "child_digest": child_digest,
        "platform_requested": f"{os_name}/{arch}",
    }
    try:
        iraw, idcd, ictype = fetch_manifest(registry, repo, index_digest, token)
    except urllib.error.HTTPError as e:
        # An unavailable pinned artifact (e.g. digest not found) is a verification
        # failure, not a crash — the pin cannot be confirmed.
        ev["error"] = f"index manifest unavailable: HTTP {e.code}"
        ev["verified"] = False
        return ev
    ev["index_local_sha256"] = sha256_digest(iraw)
    ev["index_digest_verified"] = (sha256_digest(iraw) == index_digest == (idcd or index_digest))
    if ictype in (OCI_INDEX, DOCKER_LIST):
        idx = json.loads(iraw)
        match = next((m for m in idx.get("manifests", [])
                     if m.get("platform", {}).get("architecture") == arch
                     and m.get("platform", {}).get("os") == os_name), None)
        ev["child_in_index"] = bool(match and match["digest"] == child_digest)
    else:
        # Single-arch: index_digest already is the image manifest.
        ev["child_in_index"] = (child_digest == index_digest)
    try:
        craw, cdcd, _ = fetch_manifest(registry, repo, child_digest, token)
    except urllib.error.HTTPError as e:
        ev["error"] = f"child manifest unavailable: HTTP {e.code}"
        ev["verified"] = False
        return ev
    ev["child_local_sha256"] = sha256_digest(craw)
    ev["child_digest_verified"] = (sha256_digest(craw) == child_digest == (cdcd or child_digest))
    ev["verified"] = bool(ev["index_digest_verified"] and ev["child_digest_verified"] and ev["child_in_index"])
    return ev


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("image", help="registry/repo:tag or repo:tag (defaults to Docker Hub)")
    ap.add_argument("--arch", default="amd64")
    ap.add_argument("--os", default="linux", dest="os_name")
    a = ap.parse_args()
    img = a.image
    if "/" in img.split(":")[0] and "." in img.split("/")[0]:
        registry, rest = img.split("/", 1)
    else:
        registry, rest = DEFAULT_REGISTRY, img
    if ":" in rest:
        repo, ref = rest.rsplit(":", 1)
    else:
        repo, ref = rest, "latest"
    if registry == DEFAULT_REGISTRY and "/" not in repo:
        repo = "library/" + repo
    print(json.dumps(resolve(registry, repo, ref, a.arch, a.os_name), indent=2))
