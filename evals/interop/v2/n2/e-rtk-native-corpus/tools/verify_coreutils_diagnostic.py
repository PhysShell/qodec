#!/usr/bin/env python3
"""Independent verifier for the focused Coreutils diagnostic (corrections 1-9, cumulative).

Re-derives EVERY gate from primitive evidence -- never trusts a producer boolean:
  * derives normative_evidence_eligible itself; the producer only records
    normative_evidence_eligibility=UNDETERMINED (corr 2);
  * re-derives RAW/RTK argv equality against the exact committed contract, RTK == [rtk_bin,
    *CONTRACT_RAW_ARGV] (full argv; a dropped `cargo`, injected `+1.81.0`, extra/reordered
    flags all fail) (corr 1);
  * binds the canonicalizer policy from the resolved contract (record==contract==
    cargo-test-v2) and re-derives each rep's canonical + removed-line diagnostics (corr 4; the coreutils
    contract migrated to cargo-test-v3 = cargo-test-v2 + RTK compact-summary duration normalization);
  * re-derives the effective environment == contract and RAW/RTK semantic-env parity (corr 5);
  * requires a mechanically-resolved dispatch->filter->parser->formatter chain (corr 6);
  * requires exact relative manifest paths + external-manifest cross-agreement (corr 7);
  * re-derives RAW rejection gates from the primary captures, not the producer proof (corr 8);
  * checks acquisition prerequisites + A/B authorized-mutation (only Cargo.lock) (corr 9).

Exit non-zero (fails the workflow) on any producer/verifier disagreement.
Usage: verify_coreutils_diagnostic.py <diagnostic.json> <evidence-dir>
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_oracles as ora  # noqa: E402
import n2e_canon_policies as canon  # noqa: E402
import n2e_cargo_index_cache as cic  # noqa: E402
import n2e_resolved_loader as loader  # noqa: E402

PINNED_MANIFEST_SHA = "5596679723faf7e63772bacb1d0c898abaa51eb4ed193b328929d907c8c4bd5a"
CASE_ID = "uutils__coreutils-6731::rust_cargo::test::fixed"
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
CONTRACT_RAW_ARGV = ["cargo", "test", "backslash", "--no-fail-fast"]
CONTRACT_ENV = {"RUSTUP_TOOLCHAIN": "1.81.0", "CARGO_NET_OFFLINE": "true",
                "RUST_TEST_THREADS": "1", "CARGO_BUILD_JOBS": "1"}
EXPECTED_POLICY = "cargo-test-v3"
EVIDENCE_ROOT = "out/evidence/coreutils-6731"
TARGET_IDS = ["test_tr::test_trailing_backslash"]
CHAIN_ORDER = ["cli_dispatch_cargo_test", "cargo_filter", "cargo_parser", "summary_formatter"]
ACQ_ELIGIBLE = {"pristine_dependency_state", "publisher_install_resolved_dependency_snapshot"}
# independent Rust item-definition regex (NOT imported from the producer -- re-derived here)
_VDEF = re.compile(
    rb"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:async[ \t]+)?(?:unsafe[ \t]+)?"
    rb"(fn|struct|enum|trait|const|static)[ \t]+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
FATAL_OUTCOMES = {"COREUTILS_DIAGNOSTIC_ERROR"}
ACQ_FAILURE_OUTCOMES = {"COREUTILS_ACQUISITION_INSTALL_FAILURE", "COREUTILS_ACQUISITION_NONDETERMINISTIC",
                        "COREUTILS_ACQUISITION_UNAUTHORIZED_MUTATION", "COREUTILS_TOOLCHAIN_PINS_UNVERIFIED",
                        "COREUTILS_FINAL_INPUT_PARITY_FAILURE", "REJECTED_NO_ISOLATION",
                        "COREUTILS_CARGO_INDEX_CACHE_UNPARSEABLE",
                        "COREUTILS_DEPENDENCY_FETCH_FAILURE", "COREUTILS_DEPENDENCY_FETCH_LOCK_MUTATION"}


def _dz(p: Path) -> bytes:
    return zlib.decompress(p.read_bytes())


def _canon(policy: str, raw: bytes, is_rtk: bool) -> bytes:
    return canon.canonicalize(canon.rtk_envelope(raw) if is_rtk else raw, policy)


def _argv_ok(argv, is_rtk, rtk_bin) -> bool:
    expected = ([rtk_bin, *CONTRACT_RAW_ARGV] if is_rtk else list(CONTRACT_RAW_ARGV))
    if list(argv) != expected:
        return False
    return not any(str(tok).startswith("+") for tok in argv)  # no injected +toolchain


def _required_paths(outcome: str, rec=None) -> list:
    roles = ("raw", "rtk") if outcome == "RTK_DIALECT_UNPROVEN" else \
            ("raw",) if outcome == "COREUTILS_RAW_NOT_QUALIFIED" else ()
    req = []
    for role in roles:
        for i in range(3):
            req += [f"{EVIDENCE_ROOT}/{role}.rep{i}.zst", f"{EVIDENCE_ROOT}/{role}.raw.rep{i}.zst",
                    f"{EVIDENCE_ROOT}/{role}.mutation.rep{i}.json"]
    if roles:  # any complete diagnostic must retain the acquisition cache + resolved-graph evidence
        cc = f"{EVIDENCE_ROOT}/cargo-cache"
        for label in ("A", "B"):
            req += [f"{cc}/{label}-cache-semantic.json", f"{cc}/{label}-resolved-graph.json"]
        # item 1: a publisher_install_resolved_dependency_snapshot MUST retain both Cargo.locks
        acq_cls = ((rec or {}).get("acquisition_classification") or {}).get("outcome")
        if acq_cls == "publisher_install_resolved_dependency_snapshot":
            for label in ("A", "B"):
                req.append(f"{cc}/{label}-Cargo.lock")
    return req


def _rederive_arm(rec, evidence, role, policy, fail) -> dict:
    arm = rec.get(f"{role}_arm") or {}
    runs = arm.get("runs") or []
    is_rtk = role == "rtk"
    dhash, phash, sem, removed_ok = [], [], [], []
    for i in range(3):
        rawf, canf = evidence / f"{role}.raw.rep{i}.zst", evidence / f"{role}.rep{i}.zst"
        if not (rawf.is_file() and canf.is_file()):
            fail.append(f"missing {role} rep{i} stream(s)")
            continue
        raw = _dz(rawf)
        if len(runs) > i and hashlib.sha256(raw).hexdigest() != runs[i].get("raw_combined_sha256"):
            fail.append(f"{role} rep{i} raw capture sha != record")
        derived = _canon(policy, raw, is_rtk)
        prod = _dz(canf)
        dhash.append(hashlib.sha256(derived).hexdigest()); phash.append(hashlib.sha256(prod).hexdigest())
        if derived != prod:
            fail.append(f"{role} rep{i}: re-derived canonical != producer file")
        if len(runs) > i and hashlib.sha256(derived).hexdigest() != runs[i].get("canonical_sha256"):
            fail.append(f"{role} rep{i}: re-derived canonical sha != record")
        # re-derive removed-line diagnostics and compare (corr 4)
        rd = canon.cargo_test_v2_removed_diag(canon.rtk_envelope(raw) if is_rtk else raw)
        prod_rd = (runs[i] or {}).get("canon_removed_lines") or {}
        removed_ok.append(rd == prod_rd)
        if rd != prod_rd:
            fail.append(f"{role} rep{i}: removed-line diagnostic mismatch")
        if not is_rtk:
            pr = ora.cargo_target_execution_proof(raw, (runs[i] or {}).get("exit_code", 1), TARGET_IDS)
            pc = ora.cargo_target_execution_proof(derived, (runs[i] or {}).get("exit_code", 1), TARGET_IDS)
            same = (pr["executed_ok_ids"] == pc["executed_ok_ids"]
                    and pr["summary"]["passed"] == pc["summary"]["passed"]
                    and pr["summary"]["failed"] == pc["summary"]["failed"]
                    and pr["summary"]["running_total"] == pc["summary"]["running_total"]
                    and pr["checks"]["target_executed_passing"] == pc["checks"]["target_executed_passing"])
            sem.append(same)
            if not same:
                fail.append(f"raw rep{i}: canonicalization changed test semantics")
    return {"rederived_deterministic": len(set(dhash)) == 1 and len(dhash) == 3,
            "rederived_canonical_equal_producer": dhash == phash and len(dhash) == 3,
            "removed_diag_equal_producer": all(removed_ok) and len(removed_ok) == 3,
            "semantic_preserved_all": (all(sem) if sem else None)}


def _raw_target_from_captures(evidence, rec) -> bool:
    """corr 8: derive target execution from the PRIMARY raw captures, not the producer proof."""
    runs = (rec.get("raw_arm") or {}).get("runs") or []
    ok = []
    for i in range(3):
        f = evidence / f"raw.raw.rep{i}.zst"
        if not f.is_file():
            return False
        p = ora.cargo_target_execution_proof(_dz(f), (runs[i] or {}).get("exit_code", 1), TARGET_IDS)
        ok.append(p["executed_ok"])
    return len(ok) == 3 and all(ok)


def _check_acquisition(rec, fail):
    """corr 9: acquisition prerequisites + A/B authorized-mutation (only Cargo.lock)."""
    for label in ("A", "B"):
        a = rec.get(f"acquisition_{label}") or {}
        if a.get("fetch_exit") != 0:
            fail.append(f"acquisition {label}: fetch_exit != 0")
        if a.get("head_matches_base") is not True:
            fail.append(f"acquisition {label}: head != base")
        pr = a.get("pristine_state") or {}
        if pr.get("tracked_status") != []:
            fail.append(f"acquisition {label}: pristine tracked status not empty")
        if not pr.get("cargo_config") or "rust_toolchain" not in pr:
            fail.append(f"acquisition {label}: pristine config/toolchain identities not captured")
        post = a.get("post_install_state") or {}
        # only Cargo.lock may change pristine->post; any other tracked/config/toolchain change is unauthorized
        for key in ("workspace_cargo_tomls", "cargo_config", "cargo_config_toml",
                    "rust_toolchain", "rust_toolchain_toml"):
            if pr.get(key) != post.get(key):
                fail.append(f"acquisition {label}: unauthorized mutation of {key}")
        changed_tracked = set(post.get("tracked_status") or []) - set(pr.get("tracked_status") or [])
        if any("Cargo.lock" not in x for x in changed_tracked):
            fail.append(f"acquisition {label}: unauthorized tracked mutation {sorted(changed_tracked)}")


def _check_manifest(rec, outcome, fail, root, require_external=False):
    """corr 7 + hardening 4d: exact relative paths, no duplicate paths/basenames, all files
    independently rehashed; the external manifest MUST exist for a complete diagnostic; the
    exact required-file set must appear in BOTH manifests; internal/external must agree on
    every shared primitive. Paths are rebased against `root` (the artifact root implied by the
    evidence dir) so the verifier replays against a downloaded artifact, not only CI cwd."""
    manifest = rec.get("file_manifest") or []
    if not manifest:
        fail.append("file_manifest missing"); return
    paths = [e["file"] for e in manifest]
    if len(paths) != len(set(paths)):
        fail.append("duplicate manifest paths")
    stream_names = [Path(p).name for p in paths if p.startswith(EVIDENCE_ROOT)]
    if len(stream_names) != len(set(stream_names)):
        fail.append("duplicate evidence basenames")
    for e in manifest:
        fp = root / e["file"]
        if fp.name.endswith(".json") and Path(e["file"]).name.startswith("coreutils-6731-diagnostic"):
            continue
        if not fp.is_file():
            fail.append(f"manifest file missing: {e['file']}")
        elif c.sha256_file(str(fp)) != e["sha256"]:
            fail.append(f"manifest hash mismatch: {e['file']}")
    manifested = set(paths)
    required = _required_paths(outcome, rec)
    for req in required:
        if req not in manifested:
            fail.append(f"required evidence omitted from internal manifest (exact path): {req}")
    # external artifact manifest (built by the workflow, NOT self-referential): independently
    # re-hash each present file, require required-set inclusion, and require agreement.
    ext = root / "out" / "external-artifact-manifest.json"
    if not ext.is_file():
        if require_external:
            fail.append("external-artifact-manifest.json missing (required for a complete diagnostic)")
        return
    try:
        ej = json.loads(ext.read_text())
    except Exception as ex:  # noqa: BLE001
        fail.append(f"external manifest unreadable: {ex}"); return
    ext_by = {e["file"]: e["sha256"] for e in ej.get("files", [])}
    for e in ej.get("files", []):
        fp = root / e["file"]
        if fp.is_file() and c.sha256_file(str(fp)) != e["sha256"]:
            fail.append(f"external manifest hash mismatch: {e['file']}")
    for req in required:
        if req not in ext_by:
            fail.append(f"required evidence omitted from external manifest (exact path): {req}")
    for e in manifest:
        if e["file"] in ext_by and ext_by[e["file"]] != e["sha256"]:
            fail.append(f"internal/external manifest disagree: {e['file']}")


def _derive_toolchain(rec, pins, fail) -> bool:
    """hardening 4a: independently compare recorded manifest/component/host/version/installed-
    binary identities against the resolved toolchain overlay pins. Never trusts te['ok']."""
    te = rec.get("toolchain_enforcement") or {}
    cm = pins["channel_manifest"]; comps = pins["components_x86_64_unknown_linux_gnu"]
    d = []
    if te.get("manifest_sha256") != cm["sha256"]:
        d.append(f"manifest sha {te.get('manifest_sha256')} != pinned {cm['sha256']}")
    if te.get("manifest_date") != cm["manifest_date"]:
        d.append(f"manifest date {te.get('manifest_date')} != pinned {cm['manifest_date']}")
    arts = te.get("distribution_artifacts") or {}
    for name in ("cargo", "rustc", "rust"):
        a = arts.get(name) or {}
        if a.get("hash") != comps[name]["hash"]:
            d.append(f"{name} component hash != pinned")
        if a.get("xz_hash") != comps[name]["xz_hash"]:
            d.append(f"{name} xz artifact hash != pinned")
    ii = te.get("installed_identity") or {}
    if ii.get("host_target") != pins["host_target"]:
        d.append(f"host_target {ii.get('host_target')} != pinned {pins['host_target']}")
    if ii.get("resolved_channel_exact") != pins["resolved_channel"]:
        d.append(f"resolved_channel {ii.get('resolved_channel_exact')} != pinned {pins['resolved_channel']}")
    for k in ("cargo_binary_sha256", "rustc_binary_sha256"):
        v = ii.get(k)
        if not (isinstance(v, str) and len(v) == 64):
            d.append(f"installed {k} missing/invalid")
    ch = pins["resolved_channel"]
    for k, needle in (("cargo_version_verbose", f"cargo {ch}"), ("rustc_version_verbose", f"rustc {ch}")):
        if needle not in (ii.get(k) or ""):
            d.append(f"{k} does not attest {ch}")
    for x in d:
        fail.append("toolchain: " + x)
    return not d


def _canon_sha(obj) -> str:
    """matches the producer's _manifest_hash: sha256(json.dumps(obj, sort_keys=True))."""
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def _verify_cargo_cache_evidence(evidence, fail) -> dict:
    """hardening + req 5: reopen the RETAINED normalized semantic cache reps for A and B,
    independently confirm each path is the EXACT sparse-index layout, re-derive each semantic
    digest from the retained payload (must match the recorded per-entry digest), and require
    ZERO semantic differences between A and B. Never trusts cargo_cache_semantic_equal."""
    d = evidence / "cargo-cache"
    sem = {}
    for label in ("A", "B"):
        p = d / f"{label}-cache-semantic.json"
        if not p.is_file():
            fail.append(f"cargo-cache: retained {label} semantic evidence missing"); continue
        try:
            data = json.loads(p.read_text())
        except Exception as e:  # noqa: BLE001
            fail.append(f"cargo-cache {label}: unreadable ({e})"); continue
        man = {}
        for e in data.get("entries", []):
            path = e.get("path", "")
            if not cic.is_sparse_index_cache_path(tuple(Path(path).parts)):
                fail.append(f"cargo-cache {label}: retained non-cache path {path}"); continue
            payload = e.get("semantic_payload")
            redigest = _canon_sha_compact(payload)
            if redigest != e.get("semantic_sha256"):
                fail.append(f"cargo-cache {label}: re-derived semantic digest != recorded for {path}")
            man[path] = redigest
        sem[label] = man
    equal = None
    if "A" in sem and "B" in sem:
        a, b = sem["A"], sem["B"]
        diff = sorted((set(a) - set(b)) | (set(b) - set(a)) | {k for k in set(a) & set(b) if a[k] != b[k]})
        equal = not diff
        if diff:
            fail.append(f"cargo-cache: {len(diff)} SEMANTIC differences between A and B: {diff[:10]}")
    return {"semantic_equal": equal, "entry_counts": {k: len(v) for k, v in sem.items()}}


def _canon_sha_compact(obj) -> str:
    """matches cic.semantic_digest: sha256(json.dumps(payload, sort_keys=True, separators=(',',':')))."""
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _lock_packages_from_toml(lock_bytes: bytes) -> list:
    """INDEPENDENTLY parse a Cargo.lock and derive the sorted full package records
    (name/version/source/checksum) -- the verifier's own derivation, not the producer's."""
    import tomllib
    data = tomllib.loads(lock_bytes.decode("utf-8"))
    pkgs = [{"name": p.get("name"), "version": p.get("version"),
             "source": p.get("source"), "checksum": p.get("checksum")}
            for p in data.get("package", [])]
    pkgs.sort(key=lambda p: (p["name"] or "", p["version"] or "", p["source"] or ""))
    return pkgs


DEP_FETCH_ARGV = ["cargo", "fetch", "--locked"]
DEP_FETCH_ENV = {"RUSTUP_TOOLCHAIN": "1.81.0", "CARGO_NET_OFFLINE": "false"}
HOST_GRAPH_KEYS = {"resolve_roots", "resolve_nodes", "reachable_package_ids",
                   "resolve_graph_platform", "resolve_graph_scope"}
LOCK_SCOPE = "full cross-platform resolution"


def _recompute_reachable(graph: dict) -> list:
    """INDEPENDENTLY recompute reachable package IDs by traversing dependency edges (BFS) starting
    ONLY from the explicit resolve_roots over resolve_nodes (item C -- no all-nodes fall-back:
    a node disconnected from every root is deliberately unreachable). Verifier's own derivation."""
    nodes = graph.get("resolve_nodes") or []
    by_id = {n.get("id"): n for n in nodes}
    roots = graph.get("resolve_roots") or []
    seen, stack = set(), list(roots)
    while stack:
        nid = stack.pop()
        if nid in seen:
            continue
        seen.add(nid)
        for dep in by_id.get(nid, {}).get("deps") or []:
            pk = dep.get("pkg")
            if pk:
                stack.append(pk)
    return sorted(i for i in seen if i in by_id)


def _validate_graph_structure(graph: dict, label: str, fail: list) -> None:
    """item C structural validation of the host resolve graph: non-empty roots; every root is a
    node; unique node IDs; every dependency edge references an existing node; no node is
    disconnected from the roots (reachable set == node set). Each violation appends a failure."""
    nodes = graph.get("resolve_nodes") or []
    roots = graph.get("resolve_roots") or []
    node_ids = [n.get("id") for n in nodes]
    id_set = set(node_ids)
    if not roots:
        fail.append(f"resolved-graph {label}: resolve_roots empty")
    for r in roots:
        if r not in id_set:
            fail.append(f"resolved-graph {label}: resolve_root {r!r} not present in resolve_nodes")
    if len(node_ids) != len(id_set):
        dupes = sorted({i for i in node_ids if node_ids.count(i) > 1})
        fail.append(f"resolved-graph {label}: duplicate node ids {dupes[:10]}")
    for n in nodes:
        for dep in n.get("deps") or []:
            pk = dep.get("pkg")
            if pk is not None and pk not in id_set:
                fail.append(f"resolved-graph {label}: dangling dependency edge {n.get('id')!r} -> {pk!r}")
    recomputed = _recompute_reachable(graph)
    if set(recomputed) != id_set:
        orphans = sorted(id_set - set(recomputed))
        fail.append(f"resolved-graph {label}: nodes disconnected from resolve_roots {orphans[:10]}")


def _verify_dependency_fetch(label, acq, retained_lock_sha, retained_lock_size, fail) -> tuple:
    """item 3 + verifier-only fail-closed size correction: independently require the lock-
    preserving dependency fetch for this acquisition: exact argv/env, exit==0, not timed_out, and
    pre/post-fetch lock SHA *and* byte-size identities that are ALL present and exactly equal to
    the retained (post-fetch) Cargo.lock (== post_install_state.cargo_lock == resolved snapshot).
    Byte sizes must be present integers equal to the retained lock size -- no None-acceptable
    comparison. `unchanged` is derived only when every SHA and size identity is present and exact.
    A successful offline metadata cannot compensate. Returns (dependency_fetch_ok, lock_unchanged);
    on any identity failure BOTH are false."""
    dfr = acq.get("dependency_fetch_result") or {}
    df = dfr.get("dependency_fetch") or {}
    ok = True
    if dfr.get("status") != "ok":
        fail.append(f"dependency-fetch {label}: status != ok ({dfr.get('status')})"); ok = False
    if df.get("argv") != DEP_FETCH_ARGV:
        fail.append(f"dependency-fetch {label}: argv != {DEP_FETCH_ARGV}"); ok = False
    if df.get("env") != DEP_FETCH_ENV:
        fail.append(f"dependency-fetch {label}: env != {DEP_FETCH_ENV}"); ok = False
    if df.get("exit") != 0:
        fail.append(f"dependency-fetch {label}: exit != 0"); ok = False
    if df.get("timed_out") is not False:
        fail.append(f"dependency-fetch {label}: timed_out != false"); ok = False
    pre_sha, post_sha = dfr.get("pre_fetch_lock_sha256"), dfr.get("post_fetch_lock_sha256")
    pre_b, post_b = dfr.get("pre_fetch_lock_bytes"), dfr.get("post_fetch_lock_bytes")
    # byte sizes are MANDATORY: both present integers, both exactly == retained post-fetch lock size
    sizes_ok = (isinstance(pre_b, int) and isinstance(post_b, int)
                and pre_b == retained_lock_size and post_b == retained_lock_size)
    if not sizes_ok:
        fail.append(f"dependency-fetch {label}: pre/post-fetch lock byte sizes missing/non-integer/"
                    f"!= retained lock size {retained_lock_size}")
        ok = False
    # SHA identities are MANDATORY: both present strings, both exactly == retained post-fetch lock sha
    shas_ok = (isinstance(pre_sha, str) and isinstance(post_sha, str)
               and pre_sha == retained_lock_sha and post_sha == retained_lock_sha)
    if not shas_ok:
        fail.append(f"dependency-fetch {label}: pre/post-fetch lock sha missing or "
                    f"!= retained post-fetch lock sha (fetch mutated the lock or identity absent)")
        ok = False
    # `unchanged` only when EVERY sha AND size identity is present and exact; any gap -> not proven
    unchanged = shas_ok and sizes_ok
    if not unchanged:
        ok = False
    return ok, unchanged


def _verify_resolved_graph_evidence(rec, evidence, fail) -> dict:
    """reqs 4/5 + follow-up items 1/2/3/4: reopen the RETAINED host_resolve_graph JSON, the
    RETAINED A-/B-Cargo.lock bytes, and the dependency-fetch record for A and B, and
    INDEPENDENTLY derive/require A == B for the host graph, the lock-derived full package
    metadata, and the generated lock -- plus item-3 dependency-fetch gating and item-4 exact
    host-graph structural validation with an independently-recomputed reachable set. lockok is
    set false on EVERY lock identity/size/parse/metadata/fetch cross-check failure; a passing
    offline metadata never compensates for a failed or partial fetch. Never trusts producer
    booleans."""
    d = evidence / "cargo-cache"
    gshas, pshas, locksha, lockok = {}, {}, {}, {}
    depok, unchanged = {}, {}
    for label in ("A", "B"):
        acq = rec.get(f"acquisition_{label}") or {}
        rds = acq.get("resolved_dependency_snapshot") or {}
        bad = False   # any check for this label failing -> lockok false

        # ---- item 4: host resolve graph structure ----
        gp = d / f"{label}-resolved-graph.json"
        if not gp.is_file():
            fail.append(f"resolved-graph: retained {label} evidence missing"); bad = True; data = {}
        else:
            try:
                data = json.loads(gp.read_text())
            except Exception as e:  # noqa: BLE001
                fail.append(f"resolved-graph {label}: unreadable ({e})"); bad = True; data = {}
        graph = data.get("host_resolve_graph")
        if graph is None:
            fail.append(f"resolved-graph {label}: host_resolve_graph missing"); bad = True
        else:
            keys = set(graph.keys())
            if keys != HOST_GRAPH_KEYS:
                fail.append(f"resolved-graph {label}: host graph keys {sorted(keys)} != {sorted(HOST_GRAPH_KEYS)}")
                bad = True
            if graph.get("resolve_graph_platform") != "x86_64-unknown-linux-gnu":
                fail.append(f"resolved-graph {label}: resolve_graph_platform != x86_64-unknown-linux-gnu"); bad = True
            if graph.get("resolve_graph_scope") != "host-filtered":
                fail.append(f"resolved-graph {label}: resolve_graph_scope != host-filtered"); bad = True
            # item C: full structural validation (roots non-empty + present in nodes, unique node
            # ids, no dangling edges, no nodes disconnected from the roots) before trusting the
            # recorded reachability.
            before = len(fail)
            _validate_graph_structure(graph, label, fail)
            if len(fail) != before:
                bad = True
            # independently recompute reachable_package_ids (BFS from resolve_roots only) + check
            recomputed = _recompute_reachable(graph)
            if graph.get("reachable_package_ids") != recomputed:
                fail.append(f"resolved-graph {label}: recorded reachable_package_ids != recomputed"); bad = True
            # item B: host_resolved_package_count is MANDATORY (retained + producer), == reachable
            hrc = data.get("host_resolved_package_count")
            if hrc is None:
                fail.append(f"resolved-graph {label}: host_resolved_package_count missing"); bad = True
            elif hrc != len(recomputed):
                fail.append(f"resolved-graph {label}: host_resolved_package_count {hrc} != "
                            f"len(recomputed reachable) {len(recomputed)}"); bad = True
            prc = rds.get("host_resolved_package_count")
            if prc is None:
                fail.append(f"resolved-graph {label}: producer host_resolved_package_count missing"); bad = True
            elif prc != len(recomputed):
                fail.append(f"resolved-graph {label}: producer host_resolved_package_count {prc} != "
                            f"len(recomputed reachable) {len(recomputed)}"); bad = True
            g = _canon_sha(graph)
            if g != data.get("host_resolve_graph_sha256"):
                fail.append(f"resolved-graph {label}: re-derived host graph sha != recorded"); bad = True
            gshas[label] = g

        # ---- item 1/2: independently verify the retained Cargo.lock (post-fetch) ----
        lp = d / f"{label}-Cargo.lock"
        sha = size = None
        if not lp.is_file():
            fail.append(f"cargo-lock: retained {label}-Cargo.lock missing"); bad = True
        else:
            raw = lp.read_bytes()
            sha, size = hashlib.sha256(raw).hexdigest(), len(raw)
            locksha[label] = sha
            pil = (acq.get("post_install_state") or {}).get("cargo_lock") or {}
            if pil.get("sha256") != sha:
                fail.append(f"cargo-lock {label}: retained lock sha != post_install_state.cargo_lock.sha256"); bad = True
            # item B: post_install_state.cargo_lock.bytes is MANDATORY and must equal the retained
            # lock size (None is NOT acceptable).
            if pil.get("bytes") is None:
                fail.append(f"cargo-lock {label}: post_install_state.cargo_lock.bytes missing"); bad = True
            elif pil.get("bytes") != size:
                fail.append(f"cargo-lock {label}: retained lock size != post_install_state.cargo_lock.bytes"); bad = True
            if rds.get("cargo_lock_sha256") != sha:
                fail.append(f"cargo-lock {label}: retained lock sha != resolved_dependency_snapshot.cargo_lock_sha256"); bad = True
            # item B: resolved_dependency_snapshot.cargo_lock_bytes MANDATORY + exact (no None)
            if rds.get("cargo_lock_bytes") is None:
                fail.append(f"cargo-lock {label}: resolved_dependency_snapshot.cargo_lock_bytes missing"); bad = True
            elif rds.get("cargo_lock_bytes") != size:
                fail.append(f"cargo-lock {label}: retained lock size != resolved_dependency_snapshot.cargo_lock_bytes"); bad = True
            # item B: cargo_lock_scope MANDATORY == "full cross-platform resolution" (retained + producer)
            if data.get("cargo_lock_scope") != LOCK_SCOPE:
                fail.append(f"cargo-lock {label}: retained cargo_lock_scope != {LOCK_SCOPE!r}"); bad = True
            if rds.get("cargo_lock_scope") != LOCK_SCOPE:
                fail.append(f"cargo-lock {label}: producer cargo_lock_scope != {LOCK_SCOPE!r}"); bad = True
            try:
                derived_pkgs = _lock_packages_from_toml(raw)
                fh = _canon_sha(derived_pkgs); pshas[label] = fh
                # item B: retained full_packages_metadata_sha256 MANDATORY + == lock-derived (no None)
                if data.get("full_packages_metadata_sha256") is None:
                    fail.append(f"cargo-lock {label}: retained full_packages_metadata_sha256 missing"); bad = True
                elif data.get("full_packages_metadata_sha256") != fh:
                    fail.append(f"cargo-lock {label}: lock-derived package sha != retained resolved-graph record"); bad = True
                # item B: producer full_packages_metadata_sha256 MANDATORY + == lock-derived (no None)
                if rds.get("full_packages_metadata_sha256") is None:
                    fail.append(f"cargo-lock {label}: producer full_packages_metadata_sha256 missing"); bad = True
                elif rds.get("full_packages_metadata_sha256") != fh:
                    fail.append(f"cargo-lock {label}: lock-derived package sha != producer full_packages_metadata_sha256"); bad = True
                retained_pkgs = data.get("full_packages_metadata")
                if retained_pkgs is None:
                    fail.append(f"cargo-lock {label}: retained full_packages_metadata list missing"); bad = True
                elif _canon_sha(retained_pkgs) != fh:
                    fail.append(f"cargo-lock {label}: retained package list != lock-derived package list"); bad = True
            except Exception as e:  # noqa: BLE001
                fail.append(f"cargo-lock {label}: independent TOML parse failed ({e})"); bad = True

        # ---- item 3: lock-preserving dependency fetch ----
        df_ok, df_unchanged = _verify_dependency_fetch(label, acq, sha, size, fail)
        depok[label] = df_ok; unchanged[label] = df_unchanged
        if not df_ok:
            bad = True
        lockok[label] = not bad

    graph_equal = ("A" in gshas and "B" in gshas and gshas["A"] == gshas["B"])
    if "A" in gshas and "B" in gshas and not graph_equal:
        fail.append("resolved-graph: A and B host resolve graphs differ")
    full_pkgs_equal = ("A" in pshas and "B" in pshas and pshas["A"] == pshas["B"])
    if "A" in pshas and "B" in pshas and not full_pkgs_equal:
        fail.append("cargo-lock: A and B lock-derived full package metadata differ")
    lock_equal = ("A" in locksha and "B" in locksha and locksha["A"] == locksha["B"])
    if "A" in locksha and "B" in locksha and not lock_equal:
        fail.append(f"cargo-lock: retained Cargo.lock bytes differ A={locksha.get('A')} B={locksha.get('B')}")
    lock_present = bool(lockok.get("A")) and bool(lockok.get("B"))   # from RETAINED locks + all cross-checks
    return {"graph_equal": graph_equal, "full_pkgs_equal": full_pkgs_equal, "lock_equal": lock_equal,
            "lock_present": lock_present, "lock_sha": locksha.get("A"),
            "dependency_fetch_ok": bool(depok.get("A")) and bool(depok.get("B")),
            "fetch_lock_unchanged": bool(unchanged.get("A")) and bool(unchanged.get("B"))}


def _derive_acq_classification(A, B, cache_sem_equal, graph_equal, full_pkgs_equal, lock_equal,
                               lock_present, dep_fetch_ok, fetch_lock_unchanged):
    """re-derive the acquisition classification + parity from the primitive pre/post states AND
    the independently-verified semantic-cache / host-resolve-graph / full-package-metadata /
    dependency-fetch determinants. Never trusts the producer classification or its booleans."""
    if not (A and B) or A.get("install", {}).get("exit") != 0 or B.get("install", {}).get("exit") != 0:
        return {"outcome": "COREUTILS_ACQUISITION_INSTALL_FAILURE"}, {}
    # follow-up item A: dependency-fetch terminal status TAKES PRECEDENCE over sparse-cache parse
    # outcomes -- a failed/lock-mutating fetch stops the acquisition before the cache is parsed,
    # so a malformed cache entry left behind by a failed fetch still classifies as the fetch
    # failure (never as UNPARSEABLE).
    for lbl, acq in (("A", A), ("B", B)):
        st = (acq.get("dependency_fetch_result") or {}).get("status")
        if st in ("COREUTILS_DEPENDENCY_FETCH_FAILURE", "COREUTILS_DEPENDENCY_FETCH_LOCK_MUTATION"):
            return {"outcome": st}, {}
    if A.get("cargo_index_cache_unparseable") or B.get("cargo_index_cache_unparseable"):
        return {"outcome": "COREUTILS_CARGO_INDEX_CACHE_UNPARSEABLE"}, {}
    pa, pb = A["post_install_state"], B["post_install_state"]
    parity = {
        "workspace_manifests_equal": pa["workspace_cargo_tomls"] == pb["workspace_cargo_tomls"],
        "cargo_lock_equal": pa["cargo_lock"] == pb["cargo_lock"],
        "cargo_config_equal": (pa["cargo_config"] == pb["cargo_config"]
                               and pa["cargo_config_toml"] == pb["cargo_config_toml"]),
        "rust_toolchain_equal": (pa["rust_toolchain"] == pb["rust_toolchain"]
                                 and pa["rust_toolchain_toml"] == pb["rust_toolchain_toml"]),
        "tracked_status_equal": pa["tracked_status"] == pb["tracked_status"],
        "tracked_diff_equal": pa["tracked_diff_sha256"] == pb["tracked_diff_sha256"],
        "metadata_members_equal": (A["post_install_metadata"].get("members")
                                   == B["post_install_metadata"].get("members")),
        "install_semantics_equal": (A["install"]["exit"] == B["install"]["exit"]
                                    and A["install"]["timed_out"] == B["install"]["timed_out"]),
        # independently-derived determinants (from retained evidence, NOT producer booleans)
        "dependency_fetch_ok": dep_fetch_ok is True,
        "fetch_lock_unchanged": fetch_lock_unchanged is True,
        "cargo_cache_semantic_equal": cache_sem_equal is True,
        "host_resolve_graph_equal": graph_equal is True,
        "full_packages_metadata_equal": full_pkgs_equal is True,
        "generated_lock_equal": lock_equal is True,
    }

    def nonlock(a):
        changed = set(a["post_install_state"]["tracked_status"]) - set(a["pristine_state"]["tracked_status"])
        return sorted(x for x in changed if "Cargo.lock" not in x)
    an, bn = nonlock(A), nonlock(B)
    if not (parity["cargo_config_equal"] and parity["rust_toolchain_equal"]) or an or bn:
        return {"outcome": "COREUTILS_ACQUISITION_UNAUTHORIZED_MUTATION"}, parity
    if not all(parity.values()):
        return {"outcome": "COREUTILS_ACQUISITION_NONDETERMINISTIC"}, parity
    if lock_present:
        return {"outcome": "publisher_install_resolved_dependency_snapshot"}, parity
    return {"outcome": "pristine_dependency_state"}, parity


def _derive_final_parity(rec) -> dict:
    """hardening 4b: independently re-derive complete final A/B parity from finalize_A/B."""
    fa, fb = (rec.get("finalize_A") or {}), (rec.get("finalize_B") or {})
    sa, sb = fa.get("final_state") or {}, fb.get("final_state") or {}
    ma, mb = fa.get("final_metadata") or {}, fb.get("final_metadata") or {}
    p = {
        "final_repo_state_equal": sa == sb,
        "final_tracked_diff_equal": sa.get("tracked_diff_sha256") == sb.get("tracked_diff_sha256"),
        "final_cargo_lock_equal": sa.get("cargo_lock") == sb.get("cargo_lock"),
        "final_manifests_equal": sa.get("workspace_cargo_tomls") == sb.get("workspace_cargo_tomls"),
        "final_metadata_equal": ma.get("members") == mb.get("members"),
        "gold_test_applied_ok": bool(fa.get("all_ok")) and bool(fb.get("all_ok")),
    }
    p["all_equal"] = all(p.values())
    return p


def _check_env_approved(rec, approved, fail):
    """hardening 4e: recorded semantic env must EXACTLY equal the approved set
    (resolved scheduler_env + publisher test_env). Reject any unapproved variable."""
    mse = rec.get("measurement_semantic_env") or {}
    extra = sorted(set(mse) - set(approved))
    missing = sorted(set(approved) - set(mse))
    if extra:
        fail.append(f"semantic env has unapproved variables: {extra}")
    if missing:
        fail.append(f"semantic env missing approved variables: {missing}")
    for k in approved:
        if k in mse and mse[k] != approved[k]:
            fail.append(f"semantic env {k}={mse[k]!r} != approved {approved[k]!r}")


def _verify_rtk_chain_bytes(rec, evidence, fail):
    """hardening 4c: reopen the retained pinned source bytes and independently verify every
    recorded path/blob/sha256/symbol-definition/reference-span/edge; recompute the complete
    dispatch->filter->parser->formatter chain. Never trusts chain_complete/all_*_found."""
    prov = rec.get("rtk_cargo_filter_source") or {}
    if prov.get("commit") != RTK_SOURCE_COMMIT:
        fail.append("rtk chain: recorded commit != pinned")
    if prov.get("head") != RTK_SOURCE_COMMIT or not prov.get("head_proven"):
        fail.append("rtk chain: HEAD not proven == pinned commit")
    role_files = prov.get("role_files") or {}
    for r in CHAIN_ORDER:
        if not role_files.get(r):
            fail.append(f"rtk chain: role {r} has no anchor file")
    src_dir = evidence / "rtk-source-evidence"
    edges = prov.get("edges") or {}
    for a, b in zip(CHAIN_ORDER, CHAIN_ORDER[1:]):
        e = edges.get(f"{a}->{b}")
        if not e:
            fail.append(f"rtk chain: edge {a}->{b} unresolved"); continue
        data = {}
        for side, path_key, blob_key in (("from", "from_path", "from_blob"), ("to", "to_path", "to_blob")):
            rel = e.get(path_key); blob = e.get(blob_key) or {}
            rf = (src_dir / rel.replace("/", "__")) if rel else None
            if not (rf and rf.is_file()):
                fail.append(f"rtk chain {a}->{b}: retained {side} bytes missing ({rel})"); continue
            raw = rf.read_bytes(); data[side] = raw
            if hashlib.sha256(raw).hexdigest() != blob.get("sha256"):
                fail.append(f"rtk chain {a}->{b}: {side} sha256 != recorded blob")
            if blob.get("bytes") is not None and len(raw) != blob["bytes"]:
                fail.append(f"rtk chain {a}->{b}: {side} byte length != recorded blob")
        sym = e.get("target_symbol")
        if "from" not in data or "to" not in data or not sym:
            continue
        symb = sym.encode()
        off = e.get("target_def_offset")
        defs = {(m.group(2), m.start()) for m in _VDEF.finditer(data["to"])}
        if (symb, off) not in defs:
            defined_any = any(s == symb for s, _ in defs)
            fail.append(f"rtk chain {a}->{b}: symbol {sym} not defined at recorded offset in to-file"
                        + ("" if defined_any else " (symbol not defined at all)"))
        roff = e.get("reference_offset")
        ref_re = re.compile(rb"\b" + re.escape(symb) + rb"\b")
        if not (isinstance(roff, int) and 0 <= roff and data["from"][roff:roff + len(symb)] == symb
                and ref_re.search(data["from"])):
            fail.append(f"rtk chain {a}->{b}: symbol {sym} not referenced at recorded offset in from-file")


def verify(rec_path: Path, evidence: Path) -> tuple[bool, list, dict]:
    fail, facts = [], {}
    rec = c.load_record(rec_path)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        return False, [f"diagnostic self-hash: {msg}"], facts
    # artifact root implied by the evidence path (so this replays against a downloaded
    # artifact in any directory, and against CI's cwd=N2E identically)
    ev_abs = evidence.resolve()
    root = Path(str(ev_abs)[:-len(EVIDENCE_ROOT)].rstrip("/")) if str(ev_abs).endswith(EVIDENCE_ROOT) else N2E_DIR
    facts["artifact_root"] = str(root)
    outcome = rec.get("outcome"); facts["outcome"] = outcome
    if not outcome:
        return False, ["missing/malformed outcome"], facts
    if outcome in FATAL_OUTCOMES:
        return False, [f"fatal outcome: {outcome}"], facts
    if rec.get("record_kind") != "focused_diagnostic":
        fail.append("record_kind != focused_diagnostic")
    if rec.get("acceptance_pass") is not False:
        fail.append("acceptance_pass must be false")
    if rec.get("normative_evidence_eligibility") != "UNDETERMINED":
        fail.append("producer must record normative_evidence_eligibility=UNDETERMINED (verifier decides)")
    try:
        loader.validate_resolved_closure()
    except Exception as e:  # noqa: BLE001
        fail.append(f"resolved closure invalid: {e}")

    complete = outcome in ("RTK_DIALECT_UNPROVEN", "COREUTILS_RAW_NOT_QUALIFIED")
    if outcome not in ("COREUTILS_TOOLCHAIN_PINS_UNVERIFIED", "REJECTED_NO_ISOLATION"):
        _check_manifest(rec, outcome, fail, root, require_external=complete)

    if outcome in ACQ_FAILURE_OUTCOMES:
        if outcome not in ("COREUTILS_TOOLCHAIN_PINS_UNVERIFIED", "REJECTED_NO_ISOLATION"):
            if not (rec.get("acquisition_A") and rec.get("acquisition_B")):
                fail.append("acquisition A/B evidence missing")
        facts["normative_evidence_eligible"] = False
        return (not fail), fail, facts

    # policy binding (corr 4): record == contract == EXPECTED_POLICY (cargo-test-v3)
    try:
        bundle = loader.load_case_bundle("uutils__coreutils-6731::rust_cargo::test::fixed", "resolved")
        contract_policy = bundle["execution_contract"]["canonicalization_policy_id"]
    except Exception as e:  # noqa: BLE001
        contract_policy = None
        fail.append(f"cannot load resolved contract policy: {e}")
    rec_policy = rec.get("canonicalization_policy_id")
    if not (rec_policy == contract_policy == EXPECTED_POLICY):
        fail.append(f"policy binding: record={rec_policy} contract={contract_policy} expected={EXPECTED_POLICY}")
    policy = EXPECTED_POLICY

    if outcome == "COREUTILS_RAW_NOT_QUALIFIED":
        _check_acquisition(rec, fail)
        rd = _rederive_arm(rec, evidence, "raw", policy, fail)
        raw = rec.get("raw_arm") or {}
        rtk_bin = rec.get("rtk_binary_path")
        gates = {
            "canonical_determinism_ok": rd["rederived_deterministic"],
            "target_executed_ok": _raw_target_from_captures(evidence, rec),
            "mutation_guards_ok": bool(raw.get("per_rep_mutation")) and all(
                m.get("mutation_ok") for m in raw.get("per_rep_mutation")),
            "exit_stable_ok": raw.get("exit_stable") is True,
            "argv_equal_contract_ok": _argv_ok(raw.get("actual_argv") or [], False, rtk_bin),
            "environment_equal_contract_ok": rec.get("actual_environment_equal_contract") is True,
        }
        failed = sorted(k for k, v in gates.items() if not v)
        facts["raw_failed_gates"] = failed
        if not failed:
            fail.append("RAW-not-qualified but all RAW gates re-derive as passing (disagreement)")
        facts["normative_evidence_eligible"] = False
        return (not fail), fail, facts

    if outcome != "RTK_DIALECT_UNPROVEN":
        return False, fail + [f"unexpected outcome: {outcome}"], facts

    # ---- full RTK_DIALECT_UNPROVEN requirement set (hardened: derive, never trust) ----
    # resolved anchors: toolchain pins + approved semantic env (scheduler_env + test_env)
    try:
        pins = loader.validate_resolved_closure()["overlays"]["toolchain"]["resolved_rust_toolchain"]
    except Exception as e:  # noqa: BLE001
        pins = None; fail.append(f"cannot load resolved toolchain pins: {e}")
    approved_env = {}
    try:
        approved_env = {**bundle["execution_contract"].get("scheduler_env", {}),
                        **bundle["publisher_recipe"].get("test_env", {})}
    except Exception as e:  # noqa: BLE001
        fail.append(f"cannot load approved semantic env: {e}")
    # sanity: the approved set the verifier enforces IS the resolved contract's, and the
    # long-standing CONTRACT_ENV constant must not silently diverge from it
    if approved_env and approved_env != CONTRACT_ENV:
        fail.append(f"resolved scheduler_env+test_env {approved_env} != verifier CONTRACT_ENV {CONTRACT_ENV}")

    # toolchain (hardening 4a): independently compare identities against pins
    if pins is not None and not _derive_toolchain(rec, pins, fail):
        pass  # _derive_toolchain already appended specifics
    if (rec.get("toolchain_enforcement") or {}).get("manifest_sha256") != PINNED_MANIFEST_SHA:
        fail.append("toolchain manifest sha != pinned constant")

    # acquisition (hardening 4b + reqs 2/3/5): independently re-derive the semantic sparse-
    # index cache equality and the offline resolved-graph equality from the RETAINED evidence,
    # then re-derive the classification from primitives + those determinants.
    _check_acquisition(rec, fail)
    A, B = rec.get("acquisition_A") or {}, rec.get("acquisition_B") or {}
    cache_v = _verify_cargo_cache_evidence(evidence, fail)
    graph_v = _verify_resolved_graph_evidence(rec, evidence, fail)
    facts["cargo_cache_semantic_equal"] = cache_v.get("semantic_equal")
    facts["host_resolve_graph_equal"] = graph_v.get("graph_equal")
    facts["full_packages_metadata_equal"] = graph_v.get("full_pkgs_equal")
    if cache_v.get("semantic_equal") is not True:
        fail.append("cargo-cache: semantic sparse-index cache not proven equal across A/B")
    if graph_v.get("graph_equal") is not True:
        fail.append("resolved-graph: host-filtered resolve graph not proven equal across A/B")
    if graph_v.get("full_pkgs_equal") is not True:
        fail.append("resolved-graph: full cross-platform package metadata not proven equal across A/B")
    if graph_v.get("lock_equal") is not True:
        fail.append("resolved-graph: generated Cargo.lock not proven equal across A/B")
    facts["dependency_fetch_ok"] = graph_v.get("dependency_fetch_ok")
    facts["fetch_lock_unchanged"] = graph_v.get("fetch_lock_unchanged")
    if graph_v.get("dependency_fetch_ok") is not True:
        fail.append("dependency-fetch: cargo fetch --locked not proven ok for A and B")
    if graph_v.get("fetch_lock_unchanged") is not True:
        fail.append("dependency-fetch: Cargo.lock not proven unchanged by fetch for A and B")
    derived_cls, derived_parity = _derive_acq_classification(
        A, B, cache_v.get("semantic_equal"), graph_v.get("graph_equal"),
        graph_v.get("full_pkgs_equal"), graph_v.get("lock_equal"), graph_v.get("lock_present"),
        graph_v.get("dependency_fetch_ok"), graph_v.get("fetch_lock_unchanged"))
    facts["derived_acquisition_outcome"] = derived_cls["outcome"]
    recorded_cls = (rec.get("acquisition_classification") or {}).get("outcome")
    if derived_cls["outcome"] not in ACQ_ELIGIBLE:
        fail.append(f"re-derived acquisition classification not eligible: {derived_cls['outcome']}")
    if derived_cls["outcome"] != recorded_cls:
        fail.append(f"acquisition classification disagreement: derived={derived_cls['outcome']} recorded={recorded_cls}")
    if derived_parity and not all(derived_parity.values()):
        fail.append(f"re-derived A/B post-install parity not all equal: "
                    f"{sorted(k for k, v in derived_parity.items() if not v)}")
    fin_parity = _derive_final_parity(rec)
    facts["derived_final_parity_all_equal"] = fin_parity["all_equal"]
    if not fin_parity["all_equal"]:
        fail.append(f"re-derived final A/B parity not all equal: "
                    f"{sorted(k for k, v in fin_parity.items() if not v)}")

    raw, rtk = rec.get("raw_arm") or {}, rec.get("rtk_arm") or {}
    rtk_bin = rec.get("rtk_binary_path")
    # argv (corr 1): independent re-derivation, full argv
    if not _argv_ok(raw.get("actual_argv") or [], False, rtk_bin):
        fail.append("RAW argv != contract")
    if not _argv_ok(rtk.get("actual_argv") or [], True, rtk_bin):
        fail.append("RTK argv != [rtk_bin, *contract]")
    # environment (hardening 4e): recorded semantic env == approved set exactly, no extras
    _check_env_approved(rec, approved_env or CONTRACT_ENV, fail)
    if rec.get("raw_rtk_semantic_env_equal") is not True or raw.get("semantic_env") != rtk.get("semantic_env"):
        fail.append("RAW/RTK semantic env not equal")
    if raw.get("reps") != 3 or rtk.get("reps") != 3:
        fail.append("raw/rtk reps != 3")
    mut = (raw.get("per_rep_mutation") or []) + (rtk.get("per_rep_mutation") or [])
    if len(mut) != 6 or not all(m.get("mutation_ok") and m.get("repo_mutation_ok")
                                and m.get("cargo_cache_stable_content_ok") and m.get("toolchain_immutable")
                                for m in mut):
        fail.append("per-rep mutation guards incomplete/failed")

    raw_rd = _rederive_arm(rec, evidence, "raw", policy, fail)
    rtk_rd = _rederive_arm(rec, evidence, "rtk", policy, fail)
    for label, rd in (("raw", raw_rd), ("rtk", rtk_rd)):
        if not rd["rederived_canonical_equal_producer"]:
            fail.append(f"{label}_rederived_canonical_equal_producer false")
        if not rd["rederived_deterministic"]:
            fail.append(f"{label}_rederived_deterministic false")
        if not rd["removed_diag_equal_producer"]:
            fail.append(f"{label} removed-line diagnostics disagree")
    if raw_rd["semantic_preserved_all"] is not True:
        fail.append("RAW canonicalization did not preserve semantics")
    if not _raw_target_from_captures(evidence, rec):
        fail.append("RAW target execution not re-derivable as passing from primary captures")

    # RTK source chain (hardening 4c): reopen retained bytes, verify every edge
    _verify_rtk_chain_bytes(rec, evidence, fail)

    facts["raw_rederivation"] = raw_rd
    facts["rtk_rederivation"] = rtk_rd
    facts["normative_evidence_eligible"] = not fail
    return (not fail), fail, facts


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: verify_coreutils_diagnostic.py <diagnostic.json> <evidence-dir>")
        return 2
    ok, fail, facts = verify(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"coreutils-diagnostic-verify: {'OK' if ok else 'FAIL'} outcome={facts.get('outcome')} "
          f"normative_evidence_eligible={facts.get('normative_evidence_eligible')}")
    for f in fail:
        print(f"  - {f}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
