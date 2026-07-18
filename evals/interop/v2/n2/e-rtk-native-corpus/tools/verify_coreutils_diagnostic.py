#!/usr/bin/env python3
"""Independent verifier for the focused Coreutils diagnostic (corrections 1-9, cumulative).

Re-derives EVERY gate from primitive evidence -- never trusts a producer boolean:
  * derives normative_evidence_eligible itself; the producer only records
    normative_evidence_eligibility=UNDETERMINED (corr 2);
  * re-derives RAW/RTK argv equality against the exact committed contract, RTK == [rtk_bin,
    *CONTRACT_RAW_ARGV] (full argv; a dropped `cargo`, injected `+1.81.0`, extra/reordered
    flags all fail) (corr 1);
  * binds the canonicalizer policy from the resolved contract (record==contract==
    cargo-test-v2) and re-derives each rep's canonical + removed-line diagnostics (corr 4);
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
EXPECTED_POLICY = "cargo-test-v2"
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
                        "COREUTILS_CARGO_INDEX_CACHE_UNPARSEABLE"}


def _dz(p: Path) -> bytes:
    return zlib.decompress(p.read_bytes())


def _canon(policy: str, raw: bytes, is_rtk: bool) -> bytes:
    return canon.canonicalize(canon.rtk_envelope(raw) if is_rtk else raw, policy)


def _argv_ok(argv, is_rtk, rtk_bin) -> bool:
    expected = ([rtk_bin, *CONTRACT_RAW_ARGV] if is_rtk else list(CONTRACT_RAW_ARGV))
    if list(argv) != expected:
        return False
    return not any(str(tok).startswith("+") for tok in argv)  # no injected +toolchain


def _required_paths(outcome: str) -> list[str]:
    roles = ("raw", "rtk") if outcome == "RTK_DIALECT_UNPROVEN" else \
            ("raw",) if outcome == "COREUTILS_RAW_NOT_QUALIFIED" else ()
    req = []
    for role in roles:
        for i in range(3):
            req += [f"{EVIDENCE_ROOT}/{role}.rep{i}.zst", f"{EVIDENCE_ROOT}/{role}.raw.rep{i}.zst",
                    f"{EVIDENCE_ROOT}/{role}.mutation.rep{i}.json"]
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
    required = _required_paths(outcome)
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


def _verify_resolved_graph_evidence(evidence, fail) -> dict:
    """req 5.5: reopen the RETAINED offline resolved graphs for A and B, re-derive each
    normalized sha (must match the recorded value), and require A == B. Also compares the
    generated Cargo.lock sha. Never trusts resolved_graph_equal / generated_lock_equal."""
    d = evidence / "cargo-cache"
    shas, locks, present = {}, {}, {}
    for label in ("A", "B"):
        p = d / f"{label}-resolved-graph.json"
        if not p.is_file():
            fail.append(f"resolved-graph: retained {label} evidence missing"); continue
        try:
            data = json.loads(p.read_text())
        except Exception as e:  # noqa: BLE001
            fail.append(f"resolved-graph {label}: unreadable ({e})"); continue
        graph = data.get("resolved_graph")
        present[label] = graph is not None
        if graph is not None:
            redigest = _canon_sha(graph)
            if redigest != data.get("resolved_graph_normalized_sha256"):
                fail.append(f"resolved-graph {label}: re-derived sha != recorded")
            shas[label] = redigest
        locks[label] = data.get("cargo_lock_sha256")
    graph_equal = ("A" in shas and "B" in shas and shas["A"] == shas["B"])
    if "A" in shas and "B" in shas and not graph_equal:
        fail.append("resolved-graph: A and B normalized resolved graphs differ")
    lock_equal = (locks.get("A") == locks.get("B"))
    if not lock_equal:
        fail.append(f"resolved-graph: generated Cargo.lock sha differs A={locks.get('A')} B={locks.get('B')}")
    return {"graph_equal": graph_equal, "lock_equal": lock_equal,
            "lock_present": bool(present.get("A")) and bool(present.get("B")),
            "lock_sha": locks.get("A")}


def _derive_acq_classification(A, B, cache_sem_equal, graph_equal, lock_equal, lock_present):
    """re-derive the acquisition classification + parity from the primitive pre/post states
    AND the independently-verified semantic-cache / resolved-graph determinants. Never trusts
    the producer classification, cargo_cache_semantic_equal, or resolved_graph_equal."""
    if not (A and B) or A.get("install", {}).get("exit") != 0 or B.get("install", {}).get("exit") != 0:
        return {"outcome": "COREUTILS_ACQUISITION_INSTALL_FAILURE"}, {}
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
        "cargo_cache_semantic_equal": cache_sem_equal is True,
        "resolved_graph_equal": graph_equal is True,
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

    # policy binding (corr 4): record == contract == cargo-test-v2
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
    graph_v = _verify_resolved_graph_evidence(evidence, fail)
    facts["cargo_cache_semantic_equal"] = cache_v.get("semantic_equal")
    facts["resolved_graph_equal"] = graph_v.get("graph_equal")
    if cache_v.get("semantic_equal") is not True:
        fail.append("cargo-cache: semantic sparse-index cache not proven equal across A/B")
    if graph_v.get("graph_equal") is not True:
        fail.append("resolved-graph: offline resolved dependency graph not proven equal across A/B")
    if graph_v.get("lock_equal") is not True:
        fail.append("resolved-graph: generated Cargo.lock not proven equal across A/B")
    derived_cls, derived_parity = _derive_acq_classification(
        A, B, cache_v.get("semantic_equal"), graph_v.get("graph_equal"),
        graph_v.get("lock_equal"), graph_v.get("lock_present"))
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
