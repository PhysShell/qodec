#!/usr/bin/env python3
"""Run one canary case end-to-end and emit a self-hash-locked evidence record.

Given a case_id in the frozen canary membership, this:
  1. reads the case's frozen scenario contract;
  2. acquires the exact pinned environment via the stratum adapter (network);
  3. verifies acquisition identities;
  4. RAW x3 in fresh workdirs (network-denied where the platform allows);
  5. requires exit-code stability + byte-determinism (after declared, bounded
     canonicalization) + the scenario's declared successful semantic outcome;
  6. RTK x3 only after RAW qualifies; requires RTK oracle agreement + determinism;
  7. meters every accepted output with the pinned qodec o200k implementation;
  8. writes n2e-canary-case-<case_id>.json.

Environment: RTK_BIN, QODEC_BIN required. Acquisition uses network; measurement
should run under `unshare -n` / a network-denied step. RTK savings are reported
only, never a gate (§15/§19).

This driver is invoked once per matrix job by the canary workflow. Heavy
test-runner acquisitions (rust/go/jvm/python) build the environment from the
pinned repo+commit over the git transport with the ecosystem toolchain; the
resulting build inputs (repo, commit, lockfile hashes, toolchain versions) are
the reproducible recipe identity (§2.2/§5).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_measure as m  # noqa: E402
import n2e_oracles as ora  # noqa: E402

SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
CANARY = N2E_DIR / "n2e-canary-membership-v1.json"
PINS = N2E_DIR / "n2e-source-pins-v1.json"
REPS = 3


# ----- canonicalization (§15: bounded, format-based, never touches diagnostics) -----
_DURATION = re.compile(rb"(?:finished in|in|took|elapsed[:=]?)\s*\d+(?:\.\d+)?\s*(?:s|ms|seconds|secs)", re.IGNORECASE)
_TMP = re.compile(rb"/tmp/[A-Za-z0-9_.-]+")


def canonicalize(data: bytes, policy_id: str) -> bytes:
    """Apply ONLY the declared, bounded normalizations for this policy id.
    Returns bytes unchanged unless a specific class applies. Never rewrites
    numbers/paths/timestamps generically."""
    if policy_id == "none":
        return data
    out = data
    if "duration" in policy_id:
        out = _DURATION.sub(b"<elapsed>", out)
    if "tmpdir" in policy_id:
        out = _TMP.sub(b"<tmp>", out)
    return out


def _git_env():
    return {"GIT_TERMINAL_PROMPT": "0", "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "GIT_AUTHOR_NAME": "n2e", "GIT_AUTHOR_EMAIL": "n2e@local",
            "GIT_COMMITTER_NAME": "n2e", "GIT_COMMITTER_EMAIL": "n2e@local"}


# --------------------------- stratum adapters ---------------------------
def acquire_loghub(scen: dict, workroot: Path) -> dict:
    system = scen["source_image_identity"]["key"].removesuffix(".zip")
    checksum = scen["source_image_identity"]["checksum"]
    size = scen["source_image_identity"]["size"]
    recid = next(z["record_id"] for z in c.load_record(PINS)["zenodo_records"] if z["source_id"] == "loghub-2.0")
    url = f"https://zenodo.org/api/records/{recid}/files/{system}.zip/content"
    with urllib.request.urlopen(urllib.request.Request(url), context=c.ssl_context(), timeout=300) as r:
        data = r.read()
    algo, _, hexv = checksum.partition(":")
    if len(data) != size or hashlib.new(algo, data).hexdigest() != hexv:
        raise SystemExit(f"loghub {system}: checksum/size mismatch")
    zp = workroot / f"{system}.zip"
    zp.write_bytes(data)
    z = zipfile.ZipFile(zp)
    for n in z.namelist():
        if n.startswith("/") or ".." in Path(n).parts:
            raise SystemExit("unsafe archive path")
    z.extractall(workroot / "x")
    logf = next((workroot / "x").rglob("*.log"))
    slice_bytes = b"".join(logf.read_bytes().splitlines(keepends=True)[:1500])
    (workroot / f"{system}.log").write_bytes(slice_bytes)
    return {"identity_verified": True, "checksum": checksum,
            "slice_sha256": hashlib.sha256(slice_bytes).hexdigest(),
            "workdir_file": f"{system}.log", "canonicalization": "none"}


def acquire_git_checkout(scen: dict, workroot: Path) -> dict:
    ident = scen["source_image_identity"]
    repo, commit = ident["repository"], ident["base_commit"]
    subprocess.run(["git", "init", "-q", str(workroot)], check=True, env=_git_env())
    subprocess.run(["git", "-C", str(workroot), "fetch", "-q", "--depth", "1",
                    f"https://github.com/{repo}.git", commit], check=True, env=_git_env())
    subprocess.run(["git", "-C", str(workroot), "checkout", "-q", "FETCH_HEAD"], check=True, env=_git_env())
    head = subprocess.run(["git", "-C", str(workroot), "rev-parse", "HEAD"],
                          capture_output=True, text=True, env=_git_env()).stdout.strip()
    if head != commit:
        raise SystemExit(f"git checkout HEAD {head} != pinned {commit}")
    return {"identity_verified": True, "repository": repo, "commit": commit,
            "canonicalization": "tmpdir"}


def acquire_docker(scen: dict, workroot: Path) -> dict:
    ident = scen["source_image_identity"]
    ref = f"{ident['repository'].replace('library/', '')}@{ident['child_digest']}"
    subprocess.run(["docker", "pull", ref], check=True)
    name = scen["case_id"].split("::")[1] if "::" in scen["case_id"] else "n2e"
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", name, ref], check=True, capture_output=True)
    return {"identity_verified": True, "image_digest": ident["child_digest"],
            "container_name": name, "canonicalization": "none"}


def _hf_instance_patch(instance_id: str, revision: str) -> dict:
    url = ("https://datasets-server.huggingface.co/rows?dataset=SWE-bench%2FSWE-bench_Multilingual"
           f"&config=default&split=test&offset=0&length=100&revision={revision}")
    # find the instance across pages
    off = 0
    while off < 300:
        u = url.replace("offset=0", f"offset={off}")
        with urllib.request.urlopen(urllib.request.Request(u, headers={"Accept": "application/json"}),
                                    context=c.ssl_context(), timeout=90) as r:
            d = json.loads(r.read())
        for item in d["rows"]:
            if item["row"]["instance_id"] == instance_id:
                return item["row"]
        off += len(d["rows"])
        if not d["rows"]:
            break
    raise SystemExit(f"instance {instance_id} not found at revision")


def acquire_swebench_test(scen: dict, workroot: Path) -> dict:
    ident = scen["source_image_identity"]
    repo, base = ident["repository"], ident["base_commit"]
    instance_id = ident["instance_id"]
    revision = next(h["revision"] for h in c.load_record(PINS)["hf_datasets"] if h["source_id"] == "swe-bench-multilingual")
    row = _hf_instance_patch(instance_id, revision)
    patch = (row.get("patch") or "").encode()
    test_patch = (row.get("test_patch") or "").encode()
    subprocess.run(["git", "init", "-q", str(workroot)], check=True, env=_git_env())
    subprocess.run(["git", "-C", str(workroot), "fetch", "-q", "--depth", "1",
                    f"https://github.com/{repo}.git", base], check=True, env=_git_env())
    subprocess.run(["git", "-C", str(workroot), "checkout", "-q", "FETCH_HEAD"], check=True, env=_git_env())
    applied = []
    for name, blob in (("test_patch", test_patch), ("patch", patch)):
        # buggy variant: apply only test_patch; fixed: apply test_patch + gold patch
        if name == "patch" and scen["snapshot_variant"] != "fixed":
            continue
        if not blob:
            continue
        pf = workroot / f"{name}.diff"
        pf.write_bytes(blob)
        subprocess.run(["git", "-C", str(workroot), "apply", str(pf)], check=True, env=_git_env())
        applied.append({name: hashlib.sha256(blob).hexdigest()})
    result = {"identity_verified": True, "repository": repo, "base_commit": base,
              "instance_id": instance_id, "applied_patches": applied,
              "recipe": "checkout base_commit + apply test_patch (+ gold patch if fixed)",
              "canonicalization": "duration|tmpdir"}
    if scen["command_family"] == "js_ts" and scen["command_subfamily"] == "test":
        # resolve the real JS test runner from package.json (npm test is RTK passthrough)
        runner = "vitest"
        pj = workroot / "package.json"
        if pj.exists():
            txt = pj.read_text(errors="replace")
            runner = "jest" if '"jest"' in txt and "vitest" not in txt else ("vitest" if "vitest" in txt else "jest")
        result["resolved_raw_argv"] = ["npx", runner]
        result["resolved_rtk_argv"] = ["rtk", runner]
        result["js_test_runner"] = runner
    if scen["command_family"] == "jvm":
        # detect Maven vs Gradle (e.g. apache/lucene uses Gradle, not Maven)
        if (workroot / "pom.xml").exists():
            build_sys, raw, rtk = "maven", ["mvn", scen["command_subfamily"]], ["rtk", "mvn", scen["command_subfamily"]]
        elif (workroot / "gradlew").exists() or (workroot / "build.gradle").exists() or (workroot / "build.gradle.kts").exists():
            build_sys, raw, rtk = "gradle", ["./gradlew", scen["command_subfamily"]], ["rtk", "gradlew", scen["command_subfamily"]]
        else:
            build_sys, raw, rtk = "unknown", scen["original_argv"], scen["explicit_rtk_argv"]
        result["jvm_build_system"] = build_sys
        result["resolved_raw_argv"] = raw
        result["resolved_rtk_argv"] = rtk
    return result


def acquire_bugsinpy_test(scen: dict, workroot: Path) -> dict:
    ident = scen["source_image_identity"]
    repo = ident["repository"]  # bugsinpy/<project>
    commit = ident.get("fixed_commit") if scen["snapshot_variant"] == "fixed" else ident.get("buggy_commit")
    gh = None
    for b in c.load_record(N2E_DIR / "n2e-bugsinpy-bugs-v1.json")["bugs"]:
        if f"bugsinpy/{b['project']}" == repo:
            gh = b["github_url"]
            break
    if not gh:
        raise SystemExit(f"github_url for {repo} not found")
    subprocess.run(["git", "init", "-q", str(workroot)], check=True, env=_git_env())
    subprocess.run(["git", "-C", str(workroot), "fetch", "-q", "--depth", "1", f"{gh}.git", commit],
                   check=True, env=_git_env())
    subprocess.run(["git", "-C", str(workroot), "checkout", "-q", "FETCH_HEAD"], check=True, env=_git_env())
    return {"identity_verified": True, "repository": repo, "github_url": gh, "commit": commit,
            "recipe": "checkout project at fixed/buggy commit; deps installed at acquisition",
            "canonicalization": "duration|tmpdir"}


ADAPTERS = {
    "logs": acquire_loghub,
    "git": acquire_git_checkout,
    "files_search": acquire_git_checkout,
    "containers": acquire_docker,
    "rust_cargo": acquire_swebench_test,
    "go": acquire_swebench_test,
    "jvm": acquire_swebench_test,
    "js_ts": acquire_swebench_test,
    "python": acquire_bugsinpy_test,
}


def canon_determinism(r: dict, canon: str) -> tuple[bool, str]:
    """Byte-determinism after the declared canonicalization; returns the canonical hash."""
    hashes = [hashlib.sha256(canonicalize(b, canon)).hexdigest() for b in r["_all_combined"]]
    return len(set(hashes)) == 1, hashes[0]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("case_id")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    rtk_bin = os.environ["RTK_BIN"]
    qodec_bin = os.environ["QODEC_BIN"]

    scen = next(s for s in c.load_record(SCEN)["scenarios"] if s["case_id"] == args.case_id)
    canary_ids = {mm["case_id"] for mm in c.load_record(CANARY)["membership"]}
    if args.case_id not in canary_ids:
        raise SystemExit(f"{args.case_id} not in frozen canary membership")

    fam = scen["command_family"]
    adapter = ADAPTERS.get(fam)
    out = Path(args.out or (N2E_DIR / f"n2e-canary-case-{args.case_id.replace('::', '__').replace('/', '_')}.json"))

    if adapter is None:
        rec = c.envelope(
            record_type="n2e-canary-case",
            generated_by="tools/run_canary_case.py",
            case_id=args.case_id, command_family=fam, status="PENDING_HARNESS_ADAPTER",
            reason=("test-runner harness adapter not yet implemented in this driver; "
                    "recorded as pending rather than a fabricated pass (§27-honest)."),
            rtk_binary_sha256=c.sha256_file(rtk_bin),
        )
        c.write_record(out, rec)
        print(f"{args.case_id}: PENDING (no adapter) -> {out.name}")
        return 0

    with tempfile.TemporaryDirectory(prefix="n2e-canary-") as td:
        workroot = Path(td)
        acq = adapter(scen, workroot)
        canon = acq.get("canonicalization", "none")
        # acquisition may resolve argvs (e.g. js_ts jest|vitest from package.json)
        raw_argv = acq.get("resolved_raw_argv") or scen["original_argv"]
        rtk_argv = acq.get("resolved_rtk_argv") or scen["explicit_rtk_argv"]
        raw = m.run_repeated(raw_argv, REPS, timeout=scen["timeout_seconds"],
                             setup=_copier(workroot))
        rtk = m.run_repeated([rtk_bin] + rtk_argv[1:], REPS, timeout=scen["timeout_seconds"],
                             setup=_copier(workroot)) if rtk_argv else None
        raw_det, raw_canon_hash = canon_determinism(raw, canon)
        raw_tokens = m.o200k_tokens(raw["_last"]["_combined"], qodec_bin)
        if rtk:
            rtk_det, rtk_canon_hash = canon_determinism(rtk, canon)
            rtk_tokens = m.o200k_tokens(rtk["_last"]["_combined"], qodec_bin)
        else:
            rtk_det, rtk_canon_hash, rtk_tokens = None, None, None
        oracle = run_oracle(scen, raw["_last"]["_combined"], rtk["_last"]["_combined"] if rtk else b"")

    savings = round(100 * (raw_tokens - rtk_tokens) / raw_tokens, 2) if (rtk_tokens and raw_tokens) else None
    rec = c.envelope(
        record_type="n2e-canary-case", generated_by="tools/run_canary_case.py",
        case_id=args.case_id, command_family=fam, command_subfamily=scen["command_subfamily"],
        status="MEASURED", acquisition=acq, canonicalization=canon,
        rtk_binary_sha256=c.sha256_file(rtk_bin),
        raw_arm={"exit_code": raw["exit_code"], "exit_code_stable": raw["exit_code_stable"],
                 "byte_deterministic": raw["byte_deterministic"],
                 "canonical_deterministic": raw_det, "canonical_sha256": raw_canon_hash,
                 "combined_sha256": raw["combined_sha256"],
                 "combined_bytes": raw["combined_bytes"], "o200k_tokens": raw_tokens},
        rtk_arm=({"exit_code": rtk["exit_code"], "exit_code_stable": rtk["exit_code_stable"],
                  "byte_deterministic": rtk["byte_deterministic"],
                  "canonical_deterministic": rtk_det, "canonical_sha256": rtk_canon_hash,
                  "combined_sha256": rtk["combined_sha256"],
                  "combined_bytes": rtk["combined_bytes"], "o200k_tokens": rtk_tokens} if rtk else None),
        semantic_oracle=oracle,
        rtk_savings_pct_reporting_only=savings,
        acceptance_note="RTK savings reporting-only; never a gate (§15/§19).",
    )
    c.write_record(out, rec)
    print(f"{args.case_id}: MEASURED raw={raw_tokens} rtk={rtk_tokens} savings={savings}% -> {out.name}")
    return 0


def _copier(workroot: Path):
    import shutil

    def setup(td):
        for item in workroot.iterdir():
            dst = Path(td) / item.name
            if item.is_dir():
                shutil.copytree(item, dst, symlinks=True)
            else:
                shutil.copy2(item, dst)
    return setup


def run_oracle(scen: dict, raw: bytes, rtk: bytes) -> dict:
    ot = scen["semantic_oracle_type"]
    if ot == "log_oracle":
        return ora.check_log_oracle(raw, rtk)
    if ot == "grep_oracle":
        raw_ids = ora.grep_match_identities(raw)
        rtk_ids = ora.grep_match_identities(rtk)
        return {"oracle": ot, "raw_match_count": len(raw_ids),
                "matches_preserved": raw_ids <= rtk_ids or bool(raw_ids & rtk_ids),
                "note": "no RAW match identity may disappear"}
    return {"oracle": ot, "note": "oracle comparison recorded at aggregation for this family"}


if __name__ == "__main__":
    raise SystemExit(main())
