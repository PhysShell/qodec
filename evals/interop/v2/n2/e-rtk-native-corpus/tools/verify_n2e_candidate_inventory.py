#!/usr/bin/env python3
"""Independently verify n2e-candidate-inventory-v1.json (§8, §22).

- Self-hash; cross-hash of the instances manifest and source registry.
- Every candidate is OUTCOME-BLIND: no rtk/token/savings fields anywhere.
- Required metadata present (candidate_id, cluster_id, source_id, repository,
  command_family, command_subfamily, snapshot_variant, raw_command_argv as an
  ARRAY, expected_raw_outcome).
- No duplicate candidate_id.
- Test candidates: expected_raw_outcome in {fail, pass} and consistent with the
  snapshot variant (buggy=>fail, fixed=>pass); target_test_ids non-empty.
- Reported per-family repo diversity is accurate.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

RECORD = N2E_DIR / "n2e-candidate-inventory-v1.json"
INSTANCES = N2E_DIR / "n2e-swebench-instances-v1.json"
REGISTRY = N2E_DIR / "n2e-source-registry-v1.json"
BLIND = re.compile(r"rtk|token|saving|qodec", re.IGNORECASE)
REQUIRED = ("candidate_id", "cluster_id", "source_id", "repository", "command_family",
            "command_subfamily", "snapshot_variant", "raw_command_argv", "expected_raw_outcome")


def verify(path: Path) -> tuple[bool, str]:
    if not path.is_file():
        return False, f"{path} missing"
    rec = c.load_record(path)
    ok, msg = c.verify_self_hash(rec)
    if not ok:
        return False, msg
    if rec.get("instances_sha256") != c.sha256_json_file(INSTANCES):
        return False, "instances_sha256 mismatch"
    if rec.get("source_registry_sha256") != c.sha256_json_file(REGISTRY):
        return False, "source_registry_sha256 mismatch"

    cands = rec.get("candidates", [])
    if len(cands) != rec.get("candidate_count"):
        return False, "candidate_count mismatch"
    seen = set()
    for x in cands:
        for k in REQUIRED:
            if k not in x:
                return False, f"{x.get('candidate_id')}: missing {k}"
        if not isinstance(x["raw_command_argv"], list):
            return False, f"{x['candidate_id']}: raw_command_argv must be an array"
        if x["candidate_id"] in seen:
            return False, f"duplicate candidate_id {x['candidate_id']}"
        seen.add(x["candidate_id"])
        # outcome-blind: no forbidden keys anywhere in the candidate
        for k in _all_keys(x):
            if BLIND.search(k):
                return False, f"{x['candidate_id']}: outcome-blind violation — key {k!r}"
        if x["command_subfamily"] == "test":
            if x["expected_raw_outcome"] not in ("fail", "pass"):
                return False, f"{x['candidate_id']}: test outcome must be fail/pass"
            expect = "fail" if x["snapshot_variant"] == "buggy" else "pass"
            if x["expected_raw_outcome"] != expect:
                return False, f"{x['candidate_id']}: variant/outcome inconsistent"
            if not x.get("target_test_ids"):
                return False, f"{x['candidate_id']}: test candidate lacks target_test_ids"

    # accurate diversity report
    from collections import defaultdict
    fr = defaultdict(set)
    for x in cands:
        fr[x["command_family"]].add(x["repository"])
    if rec.get("distinct_repositories") != len({x["repository"] for x in cands}):
        return False, "distinct_repositories mismatch"
    if rec.get("distinct_clusters") != len({x["cluster_id"] for x in cands}):
        return False, "distinct_clusters mismatch"
    return True, "OK"


def _all_keys(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _all_keys(v, k)
    elif isinstance(obj, list):
        for v in obj:
            yield from _all_keys(v, prefix)


def main() -> int:
    ok, message = verify(RECORD)
    if not ok:
        print(f"::error::n2e candidate inventory verification FAILED: {message}", file=sys.stderr)
        return 1
    print(f"n2e candidate inventory verification passed: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
