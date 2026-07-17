#!/usr/bin/env python3
"""Build n2e-canary-membership-v1.json (§19) — the FROZEN 12 canary case ids.

Deterministic from the frozen 70-case selection using the same seed. The §19
composition is: 2 files/search, 2 git, 2 test runners from DIFFERENT ecosystems
(chosen from go/jvm, i.e. distinct from the dedicated rust/python/js single
picks), 1 build/lint, 1 Rust/Cargo, 1 Python, 1 JS/TS, 1 log, 1 Docker = 12.

Frozen BEFORE any RAW/RTK measurement. No token or savings input.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

OUT = N2E_DIR / "n2e-canary-membership-v1.json"
SEL = N2E_DIR / "n2e-selection-result-v1.json"
POLICY = N2E_DIR / "n2e-selection-policy-v1.json"
INV = N2E_DIR / "n2e-candidate-inventory-v1.json"

BUILD_LINT = {"build", "check", "clippy", "vet", "tsc", "lint", "ruff"}

# Canary slots evaluated in order against the 70 selected cases. Each predicate is
# metadata-only; picks are seed-ordered and mutually exclusive.
CANARY_SLOTS = [
    ("files_search_1", lambda s: s["command_family"] == "files_search", 2),
    ("git_1", lambda s: s["command_family"] == "git", 2),
    ("test_generic", lambda s: s["command_family"] in ("go", "jvm") and s["command_subfamily"] == "test", 2),
    ("build_lint", lambda s: s["command_subfamily"] in BUILD_LINT, 1),
    ("rust", lambda s: s["command_family"] == "rust_cargo" and s["command_subfamily"] == "test", 1),
    ("python", lambda s: s["command_family"] == "python" and s["command_subfamily"] == "pytest", 1),
    ("js_ts", lambda s: s["command_family"] == "js_ts" and s["command_subfamily"] == "test", 1),
    ("log", lambda s: s["command_family"] == "logs", 1),
    ("docker", lambda s: s["command_family"] == "containers", 1),
]


def _order_key(seed: int, cid: str) -> str:
    return hashlib.sha256(f"{seed}:{cid}".encode()).hexdigest()


def build() -> dict:
    sel = c.load_record(SEL)
    pol = c.load_record(POLICY)
    seed = pol["seed"]
    cases = sel["selection"]
    picked_ids = set()
    ecosystems_used = set()
    membership = []
    for slot_id, pred, count in CANARY_SLOTS:
        elig = [s for s in cases if pred(s) and s["case_id"] not in picked_ids]
        elig.sort(key=lambda s: s["case_id"])
        elig.sort(key=lambda s: _order_key(seed, s["case_id"]))
        got = 0
        for s in elig:
            if got >= count:
                break
            # test_generic must span two DIFFERENT ecosystems
            if slot_id == "test_generic":
                if s["command_family"] in ecosystems_used:
                    continue
                ecosystems_used.add(s["command_family"])
            membership.append({"canary_slot": slot_id, "case_id": s["case_id"],
                               "command_family": s["command_family"],
                               "command_subfamily": s["command_subfamily"]})
            picked_ids.add(s["case_id"])
            got += 1
        if got < count:
            raise SystemExit(f"canary slot {slot_id} underfilled: {got}/{count}")
    membership.sort(key=lambda m: m["case_id"])
    return c.envelope(
        record_type="n2e-canary-membership",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_canary_membership.py",
        purpose="Frozen deterministic 12-case canary membership (§19), chosen before measurement.",
        seed=seed,
        selection_sha256=c.sha256_json_file(SEL),
        policy_sha256=c.sha256_json_file(POLICY),
        canary_case_count=len(membership),
        distinct_families=len({m["command_family"] for m in membership}),
        membership=membership,
    )


def main() -> int:
    c.write_record(OUT, build())
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name} record_sha256={rec['record_sha256']} cases={rec['canary_case_count']} families={rec['distinct_families']}")
    for m in rec["membership"]:
        print(f"  {m['canary_slot']:14} {m['command_family']}/{m['command_subfamily']:8} {m['case_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
