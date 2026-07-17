#!/usr/bin/env python3
"""Build n2e-selection-policy-v1.json (§9/§10) — the FROZEN selection policy.

Committed BEFORE selection runs. Fixes the seed, the §6 family/subfamily/outcome
quota slots (summing to exactly 70), the §10 objective weights, the §11 diversity
constraints, the raw output-size strata definitions, and the deterministic
fallback rule. Selection is evaluated from metadata only (outcome-blind wrt RTK)
so the selection record reproduces byte-identically offline.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

OUT = N2E_DIR / "n2e-selection-policy-v1.json"
SEED = 20260717

# Each slot: id, family, subfamily set (None=any), variant (None=any),
# min_target_tests (None=any), count. Slots sum to 70 and encode the §6 matrix
# plus the required outcome diversity (buggy=fail / fixed=pass, multi-failure).
SLOTS = [
    # files/search: 10  (ls/tree 2, read 2, grep 6)
    {"id": "fs_ls_tree", "family": "files_search", "subfamilies": ["ls", "tree"], "count": 2},
    {"id": "fs_read", "family": "files_search", "subfamilies": ["read"], "count": 2},
    {"id": "fs_grep", "family": "files_search", "subfamilies": ["grep"], "count": 6},
    # git: 14  (status 3, diff 3, log/show 3, add/commit/push 5)
    {"id": "git_status", "family": "git", "subfamilies": ["status"], "count": 3},
    {"id": "git_diff", "family": "git", "subfamilies": ["diff"], "count": 3},
    {"id": "git_log_show", "family": "git", "subfamilies": ["log", "show"], "count": 3},
    {"id": "git_acp", "family": "git", "subfamilies": ["add", "commit", "push"], "count": 5},
    # rust/cargo: 8  (test fail 2, test pass 2, test multi-fail 1, build 1, check 1, clippy 1)
    {"id": "rust_test_fail", "family": "rust_cargo", "subfamilies": ["test"], "variant": "buggy", "count": 2},
    {"id": "rust_test_pass", "family": "rust_cargo", "subfamilies": ["test"], "variant": "fixed", "count": 2},
    {"id": "rust_test_multi", "family": "rust_cargo", "subfamilies": ["test"], "variant": "buggy", "min_target_tests": 2, "count": 1},
    {"id": "rust_build", "family": "rust_cargo", "subfamilies": ["build"], "count": 1},
    {"id": "rust_check", "family": "rust_cargo", "subfamilies": ["check"], "count": 1},
    {"id": "rust_clippy", "family": "rust_cargo", "subfamilies": ["clippy"], "count": 1},
    # python: 8  (pytest fail 3, pytest pass 3, ruff 2)
    {"id": "py_pytest_fail", "family": "python", "subfamilies": ["pytest"], "variant": "buggy", "count": 3},
    {"id": "py_pytest_pass", "family": "python", "subfamilies": ["pytest"], "variant": "fixed", "count": 3},
    {"id": "py_ruff", "family": "python", "subfamilies": ["ruff"], "count": 2},
    # js/ts: 8  (test fail 2, test pass 2, tsc 2, lint 2)
    {"id": "js_test_fail", "family": "js_ts", "subfamilies": ["test"], "variant": "buggy", "count": 2},
    {"id": "js_test_pass", "family": "js_ts", "subfamilies": ["test"], "variant": "fixed", "count": 2},
    {"id": "js_tsc", "family": "js_ts", "subfamilies": ["tsc"], "count": 2},
    {"id": "js_lint", "family": "js_ts", "subfamilies": ["lint"], "count": 2},
    # go: 6  (test fail 2, test pass 2, build 1, vet 1)
    {"id": "go_test_fail", "family": "go", "subfamilies": ["test"], "variant": "buggy", "count": 2},
    {"id": "go_test_pass", "family": "go", "subfamilies": ["test"], "variant": "fixed", "count": 2},
    {"id": "go_build", "family": "go", "subfamilies": ["build"], "count": 1},
    {"id": "go_vet", "family": "go", "subfamilies": ["vet"], "count": 1},
    # jvm: 6  (test fail 3, test pass 3)
    {"id": "jvm_test_fail", "family": "jvm", "subfamilies": ["test"], "variant": "buggy", "count": 3},
    {"id": "jvm_test_pass", "family": "jvm", "subfamilies": ["test"], "variant": "fixed", "count": 3},
    # logs: 6
    {"id": "logs_log", "family": "logs", "subfamilies": ["log"], "count": 6},
    # containers: 4
    {"id": "containers", "family": "containers", "subfamilies": ["ps", "images", "logs"], "count": 4},
]


def build() -> dict:
    total = sum(s["count"] for s in SLOTS)
    assert total == 70, f"slots sum to {total}, must be 70"
    return c.envelope(
        record_type="n2e-selection-policy",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_selection_policy.py",
        purpose="Frozen §9/§10 selection policy: seed, quota slots (=70), objectives, diversity, size strata, fallback.",
        seed=SEED,
        target_case_count=70,
        slots=SLOTS,
        objective_weights={  # §10 (evaluated only from metadata + raw qualification)
            "command_family_coverage": 0.35, "outcome_diversity": 0.20,
            "source_repository_diversity": 0.15, "raw_output_size_balance": 0.15,
            "environment_cost": 0.10, "source_recency_diversity": 0.05,
        },
        diversity_constraints={  # §11
            "min_distinct_source_systems": 5,
            "min_distinct_repositories": 24,
            "min_repos_per_language": {"rust_cargo": 4, "go": 4, "js_ts": 4, "python": 4, "jvm": 4},
            "max_source_units_per_repository": 2,
            "max_pct_cases_per_repository": 0.10,
        },
        size_strata={  # §10 raw output token-size strata (o200k)
            "tiny": [1, 250], "small": [251, 2000], "medium": [2001, 20000],
            "large": [20001, 100000], "huge": [100001, 250000],
            "max_pct_per_family_from_one_stratum": 0.40,
            "note": "size strata are validated post-RAW-qualification; selection is frozen on metadata only.",
        },
        fallback_rule=(
            "On typed qualification failure of a selected case, replace it with the "
            "next candidate from this case's slot in the frozen reserve ordering "
            "(n2e-reserve-list-v1.json). Never replace based on observed RTK/QODEC savings."
        ),
        ordering=(
            "Within each slot: filter eligible candidates, stable-sort by candidate_id, "
            "then order by sha256(f'{seed}:{candidate_id}'). Greedily fill respecting the "
            "global per-repository source-unit cap (<=2 clusters/repo) and the 10% case cap."
        ),
    )


def main() -> int:
    c.write_record(OUT, build())
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name} record_sha256={rec['record_sha256']} slots={len(rec['slots'])} total={rec['target_case_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
