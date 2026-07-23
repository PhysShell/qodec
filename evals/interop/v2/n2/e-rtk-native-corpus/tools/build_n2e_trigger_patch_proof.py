#!/usr/bin/env python3
"""Prove the CI trigger commit T differs from the implementation commit I only by
the authorized workflow-trigger change (§20 / correction #10).

Given I and T, computes the git diff, asserts it touches ONLY the canary workflow
file and is additive (adds a narrowly-scoped push trigger, removes nothing), and
writes n2e-trigger-patch-proof-v1.json recording both identities and the diff.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
REPO = HERE.parents[5]
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402

OUT = N2E_DIR / "n2e-trigger-patch-proof-v1.json"
WORKFLOW = ".github/workflows/qodec-n2e-corpus-canary.yml"


def git(*args):
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True, check=True).stdout


def build(impl_sha: str, trigger_sha: str) -> dict:
    changed = git("diff", "--name-only", impl_sha, trigger_sha).split()
    diff = git("diff", impl_sha, trigger_sha)
    numstat = git("diff", "--numstat", impl_sha, trigger_sha).split("\n")
    added = removed = 0
    for ln in numstat:
        parts = ln.split("\t")
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            added += int(parts[0])
            removed += int(parts[1])
    additive_only = (changed == [WORKFLOW] and removed == 0 and added > 0)
    return c.envelope(
        record_type="n2e-trigger-patch-proof",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_trigger_patch_proof.py",
        purpose="Prove the CI trigger commit changes only the workflow trigger stanza (#10).",
        implementation_sha=impl_sha, trigger_sha=trigger_sha,
        changed_files=changed, added_line_count=added, removed_line_count=removed,
        additive_only=additive_only, only_workflow_changed=(changed == [WORKFLOW]),
        diff_text=diff,
    )


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: build_n2e_trigger_patch_proof.py <impl_sha> <trigger_sha>", file=sys.stderr)
        return 2
    body = build(sys.argv[1], sys.argv[2])
    c.write_record(OUT, body)
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name} additive_only={rec['additive_only']} changed={rec['changed_files']} "
          f"+{rec['added_line_count']}/-{rec['removed_line_count']}")
    return 0 if rec["additive_only"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
