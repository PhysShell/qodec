#!/usr/bin/env python3
"""Assert the frozen C1 surface still matches the crate that defines it.

`c1-panel-surface.json` is what the qualification canary sends. It is generated
from `panel::tool_schemas()` and `panel::answer_schema()` and then committed, so
it can drift the moment either changes — and drift here is silent and total: the
canary would go on reporting PASS for a provider that accepted schemas the arm
no longer uses, and the receipt would look exactly as convincing as before.

Regenerating and diffing is the whole check. Kept out of the unit tests on
purpose: those are pure Python and fast, this one needs the crate built, and a
test that quietly skips when cargo is missing is a test that reports success for
never having run.

Exit 0 when they agree, 1 when they do not, with the disagreement printed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
EMITTER_TIMEOUT = 600
FROZEN = HERE / "c1-panel-surface.json"


def unsorted_paths(value: object, path: str = "") -> list[str]:
    """Every object whose keys are not in sorted order, recursively."""
    out: list[str] = []
    if isinstance(value, dict):
        keys = list(value)
        if keys != sorted(keys):
            out.append(path)
        for key, sub in value.items():
            out.extend(unsorted_paths(sub, f"{path}.{key}" if path else key))
    elif isinstance(value, list):
        for index, sub in enumerate(value):
            out.extend(unsorted_paths(sub, f"{path}[{index}]"))
    return out


def main() -> int:
    if not FROZEN.exists():
        print(f"FAIL missing {FROZEN.name}; generate it with the emitter")
        return 1

    try:
        proc = subprocess.run(
            ["cargo", "run", "-q", "--example", "emit_panel_surface"],
            cwd=ROOT,
            capture_output=True,
            timeout=EMITTER_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        print(f"FAIL the emitter exceeded {EMITTER_TIMEOUT}s; a stalled build must fail, not hang")
        return 1
    except OSError as exc:
        # The `returncode` branch below only covers a cargo that exists and
        # fails. A cargo that is not installed raised `FileNotFoundError`
        # straight through, which is the traceback this file's docstring argues
        # against two paragraphs earlier.
        print(f"FAIL could not run the emitter: {exc}")
        return 1
    if proc.returncode != 0:
        # Reported rather than raised: an emitter that will not run is a result,
        # and a traceback from CalledProcessError buries the reason.
        print(f"FAIL emitter exited {proc.returncode}")
        print(proc.stderr.decode("utf-8", "replace")[-2000:])
        return 1

    fresh = proc.stdout
    frozen = FROZEN.read_bytes()

    # The emitter's key order comes from `serde_json::Map`, which is a BTreeMap
    # unless the `preserve_order` feature is on — a fact about feature
    # resolution, not about this artifact. Since the comparison above is
    # byte-for-byte, a silent switch would turn every future run red for a
    # reason nobody would guess. Assert the property instead of trusting it.
    unsorted = unsorted_paths(json.loads(fresh))
    if unsorted:
        print("FAIL the emitted surface is not canonically ordered")
        for path in unsorted[:10]:
            print(f"  keys out of order at {path or '<root>'}")
        print("  serde_json's `preserve_order` feature would do this")
        return 1

    if fresh == frozen:
        print("OK c1-panel-surface.json matches panel::tool_schemas() + answer_schema()")
        return 0

    print(f"FAIL {FROZEN.name} has drifted from the crate")
    print(f"  frozen: {len(frozen)} bytes")
    print(f"  fresh:  {len(fresh)} bytes")
    for n, (a, b) in enumerate(zip(frozen, fresh)):
        if a != b:
            start = max(0, n - 60)
            print(f"  first difference at byte {n}")
            print(f"  frozen: ...{frozen[start:n + 60].decode('utf-8', 'replace')}")
            print(f"  fresh:  ...{fresh[start:n + 60].decode('utf-8', 'replace')}")
            break
    else:
        print("  one is a prefix of the other")
    print("  regenerate: cargo run --example emit_panel_surface > "
          "evals/provider-matrix/c1-panel-surface.json")
    return 1


if __name__ == "__main__":
    sys.exit(main())
