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

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FROZEN = HERE / "c1-panel-surface.json"


def main() -> int:
    if not FROZEN.exists():
        print(f"FAIL missing {FROZEN.name}; generate it with the emitter")
        return 1

    proc = subprocess.run(
        ["cargo", "run", "-q", "--example", "emit_panel_surface"],
        cwd=ROOT,
        capture_output=True,
    )
    if proc.returncode != 0:
        # Reported rather than raised: an emitter that will not run is a result,
        # and a traceback from CalledProcessError buries the reason.
        print(f"FAIL emitter exited {proc.returncode}")
        print(proc.stderr.decode("utf-8", "replace")[-2000:])
        return 1

    fresh = proc.stdout
    frozen = FROZEN.read_bytes()
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
