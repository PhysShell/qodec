#!/usr/bin/env python3
"""Copy per-cell reader provenance from committed envelopes into `record.json`.

`run.py` originally kept model and effort provenance only in each cell's
`*.envelope.json` and asserted a single run-level `effort_provenance` from
the *requested* level — so `record.json` could claim confirmation that no
completed cell backed (CodeRabbit, PR #17). The runner now persists both
per cell; this script repairs runs recorded before that change.

It invents nothing. Every value it writes is read out of the envelope that
cell already produced, and `--check` re-verifies agreement without writing,
so the repair stays auditable after the fact:

    python3 evals/agent-g5/backfill_cell_provenance.py runs/effort-high-codex-* --check

Wall-clock duration is deliberately NOT backfilled: it was never recorded,
and a latency figure that cannot be traced to a frozen artifact does not
belong in the record at any confidence.
"""

import argparse
import json
import sys
from pathlib import Path

FIELDS = {
    "reader_model": "model",
    "effort_requested": "effort_requested",
    "effort_applied": "reasoning_effort",
    "effort_provenance": "effort_source",
}


def derive(record: dict) -> str | None:
    """Run-level provenance, computed from cells — mirrors `run.py`."""
    sys.path.insert(0, str(Path(__file__).parent))
    from run import derive_effort_provenance

    return derive_effort_provenance(record)


def repair(run_dir: Path, check: bool) -> int:
    """Backfill (or verify) one run directory; returns the mismatch count."""
    record_path = run_dir / "record.json"
    record = json.loads(record_path.read_text())
    bad = 0
    for cell in record["cells"]:
        if "rep" not in cell or cell.get("status") == "reader-error":
            continue
        env_path = run_dir / cell["task"] / f"{cell['arm']}.rep{cell['rep']}.envelope.json"
        env = json.loads(env_path.read_text())
        for field, source in FIELDS.items():
            want = env.get(source)
            if check:
                if cell.get(field) != want:
                    print(f"  {env_path}: {field} is {cell.get(field)!r}, envelope says {want!r}")
                    bad += 1
            else:
                cell[field] = want
    derived = derive(record)
    if check:
        if record.get("effort_provenance") != derived:
            print(f"  {record_path}: effort_provenance is "
                  f"{record.get('effort_provenance')!r}, cells imply {derived!r}")
            bad += 1
        return bad
    record["effort_provenance"] = derived
    record_path.write_text(json.dumps(record, indent=2) + "\n")
    print(f"{run_dir}: {derived}")
    return 0


def main() -> None:
    """Backfill or verify every run directory named on the command line."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("runs", nargs="+", type=Path)
    ap.add_argument("--check", action="store_true", help="verify only, write nothing")
    args = ap.parse_args()
    bad = sum(repair(r, args.check) for r in args.runs)
    if bad:
        print(f"{bad} mismatch(es)", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
