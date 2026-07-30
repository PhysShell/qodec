#!/usr/bin/env python3
"""Assert the canary's JSON gate is never more liberal than the consumer.

Six review rounds found the same defect wearing different clothes: the canary
accepted something `OpenAiChatCompletions` will refuse. Request schemas, then
the tool-call dialect, then the byte envelope, then duplicate keys, then the
character encoding. Each time the answer was to take the rule from the consumer
instead of writing a rule that resembled it.

`json.loads` is the last and largest of those, because it is not a JSON parser —
it is a parser for a superset. It admits `NaN`, `Infinity` and `-Infinity`,
turns `1e400` into `inf`, and accepts an unpaired `\\ud800` escape.
`serde_json::from_slice::<Value>` refuses all of them, and it parses the *whole*
body before reading a single field, so `{"model": "m", "unused": NaN}` yields a
model here and nothing at all there.

This is the check that the gap is closed, and it does not take anybody's word
for what `serde_json` does: it runs `serde_json` over the frozen corpus and
compares, case by case, against what the Python gate does with the same bytes.

The rule is **one-directional**. Everything the gate admits, the consumer must
admit. The reverse is allowed and used: `serde_json` accepts duplicate object
keys and this gate refuses them on purpose, because a repeated key is a tamper
channel. Being stricter is a choice; being more liberal is a false PASS.

Kept out of the unit tests for the same reason as `check_surface.py`: those are
pure Python and fast, this one needs the crate built, and a test that quietly
skips when cargo is missing is a test that reports success for never having run.

Exit 0 when the gate is no more liberal than the consumer and the frozen
verdicts still match reality, 1 otherwise, with every disagreement printed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ORACLE_TIMEOUT = 600
CORPUS = HERE / "json-admission-corpus.json"

sys.path.insert(0, str(HERE))
import provider_matrix as pm  # noqa: E402


def python_admits(raw: bytes) -> tuple[bool, str]:
    try:
        pm.strict_json_loads(raw, "case")
    except (pm.StrictJsonError, json.JSONDecodeError) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return True, ""


def main() -> int:
    if not CORPUS.exists():
        print(f"FAIL missing {CORPUS.name}")
        return 1
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    cases = corpus.get("cases", [])
    if not cases:
        print("FAIL the corpus is empty; a vacuous parity proof is not one")
        return 1

    try:
        proc = subprocess.run(
            ["cargo", "run", "-q", "--example", "json_admission_oracle", "--", str(CORPUS)],
            cwd=ROOT,
            capture_output=True,
            timeout=ORACLE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        print(f"FAIL the oracle exceeded {ORACLE_TIMEOUT}s; a stalled build must fail, not hang")
        return 1
    except OSError as exc:
        print(f"FAIL could not run the oracle: {exc}")
        return 1
    if proc.returncode != 0:
        print(f"FAIL oracle exited {proc.returncode}")
        print(proc.stderr.decode("utf-8", "replace")[-2000:])
        return 1

    verdicts = json.loads(proc.stdout)["verdicts"]

    liberal: list[str] = []
    stricter: list[str] = []
    for case in cases:
        name = case["name"]
        raw = bytes.fromhex(case["hex"])
        if name not in verdicts:
            print(f"FAIL the oracle returned no verdict for {name!r}")
            return 1
        consumer = verdicts[name]
        # The corpus carries a frozen verdict so the unit suite can check parity
        # without a Rust toolchain. Here it is compared against the live one, so
        # a frozen value cannot rot into a comfortable fiction.
        if case.get("consumer_admits") != consumer:
            print(f"FAIL {name}: frozen consumer verdict {case.get('consumer_admits')!r} "
                  f"but serde_json says {consumer!r}; regenerate the corpus")
            return 1
        ours, why = python_admits(raw)
        if ours and not consumer:
            liberal.append(f"  {name}: the gate admits it, the consumer refuses it")
        elif consumer and not ours:
            stricter.append(f"  {name}: refused here on purpose — {why}")

    for line in stricter:
        print(f"stricter {line}")

    if liberal:
        print(f"FAIL the gate is more liberal than the consumer in {len(liberal)} case(s):")
        for line in liberal:
            print(line)
        print("  a canary that accepts what the mapper refuses reports PASS for an unusable target")
        return 1

    print(f"OK {len(cases)} cases: the JSON gate admits nothing the consumer refuses")
    print(f"   ({len(stricter)} deliberately stricter, the rest identical)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
