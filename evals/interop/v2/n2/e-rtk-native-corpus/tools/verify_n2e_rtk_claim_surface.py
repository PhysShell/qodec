#!/usr/bin/env python3
"""Independently verify n2e-rtk-claim-surface-v1.json.

1. Recompute the record self-hash (never trust the builder).
2. Assert RTK identity constants and full-digest form.
3. If RTK_BIN is set: invoke the pinned `rtk rewrite "<original>"` for every
   hook-mode scenario and REQUIRE that the real rewrite agrees with the committed
   record (§7). Passthrough controls must really pass through (exit 1, no rewrite).
4. If RTK_SRC_DIR is set: re-parse rules.rs and require every recorded savings
   claim (percentage + claim_source line) matches the pinned source.

Without RTK_BIN/RTK_SRC_DIR the structural checks still run; the live-binary and
source checks report SKIPPED so the verifier never silently claims to have done
what it could not. The canonical CI job sets both.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import rtk_rules_parser as rp  # noqa: E402

RECORD = N2E_DIR / "n2e-rtk-claim-surface-v1.json"
RTK_SOURCE_COMMIT = "5d32d0736f686b69d1e8b9dc45c007d4eb77a0a2"
RTK_BINARY_SHA256 = "41f316adf7b30a568208a0a4f824bffb266ecb6d01bd9de81bed58e1d469dfcf"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PASSTHROUGH = "RTK_PASSTHROUGH_CONTROL"


def _rewrite(rtk_bin: str, cmd: str) -> tuple[str, int]:
    p = subprocess.run([rtk_bin, "rewrite", cmd], capture_output=True, text=True)
    return p.stdout.strip(), p.returncode


def verify(path: Path) -> tuple[bool, str]:
    if not path.is_file():
        return False, f"{path} does not exist"
    rec = c.load_record(path)

    ok, msg = c.verify_self_hash(rec)
    if not ok:
        return False, msg
    if rec.get("record_type") != "n2e-rtk-claim-surface":
        return False, f"unexpected record_type {rec.get('record_type')!r}"
    if rec.get("rtk_source_commit") != RTK_SOURCE_COMMIT:
        return False, "rtk_source_commit drift"
    if rec.get("rtk_binary_sha256") != RTK_BINARY_SHA256:
        return False, "rtk_binary_sha256 drift"
    if not HEX64.match(rec.get("rtk_binary_sha256", "")):
        return False, "rtk_binary_sha256 not a full digest"

    scenarios = rec.get("scenarios", [])
    if len(scenarios) != rec.get("scenario_count"):
        return False, "scenario_count mismatch"
    for s in scenarios:
        if not isinstance(s.get("original_argv"), list):
            return False, f"{s.get('original_command')!r}: original_argv must be an array (no shell strings)"
        cls = s.get("rtk_support_classification")
        if cls not in rec.get("classification_vocabulary", []):
            return False, f"unknown classification {cls!r}"
        # A passthrough control must NOT masquerade as specialized, and vice versa.
        if cls == PASSTHROUGH and s.get("expected_rewrite"):
            return False, f"{s['original_command']!r} classified passthrough but has a rewrite"

    notes = []

    # (3) live-binary agreement
    rtk_bin = os.environ.get("RTK_BIN")
    if rtk_bin:
        actual = c.sha256_file(rtk_bin)
        if actual != RTK_BINARY_SHA256:
            return False, f"RTK_BIN sha256 {actual} != pinned"
        for s in scenarios:
            if s.get("rewrite_mode") != "hook":
                continue
            live, code = _rewrite(rtk_bin, s["original_command"])
            if s["rtk_support_classification"] == PASSTHROUGH:
                if code != 1 or live:
                    return False, f"{s['original_command']!r}: expected passthrough, got exit={code} out={live!r}"
                continue
            if live != (s.get("expected_rewrite") or ""):
                return False, (
                    f"{s['original_command']!r}: live rewrite {live!r} != committed "
                    f"{s.get('expected_rewrite')!r}"
                )
        notes.append(f"live rewrite agreement verified against pinned binary ({len(scenarios)} scenarios)")
    else:
        notes.append("SKIPPED live rewrite check (RTK_BIN unset)")

    # (4) source claim agreement
    rtk_src = os.environ.get("RTK_SRC_DIR")
    if rtk_src:
        rules = rp.parse_rules(Path(rtk_src) / "src/discover/rules.rs")
        for s in scenarios:
            claim = s.get("rtk_savings_claim")
            if not claim:
                continue
            toks = s.get("explicit_rtk_argv") or []
            if len(toks) >= 2 and toks[0] == "rtk":
                subcmd = toks[2] if len(toks) >= 3 else None
                fresh = rp.claim_for(rules, f"rtk {toks[1]}", subcmd)
                if fresh != claim:
                    return False, f"{s['original_command']!r}: claim drift vs rules.rs: {claim} != {fresh}"
        notes.append("savings claims re-derived from pinned rules.rs match")
    else:
        notes.append("SKIPPED source claim check (RTK_SRC_DIR unset)")

    return True, "OK; " + "; ".join(notes)


def main() -> int:
    ok, message = verify(RECORD)
    if not ok:
        print(f"::error::n2e rtk claim surface verification FAILED: {message}", file=sys.stderr)
        return 1
    print(f"n2e rtk claim surface verification passed: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
