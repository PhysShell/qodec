#!/usr/bin/env python3
"""Fail-closed verifier for the publisher acquisition ORDER (item 4).

The one faithful gold-evaluation order is:

    base -> pre_install -> install_warm -> [gold_patch (::fixed)] -> test_patch -> measured

with the critical invariant that the publisher `--locked` install warms the FROZEN
lockfile on the PRISTINE manifest -- the gold (source/fix) patch is applied only
afterwards. Applying the gold patch first makes `cargo test --locked` fail because
Cargo.toml no longer matches the frozen Cargo.lock, so a run that got that order wrong
must FAIL this verifier rather than be disqualified for an offline-build symptom.

`verify_acquisition_order(order, fam)` operates purely on the recorded `acquisition_
order` evidence (boundary sha256 + tracked worktree state at every step). It checks:

  1. the recorded boundary sequence EQUALS the canonical sequence for the snapshot
     (a swapped gold/test order, or a patch applied before install_warm, changes this
     sequence or the manifest invariant below -> FAIL);
  2. the protected build manifest is UNCHANGED from pre_install to install_warm (the
     `--locked` install ran before any patch mutated it);
  3. rust: the install actually ran, used `--locked`, and every install step exited 0;
  4. ::fixed applied the gold patch (exit 0) after install_warm and it changed the tree;
     ::buggy has NO gold_patch boundary;
  5. the test_patch was applied (exit 0);
  6. tracked worktree state is MONOTONIC across install_warm -> gold_patch -> test_patch
     (patches only add/keep tracked changes; nothing silently reverts).
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402


def _seq_expected(variant: str) -> list:
    seq = ["base", "pre_install", "install_warm"]
    if variant == "fixed":
        seq.append("gold_patch")
    seq.append("test_patch")
    return seq


def _applied(patches: list, name: str) -> dict | None:
    for p in patches or []:
        if p.get("name") == name:
            return p
    return None


def verify_acquisition_order(order: dict, fam: str) -> tuple[bool, list]:
    reasons: list = []
    variant = order.get("snapshot_variant")
    boundaries = order.get("boundaries") or []
    bl = {b["label"]: b for b in boundaries}
    seq = [b["label"] for b in boundaries]
    expected = _seq_expected(variant)

    # 1. exact canonical sequence (order enforcement; catches a gold/test swap)
    if seq != expected:
        reasons.append(f"boundary sequence {seq} != canonical {expected}")

    # 2. locked install BEFORE any manifest mutation: manifest unchanged pre_install->install_warm
    if "pre_install" in bl and "install_warm" in bl:
        if bl["pre_install"]["protected"] != bl["install_warm"]["protected"]:
            reasons.append("protected manifest changed between pre_install and install_warm "
                           "(a patch was applied before the locked install)")
    else:
        reasons.append("missing pre_install / install_warm boundary")

    # 3. rust: install ran, --locked, all exits 0
    if fam == "rust_cargo":
        inst = order.get("install") or {}
        if not inst.get("ran"):
            reasons.append("rust publisher install did not run")
        if not inst.get("locked"):
            reasons.append("rust publisher install did not use --locked")
        for s in inst.get("steps") or []:
            if s.get("exit") != 0:
                reasons.append(f"rust --locked install exited {s.get('exit')} (must be 0)")

    # 4. gold patch presence/application by variant
    patches = order.get("applied_patches") or []
    if variant == "fixed":
        gp = bl.get("gold_patch")
        gpatch = _applied(patches, "patch")
        if gp is None:
            reasons.append("fixed snapshot missing gold_patch boundary")
        elif not gp.get("applied") or gpatch is None or gpatch.get("apply_exit") != 0:
            reasons.append("fixed snapshot did not cleanly apply the gold patch")
        elif "install_warm" in bl and \
                gp["worktree_diff_sha256"] == bl["install_warm"]["worktree_diff_sha256"]:
            reasons.append("gold patch did not change the worktree relative to install_warm")
    else:
        if "gold_patch" in bl:
            reasons.append("buggy snapshot must not have a gold_patch boundary")

    # 5. test_patch applied cleanly
    tp = bl.get("test_patch")
    tpatch = _applied(patches, "test_patch")
    if tp is None:
        reasons.append("missing test_patch boundary")
    elif not tp.get("applied") or tpatch is None or tpatch.get("apply_exit") != 0:
        reasons.append("test_patch was not cleanly applied")

    # 6. monotonic tracked-state across install_warm -> [gold_patch] -> test_patch
    chain = ["install_warm"] + (["gold_patch"] if variant == "fixed" else []) + ["test_patch"]
    prev = None
    for lab in chain:
        b = bl.get(lab)
        if b is None:
            continue
        cur = set(map(_status_path, b.get("tracked_status") or []))
        if prev is not None and not prev.issubset(cur):
            reasons.append(f"tracked worktree state at {lab} dropped inputs present earlier "
                           f"(non-monotonic acquisition)")
        prev = cur

    return (len(reasons) == 0, reasons)


def _status_path(status_line: str) -> str:
    """The pathname portion of a `git status --porcelain` line ('XY path')."""
    return status_line[3:] if len(status_line) > 3 else status_line


def verify_record(rec: dict) -> tuple[bool, list]:
    """Verify a per-case n2e-canary-case record's embedded acquisition_order."""
    fam = rec.get("command_family")
    order = (((rec.get("acquisition") or {}).get("environment_identity") or {})
             .get("acquisition_order"))
    if order is None:
        return (False, ["record has no acquisition_order evidence"])
    return verify_acquisition_order(order, fam)


def main(argv: list) -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("record", help="a per-case n2e-canary-case JSON record")
    args = ap.parse_args(argv)
    rec = c.load_record(Path(args.record))
    ok, reasons = verify_record(rec)
    print(f"acquisition-order: {'OK' if ok else 'FAIL'} ({rec.get('case_id')})")
    for r in reasons:
        print(f"  - {r}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
