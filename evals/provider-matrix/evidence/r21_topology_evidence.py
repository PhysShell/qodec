#!/usr/bin/env python3
"""Evidence for R21.0: what the oracle-topology change is allowed to move.

Removing a duplicated oracle can only be shown to be safe against a baseline
that already exists. This produces that baseline from the CI run of the head it
describes, states in advance which ownership changes are permitted, and does so
before the change is written — so the prediction cannot be adjusted afterwards
to fit the result.

Three artifacts, in order:

  baseline    the 317 specifications of 3ba3a38, joined to the oracles that
              actually objected in CI, keyed by a machine fingerprint
  measured    for each specification, whether the unit suite still fails once
              the five tests that re-run a shipped corpus are deselected
  allowed     per fingerprint, the ownership outcomes the change may produce

Keyed by fingerprint rather than by the human identifier, for two reasons. The
identifier is about to change for eight specifications, and — as this run
discovered — it is not unique: 317 specifications carry 309 distinct ids, so
eight pairs would silently merge into one row each and eight transitions would
be invented or hidden.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
MATRIX = HERE.parent
sys.path.insert(0, str(MATRIX))

BASELINE_HEAD = "3ba3a3896dca952a76f20c6507ae654b50b6408a"

# Every oracle label the harness can print.
ORACLES = ("suite", "policy-gate", "clean-tree-gate", "discovery-gate", "readme-gate")

# The five suite tests that execute a full shipped self-test corpus. All five
# run it *in process*: a check that looked for a spawned subprocess would find
# none of them and report a clean topology.
DUPLICATES = (
    ("GatesCanFailTests", "test_the_clean_tree_check_detects_all_three_kinds_of_dirt"),
    ("GatesCanFailTests", "test_the_discovery_check_detects_a_mid_file_entrypoint"),
    ("DurableFieldInventoryTests", "test_the_policy_modules_own_self_test_passes"),
    ("ReadmeContractTests",
     "test_the_readme_gate_refuses_seven_wrong_readmes_and_passes_the_real_one"),
    ("ReadmeContractTests", "test_the_committed_readme_agrees_with_this_code"),
)

RUNNER = "\n".join([
    "import sys, unittest",
    'sys.path.insert(0, ".")',
    "import test_provider_matrix",
    *[f"test_provider_matrix.{cls}.{name} = "
      f"lambda self: self.skipTest('deselected: duplicated shipped corpus')"
      for cls, name in DUPLICATES],
    "loader = unittest.TestLoader()",
    "suite = loader.loadTestsFromModule(test_provider_matrix)",
    "result = unittest.TextTestRunner(verbosity=0).run(suite)",
    'print("SUITE", "GREEN" if result.wasSuccessful() else "RED",',
    "      len(result.failures), len(result.errors), result.testsRun)",
])


def fingerprint(spec, default_target: str) -> str:
    """Stable machine identity of a mutation *operation*.

    Target path, anchors and replacements — never the display name. A rename
    must not change the identity of the operation it names, or the baseline
    cannot survive R21.0a.
    """
    old, new = spec[1], spec[2]
    target = spec[3] if len(spec) > 3 else default_target
    edits = list(zip(old, new)) if isinstance(old, list) else [(old, new)]
    payload = json.dumps([target, edits], ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def table():
    import mutations as m
    rows = {}
    for spec in m.MUTATIONS:
        rows[fingerprint(spec, m.DEFAULT_TARGET)] = {
            "name": spec[0],
            "human_id": spec[0].split()[0],
            "target": spec[3] if len(spec) > 3 else m.DEFAULT_TARGET,
        }
    return m, rows


def build_baseline(log_path: pathlib.Path, out: pathlib.Path) -> None:
    """Join the CI log of `BASELINE_HEAD` to the table of that same head."""
    _module, rows = table()
    by_name = {row["name"]: fp for fp, row in rows.items()}
    lines = json.loads(log_path.read_text())["logs_content"].split("\n")
    killed = re.compile(r"^  killed\s+(?P<name>.*?)\s+\((?=(?:" + "|".join(ORACLES) + r"):)")
    label = re.compile(r"(?:\(|; )(" + "|".join(ORACLES) + r"): ")

    manifest, unmatched = {}, []
    for raw in lines:
        body = raw[29:]
        if not body.startswith("  killed "):
            continue
        found = killed.match(body)
        if not found or found.group("name") not in by_name:
            unmatched.append(body[:120])
            continue
        fp = by_name[found.group("name")]
        manifest[fp] = {**rows[fp], "objected": sorted(set(label.findall(body)))}

    missing = sorted(set(rows) - set(manifest))
    if unmatched or missing:
        raise SystemExit(
            f"the join is incomplete: {len(unmatched)} unmatched log rows, "
            f"{len(missing)} table specs never seen in the log")
    out.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    print(f"baseline: {len(manifest)} rows, {len(set(manifest))} fingerprints, "
          f"{len({r['human_id'] for r in manifest.values()})} human ids")


def measure(out: pathlib.Path) -> None:
    """Does the suite still object once the duplicated corpora are deselected?

    Measured rather than inferred. The log records `failures=1`, which says one
    test failed and not which one.
    """
    module, rows = table()
    env = dict(os.environ, PYTHONPATH=str(module.CORPUS_TOOLS),
               PYTHONDONTWRITEBYTECODE="1")
    results = {}
    for index, spec in enumerate(module.MUTATIONS):
        fp = fingerprint(spec, module.DEFAULT_TARGET)
        old, new = spec[1], spec[2]
        target = rows[fp]["target"]
        with tempfile.TemporaryDirectory() as tmp:
            work = pathlib.Path(tmp) / "provider-matrix"
            shutil.copytree(MATRIX, work, ignore=shutil.ignore_patterns(
                "__pycache__", "evidence"))
            victim = work / target
            source = victim.read_text(encoding="utf-8")
            edits = list(zip(old, new)) if isinstance(old, list) else [(old, new)]
            mutated, bad = source, None
            for anchor, replacement in edits:
                if mutated.count(anchor) != 1:
                    bad = f"anchor matched {mutated.count(anchor)} times"
                    break
                mutated = mutated.replace(anchor, replacement)
            if bad:
                results[fp] = {**rows[fp], "suite_without_duplicates": "ANCHOR", "why": bad}
                continue
            victim.write_text(mutated, encoding="utf-8")
            (work / "_measure.py").write_text(RUNNER, encoding="utf-8")
            proc = subprocess.run([sys.executable, "_measure.py"], cwd=work,
                                  capture_output=True, text=True, env=env, timeout=900)
            said = [ln for ln in (proc.stdout + proc.stderr).splitlines()
                    if ln.startswith("SUITE ")]
            verdict = said[-1].split() if said else ["SUITE", "CRASH", "-", "-", "-"]
            results[fp] = {**rows[fp], "suite_without_duplicates": verdict[1],
                           "failures": verdict[2], "errors": verdict[3],
                           "tests_run": verdict[4]}
        if (index + 1) % 50 == 0:
            print(f"  {index + 1}/{len(module.MUTATIONS)}", flush=True)
    out.write_text(json.dumps(results, indent=1, sort_keys=True) + "\n")
    print(f"measured: {len(results)} rows")


def build_allowed(baseline: pathlib.Path, measured: pathlib.Path,
                  out: pathlib.Path) -> None:
    """The outcomes the topology change may produce, per fingerprint.

    Two shapes are permitted where the suite's only objection was a duplicated
    corpus: the gate alone, or gate and suite together — because R21.0b replaces
    each removed corpus with a cheap direct witness, and that witness may keep
    the kill in the suite. Requiring the suite to *lose* ownership would be
    demanding that the replacement be useless.

    Everything else is forbidden, and the list of what is forbidden is written
    down rather than left implied.
    """
    base = json.loads(baseline.read_text())
    meas = json.loads(measured.read_text())
    allowed, changed = {}, 0
    for fp, before in base.items():
        objected = before["objected"]
        gates = sorted(o for o in objected if o != "suite")
        suite_survives = meas[fp]["suite_without_duplicates"] == "RED"
        if "suite" in objected and gates and not suite_survives:
            outcomes = [gates, sorted(objected)]
            reason = ("the suite's only objection was a duplicated shipped corpus; a "
                      "direct witness may keep the kill in the suite")
            changed += 1
        else:
            outcomes = [sorted(objected)]
            reason = "ownership does not rest on any duplicated shipped corpus"
        allowed[fp] = {**before, "baseline": sorted(objected),
                       "allowed_after": outcomes, "reason": reason}
    summary = {
        "baseline_head": BASELINE_HEAD,
        "baseline_rows": len(base),
        "unique_fingerprints": len(set(base)),
        "unique_human_ids": len({r["human_id"] for r in base.values()}),
        "duplicate_human_id_pairs": len(base) - len({r["human_id"] for r in base.values()}),
        "specs_with_an_allowed_ownership_change": changed,
        "forbidden": [
            "suite-only becomes no killer",
            "both becomes suite-only",
            "gate-only becomes no killer",
            "a gate objects that did not object at baseline",
            "a kill by import error, NameError, traceback or missing test count",
        ],
    }
    out.write_text(json.dumps({"summary": summary, "specs": allowed},
                              indent=1, sort_keys=True) + "\n")
    for key, value in summary.items():
        if not isinstance(value, list):
            print(f"  {key}: {value}")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    command, out = argv[0], pathlib.Path(argv[-1])
    if command == "baseline":
        build_baseline(pathlib.Path(argv[1]), out)
    elif command == "measure":
        measure(out)
    elif command == "allowed":
        build_allowed(pathlib.Path(argv[1]), pathlib.Path(argv[2]), out)
    else:
        print(f"unknown command {command!r}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
