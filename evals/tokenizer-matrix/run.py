#!/usr/bin/env python3
"""Tokenizer matrix — RAW vs qodec across open tokenizer families.

Stage B of the program: token savings are a claim about a *specific*
tokenizer, so measure the whole codec table under many real ones instead of
trusting the o200k proxy. No GPU, no inference, no API keys — each family
costs one `tokenizer.json` download, then everything is offline through the
crate's fail-closed `hf:` meter (aliases and acceptance are re-chosen under
each tokenizer; nothing is scaled or extrapolated).

Honest scope, stated up front:
* Counts are payload-level (`add_special_tokens=false`), not full-request:
  the chat-template wrapping is identical in both arms, so it cancels in the
  absolute saving and only dilutes the percentage. Full-request accounting
  with exact chat templates is a later increment.
* This proves *token reduction* per tokenizer. It proves nothing about
  comprehension — that is Level 2's job (`evals/interop/`).

Usage (from the repo root, after `cargo build --release`):
    python3 evals/tokenizer-matrix/run.py            # fetch + verify + bench + report
    python3 evals/tokenizer-matrix/run.py --offline  # refuse downloads, use cache only

Downloads are pinned: the first fetch of a family records url/sha256/bytes in
tokenizers.lock.json; every later run re-verifies the cached file against the
lock and refuses on drift. Results land in results/ (committed); tokenizer
files land in .cache/ (gitignored).
"""

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
QODEC = ROOT / "target" / "release" / "qodec"
CORPUS = ROOT / "corpus"
CACHE = HERE / ".cache"
RESULTS = HERE / "results"
LOCK = HERE / "tokenizers.lock.json"

# Open-weights tokenizer families. Gated repos (meta-llama, mistralai,
# google) are represented by well-known ungated mirrors, recorded as such —
# the tokenizer.json bytes are what is pinned, not the repo's pedigree.
FAMILIES = [
    ("qwen2.5", "Qwen/Qwen2.5-Coder-7B-Instruct", None),
    ("llama3.1", "NousResearch/Meta-Llama-3.1-8B-Instruct", "mirror of gated meta-llama"),
    ("deepseek-v3", "deepseek-ai/DeepSeek-V3", None),
    ("glm4", "THUDM/glm-4-9b-chat-hf", None),
    ("phi4", "microsoft/phi-4", None),
    ("mistral0.3", "unsloth/Mistral-7B-Instruct-v0.3", "mirror of gated mistralai"),
    ("gemma2", "unsloth/gemma-2-9b-it", "mirror of gated google"),
    ("kimi-k2", "moonshotai/Kimi-K2-Instruct", None),
]

# Bundled reference meters (offline in the binary).
BUNDLED = ["o200k", "cl100k"]

CODECS = ["fold", "toon", "grep", "diag", "tmpl", "paper", "mine", "deep", "squeeze", "mosaic"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(family: str, repo: str, offline: bool, lock: dict) -> Path | None:
    """Download (or reuse) a family's tokenizer.json, pinned via the lock."""
    url = f"https://huggingface.co/{repo}/resolve/main/tokenizer.json"
    dest = CACHE / f"{family}.tokenizer.json"
    if not dest.exists():
        if offline:
            print(f"  {family}: not cached and --offline set — skipping", file=sys.stderr)
            return None
        print(f"  {family}: fetching {url}", file=sys.stderr)
        tmp = dest.with_suffix(".part")
        proc = subprocess.run(
            ["curl", "-fsSL", "--max-time", "300", "-o", str(tmp), url],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            print(f"  {family}: download failed ({proc.stderr.strip()[:200]})", file=sys.stderr)
            tmp.unlink(missing_ok=True)
            return None
        tmp.rename(dest)
    digest = sha256_file(dest)
    pinned = lock.get(family)
    if pinned is None:
        lock[family] = {"repo": repo, "url": url, "sha256": digest, "bytes": dest.stat().st_size}
    elif pinned["sha256"] != digest:
        print(
            f"  {family}: cached file drifted from lock "
            f"(lock {pinned['sha256'][:12]}…, file {digest[:12]}…) — refusing",
            file=sys.stderr,
        )
        return None
    return dest


def run_bench(meter: str) -> list[dict] | None:
    """Run `qodec bench` under one meter and parse its markdown table."""
    proc = subprocess.run(
        [str(QODEC), "bench", "--corpus", str(CORPUS), "--meter", meter],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(f"  bench failed under {meter}: {proc.stderr.strip()[:200]}", file=sys.stderr)
        return None
    rows = []
    for line in proc.stdout.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 9 or cells[0] in ("sample", "---"):
            continue
        if not cells[3].isdigit():
            continue
        rows.append(
            {
                "sample": cells[0],
                "codec": cells[1],
                "outcome": cells[2],
                "tokens_in": int(cells[3]),
                "tokens_cold": int(cells[4]),
                "tokens_warm": int(cells[6]),
                "roundtrip": cells[8],
            }
        )
    return rows


def totals(rows: list[dict]) -> dict:
    """Per-codec corpus totals: sum tokens over samples, saving = 1 - out/in."""
    out: dict[str, dict] = {}
    for codec in CODECS:
        sel = [r for r in rows if r["codec"] == codec]
        tin = sum(r["tokens_in"] for r in sel)
        cold = sum(r["tokens_cold"] for r in sel)
        warm = sum(r["tokens_warm"] for r in sel)
        out[codec] = {
            "tokens_in": tin,
            "tokens_cold": cold,
            "tokens_warm": warm,
            "cold_saving": (tin - cold) / tin if tin else 0.0,
            "warm_saving": (tin - warm) / tin if tin else 0.0,
            "roundtrip_fail": sum(1 for r in sel if r["roundtrip"] == "FAIL"),
            "raw_fallbacks": sum(1 for r in sel if r["outcome"] == "raw"),
        }
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="never download; cache only")
    args = ap.parse_args()

    if not QODEC.exists():
        print("build first: cargo build --release", file=sys.stderr)
        return 1
    CACHE.mkdir(exist_ok=True)
    RESULTS.mkdir(exist_ok=True)
    lock = json.loads(LOCK.read_text()) if LOCK.exists() else {}

    meters: list[tuple[str, str, dict]] = []  # (label, meter arg, provenance)
    for name in BUNDLED:
        meters.append((name, name, {"kind": "bundled"}))
    fetch_failed: list[str] = []
    print("fetching tokenizers:", file=sys.stderr)
    for family, repo, note in FAMILIES:
        path = fetch(family, repo, args.offline, lock)
        if path is None:
            fetch_failed.append(f"{family} ({repo})")
            continue
        prov = {"kind": "hf", "repo": repo, "sha256": lock[family]["sha256"]}
        if note:
            prov["note"] = note
        meters.append((family, f"hf:{path}", prov))
    LOCK.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")

    corpus_files = sorted(p.name for p in CORPUS.iterdir() if p.is_file())
    record = {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "fetch_failed": fetch_failed,
        "qodec_sha256": sha256_file(QODEC),
        "git_commit": subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip(),
        "corpus": {
            name: sha256_file(CORPUS / name) for name in corpus_files
        },
        "meters": {},
    }

    for label, meter_arg, prov in meters:
        print(f"bench under {label} …", file=sys.stderr)
        rows = run_bench(meter_arg)
        if rows is None:
            record["meters"][label] = {"provenance": prov, "status": "meter-failed"}
            continue
        record["meters"][label] = {
            "provenance": prov,
            "status": "ok",
            "rows": rows,
            "totals": totals(rows),
        }

    (RESULTS / "results.json").write_text(json.dumps(record, indent=2) + "\n")

    # Headline matrix: tokenizer family × codec, corpus-total cold saving.
    ok = [(l, m) for l, m in record["meters"].items() if m.get("status") == "ok"]
    lines = [
        "# Tokenizer matrix — corpus-total savings per family",
        "",
        f"date: {record['date']} · qodec commit `{record['git_commit'][:12]}` · "
        "corpus: the 6 committed samples · cold = full artifact (dictionary "
        "included), warm = body only (legend amortized in a cached prefix). "
        "Counts are payload-level (no chat template); every cell is re-encoded "
        "under that family's tokenizer, never rescaled from o200k.",
        "",
        "## Cold (net, dictionary travels in-message)",
        "",
        "| tokenizer | RAW tok | " + " | ".join(CODECS) + " |",
        "|---|---:|" + "---:|" * len(CODECS),
    ]

    def fmt(m: dict, codec: str, key: str) -> str:
        t = m["totals"][codec]
        flag = " ⚠" if t["roundtrip_fail"] else ""
        return f"{100 * t[key]:+.1f}%{flag}"

    for label, m in ok:
        tin = m["totals"]["mine"]["tokens_in"]
        lines.append(
            f"| {label} | {tin} | "
            + " | ".join(fmt(m, c, "cold_saving") for c in CODECS)
            + " |"
        )
    lines += ["", "## Warm (body only, legend amortized)", ""]
    lines.append("| tokenizer | RAW tok | " + " | ".join(CODECS) + " |")
    lines.append("|---|---:|" + "---:|" * len(CODECS))
    for label, m in ok:
        tin = m["totals"]["mine"]["tokens_in"]
        lines.append(
            f"| {label} | {tin} | "
            + " | ".join(fmt(m, c, "warm_saving") for c in CODECS)
            + " |"
        )
    failed = [l for l, m in record["meters"].items() if m.get("status") != "ok"]
    if failed:
        lines += ["", f"meters failed and excluded: {', '.join(failed)}"]
    if fetch_failed:
        lines += ["", f"families not fetched (no tokenizer.json / drift / offline): {', '.join(fetch_failed)}"]
    lines += [
        "",
        "⚠ marks a family where any sample failed byte roundtrip under that "
        "codec — investigate before trusting the number.",
        "",
        "Full per-sample rows, provenance and hashes: `results.json`.",
    ]
    (RESULTS / "matrix.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
