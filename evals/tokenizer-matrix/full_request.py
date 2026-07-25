#!/usr/bin/env python3
"""Full-request accounting — G2 taken to the wire format.

The payload-level matrix (run.py) proves net token reduction on content
alone. This closes the remaining gap in gate G2: count the *whole request*
as the model would receive it — chat template applied, special tokens in
place, and the encoded arm carrying its full freight (notation brief +
artifact, dictionary included). Uses each family's own `chat_template`
(fetched from tokenizer_config.json, pinned by SHA-256 in the lock) and the
Python `tokenizers` library, whose counts the repo already proved
bit-identical to the crate's fail-closed `hf:` meter
(evals/interop/tests/test_hf_meter_parity.py).

Honest notes:
* Templates are rendered textually with jinja2 and counted with
  `add_special_tokens=False`; special-token *strings* the template inlines
  (`<|im_start|>` …) are matched by the tokenizer's added-token machinery,
  and no extra BOS is injected on top. Families whose template needs
  runtime shims we don't provide are recorded as failed, never guessed.
* The encoded arm re-encodes under that family's tokenizer via
  `qodec encode --meter hf:…` — aliases and acceptance per family, no
  rescaling — and pays the notation brief every time (cold, one-shot).

    python3 evals/tokenizer-matrix/full_request.py            # after run.py
"""

import json
import subprocess
import sys
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

import jinja2
from tokenizers import Tokenizer

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
QODEC = ROOT / "target" / "release" / "qodec"
CORPUS = ROOT / "corpus"
CACHE = HERE / ".cache"
RESULTS = HERE / "results"
LOCK = HERE / "tokenizers.lock.json"

CODECS = ["squeeze", "paper"]
TASK = "Answer questions about the payload below.\n\n"


def fetch_config(family: str, repo: str, lock: dict) -> dict | None:
    dest = CACHE / f"{family}.tokenizer_config.json"
    if not dest.exists():
        url = f"https://huggingface.co/{repo}/resolve/main/tokenizer_config.json"
        proc = subprocess.run(
            ["curl", "-fsSL", "--max-time", "120", "-o", str(dest), url],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            return None
    digest = sha256(dest.read_bytes()).hexdigest()
    pinned = lock[family].get("config_sha256")
    if pinned is None:
        lock[family]["config_sha256"] = digest
    elif pinned != digest:
        print(f"  {family}: tokenizer_config drifted from lock — refusing", file=sys.stderr)
        return None
    return json.loads(dest.read_text())


def chat_template(config: dict) -> str | None:
    t = config.get("chat_template")
    if isinstance(t, list):  # named templates; take "default" else first
        by_name = {e.get("name"): e.get("template") for e in t if isinstance(e, dict)}
        return by_name.get("default") or next(iter(by_name.values()), None)
    return t


def token_str(v) -> str:
    return v.get("content", "") if isinstance(v, dict) else (v or "")


def render(template: str, config: dict, content: str) -> str | None:
    env = jinja2.Environment(
        trim_blocks=True, lstrip_blocks=True,
        extensions=["jinja2.ext.loopcontrols"],
    )
    env.filters["tojson"] = lambda v, **kw: json.dumps(v, **kw)
    env.globals["raise_exception"] = lambda msg: (_ for _ in ()).throw(
        jinja2.TemplateError(msg)
    )
    env.globals["strftime_now"] = lambda fmt: "1970-01-01"
    try:
        return env.from_string(template).render(
            messages=[{"role": "user", "content": content}],
            add_generation_prompt=True,
            bos_token=token_str(config.get("bos_token")),
            eos_token=token_str(config.get("eos_token")),
            unk_token=token_str(config.get("unk_token")),
            tools=None,
        )
    except Exception as e:  # recorded, never guessed
        print(f"    template failed: {str(e)[:120]}", file=sys.stderr)
        return None


def encode(sample: Path, codec: str, meter: str) -> str | None:
    proc = subprocess.run(
        [str(QODEC), "encode", "--codec", codec, "-i", str(sample), "--meter", meter],
        capture_output=True, text=True,
    )
    return proc.stdout if proc.returncode == 0 else None


def main() -> int:
    if not QODEC.exists():
        print("build first: cargo build --release", file=sys.stderr)
        return 1
    lock = json.loads(LOCK.read_text())
    brief = subprocess.run(
        [str(QODEC), "notation"], capture_output=True, text=True
    ).stdout

    samples = sorted(p for p in CORPUS.iterdir() if p.is_file())
    record = {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "git_commit": subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip(),
        "task_prefix": TASK,
        "families": {},
    }

    for family, pin in sorted(lock.items()):
        tok_path = CACHE / f"{family}.tokenizer.json"
        if not tok_path.exists():
            continue
        print(f"{family} …", file=sys.stderr)
        config = fetch_config(family, pin["repo"], lock)
        template = chat_template(config) if config else None
        if not template:
            record["families"][family] = {"status": "no-chat-template"}
            continue
        tok = Tokenizer.from_file(str(tok_path))
        count = lambda s: len(tok.encode(s, add_special_tokens=False).ids)

        rows = []
        failed = False
        for sample in samples:
            payload = sample.read_text()
            raw_req = render(template, config, TASK + payload)
            if raw_req is None:
                failed = True
                break
            row = {"sample": sample.name, "raw_request": count(raw_req)}
            for codec in CODECS:
                artifact = encode(sample, codec, f"hf:{tok_path}")
                if artifact is None:
                    row[f"{codec}_request"] = None
                    row[f"{codec}_request_warm"] = None
                    continue
                cold = render(template, config, TASK + brief + "\n\n" + artifact)
                warm = render(template, config, TASK + artifact)
                row[f"{codec}_request"] = count(cold) if cold is not None else None
                row[f"{codec}_request_warm"] = count(warm) if warm is not None else None
            rows.append(row)
        if failed:
            record["families"][family] = {"status": "template-render-failed"}
            continue
        record["families"][family] = {"status": "ok", "rows": rows}
        lockpath_note = None  # noqa: F841 — provenance lives in the lock file

    LOCK.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
    (RESULTS / "full-request.json").write_text(json.dumps(record, indent=2) + "\n")

    lines = [
        "# Full-request matrix — chat template applied, brief + dictionary paid",
        "",
        f"date {record['date']} · qodec `{record['git_commit'][:12]}` · cold one-shot: "
        "encoded arm = template(task + notation brief + artifact). Per family, "
        "corpus-total request tokens; saving vs the raw request.",
        "",
        "| tokenizer | raw req | squeeze cold | Δ | squeeze warm | Δ | paper cold | Δ | paper warm | Δ |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for family, m in sorted(record["families"].items()):
        if m.get("status") != "ok":
            lines.append(f"| {family} | {m['status']} | | | | | | | | |")
            continue
        tot = lambda k: sum(r[k] for r in m["rows"] if r.get(k) is not None)
        raw_t = tot("raw_request")
        cells = [f"| {family} | {raw_t} |"]
        for codec in CODECS:
            for key in (f"{codec}_request", f"{codec}_request_warm"):
                t = tot(key)
                cells.append(f" {t} | {100 * (raw_t - t) / raw_t:+.1f}% |")
        lines.append("".join(cells))
    lines += [
        "",
        "cold = the brief travels in every request (one-shot worst case; on "
        "payloads this small it eats the gain — the truth, not a bug). "
        "warm = brief amortized in a cached prefix, artifact still carries its "
        "own dictionary. Both are *full requests*: chat template applied, "
        "task line included.",
    ]
    (RESULTS / "full-request.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
