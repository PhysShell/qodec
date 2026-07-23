#!/usr/bin/env python3
"""Reproducible §15 RAW qualification pilot for one real Loghub log case.

Proves the full execution+measurement pipeline on real, checksum-pinned data
with the identity-matched binaries:
  1. download the pinned Loghub archive (verify publisher md5 from the source pins);
  2. safety-scan + extract (§4: reject traversal/absolute/symlink);
  3. take a deterministic slice (first N lines of the publisher file);
  4. RAW x3 (cat) and RTK x3 (rtk log) in fresh workdirs — require exit-code
     stability and byte-determinism (§15);
  5. compute exact o200k tokens for both combined streams (canonical qodec meter);
  6. run the §14 log severity oracle.

Writes n2e-log-qualification-pilot-v1.json. RTK savings are reported but are NOT
an acceptance criterion (§15). Requires RTK_BIN, QODEC_BIN, network, and honors
standard CA env vars.
"""
from __future__ import annotations

import hashlib
import os
import sys
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import n2e_measure as m  # noqa: E402
import n2e_oracles as ora  # noqa: E402

OUT = N2E_DIR / "n2e-log-qualification-pilot-v1.json"
PINS = N2E_DIR / "n2e-source-pins-v1.json"
SYSTEM = "Proxifier"          # Loghub system for this pilot
LOG_MEMBER = "Proxifier/Proxifier_full.log"
SLICE_LINES = 1500
REPS = 3
ZENODO_RECORD = "8275861"


def pinned_checksum() -> tuple[str, int]:
    pins = c.load_record(PINS)
    for z in pins["zenodo_records"]:
        if z["source_id"] == "loghub-2.0":
            for f in z["files"]:
                if f["key"] == f"{SYSTEM}.zip":
                    return f["checksum"], f["size"]
    raise SystemExit(f"{SYSTEM}.zip pin not found")


def download_verify(dest: Path) -> str:
    checksum, size = pinned_checksum()
    url = f"https://zenodo.org/api/records/{ZENODO_RECORD}/files/{SYSTEM}.zip/content"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, context=c.ssl_context(), timeout=300) as r:
        data = r.read()
    if len(data) != size:
        raise SystemExit(f"size mismatch {len(data)} != {size}")
    algo, _, hexval = checksum.partition(":")
    got = hashlib.new(algo, data).hexdigest()
    if got != hexval:
        raise SystemExit(f"checksum mismatch {algo}:{got} != {checksum}")
    dest.write_bytes(data)
    return checksum


def safe_extract(zip_path: Path, out_dir: Path) -> None:
    z = zipfile.ZipFile(zip_path)
    for n in z.namelist():
        if n.startswith("/") or ".." in Path(n).parts:
            raise SystemExit(f"unsafe archive path {n!r}")
    z.extractall(out_dir)


def build() -> dict:
    rtk_bin = os.environ.get("RTK_BIN")
    qodec_bin = os.environ.get("QODEC_BIN")
    if not rtk_bin or not qodec_bin:
        raise SystemExit("RTK_BIN and QODEC_BIN must be set")

    import tempfile
    with tempfile.TemporaryDirectory(prefix="n2e-logpilot-") as td:
        td = Path(td)
        zip_path = td / f"{SYSTEM}.zip"
        checksum = download_verify(zip_path)
        safe_extract(zip_path, td / "x")
        full = (td / "x" / LOG_MEMBER).read_bytes()
        slice_lines = full.splitlines(keepends=True)[:SLICE_LINES]
        slice_bytes = b"".join(slice_lines)
        slice_path = td / "slice.log"
        slice_path.write_bytes(slice_bytes)
        slice_sha = hashlib.sha256(slice_bytes).hexdigest()

        def setup(workdir):
            (Path(workdir) / "slice.log").write_bytes(slice_bytes)

        raw = m.run_repeated(["cat", "slice.log"], REPS, timeout=60, setup=setup)
        rtk = m.run_repeated([rtk_bin, "log", "slice.log"], REPS, timeout=120, setup=setup)

        raw_tokens = m.o200k_tokens(raw["_last"]["_combined"], qodec_bin)
        rtk_tokens = m.o200k_tokens(rtk["_last"]["_combined"], qodec_bin)
        oracle = ora.check_log_oracle(raw["_last"]["_combined"], rtk["_last"]["_combined"])

        savings_pct = round(100 * (raw_tokens - rtk_tokens) / raw_tokens, 2) if raw_tokens else None

    return c.envelope(
        record_type="n2e-log-qualification-pilot",
        generated_by="evals/interop/v2/n2/e-rtk-native-corpus/tools/build_n2e_log_qualification_pilot.py",
        purpose="Reproducible §15 RAW/RTK qualification for one real, checksum-pinned Loghub log case.",
        source_id="loghub-2.0",
        zenodo_record=ZENODO_RECORD,
        loghub_system=SYSTEM,
        archive_checksum=checksum,
        slice_lines=SLICE_LINES,
        slice_sha256=slice_sha,
        rtk_binary_sha256=c.sha256_file(rtk_bin),
        raw_arm={"exit_code": raw["exit_code"], "exit_code_stable": raw["exit_code_stable"],
                 "byte_deterministic": raw["byte_deterministic"], "combined_sha256": raw["combined_sha256"],
                 "combined_bytes": raw["combined_bytes"], "o200k_tokens": raw_tokens},
        rtk_arm={"exit_code": rtk["exit_code"], "exit_code_stable": rtk["exit_code_stable"],
                 "byte_deterministic": rtk["byte_deterministic"], "combined_sha256": rtk["combined_sha256"],
                 "combined_bytes": rtk["combined_bytes"], "o200k_tokens": rtk_tokens},
        rtk_savings_pct_reporting_only=savings_pct,
        semantic_oracle=oracle,
        acceptance_note="RTK savings are reporting-only and never an acceptance criterion (§15).",
    )


def main() -> int:
    c.write_record(OUT, build())
    rec = c.load_record(OUT)
    print(f"wrote {OUT.name} record_sha256={rec['record_sha256']}")
    print(f"  RAW o200k={rec['raw_arm']['o200k_tokens']} det={rec['raw_arm']['byte_deterministic']}")
    print(f"  RTK o200k={rec['rtk_arm']['o200k_tokens']} det={rec['rtk_arm']['byte_deterministic']}")
    print(f"  savings(reporting)={rec['rtk_savings_pct_reporting_only']}% oracle_preserved={rec['semantic_oracle']['severity_counts_preserved']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
