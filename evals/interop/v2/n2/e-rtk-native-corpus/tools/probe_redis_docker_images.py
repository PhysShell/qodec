#!/usr/bin/env python3
"""redis `rtk docker images` capture (harness 2/3) -- OBSERVATIONS ONLY, two modes:

  --mode diagnostic  : BARRED from qualification (record_kind redis_docker_images_diagnostic_capture).
  --mode acceptance  : NOT barred; the fresh observation a qualifying dispatch record is built from.

The daemon is the risk here, not the parser. We do NOT trust the runner's host Docker as the authority:
we launch TWO independent, isolated, pinned Docker-in-Docker daemons (docker@<digest>), each with a
FRESH empty --data-root and a pinned --storage-driver, sockets bind-mounted to the host, no host
/var/run/docker.sock, no preloaded images. The host Docker is only a LAUNCHER. Each daemon is
provisioned identically by the immutable image acquisition (pull library/redis@<index-digest>, then
tag). RAW `docker images` runs against daemon A; RTK `rtk docker images` (a host glibc binary that
shells to the host docker CLI via DOCKER_HOST) runs against daemon B -- so neither arm inherits the
other's daemon state. Image IDENTITY is captured from `docker image inspect` (Id, RepoDigests,
platform); RTK never reports it. Inventory is snapshotted before/after; the measurement is
network-denied (the daemon container is disconnected from its network + a denial probe).

Records observations only; the dispatch-v5 recompute decides PASS.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
N2E_DIR = HERE.parent
sys.path.insert(0, str(HERE))
import n2e_common as c  # noqa: E402
import run_canary_case as rcc  # noqa: E402
import n2e_case_adapters as adapters  # noqa: E402
import n2e_rtk_docker_images_oracle as orc  # noqa: E402

CONTRACT = N2E_DIR / "n2e-canary-execution-contract-v1.json"
SCEN = N2E_DIR / "n2e-command-scenarios-v1.json"
RECORD_TYPE = "n2e-redis-docker-images-capture"
DIAG_KIND = "redis_docker_images_diagnostic_capture"       # qualification path MUST reject this
ACCEPT_KIND = "redis_docker_images_acceptance_capture"

FMT = "{{.Repository}}:{{.Tag}}\t{{.Size}}"                  # the exact projection RTK derives from


def _run(argv, timeout=180, env=None):
    p = subprocess.run(argv, capture_output=True, timeout=timeout, env=env)
    return {"argv": argv, "exit_code": p.returncode,
            "stdout": p.stdout, "stderr": p.stderr[:65536]}


def _host_docker() -> str:
    d = shutil.which("docker")
    if not d:
        raise RuntimeError("host docker CLI not found (launcher unavailable)")
    return d


class Daemon:
    """One isolated pinned DinD daemon: fresh empty data-root, pinned storage driver, host-mounted
    socket, no host docker.sock, no preloaded images."""

    def __init__(self, role: str, workroot: Path, dind_ref: str, storage_driver: str):
        self.role = role
        self.name = f"n2e-{role}-daemon"
        self.rundir = workroot / f"{role}-run"
        self.datadir = workroot / f"{role}-data"
        self.rundir.mkdir(parents=True, exist_ok=True)
        self.datadir.mkdir(parents=True, exist_ok=True)
        self.sock = self.rundir / "docker.sock"
        self.dind_ref = dind_ref
        self.storage_driver = storage_driver
        self.host = _host_docker()
        self.env = {**os.environ, "DOCKER_HOST": f"unix://{self.sock}"}

    def start(self) -> dict:
        subprocess.run([self.host, "rm", "-f", self.name], capture_output=True)
        # launcher: host docker runs the pinned DinD image; inner dockerd listens on the mounted socket
        run = _run([
            self.host, "run", "-d", "--privileged", "--name", self.name,
            "-e", "DOCKER_TLS_CERTDIR=",                       # unix socket, no TLS
            "-v", f"{self.rundir}:/run",
            "-v", f"{self.datadir}:/var/lib/docker",
            self.dind_ref,
            "--host=unix:///run/docker.sock",
            f"--storage-driver={self.storage_driver}",
            "--data-root=/var/lib/docker",
        ])
        info = {"start": {"exit_code": run["exit_code"],
                          "stderr": run["stderr"].decode("utf-8", "replace")[:2048]}}
        # wait for the inner daemon socket + readiness
        ready = False
        for _ in range(60):
            if self.sock.exists():
                subprocess.run(["sudo", "chmod", "666", str(self.sock)], capture_output=True)
                v = _run([self.host, "version", "--format", "{{.Server.Version}}"], env=self.env, timeout=15)
                if v["exit_code"] == 0:
                    ready = True
                    break
            time.sleep(1)
        info["ready"] = ready
        return info

    def dx(self, args, timeout=180):
        """A docker command against THIS isolated daemon (host CLI + DOCKER_HOST)."""
        return _run([self.host, *args], timeout=timeout, env=self.env)

    def disconnect_network(self) -> dict:
        r = _run([self.host, "network", "disconnect", "bridge", self.name])
        return {"exit_code": r["exit_code"], "stderr": r["stderr"].decode("utf-8", "replace")[:512]}

    def teardown(self):
        subprocess.run([self.host, "rm", "-f", self.name], capture_output=True)


def _snapshot(dm: Daemon) -> dict:
    fmt = dm.dx(["images", "--format", FMT])
    ids = dm.dx(["images", "--format", "{{.ID}}"])
    return {"format_rows": fmt["stdout"].decode("utf-8", "replace"),
            "image_ids": sorted(x for x in ids["stdout"].decode("utf-8", "replace").split("\n") if x)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", default="container::redis::docker::images")
    ap.add_argument("--mode", choices=["diagnostic", "acceptance"], default="diagnostic")
    ap.add_argument("--out", required=True)
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--dind-ref", default="docker:27-dind")
    ap.add_argument("--storage-driver", default="vfs")
    ap.add_argument("--reps", type=int, default=3)
    a = ap.parse_args()
    out = Path(a.out).resolve(); ev = Path(a.evidence).resolve(); ev.mkdir(parents=True, exist_ok=True)
    barred = a.mode == "diagnostic"

    body = {"case_id": a.case, "mode": a.mode,
            "record_kind": DIAG_KIND if barred else ACCEPT_KIND,
            "barred_from_qualification": barred, "qualification_pass": None,
            "verdict_authority": "dispatch recompute only (producer records observations)",
            "note": ("DIAGNOSTIC ONLY -- reveals compact vs never_worse passthrough + real daemon "
                     "identity; moves no gate." if barred else
                     "FRESH acceptance capture; re-launches isolated daemons + re-provisions. No gate moved here.")}

    scenario = next(s for s in c.load_record(SCEN)["scenarios"] if s["case_id"] == a.case)
    contract = next(e for e in c.load_record(CONTRACT)["contracts"] if e["case_id"] == a.case)
    adapter = adapters.adapter_for(a.case)
    det = adapter.bind(contract, scenario)
    body["adapter_binding"] = det
    redis_ref = det["image_ref"]              # library/redis@sha256:<index-digest>
    case_tag = det["case_tag"]                # the exact repo:tag assigned after pull-by-digest

    def emit():
        c.write_record(out, c.envelope(record_type=RECORD_TYPE,
                       generated_by="tools/probe_redis_docker_images.py", **body))

    rtk_bin = os.environ.get("RTK_BIN")
    if not rtk_bin or c.sha256_file(rtk_bin) != rcc.RTK_BINARY_SHA256:
        body["outcome"] = "CAPTURE_REJECTED_RTK_IDENTITY"; emit()
        print("redis docker images: rtk identity gate failed"); return 0
    body["rtk_binary_sha256"] = c.sha256_file(rtk_bin)

    try:
        host_docker = _host_docker()
        body["host_docker_client_identity"] = {
            "path": host_docker, "sha256": c.sha256_file(host_docker),
            "bytes": Path(host_docker).stat().st_size,
            "version": _run([host_docker, "version", "--format", "{{.Client.Version}}"])["stdout"]
            .decode("utf-8", "replace").strip()}
    except Exception as e:  # noqa: BLE001
        body["outcome"] = "CAPTURE_REJECTED_NO_HOST_DOCKER"; body["error"] = str(e); emit()
        print("redis docker images: no host docker launcher"); return 0

    workroot = Path(tempfile.mkdtemp(prefix="n2e-redis-docker-"))
    daemons: list[Daemon] = []
    try:
        # pre-pull the pinned DinD image on the host launcher, record its resolved digest
        pull_dind = _run([host_docker, "pull", a.dind_ref], timeout=600)
        dind_inspect = _run([host_docker, "image", "inspect", a.dind_ref])
        dind_digests = []
        if dind_inspect["exit_code"] == 0:
            try:
                dind_digests = json.loads(dind_inspect["stdout"])[0].get("RepoDigests") or []
            except Exception:  # noqa: BLE001
                pass
        body["dind_daemon_image"] = {"ref": a.dind_ref, "pull_exit": pull_dind["exit_code"],
                                     "repo_digests": sorted(dind_digests),
                                     "storage_driver": a.storage_driver}

        arms = {}
        for role in ("raw", "rtk"):
            dm = Daemon(role, workroot, a.dind_ref, a.storage_driver); daemons.append(dm)
            start = dm.start()
            if not start["ready"]:
                body["outcome"] = "CAPTURE_REJECTED_DAEMON_NOT_READY"; body[f"{role}_daemon"] = start
                emit(); print(f"redis docker images: {role} daemon not ready"); return 0
            # daemon identity: version + info (storage driver, data-root, image count)
            ver = dm.dx(["version", "--format", "{{json .}}"])
            info = dm.dx(["info", "--format", "{{json .}}"])
            def _j(r):
                try:
                    return json.loads(r["stdout"])
                except Exception:  # noqa: BLE001
                    return None
            vj, ij = _j(ver), _j(info)
            inv_before = _snapshot(dm)
            # immutable acquisition: pull redis by digest (NEEDS network), then assign the case tag
            pull = dm.dx(["pull", redis_ref], timeout=600)
            tag = dm.dx(["tag", redis_ref, case_tag])
            inspect = dm.dx(["image", "inspect", redis_ref])
            inspect_parsed = orc.parse_inspect(inspect["stdout"])
            # network-denied measurement: sever the daemon container's network, then prove denial
            disc = dm.disconnect_network()
            denial = dm.dx(["run", "--rm", case_tag, "sh", "-c",
                            "timeout 3 getent hosts registry-1.docker.io || echo DENIED"], timeout=60)
            inv_after = _snapshot(dm)
            (ev / f"{role}.inspect.json").write_bytes(inspect["stdout"])
            arms[role] = {
                "daemon": {"start": start, "version": vj,
                           "storage_driver": (ij or {}).get("Driver"),
                           "data_root": (ij or {}).get("DockerRootDir"),
                           "server_version": (ij or {}).get("ServerVersion"),
                           "os_type": (ij or {}).get("OSType"), "arch": (ij or {}).get("Architecture"),
                           "images_at_start": (ij or {}).get("Images")},
                "acquisition": {"pull_exit": pull["exit_code"], "tag_exit": tag["exit_code"],
                                "redis_ref": redis_ref, "case_tag": case_tag},
                "inspect": inspect_parsed,
                "inventory_before": inv_before, "inventory_after": inv_after,
                "network_denied": {"disconnect": disc,
                                   "denial_probe_stdout": denial["stdout"].decode("utf-8", "replace")[:256],
                                   "denial_probe_exit": denial["exit_code"]},
            }

        # ---- MEASUREMENT: RAW on raw-daemon, RTK on rtk-daemon, `reps` times ----
        raw_dm = daemons[0]; rtk_dm = daemons[1]
        raw_runs, rtk_runs = [], []
        for i in range(a.reps):
            r = raw_dm.dx(["images"])
            (ev / f"raw.images.rep{i}.bin").write_bytes(r["stdout"])
            raw_runs.append({"exit_code": r["exit_code"], **c_digest(r["stdout"])})
            k = _run([rtk_bin, "docker", "images"], env=rtk_dm.env)
            (ev / f"rtk.images.rep{i}.bin").write_bytes(k["stdout"])
            rtk_runs.append({"exit_code": k["exit_code"], **c_digest(k["stdout"])})
        # RAW normative projection (the exact --format RTK derives from), on the raw daemon
        raw_fmt = raw_dm.dx(["images", "--format", FMT])
        (ev / "raw.format_rows.bin").write_bytes(raw_fmt["stdout"])

        raw_stdout = (ev / "raw.images.rep0.bin").read_bytes()
        rtk_stdout = (ev / "rtk.images.rep0.bin").read_bytes()
        raw_format_parsed = orc.parse_format_rows(raw_fmt["stdout"])
        rtk_parsed = orc.parse_rtk(rtk_stdout)
        eq = orc.equivalence(raw_format_parsed, rtk_parsed)

        arms["raw"]["measurement"] = {"argv": ["docker", "images"], "runs": raw_runs,
                                      "format_rows_text": raw_fmt["stdout"].decode("utf-8", "replace")}
        arms["rtk"]["measurement"] = {"argv": ["rtk", "docker", "images"], "runs": rtk_runs,
                                      "stdout_text": rtk_stdout.decode("utf-8", "replace")}
        body["arms"] = arms
        body["oracle_observation"] = {
            "raw_format_parsed": raw_format_parsed, "rtk_parsed": rtk_parsed,
            "output_mode": rtk_parsed.get("output_mode"),
            "raw_stdout_text": raw_stdout.decode("utf-8", "replace")[:2048],
            "rtk_stdout_text": rtk_stdout.decode("utf-8", "replace")[:2048],
            "equivalence": eq,
            "authority_note": "RTK preserves outcome + (repository:tag, size) multiset + count only; "
                              "image digest identity is an execution determinant from docker image "
                              "inspect, not an oracle claim.",
        }
        body["outcome"] = "REDIS_DOCKER_IMAGES_OBSERVED"
        emit()
        print(f"redis docker images [{a.mode}]: OBSERVED mode={rtk_parsed.get('output_mode')} "
              f"raw_rows={raw_format_parsed.get('count')} equivalent={eq.get('equivalent')} "
              f"mismatches={eq.get('mismatches')} (verifier decides PASS)")
        return 0
    except Exception as e:  # noqa: BLE001
        import traceback
        body["outcome"] = "CAPTURE_ERROR"; body["error"] = f"{type(e).__name__}: {e}"
        body["traceback"] = traceback.format_exc()[-2000:]
        emit(); print("redis docker images: ERROR", e); return 0
    finally:
        for dm in daemons:
            dm.teardown()
        shutil.rmtree(workroot, ignore_errors=True)


def c_digest(data: bytes) -> dict:
    import hashlib
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


if __name__ == "__main__":
    raise SystemExit(main())
