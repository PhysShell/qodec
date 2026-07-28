#!/usr/bin/env python3
"""Qodec provider/model discovery and qualification primitives.

ModelHubby is an untrusted discovery source. This tool turns an exported JSON
catalog into a canonical, reviewable snapshot; plans explicit provider×model
runs with fail-closed policy filters; and probes OpenAI-compatible endpoints
without fallback or model substitution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SCHEMA = "qodec-provider-catalog-v1"
PLAN_SCHEMA = "qodec-provider-plan-v1"
PROBE_SCHEMA = "qodec-provider-probe-v1"
POLICY_VALUES = {"yes", "no", "unknown"}


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


def required_text(row: dict[str, Any], field: str) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def policy(row: dict[str, Any], field: str) -> str:
    value = row.get(field, "unknown")
    if isinstance(value, bool):
        value = "yes" if value else "no"
    if not isinstance(value, str):
        raise ValueError(f"{field} must be yes/no/unknown")
    value = value.lower().strip()
    if value not in POLICY_VALUES:
        raise ValueError(f"{field} must be yes/no/unknown, got {value!r}")
    return value


def source_rows(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        rows = raw
    elif isinstance(raw, dict) and isinstance(raw.get("targets"), list):
        rows = raw["targets"]
    elif isinstance(raw, dict) and isinstance(raw.get("models"), list):
        rows = raw["models"]
    else:
        raise ValueError("source must be a JSON list or an object with targets/models")
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError("every source row must be an object")
    return rows


def normalize_target(row: dict[str, Any]) -> dict[str, Any]:
    provider = required_text(row, "provider").lower()
    model = required_text(row, "model")
    api_style = str(row.get("api_style", "openai-chat")).strip().lower()
    if api_style != "openai-chat":
        raise ValueError(f"unsupported api_style {api_style!r}; only openai-chat is qualified")
    api_base = required_text(row, "api_base").rstrip("/")
    key_env = required_text(row, "key_env")
    target = {
        "target_id": f"{provider}--{model}",
        "provider": provider,
        "model": model,
        "api_style": api_style,
        "api_base": api_base,
        "key_env": key_env,
        "free_tier": policy(row, "free_tier"),
        "card_required": policy(row, "card_required"),
        "training_use": policy(row, "training_use"),
    }
    if isinstance(row.get("source_url"), str) and row["source_url"].strip():
        target["source_url"] = row["source_url"].strip()
    return target


def import_catalog(source: Path, observed_at: str) -> dict[str, Any]:
    raw_bytes = source.read_bytes()
    rows = source_rows(json.loads(raw_bytes))
    targets = [normalize_target(row) for row in rows]
    targets.sort(key=lambda row: (row["provider"], row["model"], row["api_base"]))
    ids = [row["target_id"] for row in targets]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate provider/model target_id")
    return {
        "schema": SCHEMA,
        "source": {
            "kind": "modelhubby-export",
            "observed_at": observed_at,
            "raw_sha256": sha256_bytes(raw_bytes),
        },
        "targets": targets,
    }


def target_allowed(target: dict[str, Any], args: argparse.Namespace) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if args.free_only and target["free_tier"] != "yes":
        reasons.append(f"free_tier={target['free_tier']}")
    if args.no_card and target["card_required"] != "no":
        reasons.append(f"card_required={target['card_required']}")
    if args.no_training and target["training_use"] != "no":
        reasons.append(f"training_use={target['training_use']}")
    return not reasons, reasons


def build_plan(catalog: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    if catalog.get("schema") != SCHEMA:
        raise ValueError(f"expected {SCHEMA}")
    selected, rejected = [], []
    for target in catalog["targets"]:
        allowed, reasons = target_allowed(target, args)
        (selected if allowed else rejected).append(
            target if allowed else {"target_id": target["target_id"], "reasons": reasons}
        )
    identity = {
        "catalog_sha256": sha256_bytes(canonical_bytes(catalog)),
        "filters": {
            "free_only": args.free_only,
            "no_card": args.no_card,
            "no_training": args.no_training,
        },
        "selected_target_ids": [row["target_id"] for row in selected],
    }
    return {
        "schema": PLAN_SCHEMA,
        "identity": identity,
        "plan_sha256": sha256_bytes(canonical_bytes(identity)),
        "selected": selected,
        "rejected": rejected,
    }


def classify_http(status: int) -> str:
    if status in (401, 403):
        return "AUTH_FAILURE"
    if status == 404:
        return "MODEL_NOT_FOUND"
    if status == 429:
        return "RATE_LIMITED"
    if 500 <= status <= 599:
        return "PROVIDER_5XX"
    return "HTTP_FAILURE"


def probe_target(target: dict[str, Any], timeout: float) -> dict[str, Any]:
    started = time.time()
    request_body = canonical_bytes({
        "model": target["model"],
        "messages": [{"role": "user", "content": "Return exactly: QODEC_PROBE_OK"}],
        "temperature": 0,
        "max_tokens": 16,
    })
    base = target["api_base"]
    url = base if base.endswith("/chat/completions") else base + "/chat/completions"
    result: dict[str, Any] = {
        "schema": PROBE_SCHEMA,
        "target_id": target["target_id"],
        "provider": target["provider"],
        "requested_model": target["model"],
        "request_sha256": sha256_bytes(request_body),
        "endpoint": url,
    }
    key = os.environ.get(target["key_env"])
    if not key:
        result.update(classification="AUTH_FAILURE", detail=f"missing env {target['key_env']}")
        return result
    request = urllib.request.Request(
        url,
        data=request_body,
        method="POST",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
        result.update(
            classification=classify_http(status),
            http_status=status,
            response_sha256=sha256_bytes(raw),
            latency_ms=round((time.time() - started) * 1000),
        )
        return result
    except TimeoutError:
        result.update(classification="TIMEOUT", latency_ms=round((time.time() - started) * 1000))
        return result
    except urllib.error.URLError as exc:
        reason = exc.reason
        result.update(
            classification="TIMEOUT" if isinstance(reason, TimeoutError) else "TRANSPORT_FAILURE",
            detail=str(reason),
            latency_ms=round((time.time() - started) * 1000),
        )
        return result

    result.update(
        http_status=status,
        response_sha256=sha256_bytes(raw),
        latency_ms=round((time.time() - started) * 1000),
    )
    try:
        payload = json.loads(raw)
        reported_model = payload.get("model")
        choices = payload.get("choices", [])
        content = choices[0]["message"]["content"] if choices else None
    except (json.JSONDecodeError, KeyError, TypeError, IndexError):
        result["classification"] = "INVALID_OUTPUT"
        return result
    result["reported_model"] = reported_model
    if reported_model and reported_model != target["model"]:
        result["classification"] = "PROVIDER_SUBSTITUTED"
    elif content != "QODEC_PROBE_OK":
        result["classification"] = "INVALID_OUTPUT"
    else:
        result["classification"] = "PASS"
    if isinstance(payload.get("usage"), dict):
        result["provider_usage"] = payload["usage"]
    return result


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import")
    imp.add_argument("--source", type=Path, required=True)
    imp.add_argument("--observed-at", required=True, help="UTC ISO-8601 timestamp, supplied explicitly")
    imp.add_argument("--out", type=Path, required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--catalog", type=Path, required=True)
    plan.add_argument("--out", type=Path, required=True)
    plan.add_argument("--free-only", action="store_true")
    plan.add_argument("--no-card", action="store_true")
    plan.add_argument("--no-training", action="store_true")
    probe = sub.add_parser("probe")
    probe.add_argument("--plan", type=Path, required=True)
    probe.add_argument("--out-dir", type=Path, required=True)
    probe.add_argument("--timeout", type=float, default=30.0)
    return p


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "import":
            write_json(args.out, import_catalog(args.source, args.observed_at))
        elif args.command == "plan":
            write_json(args.out, build_plan(read_json(args.catalog), args))
        else:
            plan = read_json(args.plan)
            if plan.get("schema") != PLAN_SCHEMA:
                raise ValueError(f"expected {PLAN_SCHEMA}")
            args.out_dir.mkdir(parents=True, exist_ok=True)
            for target in plan["selected"]:
                write_json(args.out_dir / f"{target['target_id']}.json", probe_target(target, args.timeout))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"provider-matrix: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
