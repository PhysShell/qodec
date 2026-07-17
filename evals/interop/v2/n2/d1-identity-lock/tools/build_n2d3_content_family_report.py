#!/usr/bin/env python3
"""Builds the post-hoc, exploratory N2-D3 token-results-by-content-family
report. This is a pure derived view: it reads ONLY the already-accepted
canonical n2d3-primary-token-benchmark-v1.json (pinned record_sha256) and
the already-committed n2d3-content-taxonomy-v1.json, and computes every
number here fresh from their raw per-case fields -- never from the PR body,
a Markdown table, or any other rendering. It does not rerun N2-D2/N2-D3,
does not touch canonical input bytes, and does not alter the canonical
record in any way.

Primary cut: content_family. Secondary exploratory views: origin_kind,
producer_family, payload_kind. Small groups are never hidden: every group
carries an explicit sample_size_classification, and no bootstrap interval is
computed for any group with fewer than 3 measured cases -- resampling unit
is case_id, seed 20260716 (resamples=10000), the same seed already used by
the canonical record's own bootstrap (this is a fresh, independent
computation over different, per-family subsets of the same cases, not a
retrofit of the canonical corpus-wide interval).

Zero-token case (repo-pyflakes, raw_tokens=0): its own per-case ratio is
null (0/0 is undefined) -- documented explicitly here and in the rendered
report. Group/macro/median/bootstrap aggregation reuses the exact same
zero-token convention as the accepted canonical build_n2d3_primary_benchmark
builder (ratio treated as 0.0 in the aggregate, never imputed, never used to
divide by zero): see _aggregation_ratio() below, which mirrors
build_n2d3_primary_benchmark._arm_stats()'s own `if r["raw_tokens"] else 0.0`
fallback exactly.

Non-UTF-8 refusals (dataset-loghub-v8, research-corpus-loghub2) remain part
of every group's total_case_count/refusal_count and are the sole members of
payload_kind=binary-container; they are excluded from token totals and
savings denominators and are never assigned zero tokens.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import statistics
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
IDENTITY_LOCK_DIR = TOOLS_DIR.parent
sys.path.insert(0, str(TOOLS_DIR))

import build_n2d3_content_taxonomy as taxonomy_builder  # noqa: E402
import build_n2d3_primary_benchmark as bench_builder  # noqa: E402

OUT_JSON_PATH = IDENTITY_LOCK_DIR / "n2d3-token-results-by-content-family-v1.json"
OUT_MD_PATH = IDENTITY_LOCK_DIR / "n2d3-token-results-by-content-family-v1.md"
OUT_CSV_PATH = IDENTITY_LOCK_DIR / "n2d3-token-results-by-content-family-v1.csv"

N2D3_BENCHMARK_PATH = IDENTITY_LOCK_DIR / "n2d3-primary-token-benchmark-v1.json"
TAXONOMY_PATH = IDENTITY_LOCK_DIR / "n2d3-content-taxonomy-v1.json"
CANONICAL_N2D3_SHA256 = "sha256:c00d2ff8f4883c964fbd05d46840763826806ea73357511e6f38a882aaf0e1cd"

BOOTSTRAP_SEED = 20260716
BOOTSTRAP_RESAMPLES = 10000
MIN_BOOTSTRAP_MEASURED_CASES = 3
DOMINANCE_THRESHOLD_PCT = 80.0
ZERO_TOKEN_CASE_ID = "repo-pyflakes"
NON_UTF8_REFUSAL_CASE_IDS = ("dataset-loghub-v8", "research-corpus-loghub2")
DOMINANT_CORPUS_CASE_ID = "dataset-rtn-traffic-ids"

ARM_TOKEN_FIELDS = {
    "qodec": "qodec_tokens",
    "rtk": "rtk_tokens",
    "rtk_plus_qodec": "rtk_plus_qodec_tokens",
}
AXES = ("content_family", "origin_kind", "producer_family", "payload_kind")


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _aggregation_ratio(row: dict, token_field: str) -> float:
    """Mirrors build_n2d3_primary_benchmark._arm_stats()'s own per-case
    ratio exactly, including its zero-raw-token fallback to 0.0. Used for
    macro/median/bootstrap -- never for the per-case displayed ratio."""
    raw = row["raw_tokens"]
    return 1.0 - (row[token_field] / raw) if raw else 0.0


def _display_ratio(row: dict, token_field: str) -> float | None:
    """The per-case ratio as displayed/used for min/max: null (not 0.0) when
    raw_tokens is 0, since 0/0 is genuinely undefined -- documented in
    zero_token_case_policy, distinct from the aggregation convention above."""
    raw = row["raw_tokens"]
    if not raw:
        return None
    return 1.0 - (row[token_field] / raw)


def _bootstrap_ci(ratios: list[float]) -> dict:
    return {
        k: (round(100.0 * v, 4) if isinstance(v, float) else v)
        for k, v in bench_builder._bootstrap_ci(ratios, BOOTSTRAP_SEED, BOOTSTRAP_RESAMPLES).items()  # noqa: SLF001
    }


def _sample_size_classification(measured_case_count: int) -> str:
    if measured_case_count == 0:
        return "non-measurable-group"
    if measured_case_count == 1:
        return "descriptive-case-study"
    if measured_case_count == 2:
        return "exploratory-small-group"
    return "exploratory-group"


def _rtk_is_filtered(rtk_argv: list[str]) -> bool:
    return "--filter" in rtk_argv


def build_group(group_id: str, case_ids: list[str], n2d3_cases: dict, taxonomy_cases: dict,
                corpus_raw_total_n16: int) -> dict:
    case_ids = sorted(case_ids)
    measured_ids = [cid for cid in case_ids if n2d3_cases[cid]["measurement_status"] == "MEASURED"]
    refusal_ids = [cid for cid in case_ids if n2d3_cases[cid]["measurement_status"] == "UNMEASURABLE_NON_UTF8"]
    measured_rows = [n2d3_cases[cid] for cid in measured_ids]

    raw_total = sum(r["raw_tokens"] for r in measured_rows)

    arms = {}
    for arm_key, token_field in ARM_TOKEN_FIELDS.items():
        out_total = sum(r[token_field] for r in measured_rows)
        weighted = round(100.0 * (1.0 - out_total / raw_total), 4) if raw_total else None
        agg_ratios = [_aggregation_ratio(r, token_field) for r in measured_rows]
        disp_ratios = [d for d in (_display_ratio(r, token_field) for r in measured_rows) if d is not None]
        macro = round(100.0 * statistics.fmean(agg_ratios), 4) if agg_ratios else None
        median = round(100.0 * statistics.median(agg_ratios), 4) if agg_ratios else None
        min_pct = round(100.0 * min(disp_ratios), 4) if disp_ratios else None
        max_pct = round(100.0 * max(disp_ratios), 4) if disp_ratios else None
        bootstrap = _bootstrap_ci(agg_ratios) if len(measured_rows) >= MIN_BOOTSTRAP_MEASURED_CASES else None
        arms[arm_key] = {
            "total_tokens": out_total,
            "weighted_savings_pct": weighted,
            "macro_savings_pct": macro,
            "median_savings_pct": median,
            "min_case_savings_pct": min_pct,
            "max_case_savings_pct": max_pct,
            "bootstrap_ci95": bootstrap,
        }

    qodec_encoded_count = sum(1 for r in measured_rows if r["qodec_encoded"] is True)
    qodec_passthrough_count = sum(1 for r in measured_rows if r["qodec_encoded"] is False)
    rtk_filtered_count = sum(1 for cid in measured_ids if _rtk_is_filtered(taxonomy_cases[cid]["classification_evidence"]["rtk_argv"]))
    rtk_passthrough_count = len(measured_ids) - rtk_filtered_count
    exact_roundtrip_count = sum(1 for r in measured_rows if r["raw_roundtrip_ok"] and r["hybrid_roundtrip_ok"])

    dominant_case = None
    single_case_dominated = False
    if measured_rows:
        top = max(measured_rows, key=lambda r: r["raw_tokens"])
        share = round(100.0 * top["raw_tokens"] / raw_total, 4) if raw_total else 0.0
        dominant_case = {
            "case_id": top["case_id"],
            "raw_tokens": top["raw_tokens"],
            "share_of_group_raw_tokens_pct": share,
        }
        single_case_dominated = share >= DOMINANCE_THRESHOLD_PCT

    return {
        "group_id": group_id,
        "case_ids": case_ids,
        "total_case_count": len(case_ids),
        "measured_case_count": len(measured_ids),
        "refusal_count": len(refusal_ids),
        "runtime_failure_count": 0,
        "raw_total_tokens": raw_total,
        "qodec_total_tokens": arms["qodec"]["total_tokens"],
        "rtk_total_tokens": arms["rtk"]["total_tokens"],
        "rtk_plus_qodec_total_tokens": arms["rtk_plus_qodec"]["total_tokens"],
        "raw_token_share_of_measured_corpus_pct": round(100.0 * raw_total / corpus_raw_total_n16, 4),
        "qodec": arms["qodec"],
        "rtk": arms["rtk"],
        "rtk_plus_qodec": arms["rtk_plus_qodec"],
        "qodec_encoded_count": qodec_encoded_count,
        "qodec_passthrough_count": qodec_passthrough_count,
        "rtk_filtered_count": rtk_filtered_count,
        "rtk_passthrough_count": rtk_passthrough_count,
        "exact_roundtrip_count_where_measurable": exact_roundtrip_count,
        "dominant_case": dominant_case,
        "single_case_dominated": single_case_dominated,
        "sample_size_classification": _sample_size_classification(len(measured_ids)),
    }


def _subset_stats(rows: list[dict]) -> dict:
    raw_total = sum(r["raw_tokens"] for r in rows)
    out = {"raw_total_tokens": raw_total}
    for arm_key, token_field in ARM_TOKEN_FIELDS.items():
        out_total = sum(r[token_field] for r in rows)
        agg_ratios = [_aggregation_ratio(r, token_field) for r in rows]
        out[f"{arm_key}_total_tokens"] = out_total
        out[arm_key] = {
            "weighted_savings_pct": round(100.0 * (1.0 - out_total / raw_total), 4) if raw_total else None,
            "macro_savings_pct": round(100.0 * statistics.fmean(agg_ratios), 4) if agg_ratios else None,
            "median_savings_pct": round(100.0 * statistics.median(agg_ratios), 4) if agg_ratios else None,
        }
    return out


def build_dominance_sensitivity(n2d3_cases: dict) -> dict:
    measured_rows_n16 = [r for r in n2d3_cases.values() if r["measurement_status"] == "MEASURED"]
    n15_rows = [r for r in measured_rows_n16 if r["case_id"] != DOMINANT_CORPUS_CASE_ID]
    dominant_row = n2d3_cases[DOMINANT_CORPUS_CASE_ID]

    n16 = _subset_stats(measured_rows_n16)
    n15 = _subset_stats(n15_rows)

    total_qodec_savings_tokens = n16["raw_total_tokens"] - n16["qodec_total_tokens"]
    dominant_qodec_savings_tokens = dominant_row["raw_tokens"] - dominant_row["qodec_tokens"]

    return {
        "label": "post-hoc dominance sensitivity analysis",
        "canonical_measured_subset_n16": {"n": len(measured_rows_n16), **n16},
        "measured_subset_excluding_dataset_rtn_n15": {"n": len(n15_rows), **n15},
        "dataset_rtn_traffic_ids_share_of_total_raw_tokens_pct": round(
            100.0 * dominant_row["raw_tokens"] / n16["raw_total_tokens"], 4
        ),
        "dataset_rtn_traffic_ids_share_of_total_qodec_savings_pct": round(
            100.0 * dominant_qodec_savings_tokens / total_qodec_savings_tokens, 4
        ),
    }


def build_equal_family_summary(content_family_groups: dict) -> dict:
    included = sorted(gid for gid, g in content_family_groups.items() if g["measured_case_count"] >= 1)
    excluded = sorted(gid for gid, g in content_family_groups.items() if g["measured_case_count"] == 0)
    per_family = {}
    means = {}
    for arm_key in ARM_TOKEN_FIELDS:
        values = [content_family_groups[gid][arm_key]["weighted_savings_pct"] for gid in included]
        means[arm_key] = round(statistics.fmean(values), 4)
    for gid in included:
        per_family[gid] = {arm_key: content_family_groups[gid][arm_key]["weighted_savings_pct"] for arm_key in ARM_TOKEN_FIELDS}
    return {
        "label": "exploratory equal-content-family summary",
        "post_hoc_exploratory": True,
        "is_canonical_benchmark_result": False,
        "does_not_replace_corpus_weighted_or_case_macro_results": True,
        "note": (
            "gives every measured content family equal weight regardless of case count or token mass, "
            "then averages each family's own weighted savings percentage. Families with a single "
            "measured case receive the same family weight as families with more cases, so this metric "
            "is sensitive to taxonomy granularity. Not a leaderboard; not a substitute for the corpus-"
            "weighted or case-macro canonical results."
        ),
        "families_included_count": len(included),
        "families_included": included,
        "families_excluded_zero_measured_cases": excluded,
        "per_family_weighted_savings_pct": per_family,
        "qodec_mean_family_weighted_savings_pct": means["qodec"],
        "rtk_mean_family_weighted_savings_pct": means["rtk"],
        "rtk_plus_qodec_mean_family_weighted_savings_pct": means["rtk_plus_qodec"],
    }


def build_record() -> dict:
    if not N2D3_BENCHMARK_PATH.is_file():
        raise RuntimeError(f"{N2D3_BENCHMARK_PATH} does not exist")
    if not TAXONOMY_PATH.is_file():
        raise RuntimeError(f"{TAXONOMY_PATH} does not exist")

    n2d3_record = json.loads(N2D3_BENCHMARK_PATH.read_text())
    if n2d3_record.get("record_sha256") != CANONICAL_N2D3_SHA256:
        raise RuntimeError("n2d3-primary-token-benchmark-v1.json record_sha256 != pinned canonical")
    if bench_builder.compute_record_sha256(n2d3_record) != n2d3_record["record_sha256"]:
        raise RuntimeError("n2d3-primary-token-benchmark-v1.json self-hash does not verify")

    taxonomy_record = json.loads(TAXONOMY_PATH.read_text())
    if taxonomy_builder.compute_record_sha256(taxonomy_record) != taxonomy_record["record_sha256"]:
        raise RuntimeError("n2d3-content-taxonomy-v1.json self-hash does not verify")
    if taxonomy_record["canonical_benchmark_link"]["record_sha256"] != CANONICAL_N2D3_SHA256:
        raise RuntimeError("n2d3-content-taxonomy-v1.json is not linked to the pinned canonical N2-D3 record")

    n2d3_cases = n2d3_record["cases"]
    taxonomy_cases = taxonomy_record["cases"]
    if sorted(n2d3_cases.keys()) != sorted(taxonomy_cases.keys()):
        raise RuntimeError("canonical N2-D3 case set != taxonomy case set")

    corpus_raw_total_n16 = sum(r["raw_tokens"] for r in n2d3_cases.values() if r["measurement_status"] == "MEASURED")

    views = {}
    for axis in AXES:
        groups_for_axis: dict[str, list[str]] = {}
        for case_id, entry in taxonomy_cases.items():
            groups_for_axis.setdefault(entry[axis], []).append(case_id)
        views[axis] = {
            group_id: build_group(group_id, case_ids, n2d3_cases, taxonomy_cases, corpus_raw_total_n16)
            for group_id, case_ids in sorted(groups_for_axis.items())
        }

    body = {
        "record_type": "n2d3-token-results-by-content-family-v1",
        "record_version": 1,
        "schema_version": 1,
        "post_hoc_exploratory": True,
        "primary_view": "content_family",
        "secondary_views": ["origin_kind", "producer_family", "payload_kind"],
        "canonical_benchmark_link": {
            "path": "evals/interop/v2/n2/d1-identity-lock/n2d3-primary-token-benchmark-v1.json",
            "record_sha256": n2d3_record["record_sha256"],
        },
        "taxonomy_link": {
            "path": "evals/interop/v2/n2/d1-identity-lock/n2d3-content-taxonomy-v1.json",
            "record_sha256": taxonomy_record["record_sha256"],
        },
        "corpus_measured_raw_total_tokens_n16": corpus_raw_total_n16,
        "bootstrap_policy": {
            "seed": BOOTSTRAP_SEED,
            "resamples": BOOTSTRAP_RESAMPLES,
            "min_measured_case_count": MIN_BOOTSTRAP_MEASURED_CASES,
            "resampling_unit": "case_id",
            "note": (
                "same seed as the canonical corpus-wide bootstrap, but this is a fresh, independent, "
                "per-group computation over different (per-family) subsets of the same measured cases -- "
                "not a retrofit of the canonical interval. No CI is computed for any group below the "
                "minimum measured case count."
            ),
        },
        "sample_size_policy": {
            "non-measurable-group": "measured_case_count == 0",
            "descriptive-case-study": "measured_case_count == 1",
            "exploratory-small-group": "measured_case_count == 2",
            "exploratory-group": "measured_case_count >= 3",
            "note": "no strong statistical conclusions are drawn for n=1 or n=2 groups anywhere in this report",
        },
        "zero_token_case_policy": {
            "case_id": ZERO_TOKEN_CASE_ID,
            "raw_tokens": 0,
            "per_case_ratio": None,
            "per_case_ratio_note": "null: 0/0 is undefined for this single case's own displayed ratio and min/max computation",
            "group_and_corpus_aggregation_note": (
                "macro_savings_pct, median_savings_pct, and bootstrap resampling treat this case's ratio "
                "as 0.0 in the aggregate -- the exact same zero-token convention already used by the "
                "accepted canonical build_n2d3_primary_benchmark._arm_stats() builder, not a new rule"
            ),
            "case_not_removed_from_case_count": True,
        },
        "non_utf8_refusal_policy": {
            "case_ids": list(NON_UTF8_REFUSAL_CASE_IDS),
            "remain_part_of": ["total_case_count", "refusal_count", "payload_kind=binary-container"],
            "excluded_from": ["token totals", "savings denominators"],
            "never_assigned_zero_tokens": True,
            "note": (
                "binary-container is a measurement-domain classification, not evidence that the "
                "underlying archived logs are semantically binary. The canonical measured bytes for "
                "these two cases are archive containers and are therefore invalid for the current "
                "UTF-8 text meter."
            ),
        },
        "views": views,
        "dominance_sensitivity_analysis": build_dominance_sensitivity(n2d3_cases),
        "equal_family_exploratory_summary": build_equal_family_summary(views["content_family"]),
    }
    body["record_sha256"] = compute_record_sha256(body)
    return body


def _fmt(v) -> str:
    return "-" if v is None else str(v)


def render_markdown(report: dict) -> str:
    lines = [
        "# N2-D3 Token Results by Content Family (post-hoc, exploratory)",
        "",
        "## Scope and limitations",
        "",
        "This report is a **post-hoc, exploratory, non-canonical** derived view. It does not rerun "
        "N2-D2/N2-D3, does not change canonical input bytes, QODEC/RTK/tokenizer/workflow/measurement "
        "tooling, and does not alter the existing canonical N2-D3 record "
        f"(`{report['canonical_benchmark_link']['record_sha256']}`). Every number below is derived "
        "directly from that committed record and from the committed content taxonomy "
        f"(`{report['taxonomy_link']['record_sha256']}`) -- never from this report's own Markdown/PR body.",
        "",
        "Cases are classified by what was **actually measured** (frozen command + selected stream + "
        "actual canonical payload format), never by source-repository name, implementation language, or "
        "file extension.",
        "",
        "## Taxonomy table",
        "",
        "| case | content family | origin kind | producer | payload kind | rationale |",
        "|---|---|---|---|---|---|",
    ]

    taxonomy_record = json.loads(TAXONOMY_PATH.read_text())
    for case_id, entry in sorted(taxonomy_record["cases"].items()):
        lines.append(
            f"| {case_id} | {entry['content_family']} | {entry['origin_kind']} | {entry['producer_family']} | "
            f"{entry['payload_kind']} | {entry['rationale']} |"
        )

    def render_view_table(axis: str, title: str) -> list[str]:
        out = [f"## {title}", "", "| group | n (total/measured/refusal) | sample size | raw tokens | raw share % | "
               "QODEC weighted % | RTK weighted % | RTK+QODEC weighted % | dominant case | dominated? |",
               "|---|---|---|---:|---:|---:|---:|---:|---|---|"]
        for group_id, g in sorted(report["views"][axis].items()):
            dom = g["dominant_case"]["case_id"] if g["dominant_case"] else "-"
            out.append(
                f"| {group_id} | {g['total_case_count']}/{g['measured_case_count']}/{g['refusal_count']} | "
                f"{g['sample_size_classification']} | {g['raw_total_tokens']} | "
                f"{g['raw_token_share_of_measured_corpus_pct']} | {_fmt(g['qodec']['weighted_savings_pct'])} | "
                f"{_fmt(g['rtk']['weighted_savings_pct'])} | {_fmt(g['rtk_plus_qodec']['weighted_savings_pct'])} | "
                f"{dom} | {g['single_case_dominated']} |"
            )
        out.append("")
        return out

    lines.append("")
    lines += render_view_table("content_family", "Main table by content family")
    lines += render_view_table("origin_kind", "Secondary table: by origin kind")
    lines += render_view_table("producer_family", "Secondary table: by producer family")
    lines += render_view_table("payload_kind", "Secondary table: by payload kind")

    dom = report["dominance_sensitivity_analysis"]
    lines += [
        "## Dominance diagnostics",
        "",
        f"`dataset-rtn-traffic-ids` is {dom['dataset_rtn_traffic_ids_share_of_total_raw_tokens_pct']}% of total "
        f"measured RAW tokens (n=16) and accounts for "
        f"{dom['dataset_rtn_traffic_ids_share_of_total_qodec_savings_pct']}% of total corpus-wide QODEC token savings.",
        "",
        "## With/without dataset-rtn sensitivity",
        "",
        "| subset | n | RAW total | QODEC total | RTK total | hybrid total | QODEC weighted % | RTK weighted % | hybrid weighted % |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for key, label in (("canonical_measured_subset_n16", "canonical (n=16)"),
                       ("measured_subset_excluding_dataset_rtn_n15", "excluding dataset-rtn (n=15)")):
        s = dom[key]
        lines.append(
            f"| {label} | {s['n']} | {s['raw_total_tokens']} | {s['qodec_total_tokens']} | {s['rtk_total_tokens']} | "
            f"{s['rtk_plus_qodec_total_tokens']} | {_fmt(s['qodec']['weighted_savings_pct'])} | "
            f"{_fmt(s['rtk']['weighted_savings_pct'])} | {_fmt(s['rtk_plus_qodec']['weighted_savings_pct'])} |"
        )
    lines += [
        "",
        "This sensitivity block does not replace the canonical result; it exists to make the "
        "corpus-weighted total's dependence on a single dominant case visible.",
        "",
        "## Equal-family exploratory summary",
        "",
    ]
    eq = report["equal_family_exploratory_summary"]
    lines += [
        f"**{eq['label']}** -- post-hoc exploratory metric, not a canonical benchmark result, and does not "
        "replace the corpus-weighted or case-macro results. " + eq["note"],
        "",
        f"Families included (n={eq['families_included_count']}): {', '.join(eq['families_included'])}",
        f"Families excluded (zero measured cases): {', '.join(eq['families_excluded_zero_measured_cases']) or 'none'}",
        "",
        f"Mean family weighted savings % -- QODEC: {eq['qodec_mean_family_weighted_savings_pct']}, "
        f"RTK: {eq['rtk_mean_family_weighted_savings_pct']}, "
        f"RTK+QODEC: {eq['rtk_plus_qodec_mean_family_weighted_savings_pct']}",
        "",
        "No leaderboard is constructed.",
        "",
        "## Small-sample warnings",
        "",
    ]
    for group_id, g in sorted(report["views"]["content_family"].items()):
        if g["sample_size_classification"] in ("descriptive-case-study", "exploratory-small-group", "non-measurable-group"):
            lines.append(f"- `{group_id}`: {g['sample_size_classification']} (measured_case_count={g['measured_case_count']}); no bootstrap CI, no strong statistical conclusion drawn.")
    lines += [
        "",
        "## Non-UTF-8 domain boundary",
        "",
        "**binary-container is a measurement-domain classification, not evidence that the underlying "
        "archived logs are semantically binary.** The canonical measured bytes for `dataset-loghub-v8` and "
        "`research-corpus-loghub2` are archive containers (their `normalized-source.tar` wraps the "
        "originally-downloaded compressed archive un-extracted) and are therefore invalid for the current "
        "UTF-8 text meter. This is why both remain typed `UNMEASURABLE_NON_UTF8` refusals rather than "
        "measured rows.",
        "",
        "## Interpretation",
        "",
        "- Observed token behavior differs across content families.",
        "- QODEC savings are concentrated in some log-like families.",
        "- RTK savings are concentrated in `cargo-test-output`.",
        "- Weighted totals are dominated by `dataset-rtn-traffic-ids`.",
        "- Hybrid incremental savings vary by family.",
        "",
        "No claims are made about semantic quality, model task success, production superiority, a universal "
        "winner, or general behavior on all Dockerfiles/Rust files/Java projects/etc. For example, "
        "`repo-dockerfile-parser-rs` did not measure Dockerfile content or Rust source; its measured payload "
        "is the `cargo test` stdout captured from that repository. Any such claim would be a claim this "
        "benchmark never measured.",
    ]
    return "\n".join(lines) + "\n"


def render_csv(report: dict) -> str:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow([
        "group_id", "total_case_count", "measured_case_count", "refusal_count",
        "raw_total_tokens", "qodec_total_tokens", "rtk_total_tokens", "rtk_plus_qodec_total_tokens",
        "raw_token_share_of_measured_corpus_pct",
        "qodec_weighted_savings_pct", "qodec_macro_savings_pct", "qodec_median_savings_pct",
        "rtk_weighted_savings_pct", "rtk_macro_savings_pct", "rtk_median_savings_pct",
        "rtk_plus_qodec_weighted_savings_pct", "rtk_plus_qodec_macro_savings_pct", "rtk_plus_qodec_median_savings_pct",
        "dominant_case_id", "dominant_case_share_pct", "single_case_dominated", "sample_size_classification",
    ])
    for group_id, g in sorted(report["views"]["content_family"].items()):
        dom = g["dominant_case"] or {}
        writer.writerow([
            group_id, g["total_case_count"], g["measured_case_count"], g["refusal_count"],
            g["raw_total_tokens"], g["qodec_total_tokens"], g["rtk_total_tokens"], g["rtk_plus_qodec_total_tokens"],
            g["raw_token_share_of_measured_corpus_pct"],
            _fmt(g["qodec"]["weighted_savings_pct"]), _fmt(g["qodec"]["macro_savings_pct"]), _fmt(g["qodec"]["median_savings_pct"]),
            _fmt(g["rtk"]["weighted_savings_pct"]), _fmt(g["rtk"]["macro_savings_pct"]), _fmt(g["rtk"]["median_savings_pct"]),
            _fmt(g["rtk_plus_qodec"]["weighted_savings_pct"]), _fmt(g["rtk_plus_qodec"]["macro_savings_pct"]), _fmt(g["rtk_plus_qodec"]["median_savings_pct"]),
            dom.get("case_id", "-"), dom.get("share_of_group_raw_tokens_pct", "-"), g["single_case_dominated"], g["sample_size_classification"],
        ])
    return buf.getvalue()


def main() -> None:
    report = build_record()
    OUT_JSON_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    OUT_MD_PATH.write_text(render_markdown(report))
    OUT_CSV_PATH.write_text(render_csv(report))
    print(f"wrote {OUT_JSON_PATH}, {OUT_MD_PATH}, {OUT_CSV_PATH} (record_sha256={report['record_sha256']})")


if __name__ == "__main__":
    main()
