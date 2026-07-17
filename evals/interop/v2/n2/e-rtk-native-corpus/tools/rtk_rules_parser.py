"""Parse the pinned RTK rule table (src/discover/rules.rs) into structured data.

This reads the RtkRule table that RTK itself uses to decide rewrites and to
publish its own estimated savings. It is the canonical claim source for §7:
each parsed rule carries its `rtk_cmd`, `category`, default `savings_pct`,
per-subcommand savings overrides, per-subcommand status overrides, and the
1-indexed source line where the rule begins.

The parser is deliberately conservative: it extracts only the fields N2-E needs
and records the line number so the committed claim surface can cite an exact
`rules.rs:<line>` provenance. It does not evaluate the regex patterns — the
authoritative rewrite behavior is obtained by invoking the pinned binary; this
table supplies only RTK's *claimed* savings, never treated as measured truth.
"""
from __future__ import annotations

import re
from pathlib import Path

_STR = r'(?:r?"(?:[^"\\]|\\.)*")'
_RULE_START = re.compile(r"^\s*RtkRule\s*\{")
_FIELD = {
    "rtk_cmd": re.compile(r'rtk_cmd:\s*"((?:[^"\\]|\\.)*)"'),
    "category": re.compile(r'category:\s*"((?:[^"\\]|\\.)*)"'),
    "savings_pct": re.compile(r"savings_pct:\s*([0-9]+(?:\.[0-9]+)?)"),
}
_PATTERN = re.compile(r"pattern:\s*(" + _STR + r")")
_SUBCMD_SAVING = re.compile(r'\("((?:[^"\\]|\\.)*)"\s*,\s*([0-9]+(?:\.[0-9]+)?)\)')
_SUBCMD_STATUS = re.compile(r'\("((?:[^"\\]|\\.)*)"\s*,\s*RtkStatus::(\w+)\)')


def parse_rules(rules_rs: str | Path) -> list[dict]:
    text = Path(rules_rs).read_text(encoding="utf-8")
    lines = text.splitlines()
    rules: list[dict] = []
    i = 0
    n = len(lines)
    while i < n:
        if _RULE_START.match(lines[i]):
            start_line = i + 1  # 1-indexed
            depth = 0
            body_lines = []
            j = i
            started = False
            while j < n:
                depth += lines[j].count("{") - lines[j].count("}")
                body_lines.append(lines[j])
                if "{" in lines[j]:
                    started = True
                if started and depth == 0:
                    break
                j += 1
            body = "\n".join(body_lines)
            rule = _parse_rule_body(body, start_line)
            if rule:
                rules.append(rule)
            i = j + 1
        else:
            i += 1
    return rules


def _parse_rule_body(body: str, start_line: int) -> dict | None:
    rtk_cmd = _FIELD["rtk_cmd"].search(body)
    if not rtk_cmd:
        return None
    category = _FIELD["category"].search(body)
    savings = _FIELD["savings_pct"].search(body)
    pattern = _PATTERN.search(body)

    # subcmd_savings block: between `subcmd_savings:` and the following `],`
    subcmd_savings = {}
    m = re.search(r"subcmd_savings:\s*&\[(.*?)\]", body, re.DOTALL)
    if m:
        for sm in _SUBCMD_SAVING.finditer(m.group(1)):
            subcmd_savings[sm.group(1)] = float(sm.group(2))

    subcmd_status = {}
    m = re.search(r"subcmd_status:\s*&\[(.*?)\]", body, re.DOTALL)
    if m:
        for sm in _SUBCMD_STATUS.finditer(m.group(1)):
            subcmd_status[sm.group(1)] = sm.group(2)

    return {
        "rtk_cmd": rtk_cmd.group(1),
        "category": category.group(1) if category else None,
        "savings_pct": float(savings.group(1)) if savings else None,
        "pattern": pattern.group(1) if pattern else None,
        "subcmd_savings": subcmd_savings,
        "subcmd_status": subcmd_status,
        "rules_rs_line": start_line,
    }


def claim_for(rules: list[dict], rtk_cmd: str, subcmd: str | None) -> dict | None:
    """Return the savings claim for a given rtk_cmd (+ optional subcommand)."""
    for r in rules:
        if r["rtk_cmd"] == rtk_cmd:
            pct = r["savings_pct"]
            status = None
            if subcmd and subcmd in r["subcmd_savings"]:
                pct = r["subcmd_savings"][subcmd]
            if subcmd and subcmd in r["subcmd_status"]:
                status = r["subcmd_status"][subcmd]
            return {
                "rtk_cmd": r["rtk_cmd"],
                "category": r["category"],
                "estimated_savings_pct": pct,
                "subcmd_status_override": status,
                "claim_source": f"src/discover/rules.rs:{r['rules_rs_line']}",
            }
    return None
