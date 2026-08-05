#!/usr/bin/env python3
"""Frozen measurement filter for the case-0002 source planes.

Every count that appears in a source lock must come from here, so that the
filter is the artifact and the number is only its output. Prose descriptions of
a filter are not a filter.

    python3 source_profiler.py --coder-window claude-session.window-r21.jsonl
    python3 source_profiler.py --reviewer-export chatgpt-export.json \
        --reviewer-start <node-id> --reviewer-end <node-id>

Output is canonical JSON on stdout: sorted keys, two-space indent, one trailing
newline, so its digest is stable across runs.

CODER PLANE, user-role classification
    system_notification    body opens with "<task-notification>"
    relayed                body opens with "Worked for " (the reviewer plane's
                           own rendering prefix), or exceeds RELAY_BYTES and is
                           not the anchor directive
    authored_ping          under PING_BYTES
    authored_directive     everything else

    The relay rule is a heuristic over a corpus this small, so the tool emits
    the per-turn table alongside the totals. A classification that cannot be
    re-checked line by line is an assertion, not a measurement.

REVIEWER PLANE, extraction ladder
    all_assistant_nodes            every assistant node on the active chain
    after_hidden_reasoning_filter  minus content_type thoughts, reasoning_recap
    after_tool_plumbing_filter     minus tool invocations, i.e. nodes whose
                                   recipient is not "all"
    after_final_text_filter        minus preambles: a visible text node is a
                                   preamble unless it is the last assistant
                                   node before the next user node
"""

from __future__ import annotations

import argparse
import json
import re
import sys

PING_BYTES = 200
RELAY_BYTES = 2000
RELAY_PREFIX = re.compile(r"^\s*Worked for\s")
TASK_NOTIFICATION = "<task-notification>"
SYSTEM_REMINDER = "<system-reminder>"


# --------------------------------------------------------------------------
# coder plane
# --------------------------------------------------------------------------
def coder_text(record):
    message = record.get("message") or {}
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            block.get("text", "")
            for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        )
    return ""


def coder_is_user_role_turn(record):
    """A user-role record that carries text rather than a tool result."""
    if record.get("type") != "user":
        return False
    if record.get("isMeta"):
        return False
    content = (record.get("message") or {}).get("content")
    if isinstance(content, list) and any(
        isinstance(block, dict) and block.get("type") == "tool_result"
        for block in content
    ):
        return False
    body = coder_text(record)
    if not body:
        return False
    if SYSTEM_REMINDER in body[:200]:
        return False
    return True


def classify_user_turn(body, anchor_uuid, uuid):
    if body.startswith(TASK_NOTIFICATION):
        return "system_notification"
    if uuid == anchor_uuid:
        return "authored_directive"
    if RELAY_PREFIX.match(body):
        return "relayed"
    if len(body.encode("utf-8")) > RELAY_BYTES:
        return "relayed"
    if len(body.encode("utf-8")) < PING_BYTES:
        return "authored_ping"
    return "authored_directive"


def profile_coder(path, anchor_uuid):
    records = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except ValueError:
                continue

    kinds = {}
    tools = {}
    tool_use = 0
    tool_result = 0
    tool_result_bytes = 0
    assistant_text_messages = 0
    assistant_text_bytes = 0

    for record in records:
        kind = record.get("type")
        kinds[kind] = kinds.get(kind, 0) + 1
        content = (record.get("message") or {}).get("content")
        if isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_use":
                    tool_use += 1
                    name = block.get("name")
                    tools[name] = tools.get(name, 0) + 1
                elif block.get("type") == "tool_result":
                    tool_result += 1
                    tool_result_bytes += len(
                        json.dumps(block.get("content"), ensure_ascii=False).encode(
                            "utf-8"
                        )
                    )
        if record.get("type") == "assistant":
            body = coder_text(record)
            if body.strip():
                assistant_text_messages += 1
                assistant_text_bytes += len(body.encode("utf-8"))

    turns = []
    counts = {
        "system_notification": 0,
        "relayed": 0,
        "authored_directive": 0,
        "authored_ping": 0,
    }
    user_role_bytes = 0
    for record in records:
        if not coder_is_user_role_turn(record):
            continue
        body = coder_text(record)
        label = classify_user_turn(body, anchor_uuid, record.get("uuid"))
        counts[label] += 1
        size = len(body.encode("utf-8"))
        user_role_bytes += size
        turns.append(
            {
                "uuid": record.get("uuid"),
                "timestamp": record.get("timestamp"),
                "bytes": size,
                "classification": label,
                "opening": body[:60],
            }
        )

    return {
        "blob": path,
        "records": len(records),
        "record_types": kinds,
        "user_role_turns": len(turns),
        "user_role_bytes": user_role_bytes,
        "user_role_classification": counts,
        "user_role_table": turns,
        "assistant_text_messages": assistant_text_messages,
        "assistant_text_bytes": assistant_text_bytes,
        "tool_use": tool_use,
        "tool_result": tool_result,
        "tool_result_bytes": tool_result_bytes,
        "tools": tools,
    }


# --------------------------------------------------------------------------
# reviewer plane
# --------------------------------------------------------------------------
def reviewer_text(message):
    content = message.get("content") or {}
    parts = content.get("parts") or []
    joined = "".join(part for part in parts if isinstance(part, str))
    return joined or content.get("text") or ""


def profile_reviewer(path, start_id, end_id):
    with open(path, encoding="utf-8") as handle:
        export = json.load(handle)
    mapping = export["mapping"]

    chain = []
    node = end_id
    while node:
        chain.append(node)
        node = mapping[node].get("parent")
    chain.reverse()
    if start_id not in chain:
        return {"problems": ["start node is not on the parent chain of the end node"]}
    window = chain[chain.index(start_id) :]

    roles = {}
    content_types = {}
    assistant_nodes = []
    user_nodes = []
    for node_id in window:
        message = mapping[node_id].get("message")
        if not message:
            roles["<none>"] = roles.get("<none>", 0) + 1
            continue
        author = message.get("author") or {}
        role = author.get("role")
        name = author.get("name")
        key = role if not name else "%s:%s" % (role, name)
        roles[key] = roles.get(key, 0) + 1
        content_type = (message.get("content") or {}).get("content_type")
        content_types[content_type] = content_types.get(content_type, 0) + 1
        if role == "assistant" and not name:
            assistant_nodes.append((node_id, message))
        elif role == "user" and not name:
            user_nodes.append((node_id, message))

    hidden = {"thoughts", "reasoning_recap"}
    after_hidden = [
        (node_id, message)
        for node_id, message in assistant_nodes
        if (message.get("content") or {}).get("content_type") not in hidden
        and not (message.get("metadata") or {}).get(
            "is_visually_hidden_from_conversation"
        )
    ]
    after_plumbing = [
        (node_id, message)
        for node_id, message in after_hidden
        if message.get("recipient", "all") == "all"
    ]

    user_positions = {
        node_id for node_id, _ in user_nodes
    }
    order = {node_id: position for position, node_id in enumerate(window)}
    next_user_after = {}
    upcoming = None
    for node_id in reversed(window):
        if node_id in user_positions:
            upcoming = order[node_id]
        next_user_after[node_id] = upcoming

    finals = []
    preambles = []
    plumbing_ids = {node_id for node_id, _ in after_plumbing}
    for node_id, message in after_plumbing:
        boundary = next_user_after[node_id]
        later = [
            other
            for other in plumbing_ids
            if order[other] > order[node_id]
            and (boundary is None or order[other] < boundary)
        ]
        (preambles if later else finals).append((node_id, message))

    def total_bytes(nodes):
        return sum(len(reviewer_text(message).encode("utf-8")) for _, message in nodes)

    return {
        "blob": path,
        "start_node": start_id,
        "end_node": end_id,
        "window_nodes": len(window),
        "roles": roles,
        "content_types": content_types,
        "ladder": {
            "all_assistant_nodes": len(assistant_nodes),
            "after_hidden_reasoning_filter": len(after_hidden),
            "after_tool_plumbing_filter": len(after_plumbing),
            "after_final_text_filter": len(finals),
        },
        "ladder_bytes": {
            "after_hidden_reasoning_filter": total_bytes(after_hidden),
            "after_tool_plumbing_filter": total_bytes(after_plumbing),
            "after_final_text_filter": total_bytes(finals),
            "preambles": total_bytes(preambles),
        },
        "preamble_nodes": len(preambles),
        "user_nodes": len(user_nodes),
        "user_bytes": total_bytes(user_nodes),
        "problems": [],
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--coder-window")
    parser.add_argument(
        "--coder-anchor-uuid", default="3a0760a5-e751-4ece-81e8-c9aea36a4ad4"
    )
    parser.add_argument("--reviewer-export")
    parser.add_argument("--reviewer-start")
    parser.add_argument("--reviewer-end")
    args = parser.parse_args(argv)

    report = {"tool": "o7.case0002.source-profiler/v0"}
    if args.coder_window:
        report["coder"] = profile_coder(args.coder_window, args.coder_anchor_uuid)
    if args.reviewer_export:
        if not (args.reviewer_start and args.reviewer_end):
            parser.error("--reviewer-export requires --reviewer-start and --reviewer-end")
        report["reviewer"] = profile_reviewer(
            args.reviewer_export, args.reviewer_start, args.reviewer_end
        )
    if len(report) == 1:
        parser.error("nothing to profile")

    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
