"""Utility helpers used across the project.

Pure functions with no external dependencies. Safe to import from
any module without triggering side effects.
"""

import json
import re
from collections import Counter


def extract_tool_calls_from_text(content: str):
    """Extract ALL tool calls emitted as plain text in LLM response.

    Qwen 2.5 Coder via Ollama does not always emit native tool_calls.
    When the model writes the JSON inline in `content` instead, this
    function recovers them.

    Args:
        content: Raw LLM `content` string.

    Returns:
        List of dicts with shape {"name": str, "arguments": dict}.
        Empty list if no valid tool call found.
    """
    if not content:
        return []
    candidates = []

    for m in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL):
        candidates.append(m.group(1))

    stripped = content.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        candidates.append(stripped)

    depth = 0
    start = None
    for i, ch in enumerate(content):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                candidates.append(content[start:i + 1])
                start = None

    found = []
    seen_names = set()
    for cand in candidates:
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            continue

        objs = []
        if isinstance(obj, list):
            objs = obj
        elif isinstance(obj, dict):
            if "tool_calls" in obj and isinstance(obj["tool_calls"], list):
                objs = [tc.get("function", tc) for tc in obj["tool_calls"]]
            else:
                objs = [obj]

        for o in objs:
            if "name" not in o:
                continue
            key = (o["name"], json.dumps(o.get("arguments", {}), sort_keys=True))
            if key in seen_names:
                continue
            seen_names.add(key)
            found.append(o)

    return found


def normalize_args(name: str, args: dict) -> dict:
    """Unwrap the {type, description, value} pattern Qwen sometimes emits.

    Example bad:  {"target": {"type": "string", "value": "path"}}
    Example good: {"target": "path"}
    """
    fixed = {}
    for k, v in args.items():
        if isinstance(v, dict) and "value" in v:
            fixed[k] = v["value"]
        else:
            fixed[k] = v
    return fixed


def is_stuck_in_loop(current: str, previous: str, threshold: float = 0.9) -> bool:
    """Detect inter-turn repetition (current content ~ previous content)."""
    if not previous or not current:
        return False
    curr_lines = [l.strip() for l in current.splitlines() if l.strip()]
    prev_lines = [l.strip() for l in previous.splitlines() if l.strip()]
    if not curr_lines or not prev_lines:
        return False
    if curr_lines[0] == prev_lines[0]:
        return True
    curr_set = set(curr_lines)
    prev_set = set(prev_lines)
    overlap = len(curr_set & prev_set) / max(len(curr_set), 1)
    return overlap >= threshold


def is_stuck_within(content: str, min_repeats: int = 4, min_len: int = 20) -> bool:
    """Detect intra-turn repetition (same line repeated N times in one response)."""
    if not content:
        return False
    lines = [l.strip() for l in content.splitlines() if len(l.strip()) >= min_len]
    if not lines:
        return False
    counts = Counter(lines)
    _, count = counts.most_common(1)[0]
    return count >= min_repeats