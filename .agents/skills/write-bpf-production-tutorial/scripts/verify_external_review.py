#!/usr/bin/env python3
"""Extract and validate the terminal gate from a preserved review trace."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


GATE_RE = re.compile(r"(?m)^\s*(?:#{1,6}\s*)?GATE:\s*(PASS|FAIL)\s*$")


def json_lines(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid JSON on trace line {number}: {error}") from error
        if isinstance(event, dict):
            events.append(event)
    return events


def grok_text(events: list[dict[str, Any]], model: str) -> str:
    endings = [event for event in events if event.get("type") == "end"]
    if not endings:
        raise ValueError("Grok trace has no terminal end event")
    usage = endings[-1].get("modelUsage") or {}
    if not any(name.startswith(model) for name in usage):
        raise ValueError(f"Grok trace does not prove requested model {model!r}")
    if endings[-1].get("stopReason") != "EndTurn":
        raise ValueError(f"Grok review did not end normally: {endings[-1].get('stopReason')}")
    return "".join(
        str(event.get("data", ""))
        for event in events
        if event.get("type") == "text"
    )


def glm_text(events: list[dict[str, Any]]) -> str:
    endings = [event for event in events if event.get("type") == "step_finish"]
    if not endings:
        raise ValueError("OpenCode trace has no terminal step_finish event")
    part = endings[-1].get("part") or {}
    if part.get("reason") != "stop":
        raise ValueError(f"OpenCode review did not end normally: {part.get('reason')}")
    return "\n".join(
        str((event.get("part") or {}).get("text", ""))
        for event in events
        if event.get("type") == "text"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--reviewer", required=True, choices=("grok", "glm"))
    parser.add_argument("--model", required=True)
    args = parser.parse_args()

    events = json_lines(args.trace)
    text = (
        grok_text(events, args.model)
        if args.reviewer == "grok"
        else glm_text(events)
    )
    matches = GATE_RE.findall(text)
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one terminal GATE line in reviewer text, found {len(matches)}"
        )
    gate = matches[0]
    if not text.rstrip().endswith(f"GATE: {gate}"):
        raise SystemExit("GATE line is not the final reviewer result")

    print(json.dumps({"gate": gate, "reviewer": args.reviewer, "model": args.model}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
