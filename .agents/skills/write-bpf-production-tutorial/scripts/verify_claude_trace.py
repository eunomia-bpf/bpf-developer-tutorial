#!/usr/bin/env python3
"""Verify that a persisted Claude trace used the required authoring model."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_events(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        events = []
        for number, line in enumerate(raw.splitlines(), 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid JSON on trace line {number}: {error}") from error
            events.extend(value if isinstance(value, list) else [value])
        return [event for event in events if isinstance(event, dict)]

    values = value if isinstance(value, list) else [value]
    return [event for event in values if isinstance(event, dict)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--model", required=True)
    parser.add_argument("--require-write", action="store_true")
    args = parser.parse_args()

    events = load_events(args.trace)
    init_models = {
        event.get("model")
        for event in events
        if event.get("type") == "system" and event.get("subtype") == "init"
    }
    if init_models != {args.model}:
        raise SystemExit(f"expected init model {args.model!r}, found {sorted(init_models)!r}")

    base_model = args.model.split("[", 1)[0]
    authored_text = 0
    write_calls = 0
    assistant_models = set()
    for event in events:
        if event.get("type") != "assistant":
            continue
        message = event.get("message") or {}
        model = message.get("model")
        content = message.get("content") or []
        if any(item.get("type") == "text" and item.get("text") for item in content):
            authored_text += 1
            assistant_models.add(model)
        write_calls += sum(
            item.get("type") == "tool_use" and item.get("name") in {"Edit", "Write"}
            for item in content
        )

    if not authored_text:
        raise SystemExit("trace contains no authored assistant text")
    if assistant_models != {base_model}:
        raise SystemExit(
            f"expected authored text from {base_model!r}, found {sorted(assistant_models)!r}"
        )
    if args.require_write and write_calls == 0:
        raise SystemExit("trace contains no Claude Edit or Write call")

    results = [event for event in events if event.get("type") == "result"]
    if not results:
        raise SystemExit("trace contains no terminal result")
    result = results[-1]
    if result.get("is_error"):
        raise SystemExit(f"Claude run failed: {result.get('subtype', 'unknown error')}")
    usage = result.get("modelUsage") or {}
    exact_usage = usage.get(args.model) or {}
    if exact_usage.get("outputTokens", 0) <= 0:
        raise SystemExit(f"terminal usage does not prove output from {args.model}")

    print(
        json.dumps(
            {
                "model": args.model,
                "authored_text_events": authored_text,
                "write_calls": write_calls,
                "trace": str(args.trace),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
