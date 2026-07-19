#!/usr/bin/env python3
"""Extract and validate the terminal gate from a preserved review trace."""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
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


def write_model_proof(
    events: list[dict[str, Any]], model: str, database: Path, proof_path: Path
) -> None:
    session_ids = {
        value
        for event in events
        for value in (
            event.get("sessionID"),
            (event.get("part") or {}).get("sessionID"),
        )
        if value
    }
    if len(session_ids) != 1:
        raise ValueError(f"expected one OpenCode session ID, found {sorted(session_ids)}")
    session_id = next(iter(session_ids))
    provider, model_id = model.split("/", 1)
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        rows = connection.execute(
            "SELECT id, data FROM message WHERE session_id = ? ORDER BY time_created, id",
            (session_id,),
        ).fetchall()
    finally:
        connection.close()
    observed: list[dict[str, str]] = []
    for message_id, raw in rows:
        data = json.loads(raw)
        nested_model = data.get("model") or {}
        observed_provider = data.get("providerID") or nested_model.get("providerID")
        observed_model = data.get("modelID") or nested_model.get("modelID")
        if observed_provider and observed_model:
            observed.append(
                {
                    "message_id": message_id,
                    "provider": observed_provider,
                    "model": observed_model,
                    "role": data.get("role", "unknown"),
                }
            )
    if not observed or any(
        item["provider"] != provider or item["model"] != model_id
        for item in observed
    ):
        raise ValueError(
            f"OpenCode session does not prove requested model {model!r}: {observed}"
        )
    proof = {
        "requested_model": model,
        "session_id": session_id,
        "observed_messages": observed,
        "database": str(database),
    }
    temporary = proof_path.with_name(proof_path.name + ".tmp")
    temporary.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, proof_path)


def glm_text(
    events: list[dict[str, Any]],
    model: str,
    database: Path | None,
    proof_path: Path | None,
) -> str:
    endings = [event for event in events if event.get("type") == "step_finish"]
    if not endings:
        raise ValueError("OpenCode trace has no terminal step_finish event")
    part = endings[-1].get("part") or {}
    if part.get("reason") != "stop":
        raise ValueError(f"OpenCode review did not end normally: {part.get('reason')}")
    if database is None or proof_path is None:
        raise ValueError("GLM verification requires --opencode-db and --model-proof")
    write_model_proof(events, model, database, proof_path)
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
    parser.add_argument("--opencode-db", type=Path)
    parser.add_argument("--model-proof", type=Path)
    args = parser.parse_args()

    events = json_lines(args.trace)
    text = (
        grok_text(events, args.model)
        if args.reviewer == "grok"
        else glm_text(events, args.model, args.opencode_db, args.model_proof)
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
