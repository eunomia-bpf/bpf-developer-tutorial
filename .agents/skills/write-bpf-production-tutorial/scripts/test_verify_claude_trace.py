#!/usr/bin/env python3
"""Tests for the isolated Claude writer trace verifier."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("verify_claude_trace.py")
MODEL = "claude-opus-4-6[1m]"
BASE_MODEL = "claude-opus-4-6"


class VerifyClaudeTraceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.allowed = self.repo / "src/lesson/README.md"
        self.allowed.parent.mkdir(parents=True)
        self.allowed.touch()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_trace(self, events: list[dict[str, object]]) -> pathlib.Path:
        trace = self.root / "trace.jsonl"
        trace.write_text(
            "\n".join(json.dumps(event) for event in events) + "\n",
            encoding="utf-8",
        )
        return trace

    def valid_events(
        self,
        *,
        init_model: str = MODEL,
        assistant_model: str = BASE_MODEL,
        tool: str = "Edit",
        path: pathlib.Path | None = None,
    ) -> list[dict[str, object]]:
        target = path or self.allowed
        return [
            {"type": "system", "subtype": "init", "model": init_model},
            {
                "type": "assistant",
                "message": {
                    "model": assistant_model,
                    "content": [
                        {"type": "text", "text": "Updated the tutorial."},
                        {
                            "type": "tool_use",
                            "name": tool,
                            "input": {"file_path": str(target)},
                        },
                    ],
                },
            },
            {
                "type": "result",
                "is_error": False,
                "modelUsage": {MODEL: {"outputTokens": 8}},
            },
        ]

    def run_verifier(
        self, trace: pathlib.Path, *extra: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--trace",
                str(trace),
                "--model",
                MODEL,
                "--repo",
                str(self.repo),
                "--allowed-path",
                str(self.allowed),
                *extra,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_accepts_required_model_and_allowed_write(self) -> None:
        result = self.run_verifier(
            self.write_trace(self.valid_events()), "--require-write"
        )
        self.assertEqual(0, result.returncode, result.stderr)
        proof = json.loads(result.stdout)
        self.assertEqual(MODEL, proof["model"])
        self.assertEqual(1, proof["write_calls"])

    def test_rejects_wrong_init_model(self) -> None:
        result = self.run_verifier(
            self.write_trace(self.valid_events(init_model="claude-sonnet"))
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("expected init model", result.stderr)

    def test_rejects_unauthorized_write_path(self) -> None:
        outside = self.repo / "src/lesson/tool.c"
        result = self.run_verifier(
            self.write_trace(self.valid_events(path=outside)), "--require-write"
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("unauthorized path", result.stderr)

    def test_rejects_unapproved_tool(self) -> None:
        result = self.run_verifier(
            self.write_trace(self.valid_events(tool="Bash"))
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("unauthorized tools", result.stderr)

    def test_require_write_rejects_read_only_trace(self) -> None:
        events = self.valid_events(tool="Read")
        result = self.run_verifier(self.write_trace(events), "--require-write")
        self.assertEqual(1, result.returncode)
        self.assertIn("no Claude Edit or Write call", result.stderr)


if __name__ == "__main__":
    unittest.main()
