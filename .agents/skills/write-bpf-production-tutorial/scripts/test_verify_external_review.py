#!/usr/bin/env python3
"""Tests for external-review trace and model verification."""

from __future__ import annotations

import json
import pathlib
import sqlite3
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("verify_external_review.py")


class VerifyExternalReviewTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_trace(self, name: str, events: list[dict[str, object]]) -> pathlib.Path:
        path = self.root / name
        path.write_text(
            "\n".join(json.dumps(event) for event in events) + "\n",
            encoding="utf-8",
        )
        return path

    def run_verifier(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(SCRIPT), *arguments],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_grok_gate_and_model_usage(self) -> None:
        trace = self.write_trace(
            "grok.jsonl",
            [
                {"type": "text", "data": "No blockers.\nGATE: PASS"},
                {
                    "type": "end",
                    "stopReason": "EndTurn",
                    "modelUsage": {"grok-4.5-build": {"outputTokens": 3}},
                },
            ],
        )
        result = self.run_verifier(
            "--trace", str(trace),
            "--reviewer", "grok",
            "--model", "grok-4.5",
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("PASS", json.loads(result.stdout)["gate"])

    def test_glm_session_metadata_proves_model(self) -> None:
        session_id = "ses_test"
        trace = self.write_trace(
            "glm.jsonl",
            [
                {
                    "type": "text",
                    "sessionID": session_id,
                    "part": {"sessionID": session_id, "text": "Clean.\nGATE: PASS"},
                },
                {
                    "type": "step_finish",
                    "sessionID": session_id,
                    "part": {"sessionID": session_id, "reason": "stop"},
                },
            ],
        )
        database = self.root / "opencode.db"
        connection = sqlite3.connect(database)
        connection.execute(
            "CREATE TABLE message (id text, session_id text, time_created integer, data text)"
        )
        connection.execute(
            "INSERT INTO message VALUES (?, ?, ?, ?)",
            (
                "msg_test",
                session_id,
                1,
                json.dumps(
                    {
                        "role": "assistant",
                        "providerID": "zai-coding-plan",
                        "modelID": "glm-5.2",
                    }
                ),
            ),
        )
        connection.commit()
        connection.close()
        proof = self.root / "proof.json"

        result = self.run_verifier(
            "--trace", str(trace),
            "--reviewer", "glm",
            "--model", "zai-coding-plan/glm-5.2",
            "--opencode-db", str(database),
            "--model-proof", str(proof),
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("ses_test", json.loads(proof.read_text())["session_id"])

    def test_rejects_text_after_gate(self) -> None:
        trace = self.write_trace(
            "bad-gate.jsonl",
            [
                {"type": "text", "data": "GATE: PASS\nextra"},
                {
                    "type": "end",
                    "stopReason": "EndTurn",
                    "modelUsage": {"grok-4.5-build": {"outputTokens": 3}},
                },
            ],
        )
        result = self.run_verifier(
            "--trace", str(trace),
            "--reviewer", "grok",
            "--model", "grok-4.5",
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("not the final reviewer result", result.stderr)


if __name__ == "__main__":
    unittest.main()
