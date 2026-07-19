#!/usr/bin/env python3
"""Integration tests for external-review gate exit behavior."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("run-external-review.sh")
REPO = SCRIPT.parents[4]


class RunExternalReviewTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        binary = self.root / "bin"
        binary.mkdir()
        grok = binary / "grok"
        grok.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os\n"
            "print(json.dumps({'type': 'text', 'data': 'Synthetic review.\\nGATE: ' + os.environ['FAKE_GATE']}))\n"
            "print(json.dumps({'type': 'end', 'stopReason': 'EndTurn', 'modelUsage': {'grok-4.5-build': {'outputTokens': 3}}}))\n",
            encoding="utf-8",
        )
        grok.chmod(0o755)
        self.task = self.root / "task.md"
        self.task.write_text("Review the repository-local Skills.\n", encoding="utf-8")
        self.environment = os.environ.copy()
        self.environment["PATH"] = f"{binary}:{self.environment['PATH']}"
        self.environment["XDG_STATE_HOME"] = str(self.root / "state")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_wrapper(self, gate: str) -> subprocess.CompletedProcess[str]:
        environment = self.environment.copy()
        environment["FAKE_GATE"] = gate
        return subprocess.run(
            [
                str(SCRIPT),
                "--reviewer",
                "grok",
                "--scope",
                "skill",
                "--repo",
                str(REPO),
                "--task",
                str(self.task),
                "--file",
                ".agents/skills/write-bpf-production-tutorial/SKILL.md",
                "--file",
                ".agents/skills/bpf-tutorial-writing-style/SKILL.md",
            ],
            cwd=REPO,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def manifest_from(self, result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        manifest_line = next(
            line for line in result.stdout.splitlines() if line.startswith("manifest=")
        )
        path = pathlib.Path(manifest_line.removeprefix("manifest="))
        return json.loads(path.read_text(encoding="utf-8"))

    def test_pass_gate_returns_success(self) -> None:
        result = self.run_wrapper("PASS")
        self.assertEqual(0, result.returncode, result.stderr)
        manifest = self.manifest_from(result)
        self.assertEqual("complete", manifest["state"])
        self.assertEqual("PASS", manifest["gate"])

    def test_fail_gate_returns_nonzero_but_records_completed_review(self) -> None:
        result = self.run_wrapper("FAIL")
        self.assertEqual(3, result.returncode, result.stderr)
        self.assertIn("review completed with GATE: FAIL", result.stderr)
        manifest = self.manifest_from(result)
        self.assertEqual("complete", manifest["state"])
        self.assertEqual("FAIL", manifest["gate"])


if __name__ == "__main__":
    unittest.main()
