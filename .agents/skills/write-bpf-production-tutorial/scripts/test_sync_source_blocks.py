#!/usr/bin/env python3
"""Tests for marker-free tutorial source-block checks."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("sync-source-blocks.py")


class SourceBlocksTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        (self.root / ".git").mkdir()
        (self.root / "src/lesson").mkdir(parents=True)
        (self.root / "src/lesson/tool.c").write_text(
            "int main(void)\n{\n\treturn 0;\n}\n", encoding="utf-8"
        )
        (self.root / "src/lesson/contract.h").write_text(
            "#define VALUE 1\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_readme(
        self,
        name: str,
        payload: str | None = None,
        language: str = "c",
        fence: str = "```",
    ) -> pathlib.Path:
        if payload is None:
            payload = (self.root / "src/lesson/tool.c").read_text(encoding="utf-8")
        path = self.root / name
        path.write_text(
            f"# Lesson\n\n{fence}{language}\n{payload}{fence}\n", encoding="utf-8"
        )
        return path

    def write_pair(self, **kwargs: str) -> None:
        self.write_readme("src/lesson/README.md", **kwargs)
        self.write_readme("src/lesson/README.zh.md", **kwargs)

    def run_script(
        self,
        *arguments: str,
        expected: tuple[str, ...] = ("src/lesson/tool.c",),
    ) -> subprocess.CompletedProcess[str]:
        expected_arguments = [
            item for source in expected for item in ("--expected-source", source)
        ]
        return subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--repo",
                str(self.root),
                *expected_arguments,
                *arguments,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def check_pair(self, expected: tuple[str, ...] = ("src/lesson/tool.c",)):
        return self.run_script(
            "--readme",
            "src/lesson/README.md",
            "--readme",
            "src/lesson/README.zh.md",
            "--check",
            expected=expected,
        )

    def test_accepts_exact_standard_markdown_fences(self) -> None:
        self.write_pair()
        result = self.check_pair()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("checked 1 fenced source blocks", result.stdout)

    def test_rejects_stale_source_block(self) -> None:
        self.write_pair(payload="int stale;\n")
        result = self.check_pair()
        self.assertEqual(1, result.returncode)
        self.assertIn("missing exact fenced source", result.stderr)

    def test_rejects_duplicate_exact_source_block(self) -> None:
        source = (self.root / "src/lesson/tool.c").read_text(encoding="utf-8")
        payload = f"{source}```\n\n```c\n{source}"
        self.write_pair(payload=payload)
        result = self.check_pair()
        self.assertEqual(1, result.returncode)
        self.assertIn("duplicate exact fenced source", result.stderr)

    def test_rejects_legacy_html_markers(self) -> None:
        self.write_pair()
        readme = self.root / "src/lesson/README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8")
            + "<!-- END FULL SOURCE -->\n",
            encoding="utf-8",
        )
        result = self.check_pair()
        self.assertEqual(1, result.returncode)
        self.assertIn("HTML marker is not allowed", result.stderr)

    def test_rejects_source_outside_repository(self) -> None:
        self.write_pair()
        result = self.check_pair(expected=("../outside.c",))
        self.assertEqual(1, result.returncode)
        self.assertIn("escapes repository root", result.stderr)

    def test_rejects_readme_as_source(self) -> None:
        self.write_pair()
        result = self.check_pair(expected=("src/lesson/README.md",))
        self.assertEqual(1, result.returncode)
        self.assertIn("expected source cannot be a tutorial README", result.stderr)

    def test_rejects_incomplete_inventory(self) -> None:
        self.write_pair()
        result = self.check_pair(
            expected=("src/lesson/tool.c", "src/lesson/contract.h")
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("src/lesson/contract.h", result.stderr)

    def test_rejects_unsupported_source_type(self) -> None:
        source = self.root / "src/lesson/source.txt"
        source.write_text("text\n", encoding="utf-8")
        self.write_pair(payload="text\n", language="text")
        result = self.check_pair(expected=("src/lesson/source.txt",))
        self.assertEqual(1, result.returncode)
        self.assertIn("unsupported expected-source file type", result.stderr)

    def test_accepts_longer_fence_for_source_with_backticks(self) -> None:
        source = self.root / "src/lesson/tool.py"
        payload = 'value = """\n```\n"""\n'
        source.write_text(payload, encoding="utf-8")
        self.write_pair(payload=payload, language="python", fence="````")
        result = self.check_pair(expected=("src/lesson/tool.py",))
        self.assertEqual(0, result.returncode, result.stderr)

    def test_rejects_empty_source(self) -> None:
        (self.root / "src/lesson/tool.c").write_bytes(b"")
        self.write_pair(payload="")
        result = self.check_pair()
        self.assertEqual(1, result.returncode)
        self.assertIn("complete source cannot be empty", result.stderr)

    def test_rejects_source_without_final_lf(self) -> None:
        (self.root / "src/lesson/tool.c").write_bytes(b"int value = 1;")
        self.write_pair(payload="int value = 1;\n")
        result = self.check_pair()
        self.assertEqual(1, result.returncode)
        self.assertIn("must end with an LF byte", result.stderr)

    def test_requires_bilingual_pair(self) -> None:
        self.write_readme("src/lesson/README.md")
        result = self.run_script(
            "--readme", "src/lesson/README.md", "--check"
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("exactly the English and Chinese README pair", result.stderr)

    def test_rejects_unclosed_fence(self) -> None:
        self.write_pair()
        readme = self.root / "src/lesson/README.zh.md"
        readme.write_text("# Lesson\n\n```c\nint value;\n", encoding="utf-8")
        result = self.check_pair()
        self.assertEqual(1, result.returncode)
        self.assertIn("unclosed Markdown code fence", result.stderr)


if __name__ == "__main__":
    unittest.main()
