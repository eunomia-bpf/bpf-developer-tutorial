#!/usr/bin/env python3
"""Tests for the tutorial workflow's source-block synchronizer."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("sync-source-blocks.py")


class SyncSourceBlocksTest(unittest.TestCase):
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

    def write_readme(self, name: str, source: str = "src/lesson/tool.c") -> pathlib.Path:
        path = self.root / name
        path.write_text(
            "# Lesson\n\n"
            f"<!-- BEGIN FULL SOURCE: {source} -->\n"
            "```c\nold\n```\n"
            "<!-- END FULL SOURCE -->\n",
            encoding="utf-8",
        )
        return path

    def run_script(
        self,
        *arguments: str,
        expected: tuple[str, ...] = ("src/lesson/tool.c",),
    ) -> subprocess.CompletedProcess[str]:
        expected_arguments = [
            item
            for source in expected
            for item in ("--expected-source", source)
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

    def test_write_then_check_bilingual_pair(self) -> None:
        english = self.write_readme("src/lesson/README.md")
        chinese = self.write_readme("src/lesson/README.zh.md")

        written = self.run_script(
            "--readme", "src/lesson/README.md",
            "--readme", "src/lesson/README.zh.md",
            "--write",
        )
        self.assertEqual(0, written.returncode, written.stderr)
        self.assertIn("int main(void)", english.read_text(encoding="utf-8"))
        self.assertEqual(
            english.read_text(encoding="utf-8"), chinese.read_text(encoding="utf-8")
        )

        checked = self.run_script(
            "--readme", "src/lesson/README.md",
            "--readme", "src/lesson/README.zh.md",
            "--check",
        )
        self.assertEqual(0, checked.returncode, checked.stderr)

        before = english.read_bytes()
        repeated = self.run_script(
            "--readme", "src/lesson/README.md",
            "--readme", "src/lesson/README.zh.md",
            "--write",
        )
        self.assertEqual(0, repeated.returncode, repeated.stderr)
        self.assertEqual(before, english.read_bytes())

    def test_check_rejects_stale_block(self) -> None:
        self.write_readme("src/lesson/README.md")
        self.write_readme("src/lesson/README.zh.md")
        checked = self.run_script(
            "--readme", "src/lesson/README.md",
            "--readme", "src/lesson/README.zh.md",
            "--check",
        )
        self.assertEqual(1, checked.returncode)
        self.assertIn("stale complete-source block", checked.stderr)

    def test_write_validates_every_readme_before_changing_any(self) -> None:
        english = self.write_readme("src/lesson/README.md")
        original = english.read_text(encoding="utf-8")
        invalid = self.root / "src/lesson/README.zh.md"
        invalid.write_text("# No markers\n", encoding="utf-8")

        result = self.run_script(
            "--readme", "src/lesson/README.md",
            "--readme", "src/lesson/README.zh.md",
            "--write",
        )
        self.assertEqual(1, result.returncode)
        self.assertEqual(original, english.read_text(encoding="utf-8"))

    def test_rejects_source_outside_repository(self) -> None:
        self.write_readme("src/lesson/README.md", "../outside.c")
        self.write_readme("src/lesson/README.zh.md", "../outside.c")
        result = self.run_script(
            "--readme", "src/lesson/README.md",
            "--readme", "src/lesson/README.zh.md",
            "--write", expected=("../outside.c",)
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("escapes repository root", result.stderr)

    def test_rejects_nested_markers(self) -> None:
        readme = self.write_readme("src/lesson/README.md")
        self.write_readme("src/lesson/README.zh.md")
        text = readme.read_text(encoding="utf-8").replace(
            "```c\nold\n```\n",
            "<!-- BEGIN FULL SOURCE: src/lesson/tool.c -->\n",
        )
        readme.write_text(text, encoding="utf-8")
        result = self.run_script(
            "--readme", "src/lesson/README.md",
            "--readme", "src/lesson/README.zh.md",
            "--write",
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("missing generated code fence", result.stderr)

    def test_rejects_readme_as_source(self) -> None:
        self.write_readme("src/lesson/README.md", "src/lesson/README.md")
        self.write_readme("src/lesson/README.zh.md", "src/lesson/README.md")
        result = self.run_script(
            "--readme",
            "src/lesson/README.md",
            "--readme",
            "src/lesson/README.zh.md",
            "--write",
            expected=("src/lesson/README.md",),
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("expected source cannot be a tutorial README", result.stderr)

    def test_rejects_incomplete_inventory(self) -> None:
        self.write_readme("src/lesson/README.md")
        self.write_readme("src/lesson/README.zh.md")
        result = self.run_script(
            "--readme",
            "src/lesson/README.md",
            "--readme",
            "src/lesson/README.zh.md",
            "--check",
            expected=("src/lesson/tool.c", "src/lesson/contract.h"),
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("missing: src/lesson/contract.h", result.stderr)

    def test_rejects_unsupported_source_type(self) -> None:
        source = self.root / "src/lesson/source.txt"
        source.write_text("text\n", encoding="utf-8")
        self.write_readme("src/lesson/README.md", "src/lesson/source.txt")
        self.write_readme("src/lesson/README.zh.md", "src/lesson/source.txt")
        result = self.run_script(
            "--readme",
            "src/lesson/README.md",
            "--readme",
            "src/lesson/README.zh.md",
            "--write",
            expected=("src/lesson/source.txt",),
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("unsupported expected-source file type", result.stderr)

    def test_source_marker_and_backtick_collisions_are_idempotent(self) -> None:
        source = self.root / "src/lesson/tool.py"
        source.write_text(
            'payload = """\n<!-- END FULL SOURCE -->\n```\n"""\n\n',
            encoding="utf-8",
        )
        english = self.write_readme("src/lesson/README.md", "src/lesson/tool.py")
        chinese = self.write_readme("src/lesson/README.zh.md", "src/lesson/tool.py")
        arguments = (
            "--readme", "src/lesson/README.md",
            "--readme", "src/lesson/README.zh.md",
            "--write",
        )
        first = self.run_script(*arguments, expected=("src/lesson/tool.py",))
        self.assertEqual(0, first.returncode, first.stderr)
        first_english = english.read_bytes()
        first_chinese = chinese.read_bytes()
        self.assertIn(b"````python", first_english)

        second = self.run_script(*arguments, expected=("src/lesson/tool.py",))
        self.assertEqual(0, second.returncode, second.stderr)
        self.assertEqual(first_english, english.read_bytes())
        self.assertEqual(first_chinese, chinese.read_bytes())

    def test_requires_bilingual_pair(self) -> None:
        self.write_readme("src/lesson/README.md")
        result = self.run_script(
            "--readme", "src/lesson/README.md", "--check"
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("exactly the English and Chinese README pair", result.stderr)


if __name__ == "__main__":
    unittest.main()
