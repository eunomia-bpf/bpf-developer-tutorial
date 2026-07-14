import tempfile
import unittest
from pathlib import Path

from scripts.check_internal_links import find_broken_links


class InternalLinkCheckerTest(unittest.TestCase):
    def test_accepts_existing_paths_and_ignores_non_file_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "guide").mkdir()
            (root / "guide" / "target file.md").write_text("# Target\n", encoding="utf-8")
            (root / "README.md").write_text(
                "\n".join(
                    [
                        "[guide](guide/)",
                        "[encoded](guide/target%20file.md)",
                        "[with title](guide/target%20file.md \"Target\")",
                        "[anchor](#section)",
                        "[site route](/tutorials/)",
                        "[external](https://example.com/missing)",
                        "```markdown",
                        "[example](missing-example.md)",
                        "```",
                    ]
                ),
                encoding="utf-8",
            )

            self.assertEqual(find_broken_links(root), [])

    def test_reports_missing_relative_link_with_source_line(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(
                "# Guide\n\n[missing](docs/missing.md)\n", encoding="utf-8"
            )

            broken = find_broken_links(root)

            self.assertEqual(len(broken), 1)
            self.assertEqual(broken[0].source, Path("README.md"))
            self.assertEqual(broken[0].line, 3)
            self.assertEqual(broken[0].destination, "docs/missing.md")


if __name__ == "__main__":
    unittest.main()
