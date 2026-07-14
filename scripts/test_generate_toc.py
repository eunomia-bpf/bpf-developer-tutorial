import re
import unittest
from pathlib import Path

from scripts.generate_toc import generate_toc, generate_toc_cn


ROOT = Path(__file__).resolve().parent.parent
LINK_PATTERN = re.compile(r"\]\((src/.+?)/README(?:\.zh)?\.md\)")
TRACING_LESSONS = {
    "src/30-sslsniff",
    "src/31-goroutine",
    "src/33-funclatency",
    "src/37-uprobe-rust",
    "src/39-nginx",
    "src/40-mysql",
    "src/48-energy",
}


def lesson_links(markdown: str) -> set[str]:
    return set(LINK_PATTERN.findall(markdown))


def subsection(markdown: str, heading: str, next_heading: str) -> str:
    return markdown.split(f"\n\n{heading}:\n\n", 1)[1].split(
        f"\n\n{next_heading}:\n\n", 1
    )[0]


class TocParityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.english = generate_toc(ROOT / "src", ROOT, ROOT)
        cls.chinese = generate_toc_cn(ROOT / "src", ROOT, ROOT)

    def test_english_and_chinese_indexes_contain_the_same_lessons(self):
        self.assertSetEqual(lesson_links(self.english), lesson_links(self.chinese))

    def test_chinese_tracing_subsection_contains_all_tracing_lessons(self):
        english_tracing = lesson_links(subsection(self.english, "Tracing", "Security"))
        chinese_tracing = lesson_links(subsection(self.chinese, "追踪", "安全"))

        self.assertSetEqual(english_tracing, TRACING_LESSONS)
        self.assertSetEqual(chinese_tracing, TRACING_LESSONS)


if __name__ == "__main__":
    unittest.main()
