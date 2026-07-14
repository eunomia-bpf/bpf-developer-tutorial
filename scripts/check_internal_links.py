#!/usr/bin/env python3
"""Check relative Markdown links and images without making network requests."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit


LINK_PATTERN = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
FENCE_PATTERN = re.compile(r"^\s*(`{3,}|~{3,})")
IGNORED_SCHEMES = {"data", "http", "https", "javascript", "mailto"}


@dataclass(frozen=True)
class BrokenLink:
    source: Path
    line: int
    destination: str


def markdown_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*.md")
        if not {".git", "build", "node_modules", "site"}.intersection(path.parts)
    )


def link_destination(raw: str) -> str:
    value = raw.strip()
    if value.startswith("<"):
        closing = value.find(">")
        return value[1:closing] if closing >= 0 else value
    return value.split(maxsplit=1)[0]


def is_ignored(destination: str) -> bool:
    parsed = urlsplit(destination)
    return (
        not destination
        or destination.startswith(("#", "/"))
        or parsed.scheme.lower() in IGNORED_SCHEMES
        or any(marker in destination for marker in ("${", "{{", "}}"))
    )


def find_broken_links(root: Path) -> list[BrokenLink]:
    root = root.resolve()
    broken: list[BrokenLink] = []

    for source in markdown_files(root):
        fence: str | None = None
        for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            match = FENCE_PATTERN.match(line)
            if match:
                marker = match.group(1)[0]
                fence = None if fence == marker else marker if fence is None else fence
                continue
            if fence is not None:
                continue

            for raw in LINK_PATTERN.findall(line):
                destination = link_destination(raw)
                if is_ignored(destination):
                    continue
                relative_path = unquote(urlsplit(destination).path)
                if relative_path and not (source.parent / relative_path).exists():
                    broken.append(
                        BrokenLink(source.relative_to(root), line_number, destination)
                    )

    return broken


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (defaults to the parent of scripts/)",
    )
    args = parser.parse_args()

    broken = find_broken_links(args.root)
    if not broken:
        print("All relative Markdown links resolve.")
        return 0

    print(f"Found {len(broken)} broken relative Markdown link(s):", file=sys.stderr)
    for item in broken:
        print(
            f"{item.source}:{item.line}: {item.destination}",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
