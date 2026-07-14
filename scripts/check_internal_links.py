#!/usr/bin/env python3
"""Check relative Markdown links and images without making network requests."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit


INLINE_LINK_PATTERN = re.compile(r"(?<!\\)\]\(")
REFERENCE_DEFINITION_PATTERN = re.compile(r"^ {0,3}\[[^]]+\]:[ \t]*(.*)$")
FENCE_PATTERN = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
MARKDOWN_ESCAPE_PATTERN = re.compile(r"\\([!\"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~])")
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


def strip_code_spans(line: str) -> str:
    """Blank inline code while preserving character offsets."""
    result = list(line)
    position = 0
    while position < len(line):
        if line[position] != "`":
            position += 1
            continue

        delimiter_end = position
        while delimiter_end < len(line) and line[delimiter_end] == "`":
            delimiter_end += 1
        delimiter_length = delimiter_end - position
        closing = delimiter_end
        while closing < len(line):
            if line[closing] != "`":
                closing += 1
                continue
            closing_end = closing
            while closing_end < len(line) and line[closing_end] == "`":
                closing_end += 1
            if closing_end - closing == delimiter_length:
                break
            closing = closing_end
        if closing >= len(line):
            position = delimiter_end
            continue

        result[position : closing + delimiter_length] = " " * (
            closing + delimiter_length - position
        )
        position = closing + delimiter_length
    return "".join(result)


def parse_destination(text: str, start: int = 0) -> str:
    """Parse one CommonMark-style link destination from text."""
    position = start
    while position < len(text) and text[position] in " \t":
        position += 1
    if position >= len(text):
        return ""

    if text[position] == "<":
        position += 1
        destination: list[str] = []
        while position < len(text):
            if text[position] == "\\" and position + 1 < len(text):
                destination.extend(text[position : position + 2])
                position += 2
            elif text[position] == ">":
                return "".join(destination)
            else:
                destination.append(text[position])
                position += 1
        return ""

    destination = []
    parentheses = 0
    while position < len(text):
        character = text[position]
        if character == "\\" and position + 1 < len(text):
            destination.extend(text[position : position + 2])
            position += 2
            continue
        if character == "(":
            parentheses += 1
        elif character == ")":
            if parentheses == 0:
                break
            parentheses -= 1
        elif character.isspace() and parentheses == 0:
            break
        destination.append(character)
        position += 1
    return "".join(destination) if parentheses == 0 else ""


def destinations_in_line(line: str) -> list[str]:
    without_code = strip_code_spans(line)
    destinations = [
        parse_destination(without_code, match.end())
        for match in INLINE_LINK_PATTERN.finditer(without_code)
    ]
    reference = REFERENCE_DEFINITION_PATTERN.match(without_code)
    if reference:
        destinations.append(parse_destination(reference.group(1)))
    return destinations


def is_ignored(destination: str) -> bool:
    parsed = urlsplit(destination)
    return (
        not destination
        or destination.startswith(("#", "/"))
        or parsed.scheme.lower() in IGNORED_SCHEMES
        or any(marker in destination for marker in ("${", "{{", "}}"))
    )


def filesystem_path(destination: str) -> str:
    decoded = unquote(urlsplit(destination).path)
    return MARKDOWN_ESCAPE_PATTERN.sub(r"\1", decoded)


def find_broken_links(root: Path) -> list[BrokenLink]:
    root = root.resolve()
    broken: list[BrokenLink] = []

    for source in markdown_files(root):
        fence: tuple[str, int] | None = None
        for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            match = FENCE_PATTERN.match(line)
            if fence is not None:
                marker, minimum_length = fence
                if re.fullmatch(
                    rf" {{0,3}}{re.escape(marker)}{{{minimum_length},}}[ \t]*", line
                ):
                    fence = None
                continue
            if match:
                marker = match.group(1)
                if not (marker[0] == "`" and "`" in match.group(2)):
                    fence = (marker[0], len(marker))
                    continue

            for destination in destinations_in_line(line):
                if is_ignored(destination):
                    continue
                relative_path = filesystem_path(destination)
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
