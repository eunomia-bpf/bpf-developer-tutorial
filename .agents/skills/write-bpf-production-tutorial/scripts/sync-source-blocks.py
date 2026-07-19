#!/usr/bin/env python3
"""Check exact source files embedded in standard Markdown code fences."""

from __future__ import annotations

import argparse
import collections
import pathlib
import re
import sys


FENCE_RE = re.compile(r"^(`{3,})([A-Za-z0-9_+.-]*)[ \t]*$")
LEGACY_MARKERS = ("<!-- BEGIN FULL SOURCE:", "<!-- END FULL SOURCE -->")
LANGUAGES = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".go": "go",
    ".h": "c",
    ".py": "python",
    ".rs": "rust",
    ".sh": "bash",
}


def contained_path(root: pathlib.Path, value: str, label: str) -> pathlib.Path:
    path = (root / value).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{label} escapes repository root: {value}") from error
    return path


def parse_fenced_blocks(readme: pathlib.Path) -> list[tuple[str, str]]:
    text = readme.read_text(encoding="utf-8")
    for marker in LEGACY_MARKERS:
        if marker in text:
            raise ValueError(
                f"legacy complete-source HTML marker is not allowed in {readme.name}"
            )

    lines = text.splitlines(keepends=True)
    blocks: list[tuple[str, str]] = []
    index = 0
    while index < len(lines):
        opening = FENCE_RE.match(lines[index].rstrip("\r\n"))
        if not opening:
            index += 1
            continue

        fence, language = opening.groups()
        end = index + 1
        while end < len(lines) and lines[end].rstrip("\r\n") != fence:
            end += 1
        if end == len(lines):
            raise ValueError(f"unclosed Markdown code fence in {readme.name}")
        blocks.append((language, "".join(lines[index + 1 : end])))
        index = end + 1

    return blocks


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, help="absolute repository root")
    parser.add_argument(
        "--readme", action="append", required=True, help="repository-relative README"
    )
    parser.add_argument(
        "--expected-source",
        action="append",
        required=True,
        help="repository-relative complete core source; repeat for the full inventory",
    )
    parser.add_argument(
        "--check", action="store_true", required=True, help="check exact fenced source"
    )
    return parser.parse_args()


def resolve_readmes(
    root: pathlib.Path, values: list[str]
) -> list[tuple[str, pathlib.Path]]:
    readmes: list[tuple[str, pathlib.Path]] = []
    seen: set[pathlib.Path] = set()
    for value in values:
        readme = contained_path(root, value, "README path")
        if not readme.is_file():
            raise ValueError(f"README does not exist: {value}")
        if readme in seen:
            raise ValueError(f"duplicate README path: {value}")
        readmes.append((value, readme))
        seen.add(readme)
    if len(readmes) != 2:
        raise ValueError("pass exactly the English and Chinese README pair")
    names = {path.name for _, path in readmes}
    parents = {path.parent for _, path in readmes}
    if names != {"README.md", "README.zh.md"} or len(parents) != 1:
        raise ValueError("README paths must be README.md and README.zh.md from one lesson")
    return readmes


def source_payload(
    root: pathlib.Path, value: str, readme_paths: set[pathlib.Path]
) -> tuple[str, str]:
    source = contained_path(root, value, "expected source path")
    if not source.is_file():
        raise ValueError(f"expected source file does not exist: {value}")
    if source in readme_paths:
        raise ValueError(f"expected source cannot be a tutorial README: {value}")
    if source.suffix not in LANGUAGES:
        raise ValueError(f"unsupported expected-source file type: {value}")

    source_bytes = source.read_bytes()
    if not source_bytes:
        raise ValueError(f"complete source cannot be empty: {value}")
    if not source_bytes.endswith(b"\n"):
        raise ValueError(f"complete source must end with an LF byte: {value}")
    source_text = source_bytes.decode("utf-8")
    if "\r" in source_text:
        raise ValueError(f"complete source must use LF line endings: {value}")
    return LANGUAGES[source.suffix], source_text


def check_readme(
    value: str,
    readme: pathlib.Path,
    expected: collections.Counter[tuple[str, str]],
    labels: dict[tuple[str, str], list[str]],
) -> None:
    actual = collections.Counter(parse_fenced_blocks(readme))
    for payload, count in expected.items():
        found = actual[payload]
        names = ", ".join(labels[payload])
        if found < count:
            raise ValueError(f"missing exact fenced source in {value}: {names}")
        if found > count:
            raise ValueError(f"duplicate exact fenced source in {value}: {names}")


def main() -> int:
    args = parse_arguments()
    root = pathlib.Path(args.repo).resolve()
    if not (root / ".git").exists():
        print(f"not a Git worktree: {root}", file=sys.stderr)
        return 2

    try:
        readmes = resolve_readmes(root, args.readme)
        readme_paths = {path for _, path in readmes}
        labels: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
        expected: collections.Counter[tuple[str, str]] = collections.Counter()
        seen_values: set[str] = set()
        for value in args.expected_source:
            if value in seen_values:
                raise ValueError(f"duplicate expected source: {value}")
            payload = source_payload(root, value, readme_paths)
            expected[payload] += 1
            labels[payload].append(value)
            seen_values.add(value)

        for value, readme in readmes:
            check_readme(value, readme, expected, labels)
            print(f"checked {sum(expected.values())} fenced source blocks in {value}")
    except (OSError, UnicodeError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
