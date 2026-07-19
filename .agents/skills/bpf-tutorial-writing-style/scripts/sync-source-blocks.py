#!/usr/bin/env python3
"""Synchronize complete-source code blocks in tutorial READMEs."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys


BEGIN_RE = re.compile(r"^<!-- BEGIN FULL SOURCE: ([^ ]+) -->$")
END = "<!-- END FULL SOURCE -->"
LANGUAGES = {
    ".c": "c",
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


def render(readme: pathlib.Path, root: pathlib.Path) -> tuple[str, int]:
    lines = readme.read_text(encoding="utf-8").splitlines()
    rendered: list[str] = []
    blocks = 0
    index = 0

    while index < len(lines):
        match = BEGIN_RE.match(lines[index])
        if not match:
            rendered.append(lines[index])
            index += 1
            continue

        source_name = match.group(1)
        source = contained_path(root, source_name, "source path")
        if not source.is_file():
            raise ValueError(f"source file does not exist: {source_name}")

        end = index + 1
        while end < len(lines) and lines[end] != END:
            end += 1
        if end == len(lines):
            raise ValueError(f"missing {END!r} after {source_name}")

        language = LANGUAGES.get(source.suffix, "text")
        source_text = source.read_text(encoding="utf-8").rstrip("\n")
        rendered.extend(
            [
                lines[index],
                f"```{language}",
                source_text,
                "```",
                END,
            ]
        )
        blocks += 1
        index = end + 1

    return "\n".join(rendered) + "\n", blocks


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, help="absolute repository root")
    parser.add_argument(
        "--readme", action="append", required=True, help="repository-relative README"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="replace marked blocks")
    mode.add_argument("--check", action="store_true", help="fail when blocks differ")
    args = parser.parse_args()

    root = pathlib.Path(args.repo).resolve()
    if not (root / ".git").exists() and not (root / ".git").is_file():
        print(f"not a Git worktree: {root}", file=sys.stderr)
        return 2

    failed = False
    for value in args.readme:
        try:
            readme = contained_path(root, value, "README path")
            if not readme.is_file():
                raise ValueError(f"README does not exist: {value}")
            before = readme.read_text(encoding="utf-8")
            after, blocks = render(readme, root)
            if blocks == 0:
                raise ValueError(f"no complete-source markers in {value}")
            if args.write:
                if before != after:
                    readme.write_text(after, encoding="utf-8")
                print(f"synced {blocks} source blocks in {value}")
            elif before != after:
                print(f"stale complete-source block in {value}", file=sys.stderr)
                failed = True
            else:
                print(f"checked {blocks} source blocks in {value}")
        except (OSError, ValueError) as error:
            print(error, file=sys.stderr)
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
