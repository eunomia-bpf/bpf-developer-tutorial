#!/usr/bin/env python3
"""Synchronize inventoried complete-source blocks in tutorial READMEs."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
import tempfile


BEGIN_RE = re.compile(r"^<!-- BEGIN FULL SOURCE: ([^ ]+) -->$")
END = "<!-- END FULL SOURCE -->"
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


def render(
    readme: pathlib.Path,
    root: pathlib.Path,
    forbidden_sources: set[pathlib.Path],
) -> tuple[str, set[pathlib.Path]]:
    lines = readme.read_text(encoding="utf-8").splitlines()
    rendered: list[str] = []
    sources: set[pathlib.Path] = set()
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
        if source in forbidden_sources:
            raise ValueError(
                f"complete-source marker cannot name a tutorial README: {source_name}"
            )
        if source.suffix not in LANGUAGES:
            raise ValueError(f"unsupported complete-source file type: {source_name}")
        if source in sources:
            raise ValueError(f"duplicate complete-source marker: {source_name}")

        end = index + 1
        while end < len(lines) and lines[end] != END:
            if BEGIN_RE.match(lines[end]):
                raise ValueError(
                    f"nested complete-source marker before {END!r} after {source_name}"
                )
            end += 1
        if end == len(lines):
            raise ValueError(f"missing {END!r} after {source_name}")

        language = LANGUAGES[source.suffix]
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
        sources.add(source)
        index = end + 1

    return "\n".join(rendered) + "\n", sources


def display_paths(paths: set[pathlib.Path], root: pathlib.Path) -> str:
    return ", ".join(sorted(str(path.relative_to(root)) for path in paths))


def atomic_write(path: pathlib.Path, content: str) -> None:
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_name, path.stat().st_mode)
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            pathlib.Path(temporary_name).unlink(missing_ok=True)


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
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="replace marked blocks")
    mode.add_argument("--check", action="store_true", help="fail when blocks differ")
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
    return readmes


def resolve_expected_sources(
    root: pathlib.Path,
    values: list[str],
    readme_paths: set[pathlib.Path],
) -> set[pathlib.Path]:
    expected_sources: set[pathlib.Path] = set()
    for value in values:
        source = contained_path(root, value, "expected source path")
        if not source.is_file():
            raise ValueError(f"expected source file does not exist: {value}")
        if source in readme_paths:
            raise ValueError(f"expected source cannot be a tutorial README: {value}")
        if source.suffix not in LANGUAGES:
            raise ValueError(f"unsupported expected-source file type: {value}")
        if source in expected_sources:
            raise ValueError(f"duplicate expected source: {value}")
        expected_sources.add(source)
    return expected_sources


def inventory_mismatch(
    value: str,
    root: pathlib.Path,
    expected_sources: set[pathlib.Path],
    sources: set[pathlib.Path],
) -> ValueError | None:
    missing = expected_sources - sources
    extra = sources - expected_sources
    if not missing and not extra:
        return None
    details = []
    if missing:
        details.append(f"missing: {display_paths(missing, root)}")
    if extra:
        details.append(f"unexpected: {display_paths(extra, root)}")
    return ValueError(
        f"complete-source inventory mismatch in {value} ({'; '.join(details)})"
    )


def plan_updates(
    root: pathlib.Path,
    readmes: list[tuple[str, pathlib.Path]],
    expected_sources: set[pathlib.Path],
) -> list[tuple[str, pathlib.Path, str, str, int]]:
    readme_paths = {path for _, path in readmes}
    planned: list[tuple[str, pathlib.Path, str, str, int]] = []
    for value, readme in readmes:
        before = readme.read_text(encoding="utf-8")
        after, sources = render(readme, root, readme_paths)
        mismatch = inventory_mismatch(value, root, expected_sources, sources)
        if mismatch:
            raise mismatch
        planned.append((value, readme, before, after, len(sources)))
    return planned


def execute_plan(
    planned: list[tuple[str, pathlib.Path, str, str, int]], write: bool
) -> int:
    failed = False
    for value, readme, before, after, blocks in planned:
        if write:
            if before != after:
                atomic_write(readme, after)
            print(f"synced {blocks} source blocks in {value}")
        elif before != after:
            print(f"stale complete-source block in {value}", file=sys.stderr)
            failed = True
        else:
            print(f"checked {blocks} source blocks in {value}")

    return 1 if failed else 0


def main() -> int:
    args = parse_arguments()
    root = pathlib.Path(args.repo).resolve()
    if not (root / ".git").exists():
        print(f"not a Git worktree: {root}", file=sys.stderr)
        return 2

    try:
        readmes = resolve_readmes(root, args.readme)
        readme_paths = {path for _, path in readmes}
        expected_sources = resolve_expected_sources(
            root, args.expected_source, readme_paths
        )
        planned = plan_updates(root, readmes, expected_sources)
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return execute_plan(planned, args.write)


if __name__ == "__main__":
    raise SystemExit(main())
