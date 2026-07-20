#!/usr/bin/env python3
"""Deterministic KVM checks for the deferred executable image inspector."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile


MARKER = b"EIPROBE!"
PROBE_DISTANCE = 4 * 1024 * 1024

SUMMARY = re.compile(
    r"SUMMARY matched=(\d+) scheduled=(\d+) schedule_errors=(\d+) "
    r"callbacks=(\d+) header_errors=(\d+) path_errors=(\d+) "
    r"direct_probes=(\d+) direct_probe_errors=(\d+) "
    r"deferred_probes=(\d+) deferred_probe_errors=(\d+) dropped=(\d+) "
    r"events=(\d+) command_exit=(\d+)"
)


def run(*command: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
        timeout=15,
    )


def parse_summary(output: str) -> dict[str, int]:
    match = SUMMARY.search(output)
    if not match:
        raise AssertionError("missing summary:\n" + output)
    names = (
        "matched",
        "scheduled",
        "schedule_errors",
        "callbacks",
        "header_errors",
        "path_errors",
        "direct_probes",
        "direct_probe_errors",
        "deferred_probes",
        "deferred_probe_errors",
        "dropped",
        "events",
        "command_exit",
    )
    return dict(zip(names, map(int, match.groups())))


def create_probe_image(fixture: str, directory: str) -> tuple[str, int]:
    image = os.path.join(directory, "exec_fixture_image")
    shutil.copyfile(fixture, image)
    os.chmod(image, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    original_size = os.path.getsize(image)
    probe_offset = ((original_size + 4095) // 4096) * 4096 + PROBE_DISTANCE
    with open(image, "r+b", buffering=0) as executable:
        executable.seek(probe_offset)
        executable.write(MARKER)
        os.fsync(executable.fileno())
        if hasattr(os, "posix_fadvise"):
            os.posix_fadvise(executable.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
    return image, probe_offset


def test_missing_command(inspector: str) -> dict[str, int]:
    missing = "/definitely/missing/exec-image-inspector-fixture"
    result = run(
        inspector,
        "--timeout-ms", "500",
        "--",
        missing,
        check=False,
    )
    assert result.returncode != 0, result.stdout
    assert f"failed to execute {missing}" in result.stdout, result.stdout
    assert "no executable image event was observed" in result.stdout, result.stdout
    stats = parse_summary(result.stdout)
    assert stats["matched"] == 0, stats
    assert stats["scheduled"] == 0, stats
    assert stats["callbacks"] == 0, stats
    assert stats["events"] == 0, stats
    assert stats["command_exit"] == 127, stats
    return stats


def test_timeout_cleanup(inspector: str) -> dict[str, int]:
    result = run(
        inspector,
        "--timeout-ms", "200",
        "--",
        "/bin/sleep", "2",
        check=False,
    )
    assert result.returncode == 128 + 9, result.stdout
    assert "command exceeded timeout; sending SIGKILL" in result.stdout, result.stdout
    stats = parse_summary(result.stdout)
    assert stats["matched"] == 1, stats
    assert stats["scheduled"] == 1, stats
    assert stats["callbacks"] == 1, stats
    assert stats["events"] == 1, stats
    assert stats["command_exit"] == 137, stats
    return stats


def test_reexec_chain(inspector: str) -> tuple[dict[str, int], str]:
    final_path = os.path.realpath("/bin/true")
    result = run(
        inspector,
        "--timeout-ms", "1000",
        "--",
        "/bin/sh", "-c", "exec /bin/true",
        check=False,
    )
    assert result.returncode == 0, result.stdout
    exec_lines = [
        line for line in result.stdout.splitlines() if line.startswith("EXEC ")
    ]
    assert len(exec_lines) == 2, result.stdout
    assert f"path={final_path}" in exec_lines[-1], exec_lines[-1]

    stats = parse_summary(result.stdout)
    assert stats["matched"] == 2, stats
    assert stats["scheduled"] == 2, stats
    assert stats["callbacks"] == 2, stats
    assert stats["events"] == 2, stats
    assert stats["command_exit"] == 0, stats
    return stats, final_path


def test_deferred_probe(inspector: str, fixture: str) -> str:
    with tempfile.TemporaryDirectory(prefix="exec-image-inspector-") as directory:
        image, probe_offset = create_probe_image(fixture, directory)
        result = run(
            inspector,
            "--probe-offset", str(probe_offset),
            "--timeout-ms", "3000",
            "--",
            image,
            check=False,
        )
        assert result.returncode == 0, result.stdout

        exec_line = next(
            (line for line in result.stdout.splitlines() if line.startswith("EXEC ")),
            "",
        )
        assert exec_line, result.stdout
        assert f"path={image}" in exec_line, exec_line
        assert "is_elf=1" in exec_line, exec_line
        assert "class=ELF64" in exec_line, exec_line
        assert "endian=LSB" in exec_line, exec_line
        assert "machine=EM_X86_64(62)" in exec_line, exec_line
        assert "header_error=0 path_error=0" in exec_line, exec_line

        probe_line = next(
            (line for line in result.stdout.splitlines() if line.startswith("PROBE ")),
            "",
        )
        assert probe_line, result.stdout
        assert f"offset={probe_offset}" in probe_line, probe_line
        assert "direct_error=-14" in probe_line, probe_line
        assert "deferred_error=0" in probe_line, probe_line
        assert f"bytes={MARKER.hex()}" in probe_line, probe_line

        stats = parse_summary(result.stdout)
        expected = {
            "matched": 1,
            "scheduled": 1,
            "schedule_errors": 0,
            "callbacks": 1,
            "header_errors": 0,
            "path_errors": 0,
            "direct_probes": 1,
            "direct_probe_errors": 1,
            "deferred_probes": 1,
            "deferred_probe_errors": 0,
            "dropped": 0,
            "events": 1,
            "command_exit": 0,
        }
        assert stats == expected, stats
        return result.stdout


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("this integration test must run as root inside KVM")

    inspector = os.path.abspath(
        sys.argv[1] if len(sys.argv) > 1 else "./exec_image_inspector"
    )
    fixture = os.path.abspath(
        sys.argv[2] if len(sys.argv) > 2 else "./tests/exec_fixture"
    )

    missing_stats = test_missing_command(inspector)
    timeout_stats = test_timeout_cleanup(inspector)
    reexec_stats, final_path = test_reexec_chain(inspector)
    output = test_deferred_probe(inspector, fixture)
    print(
        "TEST-MISSING "
        f"matched={missing_stats['matched']} events={missing_stats['events']} "
        f"command_exit={missing_stats['command_exit']}"
    )
    print(
        "TEST-TIMEOUT "
        f"matched={timeout_stats['matched']} callbacks={timeout_stats['callbacks']} "
        f"events={timeout_stats['events']} command_exit={timeout_stats['command_exit']}"
    )
    print(
        "TEST-REEXEC "
        f"matched={reexec_stats['matched']} callbacks={reexec_stats['callbacks']} "
        f"events={reexec_stats['events']} command_exit={reexec_stats['command_exit']} "
        f"final_path={final_path}"
    )
    print(output, end="")
    print(
        "PASS: missing-command, timeout cleanup, re-exec drain, ELF decode, "
        "and deferred file read succeeded"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
