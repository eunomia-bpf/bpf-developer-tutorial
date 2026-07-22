#!/usr/bin/env python3
"""Deterministic KVM checks for the continuous executable image inspector."""

from __future__ import annotations

import os
import re
import select
import signal
import subprocess
import sys
import time


WORKERS = 16

SUMMARY = re.compile(
    r"SUMMARY matched=(\d+) scheduled=(\d+) schedule_errors=(\d+) "
    r"callbacks=(\d+) completed=(\d+) header_errors=(\d+) path_errors=(\d+) "
    r"dropped=(\d+) cleanup_errors=(\d+) events=(\d+)"
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
        "completed",
        "header_errors",
        "path_errors",
        "dropped",
        "cleanup_errors",
        "events",
    )
    return dict(zip(names, map(int, match.groups())))


def test_cli(inspector: str) -> None:
    help_result = run(inspector, "--help")
    assert help_result.returncode == 0, help_result.stdout
    assert "Continuously inspect executable images" in help_result.stdout


def stop_monitor(
    monitor: subprocess.Popen[str], signal_number: signal.Signals
) -> tuple[int, str]:
    monitor.send_signal(signal_number)
    try:
        output, _ = monitor.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        monitor.kill()
        output, _ = monitor.communicate()
        raise AssertionError("monitor did not stop after signal:\n" + output)
    return monitor.returncode, output


def wait_until_ready(monitor: subprocess.Popen[str]) -> list[str]:
    lines: list[str] = []
    deadline = time.monotonic() + 8
    assert monitor.stdout is not None

    while time.monotonic() < deadline:
        readable, _, _ = select.select([monitor.stdout], [], [], 0.25)
        if readable:
            line = monitor.stdout.readline()
            if line:
                lines.append(line)
                if line.startswith("READY "):
                    return lines
        if monitor.poll() is not None:
            break

    monitor.kill()
    remainder, _ = monitor.communicate()
    raise AssertionError("monitor did not become ready:\n" + "".join(lines) + remainder)


def test_continuous_monitor(
    inspector: str, fixture: str
) -> tuple[str, dict[str, int]]:
    monitor = subprocess.Popen(
        [inspector],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        lines = wait_until_ready(monitor)

        workers = [
            subprocess.Popen(
                [fixture], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
            )
            for _ in range(WORKERS)
        ]
        for worker in workers:
            assert worker.wait(timeout=5) == 0

        reexec = run("/bin/sh", "-c", "exec /bin/true")
        assert reexec.returncode == 0, reexec.stdout
        time.sleep(1)
        returncode, remainder = stop_monitor(monitor, signal.SIGINT)
        output = "".join(lines) + remainder
    finally:
        if monitor.poll() is None:
            monitor.kill()
            monitor.wait()

    assert returncode == 0, output
    assert "READY scope=system-wide" in output, output

    exec_lines = [line for line in output.splitlines() if line.startswith("EXEC ")]
    fixture_lines = [line for line in exec_lines if f"path={fixture}" in line]
    assert len(fixture_lines) == WORKERS, output
    assert all("is_elf=1" in line for line in fixture_lines), fixture_lines
    assert all("class=ELF64" in line for line in fixture_lines), fixture_lines
    assert all("endian=LSB" in line for line in fixture_lines), fixture_lines
    assert all("machine=EM_X86_64(62)" in line for line in fixture_lines)
    assert all("header_error=0 path_error=0" in line for line in fixture_lines)

    final_path = os.path.realpath("/bin/true")
    assert any(f"path={final_path}" in line for line in exec_lines), output

    stats = parse_summary(output)
    assert stats["matched"] >= WORKERS + 2, stats
    assert stats["scheduled"] == stats["matched"], stats
    assert stats["schedule_errors"] == 0, stats
    assert stats["callbacks"] == stats["scheduled"], stats
    assert stats["completed"] == stats["scheduled"], stats
    assert stats["events"] == stats["completed"], stats
    assert stats["dropped"] == 0, stats
    assert stats["cleanup_errors"] == 0, stats
    return output, stats


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("this integration test must run as root inside KVM")

    inspector = os.path.abspath(
        sys.argv[1] if len(sys.argv) > 1 else "./exec_image_inspector"
    )
    fixture = os.path.abspath(
        sys.argv[2] if len(sys.argv) > 2 else "./tests/exec_fixture"
    )

    test_cli(inspector)
    output, stats = test_continuous_monitor(inspector, fixture)
    print(
        "TEST-CONTINUOUS "
        f"workers={WORKERS} matched={stats['matched']} "
        f"callbacks={stats['callbacks']} events={stats['events']}"
    )
    print(output, end="")
    print(
        "PASS: persistent monitoring, concurrent execs, signal cleanup, "
        "and ELF decode succeeded"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
