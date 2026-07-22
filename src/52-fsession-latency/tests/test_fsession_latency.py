#!/usr/bin/env python3
"""Deterministic runtime checks for the fsession latency tool."""

from __future__ import annotations

import os
import pathlib
import re
import select
import subprocess
import sys
import threading
import time


SUMMARY = re.compile(
    r"SUMMARY calls=(\d+) slow=(\d+) errors=(\d+) dropped=(\d+) events=(\d+)"
)
EVENT = re.compile(
    r"^EVENT comm=.{16} tgid=(\d+) pid=(\d+) object=(\d+):(\d+):(\d+) "
    r"type=(\w+) requested=(\d+) result=(-?\d+) latency_us=(\d+)$",
    re.MULTILINE,
)


def wait_until_attached(process: subprocess.Popen[str]) -> list[str]:
    lines: list[str] = []
    deadline = time.monotonic() + 8
    assert process.stdout is not None

    while time.monotonic() < deadline:
        readable, _, _ = select.select([process.stdout], [], [], 0.25)
        if readable:
            line = process.stdout.readline()
            if line:
                lines.append(line)
                if line.startswith("Tracing vfs_read"):
                    return lines
        if process.poll() is not None:
            break

    process.kill()
    remainder, _ = process.communicate()
    raise AssertionError("tool did not attach:\n" + "".join(lines) + remainder)


def generate_reads() -> None:
    path = pathlib.Path(__file__)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        for _ in range(64):
            os.lseek(descriptor, 0, os.SEEK_SET)
            os.read(descriptor, 256)
    finally:
        os.close(descriptor)

    read_fd, write_fd = os.pipe()

    def delayed_write() -> None:
        time.sleep(0.05)
        os.write(write_fd, b"x")
        os.close(write_fd)

    writer = threading.Thread(target=delayed_write)
    writer.start()
    try:
        assert os.read(read_fd, 1) == b"x"
    finally:
        os.close(read_fd)
        writer.join()


def run_trace(
    binary: str,
    *arguments: str,
    workload: bool,
    continuous: bool = False,
) -> tuple[dict[str, int], str]:
    process = subprocess.Popen(
        [binary, *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    lines = wait_until_attached(process)
    stop_workload = threading.Event()
    producer: threading.Thread | None = None
    if continuous:
        path = pathlib.Path(__file__)

        def generate_continuous_reads() -> None:
            descriptor = os.open(path, os.O_RDONLY)
            try:
                while not stop_workload.is_set():
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    os.read(descriptor, 1)
                    time.sleep(0.001)
            finally:
                os.close(descriptor)

        producer = threading.Thread(target=generate_continuous_reads)
        producer.start()
    elif workload:
        generate_reads()
    try:
        remainder, _ = process.communicate(timeout=8)
    finally:
        stop_workload.set()
        if producer is not None:
            producer.join()
    output = "".join(lines) + remainder
    if process.returncode != 0:
        raise AssertionError(f"tool failed with {process.returncode}:\n{output}")

    match = SUMMARY.search(output)
    if not match:
        raise AssertionError("missing summary:\n" + output)
    values = dict(zip(("calls", "slow", "errors", "dropped", "events"), map(int, match.groups())))
    return values, output


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else "./fsession_latency"

    invalid = subprocess.run(
        [binary, "--duration", "invalid"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert invalid.returncode != 0
    assert "invalid duration" in invalid.stdout

    empty_threshold = subprocess.run(
        [binary, "--threshold-us", ""],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert empty_threshold.returncode != 0
    assert "invalid threshold" in empty_threshold.stdout

    pid = str(os.getpid())
    missed, _ = run_trace(
        binary,
        "--duration", "1",
        "--threshold-us", "0",
        "--pid", str(2**32 - 1),
        workload=True,
    )
    assert missed == {"calls": 0, "slow": 0, "errors": 0, "dropped": 0, "events": 0}, missed

    below_threshold, _ = run_trace(
        binary,
        "--duration", "1",
        "--threshold-us", "10000000",
        "--pid", pid,
        workload=True,
    )
    assert below_threshold["calls"] >= 64, below_threshold
    assert below_threshold["slow"] == 0, below_threshold
    assert below_threshold["events"] == 0, below_threshold

    slow, slow_output = run_trace(
        binary,
        "--duration", "1",
        "--threshold-us", "10000",
        "--pid", pid,
        workload=True,
    )
    assert slow["calls"] >= 65, slow
    assert 1 <= slow["slow"] < slow["calls"], slow
    assert slow["events"] > 0, slow
    event_records = [match.groups() for match in EVENT.finditer(slow_output)]
    assert any(
        int(record[0]) == os.getpid()
        and int(record[1]) == os.getpid()
        and int(record[4]) > 0
        and record[5] == "fifo"
        and int(record[6]) == 1
        and int(record[7]) == 1
        and int(record[8]) >= 10000
        for record in event_records
    ), slow_output

    deadline, deadline_output = run_trace(
        binary,
        "--duration", "1",
        "--threshold-us", "0",
        "--pid", pid,
        workload=False,
        continuous=True,
    )
    assert deadline["calls"] > 0, deadline
    assert deadline["events"] > 0, deadline
    assert deadline["slow"] == deadline["events"] + deadline["dropped"], deadline
    source_stat = pathlib.Path(__file__).stat()
    assert any(
        int(match.group(3)) == os.major(source_stat.st_dev)
        and int(match.group(4)) == os.minor(source_stat.st_dev)
        and int(match.group(5)) == source_stat.st_ino
        and match.group(6) == "regular"
        for match in EVENT.finditer(deadline_output)
    ), deadline_output

    tracing_line = next(line for line in slow_output.splitlines() if line.startswith("Tracing "))
    first_event = next(line for line in slow_output.splitlines() if line.startswith("EVENT "))
    tool_summary = next(line for line in slow_output.splitlines() if line.startswith("SUMMARY "))
    print(tracing_line)
    print(first_event)
    print(tool_summary)

    print(
        "TEST-SUMMARY miss_calls=0 "
        f"high_threshold_calls={below_threshold['calls']} high_threshold_slow=0 "
        f"threshold_calls={slow['calls']} threshold_slow={slow['slow']} "
        f"events={slow['events']} dropped={slow['dropped']}"
    )
    print(
        "PASS: PID filtering, threshold miss, and regular/fifo object identity "
        "behaved as expected"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
