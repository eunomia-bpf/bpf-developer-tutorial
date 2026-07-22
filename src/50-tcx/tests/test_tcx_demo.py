#!/usr/bin/env python3
"""End-to-end lifecycle test for the persistent TCX monitor."""

from __future__ import annotations

import re
import select
import signal
import socket
import subprocess
import sys
import time


COUNTERS = re.compile(
    r"COUNTERS stats_hits=(\d+) classifier_hits=(\d+) "
    r"last_ifindex=(\d+) last_protocol=0x([0-9a-fA-F]+) last_len=(\d+)"
)


def wait_ready(process: subprocess.Popen[str]) -> list[str]:
    lines: list[str] = []
    deadline = time.monotonic() + 8
    assert process.stdout is not None

    while time.monotonic() < deadline:
        readable, _, _ = select.select([process.stdout], [], [], 0.25)
        if readable:
            line = process.stdout.readline()
            if line:
                lines.append(line)
                if line.startswith("READY "):
                    return lines
        if process.poll() is not None:
            break

    process.kill()
    remainder, _ = process.communicate()
    raise AssertionError("TCX monitor did not become ready:\n" + "".join(lines) + remainder)


def generate_loopback_traffic() -> None:
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(1)
        payload = b"tcx monitor lifecycle"
        sender.sendto(payload, receiver.getsockname())
        received, _ = receiver.recvfrom(128)
        assert received == payload
    finally:
        sender.close()
        receiver.close()


def run_and_stop(binary: str, stop_signal: int) -> str:
    process = subprocess.Popen(
        [binary, "--duration", "30"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    lines = wait_ready(process)
    generate_loopback_traffic()
    process.send_signal(stop_signal)
    remainder, _ = process.communicate(timeout=5)
    output = "".join(lines) + remainder
    assert process.returncode == 0, output
    return output


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else "./tcx_demo"

    invalid = subprocess.run(
        [binary, "--duration", "invalid"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert invalid.returncode != 0
    assert "invalid duration" in invalid.stdout

    first = run_and_stop(binary, signal.SIGTERM)
    match = COUNTERS.search(first)
    assert match, first
    stats_hits, classifier_hits, ifindex, protocol, length = (
        int(value, 16) if index == 3 else int(value)
        for index, value in enumerate(match.groups())
    )
    assert stats_hits > 0, first
    assert classifier_hits == stats_hits, first
    assert ifindex > 0, first
    assert protocol == 0x0800, first
    assert length > 0, first
    assert len(re.findall(r"^  slot ", first, re.MULTILINE)) == 2, first

    # A clean second chain has exactly two slots, so neither first-run link leaked.
    second = run_and_stop(binary, signal.SIGINT)
    assert COUNTERS.search(second), second
    assert len(re.findall(r"^  slot ", second, re.MULTILINE)) == 2, second

    ready = next(line for line in first.splitlines() if line.startswith("READY "))
    counters = next(line for line in first.splitlines() if line.startswith("COUNTERS "))
    print(ready)
    print(counters)
    print("PASS: READY lifecycle, external traffic, signal shutdown, and reattach succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
