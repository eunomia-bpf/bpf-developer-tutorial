#!/usr/bin/env python3
"""Deterministic KVM integration checks for the BPF egress pacer."""

from __future__ import annotations

import errno
import os
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time


TX_INTERFACE = "epac_tx"
RX_INTERFACE = "epac_rx"
ETHERTYPE = 0x88B5
MAGIC = b"EPAC"
FRAME_SIZE = 1024
ATTEMPTS = 40
RATE_KBPS = 64
QUEUE_LIMIT = 8

SUMMARY = re.compile(
    r"SUMMARY enqueued=(\d+) dequeued=(\d+) policy_dropped=(\d+) "
    r"cleanup_dropped=(\d+) bytes_dequeued=(\d+) max_qlen=(\d+)"
)


def run(*command: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
    )


def delete_test_link() -> None:
    run("ip", "link", "del", TX_INTERFACE, check=False)


def create_test_link() -> None:
    delete_test_link()
    run("ip", "link", "add", TX_INTERFACE, "type", "veth", "peer", "name", RX_INTERFACE)
    run("ip", "link", "set", "dev", TX_INTERFACE, "addrgenmode", "none")
    run("ip", "link", "set", "dev", RX_INTERFACE, "addrgenmode", "none")
    run("ip", "link", "set", "dev", TX_INTERFACE, "up")
    run("ip", "link", "set", "dev", RX_INTERFACE, "up")


def wait_until_ready(process: subprocess.Popen[str]) -> list[str]:
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
    raise AssertionError("pacer did not become ready:\n" + "".join(lines) + remainder)


def receive_frames(
    stop: threading.Event,
    ready: threading.Event,
    times: list[float],
    errors: list[Exception],
) -> None:
    receiver: socket.socket | None = None
    try:
        receiver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE))
        receiver.bind((RX_INTERFACE, 0))
        receiver.settimeout(0.1)
        ready.set()
        while not stop.is_set():
            try:
                frame = receiver.recv(2048)
            except TimeoutError:
                continue
            if len(frame) >= 18 and frame[12:14] == struct.pack("!H", ETHERTYPE):
                if frame[14:18] == MAGIC:
                    times.append(time.monotonic())
    except Exception as error:
        errors.append(error)
        ready.set()
    finally:
        if receiver is not None:
            receiver.close()


def send_burst() -> int:
    sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sender.bind((TX_INTERFACE, 0))
    send_errors = 0
    try:
        for sequence in range(ATTEMPTS):
            header = b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x01" + struct.pack("!H", ETHERTYPE)
            payload = MAGIC + struct.pack("!I", sequence)
            frame = header + payload + b"x" * (FRAME_SIZE - len(header) - len(payload))
            try:
                sender.send(frame)
            except OSError as error:
                if error.errno != errno.ENOBUFS:
                    raise
                send_errors += 1
    finally:
        sender.close()
    return send_errors


def parse_summary(output: str) -> dict[str, int]:
    match = SUMMARY.search(output)
    if not match:
        raise AssertionError("missing summary:\n" + output)
    names = (
        "enqueued",
        "dequeued",
        "policy_dropped",
        "cleanup_dropped",
        "bytes_dequeued",
        "max_qlen",
    )
    return dict(zip(names, map(int, match.groups())))


def main() -> int:
    binary = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "./egress_pacer")
    stop = threading.Event()
    receiver: threading.Thread | None = None
    process: subprocess.Popen[str] | None = None

    invalid = run(binary, "--interface", "definitely_missing", "--duration", "1", check=False)
    assert invalid.returncode != 0
    assert "interface does not exist" in invalid.stdout

    create_test_link()
    try:
        run("tc", "qdisc", "add", "dev", TX_INTERFACE, "root", "handle", "1:",
            "pfifo", "limit", "16")
        conflict = run(
            binary,
            "--interface", TX_INTERFACE,
            "--rate-kbps", str(RATE_KBPS),
            "--queue-limit", str(QUEUE_LIMIT),
            "--duration", "1",
            check=False,
        )
        assert conflict.returncode != 0, conflict.stdout
        assert "refusing to replace" in conflict.stdout, conflict.stdout
        run("tc", "qdisc", "del", "dev", TX_INTERFACE, "root")

        receiver_ready = threading.Event()
        receive_times: list[float] = []
        receiver_errors: list[Exception] = []
        receiver = threading.Thread(
            target=receive_frames,
            args=(stop, receiver_ready, receive_times, receiver_errors),
        )
        receiver.start()
        assert receiver_ready.wait(timeout=2)
        assert not receiver_errors, receiver_errors

        process = subprocess.Popen(
            [
                binary,
                "--interface", TX_INTERFACE,
                "--rate-kbps", str(RATE_KBPS),
                "--queue-limit", str(QUEUE_LIMIT),
                "--duration", "2",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
        )
        lines = wait_until_ready(process)
        send_errors = send_burst()
        remainder, _ = process.communicate(timeout=8)
        output = "".join(lines) + remainder
        stop.set()
        receiver.join(timeout=2)
        assert not receiver.is_alive()
        assert not receiver_errors, receiver_errors
        assert process.returncode == 0, output

        stats = parse_summary(output)
        assert stats["enqueued"] + stats["policy_dropped"] == ATTEMPTS, stats
        assert stats["policy_dropped"] > 0, stats
        assert stats["dequeued"] == stats["enqueued"], stats
        assert stats["cleanup_dropped"] == 0, stats
        assert stats["max_qlen"] <= QUEUE_LIMIT, stats
        assert stats["max_qlen"] >= 2, stats
        assert len(receive_times) == stats["dequeued"], (len(receive_times), stats)
        assert len(receive_times) >= 5, receive_times

        span = receive_times[-1] - receive_times[0]
        assert span >= 0.4, span
        observed_kbps = (len(receive_times) - 1) * FRAME_SIZE * 8 / span / 1000
        assert observed_kbps <= RATE_KBPS * 1.5, observed_kbps

        qdisc_after = run("tc", "qdisc", "show", "dev", TX_INTERFACE).stdout
        assert "bpf_pacer" not in qdisc_after, qdisc_after

        process = subprocess.Popen(
            [
                binary,
                "--interface", TX_INTERFACE,
                "--rate-kbps", str(RATE_KBPS),
                "--queue-limit", str(QUEUE_LIMIT),
                "--duration", "30",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
        )
        signal_lines = wait_until_ready(process)
        send_burst()
        process.terminate()
        signal_remainder, _ = process.communicate(timeout=4)
        signal_output = "".join(signal_lines) + signal_remainder
        assert process.returncode == 0, signal_output
        signal_stats = parse_summary(signal_output)
        assert signal_stats["enqueued"] + signal_stats["policy_dropped"] == ATTEMPTS, signal_stats
        assert signal_stats["cleanup_dropped"] > 0, signal_stats
        assert signal_stats["enqueued"] == (
            signal_stats["dequeued"] + signal_stats["cleanup_dropped"]
        ), signal_stats
        qdisc_after_signal = run("tc", "qdisc", "show", "dev", TX_INTERFACE).stdout
        assert "bpf_pacer" not in qdisc_after_signal, qdisc_after_signal

        process = subprocess.Popen(
            [
                binary,
                "--interface", TX_INTERFACE,
                "--rate-kbps", str(RATE_KBPS),
                "--queue-limit", str(QUEUE_LIMIT),
                "--duration", "30",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
        )
        wait_until_ready(process)
        process.kill()
        process.communicate(timeout=4)
        assert process.returncode == -signal.SIGKILL, process.returncode
        qdisc_after_kill = run("tc", "qdisc", "show", "dev", TX_INTERFACE).stdout
        assert "bpf_pacer" in qdisc_after_kill, qdisc_after_kill
        run("tc", "qdisc", "del", "dev", TX_INTERFACE, "root")
        qdisc_after_recovery = run("tc", "qdisc", "show", "dev", TX_INTERFACE).stdout
        assert "bpf_pacer" not in qdisc_after_recovery, qdisc_after_recovery

        ready_line = next(line for line in output.splitlines() if line.startswith("READY "))
        summary_line = next(line for line in output.splitlines() if line.startswith("SUMMARY "))
        print(ready_line)
        print(summary_line)
        print(
            f"TEST-SUMMARY attempts={ATTEMPTS} received={len(receive_times)} "
            f"send_errors={send_errors} span_ms={span * 1000:.0f} "
            f"observed_kbps={observed_kbps:.1f}"
        )
        print(
            "PASS: conflict refusal, bounded drops, pacing, accounting, "
            "normal/signal cleanup, and SIGKILL recovery succeeded"
        )
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
        stop.set()
        if receiver is not None:
            receiver.join(timeout=2)
        delete_test_link()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
