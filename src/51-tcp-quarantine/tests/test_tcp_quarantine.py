#!/usr/bin/env python3
"""End-to-end safety checks for exact TCP 4-tuple quarantine."""

from __future__ import annotations

import errno
import pathlib
import re
import socket
import subprocess
import sys
import time


BROKEN_ERRORS = {errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE}
MATCH = re.compile(r"^MATCH local=([^ ]+) remote=([^ ]+)$", re.MULTILINE)


def open_listener() -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    return listener


def connect(listener: socket.socket) -> tuple[socket.socket, socket.socket]:
    client = socket.create_connection(listener.getsockname(), timeout=2)
    server, _ = listener.accept()
    client.settimeout(1)
    server.settimeout(1)
    return client, server


def endpoint(address: tuple[str, int]) -> str:
    return f"{address[0]}:{address[1]}"


def round_trip(client: socket.socket, server: socket.socket, payload: bytes) -> None:
    client.sendall(payload)
    assert server.recv(len(payload)) == payload
    server.sendall(payload)
    assert client.recv(len(payload)) == payload


def run_tool(binary: pathlib.Path, remote: str, local: str | None = None) -> str:
    command = [str(binary), remote]
    if local is not None:
        command.extend(("--apply", local))
    result = subprocess.run(command, check=True, text=True, capture_output=True)
    print(result.stdout, end="")
    return result.stdout


def wait_for_destroy(client: socket.socket) -> None:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            client.send(b"x")
        except OSError as error:
            if error.errno in BROKEN_ERRORS:
                return
            raise
        error = client.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if error in BROKEN_ERRORS:
            return
        time.sleep(0.05)
    raise AssertionError("selected TCP socket remained usable")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} /path/to/tcp_quarantine")

    binary = pathlib.Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"missing binary: {binary}")

    invalid = subprocess.run(
        [str(binary), "not-an-endpoint"],
        text=True,
        capture_output=True,
    )
    assert invalid.returncode != 0
    assert "invalid remote IPv4 endpoint" in invalid.stderr

    target_listener = open_listener()
    control_listener = open_listener()
    selected_client, selected_server = connect(target_listener)
    sibling_client, sibling_server = connect(target_listener)
    control_client, control_server = connect(control_listener)
    sockets = (
        target_listener,
        control_listener,
        selected_client,
        selected_server,
        sibling_client,
        sibling_server,
        control_client,
        control_server,
    )
    try:
        remote = endpoint(target_listener.getsockname())
        selected_local = endpoint(selected_client.getsockname())
        sibling_local = endpoint(sibling_client.getsockname())
        round_trip(selected_client, selected_server, b"before-selected")
        round_trip(sibling_client, sibling_server, b"before-sibling")
        round_trip(control_client, control_server, b"before-control")

        dry_run = run_tool(binary, remote)
        matches = set(MATCH.findall(dry_run))
        assert matches == {
            (selected_local, remote),
            (sibling_local, remote),
        }, dry_run
        assert "SUMMARY mode=dry-run" in dry_run
        assert "matched=2" in dry_run
        assert "destroyed=0" in dry_run
        round_trip(selected_client, selected_server, b"after-dry-run")
        round_trip(sibling_client, sibling_server, b"sibling-after-dry-run")

        applied = run_tool(binary, remote, selected_local)
        assert f"MATCH local={selected_local} remote={remote}" in applied
        assert sibling_local not in applied
        assert "SUMMARY mode=apply" in applied
        assert "matched=1" in applied
        assert "destroyed=1" in applied
        assert "failed=0" in applied
        wait_for_destroy(selected_client)
        round_trip(sibling_client, sibling_server, b"sibling-survives")
        round_trip(control_client, control_server, b"control-survives")
    finally:
        for sock in sockets:
            sock.close()

    print("PASS: dry-run listed two sockets; exact 4-tuple apply destroyed only one")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
