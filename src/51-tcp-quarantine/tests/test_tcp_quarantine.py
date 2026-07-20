#!/usr/bin/env python3
"""End-to-end smoke test for the TCP quarantine tool."""

from __future__ import annotations

import errno
import pathlib
import socket
import subprocess
import sys
import time


BROKEN_ERRORS = {errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE}


def open_connection() -> tuple[socket.socket, socket.socket, socket.socket, int]:
	listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	listener.bind(("127.0.0.1", 0))
	listener.listen(1)
	client = socket.create_connection(listener.getsockname(), timeout=2)
	server, _ = listener.accept()
	client.settimeout(1)
	server.settimeout(1)
	return listener, client, server, listener.getsockname()[1]


def round_trip(client: socket.socket, server: socket.socket, payload: bytes) -> None:
	client.sendall(payload)
	assert server.recv(len(payload)) == payload
	server.sendall(payload)
	assert client.recv(len(payload)) == payload


def run_tool(binary: pathlib.Path, port: int, apply: bool) -> str:
	command = [str(binary), "--destination", "127.0.0.1", "--port", str(port)]
	if apply:
		command.append("--apply")
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
	raise AssertionError("quarantined TCP socket remained usable")


def main() -> int:
	if len(sys.argv) != 2:
		raise SystemExit(f"usage: {sys.argv[0]} /path/to/tcp_quarantine")
	if not hasattr(socket, "SO_ERROR"):
		raise SystemExit("SO_ERROR is unavailable")

	binary = pathlib.Path(sys.argv[1]).resolve()
	if not binary.is_file():
		raise SystemExit(f"missing binary: {binary}")

	invalid = subprocess.run(
		[str(binary), "--destination", "not-an-ip", "--port", "1"],
		text=True,
		capture_output=True,
	)
	assert invalid.returncode != 0
	assert "invalid IPv4 destination" in invalid.stderr

	target = open_connection()
	control = open_connection()
	all_sockets = target[:3] + control[:3]
	try:
		round_trip(target[1], target[2], b"before-target")
		round_trip(control[1], control[2], b"before-control")

		dry_run = run_tool(binary, target[3], apply=False)
		assert "mode=dry-run" in dry_run
		assert "matched=1" in dry_run
		assert "destroyed=0" in dry_run
		round_trip(target[1], target[2], b"after-dry-run")
		round_trip(control[1], control[2], b"control-after-dry-run")

		applied = run_tool(binary, target[3], apply=True)
		assert "mode=apply" in applied
		assert "matched=1" in applied
		assert "destroyed=1" in applied
		assert "failed=0" in applied
		wait_for_destroy(target[1])
		round_trip(control[1], control[2], b"control-survives")
	finally:
		for sock in all_sockets:
			sock.close()

	print("PASS: dry-run preserved both connections; apply destroyed only the target")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
