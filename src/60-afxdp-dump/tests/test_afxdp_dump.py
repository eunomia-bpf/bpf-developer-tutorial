#!/usr/bin/env python3
import os
import pathlib
import select
import socket
import subprocess
import sys


SUFFIX = os.getpid() % 10000
RX = f"axdp{SUFFIX}r"
TX = f"axdp{SUFFIX}t"
NETNS = f"afxdp-tx-ns-{os.getpid()}"


def run(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check)


def cleanup():
    run("ip", "link", "del", RX, check=False)
    run("ip", "netns", "del", NETNS, check=False)


def setup():
    cleanup()
    run("ip", "netns", "add", NETNS)
    run("ip", "link", "add", RX, "type", "veth", "peer", "name", TX)
    run("ip", "link", "set", TX, "netns", NETNS)
    run("ip", "addr", "add", "10.77.0.2/24", "dev", RX)
    run("ip", "link", "set", RX, "up")
    run(
        "ip", "netns", "exec", NETNS,
        "ip", "addr", "add", "10.77.0.1/24", "dev", TX,
    )
    run("ip", "netns", "exec", NETNS, "ip", "link", "set", TX, "up")
    run("ip", "netns", "exec", NETNS, "ip", "link", "set", "lo", "up")


def send_packets(count):
    code = (
        "import socket,time; "
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
        f"[(s.sendto(b'hello-afxdp',('10.77.0.2',8080)),time.sleep(0.005)) "
        f"for _ in range({count})]; s.close()"
    )
    run("ip", "netns", "exec", NETNS, "python3", "-c", code)


def verify_nonmatching_passes():
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        receiver.bind(("10.77.0.2", 8081))
        receiver.settimeout(3)
        code = (
            "import socket; "
            "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
            "s.sendto(b'pass-afxdp',('10.77.0.2',8081)); s.close()"
        )
        run("ip", "netns", "exec", NETNS, "python3", "-c", code)
        payload, _ = receiver.recvfrom(64)
        assert payload == b"pass-afxdp", payload
    finally:
        receiver.close()


def main():
    binary = str(pathlib.Path(sys.argv[1]).resolve())
    process = None
    try:
        setup()
        command = [
                binary,
                "--interface", RX,
                "--queue", "0",
                "--port", "8080",
                "--count", "65",
            ] + sys.argv[2:]
        process = subprocess.Popen(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        readable, _, _ = select.select([process.stdout], [], [], 5)
        if not readable:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
            raise AssertionError("timed out waiting for ready line\n" + stdout + stderr)
        ready = process.stdout.readline()
        if "afxdp-dump ready" not in ready:
            stdout, stderr = process.communicate(timeout=5)
            raise AssertionError(ready + stdout + stderr)
        verify_nonmatching_passes()
        send_packets(65)
        stdout, stderr = process.communicate(timeout=20)
        output = ready + stdout + stderr
        if process.returncode:
            raise AssertionError(output)
        assert "10.77.0.1:" in output and "-> 10.77.0.2:8080" in output, output
        assert 'payload="hello-afxdp"' in output, output
        assert "packet=65 " in output and "redirected=65" in output, output
        lines = output.splitlines()
        print(ready, end="")
        print(next(line for line in lines if line.startswith("packet=1 ")))
        print(next(line for line in lines if line.startswith("packet=65 ")))
        print(next(line for line in lines if line == "redirected=65"))
        print("nonmatching-pass=verified")
        print("AF_XDP dump integration test: PASS")
    finally:
        if process and process.poll() is None:
            process.kill()
            process.wait()
        cleanup()


if __name__ == "__main__":
    main()
