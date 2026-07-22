#!/usr/bin/env python3
import subprocess
import sys


def main():
    result = subprocess.run(
        [sys.argv[1], "--demo"],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    output = result.stdout + result.stderr
    if result.returncode:
        raise AssertionError(output)
    assert "demo step=before-dns result=blocked" in output, output
    assert "demo step=unsolicited-response result=blocked" in output, output
    assert "demo step=wrong-transaction-id result=blocked" in output, output
    assert "event=learned" in output and "ip=127.0.0.1 ttl=1" in output, output
    assert "demo step=live-answer result=allowed" in output, output
    assert "event=expired" in output, output
    assert "demo step=expired-answer result=blocked" in output, output
    assert output.count("event=denied") == 4, output
    print("DNS-aware egress integration test: PASS")


if __name__ == "__main__":
    main()
