#!/usr/bin/env python3
import subprocess
import sys


def main():
    result = subprocess.run(
        [sys.argv[1], "--demo", "--min-ms", "10"],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    output = result.stdout + result.stderr
    if result.returncode:
        raise AssertionError(output)
    assert "syscall=read(" in output, output
    assert "Slow syscall index, ranked by total latency:" in output, output
    assert "completed=" in output and "slow=1" in output, output
    assert "unaggregated=0" in output, output
    print("slow syscall index integration test: PASS")


if __name__ == "__main__":
    main()
