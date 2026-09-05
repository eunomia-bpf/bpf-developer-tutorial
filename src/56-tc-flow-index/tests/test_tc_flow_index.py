#!/usr/bin/env python3
import re
import subprocess
import sys


def run_demo():
    result = subprocess.run(
        [sys.argv[1], "--demo", "--top", "3"],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    output = result.stdout + result.stderr
    if result.returncode:
        raise AssertionError(output)
    assert "ranked in the BPF rbtree by bytes:" in output, output
    assert "indexed_flows=3" in output, output
    assert "allocation_failures=0" in output, output
    assert "refcount_failures=0" in output, output
    assert "rank_update_failures=0" in output, output
    byte_counts = [int(value) for value in re.findall(r"UDP\s+\d+\s+(\d+)", output)]
    assert len(byte_counts) == 3, output
    assert byte_counts == sorted(byte_counts, reverse=True), output


def main():
    run_demo()
    run_demo()
    invalid = subprocess.run(
        [sys.argv[1], "--interface", "no-such-interface"],
        text=True,
        capture_output=True,
        check=False,
        timeout=5,
    )
    assert invalid.returncode == 2, invalid.stdout + invalid.stderr
    assert "interface does not exist" in invalid.stderr, invalid.stderr
    print("TC flow index integration test: PASS")


if __name__ == "__main__":
    main()
