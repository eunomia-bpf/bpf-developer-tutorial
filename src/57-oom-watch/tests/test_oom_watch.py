#!/usr/bin/env python3
import re
import subprocess
import sys
from pathlib import Path


def main():
    subtree_control = Path("/sys/fs/cgroup/cgroup.subtree_control")
    before = subtree_control.read_text()
    result = subprocess.run(
        [sys.argv[1], "--demo"],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    output = result.stdout + result.stderr
    after = subtree_control.read_text()
    if result.returncode:
        raise AssertionError(output)
    assert before == after, (before, after, output)
    assert "event=oom-victim" in output, output
    match = re.search(r"event=oom-victim pid=(\d+) tid=(\d+)", output)
    assert match and match.group(1) != match.group(2), output
    assert "reclaim_cycles=" in output, output
    assert "cross_cgroup_reclaims=" in output, output
    assert "reclaim_profile cgroup_id=" in output, output
    assert "reclaim_latency_us=" in output, output
    assert "reclaim_stack rank=1" in output, output
    assert "try_to_free_mem_cgroup_pages" in output, output
    assert "event=victim-exit" in output, output
    assert "demo workload signaled=1 signal=9" in output, output
    assert "demo result=matched-profile-to-victim" in output, output
    assert "dropped_victim_states=0 dropped_reclaim_states=0" in output, output
    print("OOM watch integration test: PASS")


if __name__ == "__main__":
    main()
