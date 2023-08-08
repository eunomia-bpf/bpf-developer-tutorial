# eBPF Getting Started Tutorial: Writing eBPF Program Biopattern: Statistical Random/Sequential Disk I/O

## Background

Biopattern can statistically count the ratio of random/sequential disk I/O.

TODO

## Implementation Principle

The ebpf code of Biopattern is implemented under the mount point tracepoint/block/block_rq_complete. After the disk completes an IO request, the program will pass through this mount point. Biopattern has an internal hash table with device number as the primary key. When the program passes through the mount point, Biopattern obtains the operation information and determines whether the current operation is random or sequential IO based on the previous operation record of the device in the hash table, and updates the operation count.

## Writing eBPF Program

TODO

### Summary

Biopattern can show the ratio of random/sequential disk I/O, which is very helpful for developers to grasp the overall I/O situation.

TODO