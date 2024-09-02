/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2022- The Yunshan Networks Authors.
 *
 * Modify from https://github.com/deepflowio/deepflow
 * By Yusheng Zheng <1067852565@qq.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <vmlinux.h>
#include "goroutine.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define GOID_OFFSET 0x98

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("uprobe/./go-server-http/main:runtime.casgstatus")
int uprobe_runtime_casgstatus(struct pt_regs *ctx) {
  int newval = ctx->cx;
  void *gp = (void*)ctx->ax;
  struct goroutine_execute_data *data;
  u64 goid;
  if (bpf_probe_read_user(&goid, sizeof(goid), gp + GOID_OFFSET) == 0) {
    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
    if (data) {
      u64 pid_tgid = bpf_get_current_pid_tgid();
      data->pid = pid_tgid;
      data->tgid = pid_tgid >> 32;
      data->goid = goid;
      data->state = newval;
      bpf_ringbuf_submit(data, 0);
    }
  }
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
