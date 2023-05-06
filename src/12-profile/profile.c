// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "profile.skel.h"
#include "profile.h"
#include "blazesym.h"

/*
 * This function is from libbpf, but it is not a public API and can only be
 * used for demonstration. We can use this here because we statically link
 * against the libbpf built from submodule during build.
 */
extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
			    int cpu, int group_fd, unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

static struct blazesym *symbolizer;

static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
	const struct blazesym_result *result;
	const struct blazesym_csym *sym;
	sym_src_cfg src;
	int i, j;

	if (pid) {
		src.src_type = SRC_T_PROCESS;
		src.params.process.pid = pid;
	} else {
		src.src_type = SRC_T_KERNEL;
		src.params.kernel.kallsyms = NULL;
		src.params.kernel.kernel_image = NULL;
	}

	result = blazesym_symbolize(symbolizer, &src, 1, (const uint64_t *)stack, stack_sz);

	for (i = 0; i < stack_sz; i++) {
		if (!result || result->size <= i || !result->entries[i].size) {
			printf("  %d [<%016llx>]\n", i, stack[i]);
			continue;
		}

		if (result->entries[i].size == 1) {
			sym = &result->entries[i].syms[0];
			if (sym->path && sym->path[0]) {
				printf("  %d [<%016llx>] %s+0x%llx %s:%ld\n",
				       i, stack[i], sym->symbol,
				       stack[i] - sym->start_address,
				       sym->path, sym->line_no);
			} else {
				printf("  %d [<%016llx>] %s+0x%llx\n",
				       i, stack[i], sym->symbol,
				       stack[i] - sym->start_address);
			}
			continue;
		}

		printf("  %d [<%016llx>]\n", i, stack[i]);
		for (j = 0; j < result->entries[i].size; j++) {
			sym = &result->entries[i].syms[j];
			if (sym->path && sym->path[0]) {
				printf("        %s+0x%llx %s:%ld\n",
				       sym->symbol, stack[i] - sym->start_address,
				       sym->path, sym->line_no);
			} else {
				printf("        %s+0x%llx\n", sym->symbol,
				       stack[i] - sym->start_address);
			}
		}
	}

	blazesym_result_free(result);
}

/* Receive events from the ring buffer. */
static int event_handler(void *_ctx, void *data, size_t size)
{
	struct stacktrace_event *event = data;

	if (event->kstack_sz <= 0 && event->ustack_sz <= 0)
		return 1;

	printf("COMM: %s (pid=%d) @ CPU %d\n", event->comm, event->pid, event->cpu_id);

	if (event->kstack_sz > 0) {
		printf("Kernel:\n");
		show_stack_trace(event->kstack, event->kstack_sz / sizeof(__u64), 0);
	} else {
		printf("No Kernel Stack\n");
	}

	if (event->ustack_sz > 0) {
		printf("Userspace:\n");
		show_stack_trace(event->ustack, event->ustack_sz / sizeof(__u64), event->pid);
	} else {
		printf("No Userspace Stack\n");
	}

	printf("\n");
	return 0;
}

static void show_help(const char *progname)
{
	printf("Usage: %s [-f <frequency>] [-h]\n", progname);
}

int main(int argc, char * const argv[])
{
	const char *online_cpus_file = "/sys/devices/system/cpu/online";
	int freq = 1, pid = -1, cpu;
	struct profile_bpf *skel = NULL;
	struct perf_event_attr attr;
	struct bpf_link **links = NULL;
	struct ring_buffer *ring_buf = NULL;
	int num_cpus, num_online_cpus;
	int *pefds = NULL, pefd;
	int argp, i, err = 0;
	bool *online_mask = NULL;

	while ((argp = getopt(argc, argv, "hf:")) != -1) {
		switch (argp) {
		case 'f':
			freq = atoi(optarg);
			if (freq < 1)
				freq = 1;
			break;

		case 'h':
		default:
			show_help(argv[0]);
			return 1;
		}
	}

	err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
	if (err) {
		fprintf(stderr, "Fail to get online CPU numbers: %d\n", err);
		goto cleanup;
	}

	num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		fprintf(stderr, "Fail to get the number of processors\n");
		err = -1;
		goto cleanup;
	}

	skel = profile_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Fail to open and load BPF skeleton\n");
		err = -1;
		goto cleanup;
	}

	symbolizer = blazesym_new();
	if (!symbolizer) {
		fprintf(stderr, "Fail to create a symbolizer\n");
		err = -1;
		goto cleanup;
	}

	/* Prepare ring buffer to receive events from the BPF program. */
	ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.events), event_handler, NULL, NULL);
	if (!ring_buf) {
		err = -1;
		goto cleanup;
	}

	pefds = malloc(num_cpus * sizeof(int));
	for (i = 0; i < num_cpus; i++) {
		pefds[i] = -1;
	}

	links = calloc(num_cpus, sizeof(struct bpf_link *));

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_HARDWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.sample_freq = freq;
	attr.freq = 1;

	for (cpu = 0; cpu < num_cpus; cpu++) {
		/* skip offline/not present CPUs */
		if (cpu >= num_online_cpus || !online_mask[cpu])
			continue;

		/* Set up performance monitoring on a CPU/Core */
		pefd = perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pefd < 0) {
			fprintf(stderr, "Fail to set up performance monitor on a CPU/Core\n");
			err = -1;
			goto cleanup;
		}
		pefds[cpu] = pefd;

		/* Attach a BPF program on a CPU */
		links[cpu] = bpf_program__attach_perf_event(skel->progs.profile, pefd);
		if (!links[cpu]) {
			err = -1;
			goto cleanup;
		}
	}
	
	/* Wait and receive stack traces */
	while (ring_buffer__poll(ring_buf, -1) >= 0) {
	}

cleanup:
	if (links) {
		for (cpu = 0; cpu < num_cpus; cpu++)
			bpf_link__destroy(links[cpu]);
		free(links);
	}
	if (pefds) {
		for (i = 0; i < num_cpus; i++) {
			if (pefds[i] >= 0)
				close(pefds[i]);
		}
		free(pefds);
	}
	ring_buffer__free(ring_buf);
	profile_bpf__destroy(skel);
	blazesym_free(symbolizer);
	free(online_mask);
	return -err;
}
