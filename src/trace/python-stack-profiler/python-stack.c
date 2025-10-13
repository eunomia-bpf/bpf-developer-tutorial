// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Python Stack Profiler - Profile Python applications with eBPF
 * Based on oncputime by Eunseon Lee
 */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/stat.h>
#include <string.h>
#include "python-stack.h"
#include "python-stack.skel.h"

#define STACK_ID_EFAULT(stack_id)	(stack_id == -EFAULT)
#define STACK_ID_ERR(stack_id)		((stack_id < 0) && !STACK_ID_EFAULT(stack_id))
#define CHECK_STACK_COLLISION(ustack_id, kstack_id)	\
	(kstack_id == -EEXIST || ustack_id == -EEXIST)
#define MISSING_STACKS(ustack_id, kstack_id)	\
	(STACK_ID_ERR(kstack_id) + STACK_ID_ERR(ustack_id))

struct key_ext_t {
	struct key_t k;
	__u64 v;
};

static struct env {
	int duration;
	int sample_freq;
	int cpu;
	bool verbose;
	bool folded;
	bool python_only;
	int pid;
	int perf_max_stack_depth;
	int stack_storage_size;
} env = {
	.duration = 10,
	.sample_freq = 49,
	.cpu = -1,
	.verbose = false,
	.folded = false,
	.python_only = true,
	.pid = -1,
	.perf_max_stack_depth = 127,
	.stack_storage_size = 10240,
};

static int nr_cpus;
static volatile sig_atomic_t exiting = 0;

const char argp_program_doc[] =
"Profile Python applications using eBPF.\n"
"\n"
"USAGE: python-stack [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    python-stack              # profile all Python processes for 10 seconds\n"
"    python-stack -p 1234      # profile Python process with PID 1234\n"
"    python-stack -F 99 -d 30  # profile at 99 Hz for 30 seconds\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Profile Python process with this PID" },
	{ "frequency", 'F', "FREQ", 0, "Sample frequency (default: 49 Hz)" },
	{ "duration", 'd', "DURATION", 0, "Duration in seconds (default: 10)" },
	{ "cpu", 'C', "CPU", 0, "CPU to profile on" },
	{ "folded", 'f', NULL, 0, "Output folded format for flame graphs" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p':
		env.pid = atoi(arg);
		break;
	case 'F':
		env.sample_freq = atoi(arg);
		break;
	case 'd':
		env.duration = atoi(arg);
		break;
	case 'C':
		env.cpu = atoi(arg);
		break;
	case 'f':
		env.folded = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			    va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static int open_and_attach_perf_event(struct bpf_program *prog,
				      struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = 1,
		.sample_freq = env.sample_freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
	int i, fd;

	for (i = 0; i < nr_cpus; i++) {
		if (env.cpu != -1 && env.cpu != i)
			continue;

		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			if (errno == ENODEV)
				continue;
			fprintf(stderr, "failed to init perf sampling: %s\n",
				strerror(errno));
			return -1;
		}

		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i]) {
			fprintf(stderr, "failed to attach perf event on cpu %d\n", i);
			close(fd);
			return -1;
		}
	}

	return 0;
}

static int cmp_counts(const void *a, const void *b)
{
	const __u64 x = ((struct key_ext_t *)a)->v;
	const __u64 y = ((struct key_ext_t *)b)->v;
	return y - x;
}

static void print_python_stack(const struct python_stack *py_stack)
{
	if (py_stack->depth == 0)
		return;

	for (int i = py_stack->depth - 1; i >= 0; i--) {
		const struct python_frame *frame = &py_stack->frames[i];

		if (env.folded) {
			// Folded format for flamegraphs
			if (i < py_stack->depth - 1)
				printf(";");
			printf("%s:%s:%d", frame->file_name,
			       frame->function_name, frame->line_number);
		} else {
			// Multi-line format
			printf("    %s:%d %s\n", frame->file_name,
			       frame->line_number, frame->function_name);
		}
	}
}

static int print_count(struct key_t *event, __u64 count, int stack_map)
{
	bool has_python_stack = (event->py_stack.depth > 0);

	if (!env.folded) {
		// Multi-line format
		printf("Process: %s (PID: %d)\n", event->name, event->pid);

		// Print Python stack if available
		if (has_python_stack) {
			printf("  Python Stack:\n");
			print_python_stack(&event->py_stack);
		}

		// Print native stacks
		unsigned long *ip = calloc(env.perf_max_stack_depth, sizeof(unsigned long));
		if (!ip) {
			fprintf(stderr, "failed to alloc ip\n");
			return -ENOMEM;
		}

		// Show user stack
		if (!STACK_ID_EFAULT(event->user_stack_id)) {
			if (bpf_map_lookup_elem(stack_map, &event->user_stack_id, ip) == 0) {
				printf("  Native User Stack:\n");
				for (int i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
					printf("    0x%lx\n", ip[i]);
				}
			}
		}

		free(ip);
		printf("  Count: %lld\n\n", count);
	} else {
		// Folded format for flamegraphs
		printf("%s;", event->name);

		if (has_python_stack) {
			print_python_stack(&event->py_stack);
		} else {
			printf("<no python stack>");
		}

		printf(" %lld\n", count);
	}

	return 0;
}

static int print_counts(int counts_map, int stack_map)
{
	struct key_ext_t *counts;
	struct key_t empty = {};
	struct key_t *lookup_key = &empty;
	int i = 0, err;
	__u32 nr_count = 0;

	counts = calloc(MAX_ENTRIES, sizeof(struct key_ext_t));
	if (!counts) {
		fprintf(stderr, "Out of memory\n");
		return -ENOMEM;
	}

	// Read all entries from the map
	while (bpf_map_get_next_key(counts_map, lookup_key, &counts[i].k) == 0) {
		err = bpf_map_lookup_elem(counts_map, &counts[i].k, &counts[i].v);
		if (err < 0) {
			fprintf(stderr, "failed to lookup counts: %d\n", err);
			free(counts);
			return -err;
		}

		if (counts[i].v == 0) {
			lookup_key = &counts[i].k;
			continue;
		}

		lookup_key = &counts[i].k;
		i++;
	}

	nr_count = i;
	qsort(counts, nr_count, sizeof(struct key_ext_t), cmp_counts);

	// Print results
	if (!env.folded) {
		printf("\n=== Python Stack Profile ===\n");
		printf("Captured %d unique stacks\n\n", nr_count);
	}

	for (i = 0; i < nr_count; i++) {
		print_count(&counts[i].k, counts[i].v, stack_map);
	}

	free(counts);
	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_link *links[MAX_CPU_NR] = {};
	struct python_stack_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		fprintf(stderr, "failed to get # of possible cpus: %s\n",
			strerror(-nr_cpus));
		return 1;
	}
	if (nr_cpus > MAX_CPU_NR) {
		fprintf(stderr, "the number of cpu cores is too big\n");
		return 1;
	}

	obj = python_stack_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	// Configure BPF program
	obj->rodata->python_only = env.python_only;
	if (env.pid > 0)
		obj->rodata->filter_by_pid = true;

	bpf_map__set_value_size(obj->maps.stackmap,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stackmap, env.stack_storage_size);

	err = python_stack_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF programs: %d\n", err);
		goto cleanup;
	}

	// Setup PID filter if specified
	if (env.pid > 0) {
		int pids_fd = bpf_map__fd(obj->maps.pids);
		__u8 val = 1;
		if (bpf_map_update_elem(pids_fd, &env.pid, &val, BPF_ANY) != 0) {
			fprintf(stderr, "failed to set pid filter: %s\n",
				strerror(errno));
			goto cleanup;
		}
	}

	err = open_and_attach_perf_event(obj->progs.do_perf_event, links);
	if (err)
		goto cleanup;

	signal(SIGINT, sig_handler);

	if (!env.folded) {
		printf("Profiling Python stacks at %d Hz", env.sample_freq);
		if (env.pid > 0)
			printf(" for PID %d", env.pid);
		printf("... Hit Ctrl-C to end.\n");
	}

	sleep(env.duration);

	if (!env.folded)
		printf("\nCollecting results...\n");

	print_counts(bpf_map__fd(obj->maps.counts),
		     bpf_map__fd(obj->maps.stackmap));

cleanup:
	for (int i = 0; i < nr_cpus; i++)
		bpf_link__destroy(links[i]);

	python_stack_bpf__destroy(obj);
	return err != 0;
}
