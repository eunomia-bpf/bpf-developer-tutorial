// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Google LLC.
 *
 * Based on funclatency from BCC by Brendan Gregg and others
 * 2021-02-26   Barret Rhoden   Created this.
 *
 * TODO:
 * - support uprobes on libraries without -p PID. (parse ld.so.cache)
 * - support regexp pattern matching and per-function histograms
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "funclatency.h"
#include "funclatency.skel.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static struct prog_env
{
	int units;
	pid_t pid;
	unsigned int duration;
	unsigned int interval;
	unsigned int iterations;
	bool timestamp;
	char *funcname;
	bool verbose;
	bool kprobes;
	bool is_kernel_func;
} env = {
	.interval = 99999999,
	.iterations = 99999999,
};

const char *argp_program_version = "funclatency 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char args_doc[] = "FUNCTION";
static const char program_doc[] =
	"Time functions and print latency as a histogram\n"
	"\n"
	"Usage: funclatency [-h] [-m|-u] [-p PID] [-d DURATION] [ -i INTERVAL ]\n"
	"                   [-T] FUNCTION\n"
	"       Choices for FUNCTION: FUNCTION         (kprobe)\n"
	"                             LIBRARY:FUNCTION (uprobe a library in -p PID)\n"
	"                             :FUNCTION        (uprobe the binary of -p PID)\n"
	"                             PROGRAM:FUNCTION (uprobe the binary PROGRAM)\n"
	"\v"
	"Examples:\n"
	"  ./funclatency do_sys_open         # time the do_sys_open() kernel function\n"
	"  ./funclatency -m do_nanosleep     # time do_nanosleep(), in milliseconds\n"
	"  ./funclatency -u vfs_read         # time vfs_read(), in microseconds\n"
	"  ./funclatency -p 181 vfs_read     # time process 181 only\n"
	"  ./funclatency -p 181 /usr/lib/x86_64-linux-gnu/libc.so.6:read       # time the read() C library function\n"
	"  ./funclatency -p 181 :foo         # time foo() from pid 181's userspace\n"
	"  ./funclatency -i 2 -d 10 vfs_read # output every 2 seconds, for 10s\n"
	"  ./funclatency -mTi 5 vfs_read     # output every 5 seconds, with timestamps\n";

static const struct argp_option opts[] = {
	{"milliseconds", 'm', NULL, 0, "Output in milliseconds"},
	{"microseconds", 'u', NULL, 0, "Output in microseconds"},
	{0, 0, 0, 0, ""},
	{"pid", 'p', "PID", 0, "Process ID to trace"},
	{0, 0, 0, 0, ""},
	{"interval", 'i', "INTERVAL", 0, "Summary interval in seconds"},
	{"duration", 'd', "DURATION", 0, "Duration to trace"},
	{"timestamp", 'T', NULL, 0, "Print timestamp"},
	{"verbose", 'v', NULL, 0, "Verbose debug output"},
	{"kprobes", 'k', NULL, 0, "Use kprobes instead of fentry"},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct prog_env *env = state->input;
	long duration, interval, pid;

	switch (key)
	{
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0)
		{
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env->pid = pid;
		break;
	case 'm':
		if (env->units != NSEC)
		{
			warn("only set one of -m or -u\n");
			argp_usage(state);
		}
		env->units = MSEC;
		break;
	case 'u':
		if (env->units != NSEC)
		{
			warn("only set one of -m or -u\n");
			argp_usage(state);
		}
		env->units = USEC;
		break;
	case 'd':
		errno = 0;
		duration = strtol(arg, NULL, 10);
		if (errno || duration <= 0)
		{
			warn("Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		env->duration = duration;
		break;
	case 'i':
		errno = 0;
		interval = strtol(arg, NULL, 10);
		if (errno || interval <= 0)
		{
			warn("Invalid interval: %s\n", arg);
			argp_usage(state);
		}
		env->interval = interval;
		break;
	case 'T':
		env->timestamp = true;
		break;
	case 'k':
		env->kprobes = true;
		break;
	case 'v':
		env->verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		if (env->funcname)
		{
			warn("Too many function names: %s\n", arg);
			argp_usage(state);
		}
		env->funcname = arg;
		break;
	case ARGP_KEY_END:
		if (!env->funcname)
		{
			warn("Need a function to trace\n");
			argp_usage(state);
		}
		if (env->duration)
		{
			if (env->interval > env->duration)
				env->interval = env->duration;
			env->iterations = env->duration / env->interval;
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static const char *unit_str(void)
{
	switch (env.units)
	{
	case NSEC:
		return "nsec";
	case USEC:
		return "usec";
	case MSEC:
		return "msec";
	};

	return "bad units";
}

static int attach_kprobes(struct funclatency_bpf *obj)
{
	obj->links.dummy_kprobe =
		bpf_program__attach_kprobe(obj->progs.dummy_kprobe, false,
								   env.funcname);
	if (!obj->links.dummy_kprobe)
	{
		warn("failed to attach kprobe: %d\n", -errno);
		return -1;
	}

	obj->links.dummy_kretprobe =
		bpf_program__attach_kprobe(obj->progs.dummy_kretprobe, true,
								   env.funcname);
	if (!obj->links.dummy_kretprobe)
	{
		warn("failed to attach kretprobe: %d\n", -errno);
		return -1;
	}

	return 0;
}

static int attach_uprobes(struct funclatency_bpf *obj)
{
	char *binary, *function;
	int ret = -1;
	long err;

	binary = strdup(env.funcname);
	if (!binary)
	{
		warn("strdup failed");
		return -1;
	}
	printf("tracing %s...\n", binary);
	function = strchr(binary, ':');
	if (!function)
	{
		warn("Binary should have contained ':' (internal bug!)\n");
		return -1;
	}
	*function = '\0';
	function++;
	printf("tracing func %s in %s...\n", function, binary);

	LIBBPF_OPTS(bpf_uprobe_opts, opts);
	opts.func_name = function;
	opts.retprobe = false;

	obj->links.dummy_kprobe =
		bpf_program__attach_uprobe_opts(obj->progs.dummy_kprobe, 
								   env.pid ?: -1, binary, 0, &opts);
	if (!obj->links.dummy_kprobe)
	{
		err = -errno;
		warn("Failed to attach uprobe: %ld\n", err);
		goto out_binary;
	}

	opts.retprobe = true;

	obj->links.dummy_kretprobe =
		bpf_program__attach_uprobe_opts(obj->progs.dummy_kretprobe, 
								   env.pid ?: -1, binary, 0, &opts);
	if (!obj->links.dummy_kretprobe)
	{
		err = -errno;
		warn("Failed to attach uretprobe: %ld\n", err);
		goto out_binary;
	}

	ret = 0;

out_binary:
	free(binary);

	return ret;
}

static volatile bool exiting;

static void sig_hand(int signr)
{
	exiting = true;
}

static struct sigaction sigact = {.sa_handler = sig_hand};

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

static void print_stars(unsigned int val, unsigned int val_max, int width)
{
	int num_stars, num_spaces, i;
	bool need_plus;

	num_stars = min(val, val_max) * width / val_max;
	num_spaces = width - num_stars;
	need_plus = val > val_max;

	for (i = 0; i < num_stars; i++)
		printf("*");
	for (i = 0; i < num_spaces; i++)
		printf(" ");
	if (need_plus)
		printf("+");
}

void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type)
{
	int stars_max = 40, idx_max = -1;
	unsigned int val, val_max = 0;
	unsigned long long low, high;
	int stars, width, i;

	for (i = 0; i < vals_size; i++)
	{
		val = vals[i];
		if (val > 0)
			idx_max = i;
		if (val > val_max)
			val_max = val;
	}

	if (idx_max < 0)
		return;

	printf("%*s%-*s : count    distribution\n", idx_max <= 32 ? 5 : 15, "",
		   idx_max <= 32 ? 19 : 29, val_type);

	if (idx_max <= 32)
		stars = stars_max;
	else
		stars = stars_max / 2;

	for (i = 0; i <= idx_max; i++)
	{
		low = (1ULL << (i + 1)) >> 1;
		high = (1ULL << (i + 1)) - 1;
		if (low == high)
			low -= 1;
		val = vals[i];
		width = idx_max <= 32 ? 10 : 20;
		printf("%*lld -> %-*lld : %-8d |", width, low, width, high, val);
		print_stars(val, val_max, stars);
		printf("|\n");
	}
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.args_doc = args_doc,
		.doc = program_doc,
	};
	struct funclatency_bpf *obj;
	int i, err;
	struct tm *tm;
	char ts[32];
	time_t t;
	int cgfd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
		return err;

	env.is_kernel_func = !strchr(env.funcname, ':');

	sigaction(SIGINT, &sigact, 0);

	libbpf_set_print(libbpf_print_fn);

	obj = funclatency_bpf__open_opts(&open_opts);
	if (!obj)
	{
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->units = env.units;
	obj->rodata->targ_tgid = env.pid;

	err = funclatency_bpf__load(obj);
	if (err)
	{
		warn("failed to load BPF object\n");
		return 1;
	}

	if (!obj->bss)
	{
		warn("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	if (env.is_kernel_func)
		err = attach_kprobes(obj);
	else
		err = attach_uprobes(obj);
	if (err)
		goto cleanup;

	err = funclatency_bpf__attach(obj);
	if (err)
	{
		fprintf(stderr, "failed to attach BPF programs: %s\n",
				strerror(-err));
		goto cleanup;
	}

	printf("Tracing %s.  Hit Ctrl-C to exit\n", env.funcname);

	for (i = 0; i < env.iterations && !exiting; i++)
	{
		sleep(env.interval);

		printf("\n");
		if (env.timestamp)
		{
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		print_log2_hist(obj->bss->hist, MAX_SLOTS, unit_str());

		/* Cleanup histograms for interval output */
		memset(obj->bss->hist, 0, sizeof(obj->bss->hist));
	}

	printf("Exiting trace of %s\n", env.funcname);

cleanup:
	funclatency_bpf__destroy(obj);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}