// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __ARG_PARSE_H
#define __ARG_PARSE_H

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include "common.h"

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */
#define OPT_STATE			3 /* --state */

typedef enum {
	TOOL_OFFCPUTIME,
	TOOL_PROFILE
} tool_type_t;

struct common_env {
	pid_t pids[MAX_PID_NR];
	pid_t tids[MAX_TID_NR];
	bool user_threads_only;
	bool kernel_threads_only;
	bool user_stacks_only;
	bool kernel_stacks_only;
	int stack_storage_size;
	int perf_max_stack_depth;
	__u64 min_block_time;
	__u64 max_block_time;
	long state;
	int duration;
	bool verbose;
	bool folded;
	bool delimiter;
	bool freq;
	int sample_freq;
	bool include_idle;
	int cpu;
	tool_type_t tool_type;
};

static struct common_env env = {
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.min_block_time = 1,
	.max_block_time = -1,
	.state = -1,
	.duration = 99999999,
	.freq = 1,
	.sample_freq = 49,
	.cpu = -1,
};

static const char *get_program_doc(void)
{
	switch (env.tool_type) {
	case TOOL_OFFCPUTIME:
		return "Summarize off-CPU time by stack trace.\n"
		"\n"
		"USAGE: offcputime [--help] [-p PID | -u | -k] [-m MIN-BLOCK-TIME] "
		"[-M MAX-BLOCK-TIME] [--state] [--perf-max-stack-depth] [--stack-storage-size] "
		"[-f] [-d] [duration]\n"
		"EXAMPLES:\n"
		"    offcputime             # trace off-CPU stack time until Ctrl-C\n"
		"    offcputime 5           # trace for 5 seconds only\n"
		"    offcputime -m 1000     # trace only events that last more than 1000 usec\n"
		"    offcputime -M 10000    # trace only events that last less than 10000 usec\n"
		"    offcputime -p 185,175,165 # only trace threads for PID 185,175,165\n"
		"    offcputime -t 188,120,134 # only trace threads 188,120,134\n"
		"    offcputime -u          # only trace user threads (no kernel)\n"
		"    offcputime -k          # only trace kernel threads (no user)\n"
		"    offcputime -f          # output in folded format for flame graphs\n"
		"    offcputime -fd         # folded format with delimiter between stacks\n";
	case TOOL_PROFILE:
		return "Profile CPU usage by sampling stack traces at a timed interval.\n"
		"\n"
		"USAGE: profile [OPTIONS...] [duration]\n"
		"EXAMPLES:\n"
		"    profile             # profile stack traces at 49 Hertz until Ctrl-C\n"
		"    profile -F 99       # profile stack traces at 99 Hertz\n"
		"    profile -c 1000000  # profile stack traces every 1 in a million events\n"
		"    profile 5           # profile at 49 Hertz for 5 seconds only\n"
		"    profile -f          # output in folded format for flame graphs\n"
		"    profile -p 185      # only profile process with PID 185\n"
		"    profile -L 185      # only profile thread with TID 185\n"
		"    profile -U          # only show user space stacks (no kernel)\n"
		"    profile -K          # only show kernel space stacks (no user)\n";
	default:
		return "Unknown tool\n";
	}
}

static const struct argp_option common_opts[] = {
	{ "pid", 'p', "PID", 0, "Trace these PIDs only, comma-separated list", 0 },
	{ "tid", 't', "TID", 0, "Trace these TIDs only, comma-separated list", 0 },
	{ "tid", 'L', "TID", 0, "profile threads with one or more comma-separated TIDs only", 0 },
	{ "user-threads-only", 'u', NULL, 0,
	  "User threads only (no kernel threads)", 0 },
	{ "kernel-threads-only", 'k', NULL, 0,
	  "Kernel threads only (no user threads)", 0 },
	{ "user-stacks-only", 'U', NULL, 0,
	  "show stacks from user space only (no kernel space stacks)", 0 },
	{ "kernel-stacks-only", 'K', NULL, 0,
	  "show stacks from kernel space only (no user space stacks)", 0 },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)", 0 },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default 1024)", 0 },
	{ "min-block-time", 'm', "MIN-BLOCK-TIME", 0,
	  "the amount of time in microseconds over which we store traces (default 1)", 0 },
	{ "max-block-time", 'M', "MAX-BLOCK-TIME", 0,
	  "the amount of time in microseconds under which we store traces (default U64_MAX)", 0 },
	{ "state", OPT_STATE, "STATE", 0, "filter on this thread state bitmask (eg, 2 == TASK_UNINTERRUPTIBLE) see include/linux/sched.h", 0 },
	{ "frequency", 'F', "FREQUENCY", 0, "sample frequency, Hertz", 0 },
	{ "delimited", 'd', NULL, 0, "insert delimiter between kernel/user stacks", 0 },
	{ "include-idle ", 'I', NULL, 0, "include CPU idle stacks", 0 },
	{ "cpu", 'C', "CPU", 0, "cpu number to run profile on", 0 },
	{ "folded", 'f', NULL, 0, "output folded format, one line per stack (for flame graphs)", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_common_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	int ret;
	char *arg_copy;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'f':
		env.folded = true;
		break;
	case 'd':
		env.delimiter = true;
		break;
	case 'p':
		arg_copy = safe_strdup(arg);
		ret = split_convert(arg_copy, ",", env.pids, sizeof(env.pids),
				    sizeof(pid_t), str_to_int);
		free(arg_copy);
		if (ret) {
			if (ret == -ENOBUFS)
				fprintf(stderr, "the number of pid is too big, please "
					"increase MAX_PID_NR's value and recompile\n");
			else
				fprintf(stderr, "invalid PID: %s\n", arg);

			argp_usage(state);
		}
		break;
	case 't':
	case 'L':
		arg_copy = safe_strdup(arg);
		ret = split_convert(arg_copy, ",", env.tids, sizeof(env.tids),
				    sizeof(pid_t), str_to_int);
		free(arg_copy);
		if (ret) {
			if (ret == -ENOBUFS)
				fprintf(stderr, "the number of tid is too big, please "
					"increase MAX_TID_NR's value and recompile\n");
			else
				fprintf(stderr, "invalid TID: %s\n", arg);

			argp_usage(state);
		}
		break;
	case 'u':
		if (env.tool_type == TOOL_OFFCPUTIME) {
			env.user_threads_only = true;
		}
		/* No-op for profile */
		break;
	case 'k':
		if (env.tool_type == TOOL_OFFCPUTIME) {
			env.kernel_threads_only = true;
		}
		/* No-op for profile */
		break;
	case 'U':
		if (env.tool_type == TOOL_PROFILE) {
			env.user_stacks_only = true;
		}
		/* No-op for offcputime */
		break;
	case 'K':
		if (env.tool_type == TOOL_PROFILE) {
			env.kernel_stacks_only = true;
		}
		/* No-op for offcputime */
		break;
	case 'F':
		if (env.tool_type == TOOL_PROFILE) {
			errno = 0;
			env.sample_freq = strtol(arg, NULL, 10);
			if (errno || env.sample_freq <= 0) {
				fprintf(stderr, "invalid FREQUENCY: %s\n", arg);
				argp_usage(state);
			}
		}
		/* No-op for offcputime */
		break;
	case 'I':
		if (env.tool_type == TOOL_PROFILE) {
			env.include_idle = true;
		}
		/* No-op for offcputime */
		break;
	case 'C':
		if (env.tool_type == TOOL_PROFILE) {
			errno = 0;
			env.cpu = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid CPU: %s\n", arg);
				argp_usage(state);
			}
		}
		/* No-op for offcputime */
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		errno = 0;
		env.perf_max_stack_depth = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid perf max stack depth: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_STACK_STORAGE_SIZE:
		errno = 0;
		env.stack_storage_size = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid stack storage size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'm':
		if (env.tool_type == TOOL_OFFCPUTIME) {
			errno = 0;
			env.min_block_time = strtoll(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "Invalid min block time (in us): %s\n", arg);
				argp_usage(state);
			}
		}
		/* No-op for profile */
		break;
	case 'M':
		if (env.tool_type == TOOL_OFFCPUTIME) {
			errno = 0;
			env.max_block_time = strtoll(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "Invalid max block time (in us): %s\n", arg);
				argp_usage(state);
			}
		}
		/* No-op for profile */
		break;
	case OPT_STATE:
		if (env.tool_type == TOOL_OFFCPUTIME) {
			errno = 0;
			env.state = strtol(arg, NULL, 10);
			if (errno || env.state < 0 || env.state > 2) {
				fprintf(stderr, "Invalid task state: %s\n", arg);
				argp_usage(state);
			}
		}
		/* No-op for profile */
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		if (env.tool_type == TOOL_PROFILE) {
			env.duration = strtol(arg, NULL, 10);
			if (errno || env.duration <= 0) {
				fprintf(stderr, "Invalid duration (in s): %s\n", arg);
				argp_usage(state);
			}
		} else {
			env.duration = strtol(arg, NULL, 10);
			if (errno || env.duration <= 0) {
				fprintf(stderr, "Invalid duration (in s): %s\n", arg);
				argp_usage(state);
			}
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static void init_common_env(tool_type_t tool)
{
	env.tool_type = tool;
	
	/* Set tool-specific defaults */
	if (tool == TOOL_PROFILE) {
		env.duration = INT_MAX;
	}
}

static int parse_common_args(int argc, char **argv, tool_type_t tool)
{
	init_common_env(tool);
	
	const struct argp argp = {
		.options = common_opts,
		.parser = parse_common_arg,
		.doc = get_program_doc(),
	};
	
	return argp_parse(&argp, argc, argv, 0, NULL, NULL);
}

static int validate_common_args(void)
{
	if (env.tool_type == TOOL_OFFCPUTIME) {
		if (env.user_threads_only && env.kernel_threads_only) {
			fprintf(stderr, "user_threads_only and kernel_threads_only cannot be used together.\n");
			return 1;
		}
		if (env.min_block_time >= env.max_block_time) {
			fprintf(stderr, "min_block_time should be smaller than max_block_time\n");
			return 1;
		}
	} else if (env.tool_type == TOOL_PROFILE) {
		if (env.user_stacks_only && env.kernel_stacks_only) {
			fprintf(stderr, "user_stacks_only and kernel_stacks_only cannot be used together.\n");
			return 1;
		}
	}
	
	return 0;
}

#endif /* __ARG_PARSE_H */ 