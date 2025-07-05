// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "energy_monitor.h"
#include "energy_monitor.skel.h"
#include <bpf/bpf.h>

static volatile bool exiting = false;

static struct env {
	bool verbose;
	int duration;
	double cpu_power_watts; // CPU power in watts
} env = {
	.verbose = false,
	.duration = 0,
	.cpu_power_watts = 15.0, // Default 15W per CPU
};

const char *argp_program_version = "energy_monitor 0.1";
const char *argp_program_bug_address = "<>";
const char argp_program_doc[] =
"eBPF-based energy monitoring tool.\n"
"\n"
"This tool monitors process energy consumption by tracking CPU time\n"
"and estimating energy usage based on configured CPU power.\n"
"\n"
"USAGE: ./energy_monitor [-v] [-d <duration>] [-p <power>]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "SECONDS", 0, "Duration to run (0 for infinite)" },
	{ "power", 'p', "WATTS", 0, "CPU power in watts (default: 15.0)" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		env.duration = strtol(arg, NULL, 10);
		if (env.duration < 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'p':
		env.cpu_power_watts = strtod(arg, NULL);
		if (env.cpu_power_watts <= 0) {
			fprintf(stderr, "Invalid power value: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct energy_event *e = data;
	static __u64 total_energy_nj = 0;
	
	// Calculate energy in nanojoules
	// Energy (J) = Power (W) * Time (s)
	// Energy (nJ) = Power (W) * Time (ns)
	__u64 energy_nj = (__u64)(env.cpu_power_watts * e->runtime_ns);
	total_energy_nj += energy_nj;
	
	if (env.verbose) {
		printf("%-16s pid=%-6d cpu=%-2d runtime=%llu ns energy=%llu nJ\n",
		       e->comm, e->pid, e->cpu, e->runtime_ns, energy_nj);
	}
	
	return 0;
}

static void print_stats(struct energy_monitor_bpf *skel)
{
	__u32 key = 0, next_key;
	__u64 total_runtime_us = 0;
	__u64 *values;
	int num_cpus = libbpf_num_possible_cpus();
	
	values = calloc(num_cpus, sizeof(__u64));
	if (!values) {
		fprintf(stderr, "Failed to allocate memory\n");
		return;
	}
	
	printf("\n=== Energy Usage Summary ===\n");
	printf("%-10s %-16s %-15s %-15s\n", "PID", "COMM", "Runtime (ms)", "Energy (mJ)");
	printf("%-10s %-16s %-15s %-15s\n", "----------", "----------------", "---------------", "---------------");
	
	// Iterate through all PIDs in the runtime map
	while (bpf_map_get_next_key(bpf_map__fd(skel->maps.runtime_lookup), &key, &next_key) == 0) {
		char comm[TASK_COMM_LEN] = "unknown";
		__u64 runtime_us = 0;
		
		if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.runtime_lookup), &next_key, values) == 0) {
			// Sum up values from all CPUs
			for (int i = 0; i < num_cpus; i++) {
				runtime_us += values[i];
			}
			
			// Try to get process name
			char path[256];
			snprintf(path, sizeof(path), "/proc/%d/comm", next_key);
			FILE *f = fopen(path, "r");
			if (f) {
				if (fgets(comm, sizeof(comm), f)) {
					comm[strcspn(comm, "\n")] = 0;
				}
				fclose(f);
			}
			
			// Calculate energy in millijoules
			double runtime_ms = runtime_us / 1000.0;
			double energy_mj = (env.cpu_power_watts * runtime_us) / 1000000.0;
			
			printf("%-10d %-16s %-15.2f %-15.4f\n", next_key, comm, runtime_ms, energy_mj);
			
			total_runtime_us += runtime_us;
		}
		
		key = next_key;
	}
	
	double total_energy_j = (env.cpu_power_watts * total_runtime_us) / 1000000000.0;
	printf("\nTotal CPU time: %.2f ms\n", total_runtime_us / 1000.0);
	printf("Total estimated energy: %.4f J (%.4f mJ)\n", total_energy_j, total_energy_j * 1000);
	printf("CPU power setting: %.2f W\n", env.cpu_power_watts);
	
	free(values);
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct energy_monitor_bpf *skel;
	int err;
	
	// Parse command line arguments
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	
	// Set up libbpf errors and debug info callback
	libbpf_set_print(libbpf_print_fn);
	
	// Bump RLIMIT_MEMLOCK to create BPF maps
	struct rlimit rlim = {
		.rlim_cur = 512UL << 20, // 512 MB
		.rlim_max = 512UL << 20,
	};
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		return 1;
	}
	
	// Clean handling of Ctrl-C
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	
	// Open and load BPF application
	skel = energy_monitor_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	
	// Set program parameters
	skel->rodata->verbose = env.verbose;
	
	// Load & verify BPF programs
	err = energy_monitor_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	
	// Attach tracepoints
	err = energy_monitor_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	
	// Set up ring buffer polling
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	
	printf("Energy monitor started... Hit Ctrl-C to end.\n");
	printf("CPU Power: %.2f W\n", env.cpu_power_watts);
	if (env.duration > 0)
		printf("Running for %d seconds\n", env.duration);
	printf("\n");
	
	// Process events
	time_t start_time = time(NULL);
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		// Ctrl-C will cause -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
		
		// Check duration
		if (env.duration > 0 && (time(NULL) - start_time) >= env.duration)
			break;
	}
	
	// Print final statistics
	print_stats(skel);
	
cleanup:
	ring_buffer__free(rb);
	energy_monitor_bpf__destroy(skel);
	
	return err < 0 ? -err : 0;
}