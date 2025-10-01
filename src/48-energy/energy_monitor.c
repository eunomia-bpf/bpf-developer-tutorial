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
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include "energy_monitor.h"
#include "energy_monitor.skel.h"
#include <bpf/bpf.h>

static volatile bool exiting = false;

static struct env {
	bool verbose;
	int duration;
	double cpu_power_watts; // CPU power in watts (fallback if RAPL unavailable)
	bool use_rapl; // Use RAPL counters if available
} env = {
	.verbose = false,
	.duration = 0,
	.cpu_power_watts = 15.0, // Default 15W per CPU
	.use_rapl = true, // Try to use RAPL by default
};

// RAPL perf event file descriptors
static int rapl_fds[MAX_CPUS][RAPL_MAX_DOMAINS];
static int num_rapl_domains = 0;
static const char *rapl_domain_names[] = {
	[RAPL_PKG] = "pkg",
	[RAPL_CORE] = "cores",
	[RAPL_UNCORE] = "uncore",
	[RAPL_DRAM] = "ram",
	[RAPL_PSYS] = "psys",
};

const char *argp_program_version = "energy_monitor 0.1";
const char *argp_program_bug_address = "<>";
const char argp_program_doc[] =
"eBPF-based energy monitoring tool with RAPL support.\n"
"\n"
"This tool monitors process energy consumption by tracking CPU time\n"
"and reading hardware RAPL (Running Average Power Limit) counters.\n"
"Falls back to power estimation if RAPL is unavailable.\n"
"\n"
"USAGE: ./energy_monitor [-v] [-d <duration>] [-p <power>] [--no-rapl]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "SECONDS", 0, "Duration to run (0 for infinite)" },
	{ "power", 'p', "WATTS", 0, "CPU power in watts for estimation (default: 15.0, used if RAPL unavailable)" },
	{ "no-rapl", 'n', NULL, 0, "Disable RAPL and use power estimation" },
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
	case 'n':
		env.use_rapl = false;
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

// Helper function to open perf event
static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

// Read RAPL type from sysfs
static int read_rapl_type(void)
{
	FILE *f;
	int type = -1;

	f = fopen("/sys/bus/event_source/devices/power/type", "r");
	if (!f) {
		if (env.verbose)
			fprintf(stderr, "Cannot open RAPL type file (RAPL may not be available)\n");
		return -1;
	}

	if (fscanf(f, "%d", &type) != 1) {
		fclose(f);
		return -1;
	}

	fclose(f);
	return type;
}

// Read RAPL event configuration for a specific domain
static int read_rapl_config(const char *domain)
{
	char path[256];
	FILE *f;
	int config = -1;
	char buf[64];

	snprintf(path, sizeof(path), "/sys/bus/event_source/devices/power/events/energy-%s", domain);
	f = fopen(path, "r");
	if (!f)
		return -1;

	// Parse "event=0xXX" format (hexadecimal)
	if (fgets(buf, sizeof(buf), f)) {
		if (sscanf(buf, "event=%i", &config) != 1) {
			// Try parsing as hex if decimal fails
			sscanf(buf, "event=0x%x", &config);
		}
	}

	fclose(f);
	return config;
}

// Initialize RAPL perf events
static int init_rapl(void)
{
	int rapl_type;
	int num_cpus = libbpf_num_possible_cpus();

	if (!env.use_rapl)
		return -1;

	rapl_type = read_rapl_type();
	if (rapl_type < 0) {
		fprintf(stderr, "RAPL not available on this system, falling back to estimation\n");
		return -1;
	}

	if (env.verbose)
		printf("RAPL type: %d\n", rapl_type);

	// Initialize all FDs to -1
	for (int cpu = 0; cpu < MAX_CPUS; cpu++) {
		for (int domain = 0; domain < RAPL_MAX_DOMAINS; domain++) {
			rapl_fds[cpu][domain] = -1;
		}
	}

	// Try to open each domain
	for (int domain = 0; domain < RAPL_MAX_DOMAINS; domain++) {
		int config = read_rapl_config(rapl_domain_names[domain]);
		if (config < 0)
			continue;

		if (env.verbose)
			printf("Found RAPL domain: %s (config=0x%x)\n", rapl_domain_names[domain], config);

		// Open perf event for CPU 0 (package-level events are per-socket, not per-CPU)
		struct perf_event_attr attr = {
			.type = rapl_type,
			.config = config,
			.size = sizeof(struct perf_event_attr),
			.inherit = 0,
			.disabled = 0,
			.exclude_kernel = 0,
			.exclude_hv = 0,
		};

		int fd = perf_event_open(&attr, -1, 0, -1, 0);
		if (fd < 0) {
			if (env.verbose)
				fprintf(stderr, "Failed to open RAPL %s: %s\n",
					rapl_domain_names[domain], strerror(errno));
			continue;
		}

		rapl_fds[0][domain] = fd;
		num_rapl_domains++;

		if (env.verbose)
			printf("Opened RAPL %s on CPU 0 (fd=%d)\n", rapl_domain_names[domain], fd);
	}

	if (num_rapl_domains == 0) {
		fprintf(stderr, "No RAPL domains available, falling back to estimation\n");
		return -1;
	}

	printf("RAPL initialized with %d domains\n", num_rapl_domains);
	return 0;
}

// Read RAPL energy counter (in nanojoules)
static __u64 read_rapl_energy(int cpu, enum rapl_domain domain)
{
	__u64 energy = 0;
	int fd = rapl_fds[cpu][domain];

	if (fd < 0)
		return 0;

	if (read(fd, &energy, sizeof(energy)) != sizeof(energy)) {
		if (env.verbose)
			fprintf(stderr, "Failed to read RAPL counter\n");
		return 0;
	}

	return energy;
}

// Close all RAPL file descriptors
static void cleanup_rapl(void)
{
	for (int cpu = 0; cpu < MAX_CPUS; cpu++) {
		for (int domain = 0; domain < RAPL_MAX_DOMAINS; domain++) {
			if (rapl_fds[cpu][domain] >= 0) {
				close(rapl_fds[cpu][domain]);
				rapl_fds[cpu][domain] = -1;
			}
		}
	}
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

static void print_stats(struct energy_monitor_bpf *skel, __u64 start_energy[], __u64 end_energy[])
{
	__u32 key = 0, next_key;
	__u64 total_runtime_us = 0;
	__u64 *values;
	int num_cpus = libbpf_num_possible_cpus();
	bool using_rapl = (num_rapl_domains > 0);

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

	printf("\nTotal CPU time: %.2f ms\n", total_runtime_us / 1000.0);

	if (using_rapl) {
		// Calculate actual energy from RAPL counters
		printf("\n=== RAPL Hardware Energy Measurements ===\n");
		double total_energy_j = 0;

		for (int domain = 0; domain < RAPL_MAX_DOMAINS; domain++) {
			if (rapl_fds[0][domain] < 0)
				continue;

			__u64 energy_diff = end_energy[domain] - start_energy[domain];
			// RAPL returns energy in nanojoules (on most systems)
			// But the scale varies, typically it's in units that need to be divided by 2^32 to get joules
			// For perf_event interface, it's typically already in nanojoules
			double energy_j = energy_diff / 1e9;
			total_energy_j += energy_j;

			printf("%-10s: %.6f J (%.2f mJ)\n",
				rapl_domain_names[domain], energy_j, energy_j * 1000);
		}

		printf("\nTotal RAPL energy: %.6f J (%.2f mJ)\n", total_energy_j, total_energy_j * 1000);
		printf("Measurement method: Hardware RAPL counters\n");
	} else {
		double total_energy_j = (env.cpu_power_watts * total_runtime_us) / 1000000000.0;
		printf("Total estimated energy: %.4f J (%.4f mJ)\n", total_energy_j, total_energy_j * 1000);
		printf("CPU power setting: %.2f W\n", env.cpu_power_watts);
		printf("Measurement method: Software estimation (RAPL unavailable)\n");
	}

	free(values);
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct energy_monitor_bpf *skel;
	int err;
	__u64 start_energy[RAPL_MAX_DOMAINS] = {0};
	__u64 end_energy[RAPL_MAX_DOMAINS] = {0};

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

	// Initialize RAPL if available
	if (init_rapl() == 0) {
		printf("Using hardware RAPL energy counters\n");
	} else {
		printf("Using software power estimation (%.2f W)\n", env.cpu_power_watts);
	}

	// Clean handling of Ctrl-C
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// Open and load BPF application
	skel = energy_monitor_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		err = 1;
		goto cleanup_rapl;
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
	if (env.duration > 0)
		printf("Running for %d seconds\n", env.duration);
	printf("\n");

	// Read initial RAPL energy values
	if (num_rapl_domains > 0) {
		for (int domain = 0; domain < RAPL_MAX_DOMAINS; domain++) {
			start_energy[domain] = read_rapl_energy(0, domain);
		}
	}

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

	// Read final RAPL energy values
	if (num_rapl_domains > 0) {
		for (int domain = 0; domain < RAPL_MAX_DOMAINS; domain++) {
			end_energy[domain] = read_rapl_energy(0, domain);
		}
	}

	// Print final statistics
	print_stats(skel, start_energy, end_energy);

cleanup:
	ring_buffer__free(rb);
	energy_monitor_bpf__destroy(skel);
cleanup_rapl:
	cleanup_rapl();

	return err < 0 ? -err : 0;
}