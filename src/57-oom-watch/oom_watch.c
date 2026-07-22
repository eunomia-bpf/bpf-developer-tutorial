// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "oom_watch.h"
#include "oom_watch.skel.h"

struct options {
	const char *cgroup_path;
	unsigned int duration_seconds;
	unsigned int sample_every;
	bool demo;
};

static volatile sig_atomic_t stop;
static int victim_events;
static int exit_events;
static unsigned long long observed_cgroup_id;
static unsigned int observed_victim_pid;
static unsigned int observed_victim_tid;
static unsigned long long observed_reclaims;
static unsigned long long observed_cross_cgroup_reclaims;
static unsigned long long observed_stack_samples;

struct kernel_symbol {
	unsigned long long address;
	char *name;
};

struct kernel_symbols {
	struct kernel_symbol *items;
	size_t count;
	size_t capacity;
};

struct runtime_context {
	int profiles_fd;
	int stack_profiles_fd;
	int stack_traces_fd;
	struct kernel_symbols symbols;
};

struct oom_runtime {
	struct oom_watch_bpf *skel;
	struct ring_buffer *ring;
	struct runtime_context context;
};

struct selected_cgroup {
	char demo_path[256];
	const char *path;
	struct stat metadata;
	bool demo_created;
	bool memory_enabled_by_demo;
};

struct demo_process {
	pid_t child;
	int ready_pipe[2];
	int continue_pipe[2];
	int status;
};

struct ranked_stack {
	struct reclaim_stack_key key;
	struct reclaim_stack_profile profile;
};

struct allocation_context {
	int ready_fd;
	int continue_fd;
};

static struct allocation_context allocation_context;

static void handle_signal(int signal_number)
{
	(void)signal_number;
	stop = 1;
}

static unsigned long long monotonic_ns(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static int write_text(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t length = strlen(text);
	int err = 0;

	if (fd < 0)
		return -1;
	if (write(fd, text, length) != length)
		err = -1;
	close(fd);
	return err;
}

static int memory_controller_enabled(bool *enabled)
{
	char controllers[4096];
	ssize_t length;
	int fd;

	fd = open("/sys/fs/cgroup/cgroup.subtree_control",
		  O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	length = read(fd, controllers, sizeof(controllers) - 1);
	close(fd);
	if (length < 0)
		return -1;
	controllers[length] = '\0';
	*enabled = strstr(controllers, "memory") != NULL;
	return 0;
}

static int compare_symbols(const void *left, const void *right)
{
	const struct kernel_symbol *a = left;
	const struct kernel_symbol *b = right;

	return a->address < b->address ? -1 : a->address > b->address ? 1 : 0;
}

static int load_kernel_symbols(struct kernel_symbols *symbols)
{
	char name[256];
	char type;
	unsigned long long address;
	FILE *file = fopen("/proc/kallsyms", "r");

	if (!file)
		return -1;
	while (fscanf(file, "%llx %c %255s%*[^\n]\n", &address, &type,
		      name) == 3) {
		struct kernel_symbol *item;

		(void)type;
		if (symbols->count == symbols->capacity) {
			size_t capacity = symbols->capacity ? symbols->capacity * 2 : 4096;
			void *items = realloc(symbols->items,
					      capacity * sizeof(*symbols->items));

			if (!items)
				goto error;
			symbols->items = items;
			symbols->capacity = capacity;
		}
		item = &symbols->items[symbols->count++];
		item->address = address;
		item->name = strdup(name);
		if (!item->name)
			goto error;
	}
	fclose(file);
	qsort(symbols->items, symbols->count, sizeof(*symbols->items),
	      compare_symbols);
	return symbols->count ? 0 : -1;

error:
	fclose(file);
	return -1;
}

static void free_kernel_symbols(struct kernel_symbols *symbols)
{
	for (size_t i = 0; i < symbols->count; i++)
		free(symbols->items[i].name);
	free(symbols->items);
}

static const struct kernel_symbol *find_kernel_symbol(
	const struct kernel_symbols *symbols, unsigned long long address)
{
	size_t low = 0, high = symbols->count;

	while (low < high) {
		size_t middle = low + (high - low) / 2;

		if (symbols->items[middle].address <= address)
			low = middle + 1;
		else
			high = middle;
	}
	return low ? &symbols->items[low - 1] : NULL;
}

static void insert_ranked_stack(struct ranked_stack top[5], size_t *count,
				const struct reclaim_stack_key *key,
				const struct reclaim_stack_profile *profile)
{
	size_t position = 0;

	while (position < *count &&
	       top[position].profile.total_ns >= profile->total_ns)
		position++;
	if (position >= 5)
		return;
	if (*count < 5)
		(*count)++;
	for (size_t i = *count - 1; i > position; i--)
		top[i] = top[i - 1];
	top[position].key = *key;
	top[position].profile = *profile;
}

static void print_reclaim_stacks(struct runtime_context *runtime,
				 __u64 cgroup_id)
{
	struct ranked_stack top[5] = {};
	struct reclaim_stack_key previous, next;
	bool have_previous = false;
	size_t count = 0;

	while (!bpf_map_get_next_key(runtime->stack_profiles_fd,
				     have_previous ? &previous : NULL, &next)) {
		struct reclaim_stack_profile profile;

		if (next.cgroup_id == cgroup_id &&
		    !bpf_map_lookup_elem(runtime->stack_profiles_fd, &next,
					 &profile))
			insert_ranked_stack(top, &count, &next, &profile);
		previous = next;
		have_previous = true;
	}

	for (size_t rank = 0; rank < count; rank++) {
		unsigned long long addresses[OOM_STACK_DEPTH] = {};

		printf("reclaim_stack rank=%zu samples=%llu total_ms=%.3f "
		       "max_ms=%.3f reclaimed_pages=%llu\n",
		       rank + 1, top[rank].profile.samples,
		       top[rank].profile.total_ns / 1000000.0,
		       top[rank].profile.maximum_ns / 1000000.0,
		       top[rank].profile.reclaimed_pages);
		if (bpf_map_lookup_elem(runtime->stack_traces_fd,
					&top[rank].key.stack_id, addresses))
			continue;
		for (size_t frame = 0; frame < OOM_STACK_DEPTH && addresses[frame];
		     frame++) {
			const struct kernel_symbol *symbol =
				find_kernel_symbol(&runtime->symbols, addresses[frame]);

			if (symbol && symbol->address)
				printf("  #%zu %s+0x%llx\n", frame, symbol->name,
				       addresses[frame] - symbol->address);
			else
				printf("  #%zu 0x%llx\n", frame, addresses[frame]);
		}
	}
}

static void print_reclaim_profile(struct runtime_context *runtime,
				  __u64 cgroup_id,
				  const struct reclaim_profile *profile)
{
	printf("reclaim_profile cgroup_id=%llu cycles=%llu completed=%llu "
	       "total_ms=%.3f max_ms=%.3f reclaimed_pages=%llu "
	       "cross_cgroup=%llu stack_samples=%llu stack_failures=%llu\n",
	       (unsigned long long)cgroup_id, profile->begin_count,
	       profile->end_count, profile->total_reclaim_ns / 1000000.0,
	       profile->maximum_reclaim_ns / 1000000.0,
	       profile->reclaimed_pages, profile->cross_cgroup_reclaims,
	       profile->stack_samples, profile->stack_failures);
	for (unsigned int bucket = 0; bucket < OOM_RECLAIM_BUCKETS; bucket++) {
		unsigned long long low, high;

		if (!profile->latency_slots[bucket])
			continue;
		low = bucket ? 1ULL << bucket : 0;
		high = (1ULL << (bucket + 1)) - 1;
		if (bucket == OOM_RECLAIM_BUCKETS - 1)
			printf("reclaim_latency_us=>=%llu count=%llu\n", low,
			       profile->latency_slots[bucket]);
		else
			printf("reclaim_latency_us=%llu-%llu count=%llu\n", low,
			       high, profile->latency_slots[bucket]);
	}
	print_reclaim_stacks(runtime, cgroup_id);
}

static void print_live_profiles(struct runtime_context *runtime)
{
	__u64 previous, next;
	bool have_previous = false;

	while (!bpf_map_get_next_key(runtime->profiles_fd,
				     have_previous ? &previous : NULL, &next)) {
		struct reclaim_profile profile;

		if (!bpf_map_lookup_elem(runtime->profiles_fd, &next, &profile))
			print_reclaim_profile(runtime, next, &profile);
		previous = next;
		have_previous = true;
	}
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct oom_watch_event *event = data;
	struct runtime_context *runtime = ctx;

	if (size != sizeof(*event))
		return 0;
	if (event->type == OOM_VICTIM_MARKED) {
		victim_events++;
		observed_cgroup_id = event->cgroup_id;
		observed_victim_pid = event->victim_pid;
		observed_reclaims = event->profile.begin_count;
		observed_victim_tid = event->victim_tid;
		observed_cross_cgroup_reclaims =
			event->profile.cross_cgroup_reclaims;
		observed_stack_samples = event->profile.stack_samples;
		printf("event=oom-victim pid=%u tid=%u comm=%s trigger_pid=%u cgroup_id=%llu "
		       "anon_rss_kb=%llu file_rss_kb=%llu total_vm_kb=%llu "
		       "reclaim_cycles=%llu cross_cgroup_reclaims=%llu "
		       "reclaimed_pages=%llu\n",
		       event->victim_pid, event->victim_tid, event->comm,
		       event->triggering_tgid,
		       (unsigned long long)event->cgroup_id,
		       (unsigned long long)event->anon_rss_kb,
		       (unsigned long long)event->file_rss_kb,
		       (unsigned long long)event->total_vm_kb,
		       (unsigned long long)event->profile.begin_count,
		       (unsigned long long)event->profile.cross_cgroup_reclaims,
		       (unsigned long long)event->profile.reclaimed_pages);
		print_reclaim_profile(runtime, event->cgroup_id, &event->profile);
	} else if (event->type == OOM_VICTIM_EXITED) {
		exit_events++;
		printf("event=victim-exit pid=%u tid=%u cgroup_id=%llu exit_code=%d\n",
		       event->victim_pid, event->victim_tid,
		       (unsigned long long)event->cgroup_id, event->exit_code);
	}
	return 0;
}

static int parse_uint(const char *text, unsigned int maximum,
		      unsigned int *value)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !*text || *end || !parsed || parsed > maximum)
		return -1;
	*value = parsed;
	return 0;
}

static void usage(const char *program)
{
	printf("Usage: %s [--cgroup PATH] [--duration SEC] [--sample-every N]\n"
	       "       %s --demo [--sample-every N]\n", program, program);
}

static int parse_options(int argc, char **argv, struct options *options)
{
	static const struct option long_options[] = {
		{ "cgroup", required_argument, NULL, 'c' },
		{ "duration", required_argument, NULL, 'd' },
		{ "sample-every", required_argument, NULL, 's' },
		{ "demo", no_argument, NULL, 'D' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "c:d:s:Dh", long_options,
				     NULL)) != -1) {
		switch (option) {
		case 'c': options->cgroup_path = optarg; break;
		case 'd':
			if (parse_uint(optarg, 86400, &options->duration_seconds))
				return -1;
			break;
		case 's':
			if (parse_uint(optarg, 1000000, &options->sample_every))
				return -1;
			break;
		case 'D': options->demo = true; break;
		case 'h': usage(argv[0]); exit(0);
		default: return -1;
		}
	}
	return optind == argc && !(options->demo && options->cgroup_path) ? 0 : -1;
}

static void *allocation_worker(void *argument)
{
	struct allocation_context *context = argument;
	size_t first_stage = 24 * 1024 * 1024;
	size_t length = 128 * 1024 * 1024;
	unsigned char *memory;
	char byte = 'x';

	memory = mmap(NULL, length, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (memory == MAP_FAILED)
		_exit(4);
	for (size_t offset = 0; offset < first_stage; offset += 4096)
		memory[offset] = 0xa5;
	if (write(context->ready_fd, &byte, 1) != 1 ||
	    read(context->continue_fd, &byte, 1) != 1)
		_exit(5);
	for (size_t offset = first_stage; offset < length; offset += 4096)
		memory[offset] = 0xa5;
	_exit(6);
}

static void allocate_until_killed(const char *cgroup_path, int ready_fd,
				  int continue_fd)
{
	char procs_path[512];
	char pid_text[32];
	pthread_t worker;

	snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_path);
	snprintf(pid_text, sizeof(pid_text), "%d", getpid());
	if (write_text(procs_path, pid_text))
		_exit(3);
	allocation_context.ready_fd = ready_fd;
	allocation_context.continue_fd = continue_fd;
	if (pthread_create(&worker, NULL, allocation_worker,
			   &allocation_context))
		_exit(4);
	pthread_detach(worker);
	pthread_exit(NULL);
}

static int configure_demo_cgroup(const char *path, bool *created,
				 bool *enabled_by_demo)
{
	bool memory_enabled;
	char file[512];

	if (memory_controller_enabled(&memory_enabled))
		return -1;
	if (!memory_enabled) {
		if (write_text("/sys/fs/cgroup/cgroup.subtree_control", "+memory"))
			return -1;
		*enabled_by_demo = true;
	}
	if (mkdir(path, 0755))
		return -1;
	*created = true;
	snprintf(file, sizeof(file), "%s/memory.max", path);
	if (write_text(file, "33554432"))
		return -1;
	snprintf(file, sizeof(file), "%s/memory.swap.max", path);
	if (write_text(file, "0"))
		return -1;
	snprintf(file, sizeof(file), "%s/memory.oom.group", path);
	return write_text(file, "1");
}

static int trigger_cross_cgroup_reclaim(const char *cgroup_path)
{
	char reclaim_path[512];

	snprintf(reclaim_path, sizeof(reclaim_path), "%s/memory.reclaim",
		 cgroup_path);
	if (!write_text(reclaim_path, "8388608") || errno == EAGAIN)
		return 0;
	return -1;
}

static int select_cgroup(const struct options *options,
			 struct selected_cgroup *selected)
{
	if (options->demo) {
		snprintf(selected->demo_path, sizeof(selected->demo_path),
			 "/sys/fs/cgroup/ebpf-oom-watch-%d", getpid());
		if (configure_demo_cgroup(selected->demo_path,
					  &selected->demo_created,
					  &selected->memory_enabled_by_demo)) {
			fprintf(stderr, "failed to configure demo memory cgroup: %s\n",
				strerror(errno));
			return -1;
		}
		selected->path = selected->demo_path;
	} else {
		selected->path = options->cgroup_path;
	}
	if (!selected->path)
		return 0;
	if (!stat(selected->path, &selected->metadata))
		return 0;
	fprintf(stderr, "failed to stat cgroup %s: %s\n", selected->path,
		strerror(errno));
	return -1;
}

static void cleanup_selected_cgroup(struct selected_cgroup *selected,
				    int *result)
{
	if (selected->demo_created && rmdir(selected->demo_path) && !*result)
		*result = 1;
	if (selected->memory_enabled_by_demo &&
	    write_text("/sys/fs/cgroup/cgroup.subtree_control", "-memory") &&
	    !*result)
		*result = 1;
}

static int prepare_runtime(struct oom_runtime *runtime,
			   const struct options *options,
			   const struct selected_cgroup *selected)
{
	runtime->skel = oom_watch_bpf__open();
	if (!runtime->skel)
		return -1;
	runtime->skel->rodata->target_cgroup_id =
		selected->path ? selected->metadata.st_ino : 0;
	runtime->skel->rodata->sample_every = options->sample_every;
	if (oom_watch_bpf__load(runtime->skel) ||
	    oom_watch_bpf__attach(runtime->skel)) {
		fprintf(stderr, "failed to load and attach OOM watcher\n");
		return -1;
	}
	runtime->context.profiles_fd =
		bpf_map__fd(runtime->skel->maps.profiles);
	runtime->context.stack_profiles_fd =
		bpf_map__fd(runtime->skel->maps.stack_profiles);
	runtime->context.stack_traces_fd =
		bpf_map__fd(runtime->skel->maps.stack_traces);
	if (load_kernel_symbols(&runtime->context.symbols))
		fprintf(stderr, "warning: kernel symbols unavailable; printing raw stack addresses\n");
	runtime->ring = ring_buffer__new(
		bpf_map__fd(runtime->skel->maps.events), handle_event,
		&runtime->context, NULL);
	return runtime->ring ? 0 : -1;
}

static void destroy_runtime(struct oom_runtime *runtime)
{
	ring_buffer__free(runtime->ring);
	free_kernel_symbols(&runtime->context.symbols);
	oom_watch_bpf__destroy(runtime->skel);
}

static void init_demo_process(struct demo_process *demo)
{
	memset(demo, 0, sizeof(*demo));
	demo->child = -1;
	demo->ready_pipe[0] = -1;
	demo->ready_pipe[1] = -1;
	demo->continue_pipe[0] = -1;
	demo->continue_pipe[1] = -1;
}

static void close_demo_pipe(int *fd)
{
	if (*fd >= 0)
		close(*fd);
	*fd = -1;
}

static void cleanup_demo_process(struct demo_process *demo)
{
	if (demo->child > 0) {
		kill(demo->child, SIGKILL);
		waitpid(demo->child, NULL, 0);
	}
	close_demo_pipe(&demo->ready_pipe[0]);
	close_demo_pipe(&demo->ready_pipe[1]);
	close_demo_pipe(&demo->continue_pipe[0]);
	close_demo_pipe(&demo->continue_pipe[1]);
}

static int start_demo_process(struct demo_process *demo,
			      const char *cgroup_path)
{
	struct pollfd ready = { .events = POLLIN };
	struct timespec leader_exit_delay = { .tv_nsec = 100000000 };
	char byte = 'x';

	if (pipe(demo->ready_pipe) || pipe(demo->continue_pipe))
		return -1;
	demo->child = fork();
	if (demo->child < 0)
		return -1;
	if (!demo->child) {
		close(demo->ready_pipe[0]);
		close(demo->continue_pipe[1]);
		allocate_until_killed(cgroup_path, demo->ready_pipe[1],
				      demo->continue_pipe[0]);
	}
	close_demo_pipe(&demo->ready_pipe[1]);
	close_demo_pipe(&demo->continue_pipe[0]);
	ready.fd = demo->ready_pipe[0];
	if (poll(&ready, 1, 5000) != 1 ||
	    read(demo->ready_pipe[0], &byte, 1) != 1 ||
	    trigger_cross_cgroup_reclaim(cgroup_path))
		return -1;
	nanosleep(&leader_exit_delay, NULL);
	if (write(demo->continue_pipe[1], &byte, 1) != 1)
		return -1;
	close_demo_pipe(&demo->ready_pipe[0]);
	close_demo_pipe(&demo->continue_pipe[1]);
	return 0;
}

static int collect_demo_events(struct demo_process *demo,
			       struct ring_buffer *ring)
{
	for (int i = 0; i < 200; i++) {
		pid_t waited;

		ring_buffer__poll(ring, 50);
		waited = waitpid(demo->child, &demo->status, WNOHANG);
		if (waited == demo->child) {
			demo->child = -1;
			break;
		}
	}
	for (int i = 0; i < 10 && exit_events < 1; i++)
		ring_buffer__poll(ring, 50);
	return demo->child < 0 ? 0 : -1;
}

static bool valid_demo_observation(const struct demo_process *demo,
				   unsigned long long cgroup_id,
				   const struct oom_watch_bpf *skel)
{
	return WIFSIGNALED(demo->status) &&
	       WTERMSIG(demo->status) == SIGKILL && victim_events == 1 &&
	       exit_events == 1 && observed_cgroup_id == cgroup_id &&
	       observed_victim_pid && observed_victim_tid &&
	       observed_victim_pid != observed_victim_tid && observed_reclaims &&
	       observed_cross_cgroup_reclaims && observed_stack_samples &&
	       !skel->bss->dropped_victim_states &&
	       !skel->bss->dropped_reclaim_states;
}

static int run_demo(struct oom_runtime *runtime,
		    const struct selected_cgroup *selected)
{
	struct demo_process demo;
	int result = -1;

	init_demo_process(&demo);
	if (start_demo_process(&demo, selected->path) ||
	    collect_demo_events(&demo, runtime->ring))
		goto cleanup;
	printf("demo workload signaled=%d signal=%d\n",
	       WIFSIGNALED(demo.status),
	       WIFSIGNALED(demo.status) ? WTERMSIG(demo.status) : 0);
	if (!valid_demo_observation(&demo, selected->metadata.st_ino,
				    runtime->skel))
		goto cleanup;
	printf("demo result=matched-profile-to-victim\n");
	result = 0;

cleanup:
	cleanup_demo_process(&demo);
	return result;
}

static int watch_profiles(struct oom_runtime *runtime,
			  unsigned int duration_seconds)
{
	unsigned long long deadline = 0;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	if (duration_seconds)
		deadline = monotonic_ns() +
			   (unsigned long long)duration_seconds * 1000000000ULL;
	while (!stop && (!deadline || monotonic_ns() < deadline)) {
		int result = ring_buffer__poll(runtime->ring, 100);

		if (result < 0 && result != -EINTR) {
			fprintf(stderr, "ring buffer poll failed: %d\n", result);
			return -1;
		}
	}
	print_live_profiles(&runtime->context);
	return 0;
}

int main(int argc, char **argv)
{
	struct options options = { .sample_every = 1 };
	struct selected_cgroup selected = {};
	struct oom_runtime runtime = {};
	int err = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (parse_options(argc, argv, &options)) {
		usage(argv[0]);
		return 2;
	}
	if (select_cgroup(&options, &selected) ||
	    prepare_runtime(&runtime, &options, &selected))
		goto cleanup;

	if (selected.path)
		printf("oom-watch tracing cgroup=%s cgroup_id=%llu\n",
		       selected.path,
		       (unsigned long long)selected.metadata.st_ino);
	else
		printf("oom-watch tracing all cgroups\n");

	if ((options.demo && run_demo(&runtime, &selected)) ||
	    (!options.demo && watch_profiles(&runtime,
					     options.duration_seconds)))
		goto cleanup;
	printf("dropped_victim_states=%llu dropped_reclaim_states=%llu\n",
	       (unsigned long long)runtime.skel->bss->dropped_victim_states,
	       (unsigned long long)runtime.skel->bss->dropped_reclaim_states);
	err = 0;

cleanup:
	destroy_runtime(&runtime);
	cleanup_selected_cgroup(&selected, &err);
	return err;
}
