// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "oom_watch.h"
#include "oom_watch.skel.h"

struct options {
	const char *cgroup_path;
	unsigned int duration_seconds;
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

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct oom_watch_event *event = data;

	(void)ctx;
	if (size != sizeof(*event))
		return 0;
	if (event->type == OOM_VICTIM_MARKED) {
		victim_events++;
		observed_cgroup_id = event->cgroup_id;
		observed_victim_pid = event->victim_pid;
		observed_reclaims = event->reclaim_begin_count;
		observed_victim_tid = event->victim_tid;
		observed_cross_cgroup_reclaims = event->cross_cgroup_reclaims;
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
		       (unsigned long long)event->reclaim_begin_count,
		       (unsigned long long)event->cross_cgroup_reclaims,
		       (unsigned long long)event->reclaimed_pages);
	} else if (event->type == OOM_VICTIM_EXITED) {
		exit_events++;
		printf("event=victim-exit pid=%u tid=%u cgroup_id=%llu exit_code=%d\n",
		       event->victim_pid, event->victim_tid,
		       (unsigned long long)event->cgroup_id, event->exit_code);
	}
	return 0;
}

static int parse_uint(const char *text, unsigned int *value)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !*text || *end || parsed > 86400)
		return -1;
	*value = parsed;
	return 0;
}

static void usage(const char *program)
{
	printf("Usage: %s [--cgroup PATH] [--duration SEC]\n"
	       "       %s --demo\n", program, program);
}

static int parse_options(int argc, char **argv, struct options *options)
{
	static const struct option long_options[] = {
		{ "cgroup", required_argument, NULL, 'c' },
		{ "duration", required_argument, NULL, 'd' },
		{ "demo", no_argument, NULL, 'D' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "c:d:Dh", long_options,
				     NULL)) != -1) {
		switch (option) {
		case 'c': options->cgroup_path = optarg; break;
		case 'd':
			if (parse_uint(optarg, &options->duration_seconds))
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

int main(int argc, char **argv)
{
	struct options options = {};
	struct oom_watch_bpf *skel = NULL;
	struct ring_buffer *ring = NULL;
	char demo_cgroup_path[256];
	unsigned long long deadline = 0;
	struct stat cgroup_stat = {};
	const char *selected_path = NULL;
	pid_t child = -1;
	int ready_pipe[2] = { -1, -1 };
	int continue_pipe[2] = { -1, -1 };
	int status = 0;
	int err = 1;
	bool demo_cgroup_created = false;
	bool memory_enabled_by_demo = false;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (parse_options(argc, argv, &options)) {
		usage(argv[0]);
		return 2;
	}
	if (options.demo) {
		snprintf(demo_cgroup_path, sizeof(demo_cgroup_path),
			 "/sys/fs/cgroup/ebpf-oom-watch-%d", getpid());
		if (configure_demo_cgroup(demo_cgroup_path,
					  &demo_cgroup_created,
					  &memory_enabled_by_demo)) {
			fprintf(stderr, "failed to configure demo memory cgroup: %s\n",
				strerror(errno));
			goto cleanup;
		}
		selected_path = demo_cgroup_path;
	} else {
		selected_path = options.cgroup_path;
	}
	if (selected_path && stat(selected_path, &cgroup_stat)) {
		fprintf(stderr, "failed to stat cgroup %s: %s\n", selected_path,
			strerror(errno));
		goto cleanup;
	}

	skel = oom_watch_bpf__open();
	if (!skel)
		goto cleanup;
	skel->rodata->target_cgroup_id = selected_path ? cgroup_stat.st_ino : 0;
	if (oom_watch_bpf__load(skel) || oom_watch_bpf__attach(skel)) {
		fprintf(stderr, "failed to load and attach OOM watcher\n");
		goto cleanup;
	}
	ring = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
				NULL, NULL);
	if (!ring)
		goto cleanup;

	if (selected_path)
		printf("oom-watch tracing cgroup=%s cgroup_id=%llu\n",
		       selected_path, (unsigned long long)cgroup_stat.st_ino);
	else
		printf("oom-watch tracing all cgroups\n");

	if (options.demo) {
		struct pollfd ready = { .events = POLLIN };
		struct timespec leader_exit_delay = { .tv_nsec = 100000000 };
		char byte = 'x';

		if (pipe(ready_pipe) || pipe(continue_pipe))
			goto cleanup;
		child = fork();
		if (child < 0)
			goto cleanup;
		if (!child) {
			close(ready_pipe[0]);
			close(continue_pipe[1]);
			allocate_until_killed(selected_path, ready_pipe[1],
					      continue_pipe[0]);
		}
		close(ready_pipe[1]); ready_pipe[1] = -1;
		close(continue_pipe[0]); continue_pipe[0] = -1;
		ready.fd = ready_pipe[0];
		if (poll(&ready, 1, 5000) != 1 ||
		    read(ready_pipe[0], &byte, 1) != 1 ||
		    trigger_cross_cgroup_reclaim(selected_path))
			goto cleanup;
		nanosleep(&leader_exit_delay, NULL);
		if (write(continue_pipe[1], &byte, 1) != 1)
			goto cleanup;
		close(ready_pipe[0]); ready_pipe[0] = -1;
		close(continue_pipe[1]); continue_pipe[1] = -1;

		for (int i = 0; i < 200; i++) {
			pid_t waited;

			ring_buffer__poll(ring, 50);
			waited = waitpid(child, &status, WNOHANG);
			if (waited == child) {
				child = -1;
				break;
			}
		}
		for (int i = 0; i < 10 && exit_events < 1; i++)
			ring_buffer__poll(ring, 50);

		printf("demo workload signaled=%d signal=%d\n",
		       WIFSIGNALED(status),
		       WIFSIGNALED(status) ? WTERMSIG(status) : 0);
		if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL ||
		    victim_events != 1 || exit_events != 1 ||
		    observed_cgroup_id != (unsigned long long)cgroup_stat.st_ino ||
		    !observed_victim_pid || !observed_victim_tid ||
		    observed_victim_pid == observed_victim_tid ||
		    !observed_reclaims || !observed_cross_cgroup_reclaims ||
		    skel->bss->dropped_victim_states)
			goto cleanup;
		printf("demo result=matched-profile-to-victim\n");
	} else {
		signal(SIGINT, handle_signal);
		signal(SIGTERM, handle_signal);
		if (options.duration_seconds)
			deadline = monotonic_ns() +
				   (unsigned long long)options.duration_seconds *
				   1000000000ULL;
		while (!stop && (!deadline || monotonic_ns() < deadline)) {
			int poll_result = ring_buffer__poll(ring, 100);

			if (poll_result < 0 && poll_result != -EINTR) {
				fprintf(stderr, "ring buffer poll failed: %d\n",
					poll_result);
				goto cleanup;
			}
		}
	}
	printf("dropped_victim_states=%llu\n",
	       (unsigned long long)skel->bss->dropped_victim_states);
	err = 0;

cleanup:
	if (child > 0) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
	}
	for (size_t i = 0; i < 2; i++) {
		if (ready_pipe[i] >= 0) close(ready_pipe[i]);
		if (continue_pipe[i] >= 0) close(continue_pipe[i]);
	}
	ring_buffer__free(ring);
	oom_watch_bpf__destroy(skel);
	if (demo_cgroup_created && rmdir(demo_cgroup_path) && !err)
		err = 1;
	if (memory_enabled_by_demo &&
	    write_text("/sys/fs/cgroup/cgroup.subtree_control", "-memory") &&
	    !err)
		err = 1;
	return err;
}
