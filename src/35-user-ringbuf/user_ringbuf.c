// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "user_ringbuf.h"
#include "user_ringbuf.skel.h"

static void drain_current_samples(void)
{
	printf("Draining current samples...\n");
}

static int write_samples(struct user_ring_buffer *ringbuf)
{
	int i, err = 0;
	struct user_sample *entry;

	entry = user_ring_buffer__reserve(ringbuf, sizeof(*entry));
	if (!entry)
	{
		err = -errno;
		goto done;
	}

	entry->i = getpid();
	strcpy(entry->comm, "hello");

	int read = snprintf(entry->comm, sizeof(entry->comm), "%u", i);
	if (read <= 0)
	{
		/* Assert on the error path to avoid spamming logs with
		 * mostly success messages.
		 */
		err = read;
		user_ring_buffer__discard(ringbuf, entry);
		goto done;
	}

	user_ring_buffer__submit(ringbuf, entry);

done:
	drain_current_samples();

	return err;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

struct user_ring_buffer *user_ringbuf = NULL;

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-5s %-16s %-7d\n",
		   ts, "SIGN", e->comm, e->pid);
	write_samples(user_ringbuf);
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct user_ringbuf_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = user_ringbuf_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	skel->bss->read = 0;

	/* Load & verify BPF programs */
	err = user_ringbuf_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = user_ringbuf_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.kernel_ringbuf), handle_event, NULL, NULL);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	user_ringbuf = user_ring_buffer__new(bpf_map__fd(skel->maps.user_ringbuf), NULL);

	write_samples(user_ringbuf);

	/* Process events */
	printf("%-8s %-5s %-16s %-7s %-7s %s\n",
		   "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT CODE");
	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	user_ringbuf_bpf__destroy(skel);
	user_ring_buffer__free(user_ringbuf);

	return err < 0 ? -err : 0;
}
