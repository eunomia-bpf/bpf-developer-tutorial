// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "dns_egress.h"
#include "dns_egress.skel.h"

#define DEMO_DNS_PORT 15353
#define DEMO_TCP_PORT 19090
#define DNS_ID 0x4b1d

struct options {
	const char *cgroup_path;
	const char *domain;
	const char *dns_server;
	unsigned int port;
	unsigned int dns_port;
	unsigned int duration_seconds;
	bool demo;
};

struct dns_runtime {
	struct dns_egress_bpf *skel;
	struct bpf_link *query_link;
	struct bpf_link *ingress_link;
	struct bpf_link *connect_link;
	struct ring_buffer *ring;
	int cgroup_fd;
};

static int event_counts[5];
static volatile sig_atomic_t stop;

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

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct dns_egress_event *event = data;
	char address[INET_ADDRSTRLEN];
	const char *name;

	(void)ctx;
	if (size != sizeof(*event) || event->type > DNS_EXPIRED)
		return 0;
	event_counts[event->type]++;
	inet_ntop(AF_INET, &event->ip4, address, sizeof(address));
	name = event->type == DNS_LEARNED ? "learned" :
	       event->type == DNS_ALLOWED ? "allowed" :
	       event->type == DNS_DENIED ? "denied" : "expired";
	printf("event=%s pid=%u ip=%s ttl=%u\n", name, event->pid, address,
	       event->ttl_seconds);
	return 0;
}

static int parse_uint(const char *text, unsigned int maximum,
		      unsigned int *value)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !*text || *end || parsed > maximum)
		return -1;
	*value = parsed;
	return 0;
}

static void usage(const char *program)
{
	printf("Usage: %s --cgroup PATH --domain NAME --dns-server IPV4 [--port PORT] [--dns-port PORT] [--duration SEC]\n"
	       "       %s --demo\n", program, program);
}

static int apply_option(int option, const char *program,
			struct options *options)
{
	switch (option) {
	case 'c': options->cgroup_path = optarg; return 0;
	case 'n': options->domain = optarg; return 0;
	case 'r': options->dns_server = optarg; return 0;
	case 'p':
		return parse_uint(optarg, 65535, &options->port) || !options->port ?
		       -1 : 0;
	case 's':
		return parse_uint(optarg, 65535, &options->dns_port) ||
		       !options->dns_port ? -1 : 0;
	case 'd':
		return parse_uint(optarg, 86400, &options->duration_seconds);
	case 'D': options->demo = true; return 0;
	case 'h': usage(program); exit(0);
	default: return -1;
	}
}

static int finish_options(struct options *options)
{
	if (!options->demo)
		return options->cgroup_path && options->domain &&
		       options->dns_server ? 0 : -1;
	if (options->cgroup_path || options->domain || options->dns_server)
		return -1;
	options->cgroup_path = "/sys/fs/cgroup";
	options->domain = "lab.test";
	options->dns_server = "127.0.0.1";
	options->port = DEMO_TCP_PORT;
	options->dns_port = DEMO_DNS_PORT;
	return 0;
}

static int parse_options(int argc, char **argv, struct options *options)
{
	static const struct option long_options[] = {
		{ "cgroup", required_argument, NULL, 'c' },
		{ "domain", required_argument, NULL, 'n' },
		{ "dns-server", required_argument, NULL, 'r' },
		{ "port", required_argument, NULL, 'p' },
		{ "dns-port", required_argument, NULL, 's' },
		{ "duration", required_argument, NULL, 'd' },
		{ "demo", no_argument, NULL, 'D' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int option;

	while ((option = getopt_long(argc, argv, "c:n:r:p:s:d:Dh", long_options,
				     NULL)) != -1)
		if (apply_option(option, argv[0], options))
			return -1;
	return optind == argc ? finish_options(options) : -1;
}

static int encode_qname(const char *domain, unsigned char output[DNS_QNAME_MAX],
			unsigned int *output_length)
{
	const char *label = domain;
	unsigned int used = 0;

	if (!*domain)
		return -1;
	while (*label) {
		const char *dot = strchr(label, '.');
		size_t length = dot ? (size_t)(dot - label) : strlen(label);

		if (!length || length > 63 || used + length + 2 > DNS_QNAME_MAX)
			return -1;
		output[used++] = length;
		memcpy(output + used, label, length);
		used += length;
		if (!dot)
			break;
		label = dot + 1;
		if (!*label)
			break;
	}
	output[used++] = 0;
	*output_length = used;
	return 0;
}

static int bind_udp(struct sockaddr_in *address)
{
	socklen_t length = sizeof(*address);
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	if (bind(fd, (struct sockaddr *)address, sizeof(*address)) ||
	    getsockname(fd, (struct sockaddr *)address, &length)) {
		close(fd);
		return -1;
	}
	return fd;
}

static int begin_dns_exchange(int server, int client,
			      struct sockaddr_in *server_address,
			      const unsigned char *qname,
			      unsigned int qname_length,
			      unsigned char message[512],
			      size_t *query_length,
			      struct sockaddr_in *client_address)
{
	struct dns_question question = {
		.type = htons(1),
		.class = htons(1),
	};
	struct dns_header *header = (void *)message;
	socklen_t address_length = sizeof(*client_address);
	ssize_t received;

	memset(message, 0, 512);
	header->id = htons(DNS_ID);
	header->flags = htons(0x0100);
	header->questions = htons(1);
	memcpy(message + sizeof(*header), qname, qname_length);
	memcpy(message + sizeof(*header) + qname_length, &question,
	       sizeof(question));
	*query_length = sizeof(*header) + qname_length + sizeof(question);
	if (sendto(client, message, *query_length, 0,
		   (struct sockaddr *)server_address, sizeof(*server_address)) !=
	    (ssize_t)*query_length)
		return -1;
	received = recvfrom(server, message, 512, 0,
			    (struct sockaddr *)client_address, &address_length);
	return received == (ssize_t)*query_length ? 0 : -1;
}

static int send_dns_answer(int server, int client,
			   struct sockaddr_in *client_address,
			   unsigned char message[512], size_t query_length,
			   unsigned short transaction_id,
			   unsigned int ttl_seconds)
{
	struct dns_a_answer answer = {
		.name = htons(0xc00c),
		.type = htons(1),
		.class = htons(1),
		.ttl = htonl(ttl_seconds),
		.address_length = htons(4),
	};
	struct dns_header *header = (void *)message;

	if (query_length + sizeof(answer) > 512)
		return -1;
	header->id = htons(transaction_id);
	header->flags = htons(0x8180);
	header->answers = htons(1);
	inet_pton(AF_INET, "127.0.0.1", &answer.address);
	memcpy(message + query_length, &answer, sizeof(answer));
	if (sendto(server, message, query_length + sizeof(answer), 0,
		   (struct sockaddr *)client_address, sizeof(*client_address)) !=
	    (ssize_t)(query_length + sizeof(answer)))
		return -1;
	return recv(client, message, 512, 0) ==
	       (ssize_t)(query_length + sizeof(answer)) ? 0 : -1;
}

static int send_unsolicited_dns(int server, int client,
				const unsigned char *qname,
				unsigned int qname_length)
{
	unsigned char message[512] = {};
	struct sockaddr_in client_address;
	struct dns_a_answer answer = {
		.name = htons(0xc00c),
		.type = htons(1),
		.class = htons(1),
		.ttl = htonl(30),
		.address_length = htons(4),
	};
	struct dns_question question = {
		.type = htons(1),
		.class = htons(1),
	};
	struct dns_header *header = (void *)message;
	socklen_t address_length = sizeof(client_address);
	size_t message_length;

	if (getsockname(client, (struct sockaddr *)&client_address,
			&address_length))
		return -1;
	header->id = htons(DNS_ID + 1);
	header->flags = htons(0x8180);
	header->questions = htons(1);
	header->answers = htons(1);
	memcpy(message + sizeof(*header), qname, qname_length);
	memcpy(message + sizeof(*header) + qname_length, &question,
	       sizeof(question));
	message_length = sizeof(*header) + qname_length + sizeof(question);
	inet_pton(AF_INET, "127.0.0.1", &answer.address);
	memcpy(message + message_length, &answer, sizeof(answer));
	message_length += sizeof(answer);
	if (sendto(server, message, message_length, 0,
		   (struct sockaddr *)&client_address, address_length) !=
	    (ssize_t)message_length)
		return -1;
	return recv(client, message, sizeof(message), 0) ==
	       (ssize_t)message_length ? 0 : -1;
}

static int create_tcp_listener(unsigned int port)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(port),
	};
	int one = 1;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) ||
	    listen(fd, 4)) {
		close(fd);
		return -1;
	}
	return fd;
}

static int connect_tcp(unsigned int port)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(port),
	};
	int saved_errno;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	if (!connect(fd, (struct sockaddr *)&address, sizeof(address)))
		return fd;
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return -1;
}

static int complete_tcp(int listener, int client)
{
	int accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
	char byte = 'x';
	int result = 0;

	if (accepted < 0) {
		close(client);
		return -1;
	}
	if (write(accepted, &byte, 1) != 1 || read(client, &byte, 1) != 1)
		result = -1;
	close(accepted);
	close(client);
	return result;
}

static int poll_demo_events(struct ring_buffer *ring)
{
	int result = ring_buffer__poll(ring, 100);

	return result < 0 && result != -EINTR ? -1 : 0;
}

static int expect_blocked_connect(struct ring_buffer *ring,
				  unsigned int port, const char *step)
{
	int client;

	errno = 0;
	client = connect_tcp(port);
	if (client >= 0) {
		close(client);
		return -1;
	}
	if (errno != EPERM || poll_demo_events(ring))
		return -1;
	printf("demo step=%s result=blocked\n", step);
	return 0;
}

static int expect_allowed_connect(struct ring_buffer *ring, int listener,
				  unsigned int port)
{
	int client = connect_tcp(port);

	if (client < 0 || complete_tcp(listener, client))
		return -1;
	if (poll_demo_events(ring))
		return -1;
	printf("demo step=live-answer result=allowed\n");
	return 0;
}

static int expected_demo_events(void)
{
	return event_counts[DNS_LEARNED] == 1 &&
	       event_counts[DNS_ALLOWED] == 1 &&
	       event_counts[DNS_DENIED] == 4 &&
	       event_counts[DNS_EXPIRED] == 1 ? 0 : -1;
}

struct demo_context {
	struct sockaddr_in server_address;
	struct sockaddr_in response_client_address;
	unsigned char dns_message[512];
	size_t query_length;
	int dns_server;
	int dns_client;
	int listener;
};

static int open_demo_sockets(struct demo_context *demo,
			     const struct options *options)
{
	struct sockaddr_in client_address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};

	demo->server_address = (struct sockaddr_in) {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(options->dns_port),
	};
	demo->dns_server = bind_udp(&demo->server_address);
	demo->dns_client = bind_udp(&client_address);
	demo->listener = create_tcp_listener(options->port);
	return demo->dns_server < 0 || demo->dns_client < 0 || demo->listener < 0 ?
		-1 : 0;
}

static int test_rejected_dns_answers(struct ring_buffer *ring,
				     const struct options *options,
				     const unsigned char *qname,
				     unsigned int qname_length,
				     struct demo_context *demo)
{
	if (expect_blocked_connect(ring, options->port, "before-dns"))
		return -1;
	if (send_unsolicited_dns(demo->dns_server, demo->dns_client, qname,
				   qname_length) ||
	    poll_demo_events(ring) ||
	    expect_blocked_connect(ring, options->port,
				   "unsolicited-response"))
		return -1;
	if (begin_dns_exchange(demo->dns_server, demo->dns_client,
			       &demo->server_address, qname, qname_length,
			       demo->dns_message, &demo->query_length,
			       &demo->response_client_address) ||
	    send_dns_answer(demo->dns_server, demo->dns_client,
			    &demo->response_client_address, demo->dns_message,
			    demo->query_length, DNS_ID + 1, 30) ||
	    poll_demo_events(ring) ||
	    expect_blocked_connect(ring, options->port, "wrong-transaction-id"))
		return -1;
	return 0;
}

static int test_live_and_expired_answer(struct ring_buffer *ring,
					const struct options *options,
					struct demo_context *demo)
{
	struct timespec wait_time = { .tv_sec = 1, .tv_nsec = 300000000 };

	if (send_dns_answer(demo->dns_server, demo->dns_client,
			    &demo->response_client_address, demo->dns_message,
			    demo->query_length, DNS_ID, 1) ||
	    poll_demo_events(ring) ||
	    expect_allowed_connect(ring, demo->listener, options->port))
		return -1;
	nanosleep(&wait_time, NULL);
	if (poll_demo_events(ring) ||
	    expect_blocked_connect(ring, options->port, "expired-answer"))
		return -1;
	return expected_demo_events();
}

static void close_demo_sockets(struct demo_context *demo)
{
	if (demo->listener >= 0)
		close(demo->listener);
	if (demo->dns_client >= 0)
		close(demo->dns_client);
	if (demo->dns_server >= 0)
		close(demo->dns_server);
}

static int run_demo(struct ring_buffer *ring, const struct options *options,
		    const unsigned char *qname, unsigned int qname_length)
{
	struct demo_context demo = {
		.dns_server = -1,
		.dns_client = -1,
		.listener = -1,
	};
	int err;

	err = open_demo_sockets(&demo, options);
	if (!err)
		err = test_rejected_dns_answers(ring, options, qname,
						qname_length, &demo);
	if (!err)
		err = test_live_and_expired_answer(ring, options, &demo);
	close_demo_sockets(&demo);
	return err;
}

static bool link_failed(struct bpf_link **link)
{
	if (!libbpf_get_error(*link))
		return false;
	*link = NULL;
	return true;
}

static int prepare_runtime(struct dns_runtime *runtime,
			   const struct options *options,
			   const struct in_addr *dns_server,
			   const unsigned char *qname,
			   unsigned int qname_length)
{
	bool failed;

	runtime->cgroup_fd = open(options->cgroup_path,
				  O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (runtime->cgroup_fd < 0) {
		fprintf(stderr, "failed to open cgroup %s: %s\n",
			options->cgroup_path, strerror(errno));
		return -1;
	}
	runtime->skel = dns_egress_bpf__open();
	if (!runtime->skel)
		return -1;
	runtime->skel->rodata->target_tgid = options->demo ? getpid() : 0;
	runtime->skel->rodata->dns_server_ip = dns_server->s_addr;
	runtime->skel->rodata->dns_server_port = options->dns_port;
	runtime->skel->rodata->protected_tcp_port = options->port;
	runtime->skel->rodata->configured_qname_length = qname_length;
	memcpy((void *)runtime->skel->rodata->configured_qname, qname,
	       qname_length);
	if (dns_egress_bpf__load(runtime->skel)) {
		fprintf(stderr, "failed to load DNS egress BPF programs\n");
		return -1;
	}
	runtime->query_link = bpf_program__attach_cgroup(
		runtime->skel->progs.record_dns_query, runtime->cgroup_fd);
	runtime->ingress_link = bpf_program__attach_cgroup(
		runtime->skel->progs.learn_dns_answer, runtime->cgroup_fd);
	runtime->connect_link = bpf_program__attach_cgroup(
		runtime->skel->progs.enforce_dns_policy, runtime->cgroup_fd);
	failed = link_failed(&runtime->query_link);
	failed |= link_failed(&runtime->ingress_link);
	failed |= link_failed(&runtime->connect_link);
	if (failed) {
		fprintf(stderr, "failed to attach programs to cgroup %s\n",
			options->cgroup_path);
		return -1;
	}
	runtime->ring = ring_buffer__new(
		bpf_map__fd(runtime->skel->maps.events), handle_event, NULL, NULL);
	return runtime->ring ? 0 : -1;
}

static int poll_policy_events(struct ring_buffer *ring,
			      unsigned int duration_seconds)
{
	unsigned long long deadline = 0;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	if (duration_seconds)
		deadline = monotonic_ns() +
			   (unsigned long long)duration_seconds * 1000000000ULL;
	while (!stop && (!deadline || monotonic_ns() < deadline)) {
		int result = ring_buffer__poll(ring, 100);

		if (result < 0 && result != -EINTR) {
			fprintf(stderr, "ring buffer poll failed: %d\n", result);
			return -1;
		}
	}
	return 0;
}

static void destroy_runtime(struct dns_runtime *runtime)
{
	ring_buffer__free(runtime->ring);
	bpf_link__destroy(runtime->connect_link);
	bpf_link__destroy(runtime->ingress_link);
	bpf_link__destroy(runtime->query_link);
	if (runtime->cgroup_fd >= 0)
		close(runtime->cgroup_fd);
	dns_egress_bpf__destroy(runtime->skel);
}

int main(int argc, char **argv)
{
	struct options options = { .port = 443, .dns_port = 53 };
	struct dns_runtime runtime = { .cgroup_fd = -1 };
	struct in_addr dns_server = {};
	unsigned char qname[DNS_QNAME_MAX] = {};
	unsigned int qname_length = 0;
	int err = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (parse_options(argc, argv, &options) ||
	    encode_qname(options.domain, qname, &qname_length) ||
	    inet_pton(AF_INET, options.dns_server, &dns_server) != 1) {
		usage(argv[0]);
		return 2;
	}
	if (prepare_runtime(&runtime, &options, &dns_server, qname,
			    qname_length))
		goto cleanup;

	printf("dns-egress attached cgroup=%s domain=%s resolver=%s tcp_port=%u dns_port=%u\n",
	       options.cgroup_path, options.domain, options.dns_server,
	       options.port, options.dns_port);
	if (options.demo) {
		if (run_demo(runtime.ring, &options, qname, qname_length))
			goto cleanup;
	} else if (poll_policy_events(runtime.ring, options.duration_seconds))
		goto cleanup;
	err = 0;

cleanup:
	destroy_runtime(&runtime);
	return err;
}
