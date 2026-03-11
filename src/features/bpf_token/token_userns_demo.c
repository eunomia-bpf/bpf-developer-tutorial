// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static struct env {
	bool verbose;
	bool no_trigger;
} env = {
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-v] [-n]\n"
		"  -v  enable verbose token_trace logs\n"
		"  -n  do not generate loopback traffic automatically\n",
		prog);
}

static int parse_args(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "vn")) != -1) {
		switch (opt) {
		case 'v':
			env.verbose = true;
			break;
		case 'n':
			env.no_trigger = true;
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

static inline int sys_fsopen(const char *fsname, unsigned flags)
{
	return syscall(__NR_fsopen, fsname, flags);
}

static inline int sys_fsconfig(int fs_fd, unsigned cmd, const char *key,
			       const void *val, int aux)
{
	return syscall(__NR_fsconfig, fs_fd, cmd, key, val, aux);
}

static inline int sys_fsmount(int fs_fd, unsigned flags, unsigned ms_flags)
{
	return syscall(__NR_fsmount, fs_fd, flags, ms_flags);
}

static ssize_t write_nointr(int fd, const void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = write(fd, buf, count);
	} while (ret < 0 && errno == EINTR);

	return ret;
}

static int write_file(const char *path, const void *buf, size_t count)
{
	int fd;
	ssize_t ret;

	fd = open(path, O_WRONLY | O_CLOEXEC | O_NOCTTY);
	if (fd < 0)
		return -errno;

	ret = write_nointr(fd, buf, count);
	close(fd);
	if (ret < 0)
		return -errno;
	if ((size_t)ret != count)
		return -EIO;

	return 0;
}

static int sendfd(int sockfd, int fd)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	int fds[1] = { fd };
	char iobuf[1] = { 0 };
	struct iovec io = {
		.iov_base = iobuf,
		.iov_len = sizeof(iobuf),
	};
	union {
		char buf[CMSG_SPACE(sizeof(fds))];
		struct cmsghdr align;
	} u = {};
	ssize_t ret;

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
	memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

	ret = sendmsg(sockfd, &msg, 0);
	if (ret < 0)
		return -errno;
	if (ret != 1)
		return -EIO;

	return 0;
}

static int recvfd(int sockfd, int *fd)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	int fds[1];
	char iobuf[1];
	struct iovec io = {
		.iov_base = iobuf,
		.iov_len = sizeof(iobuf),
	};
	union {
		char buf[CMSG_SPACE(sizeof(fds))];
		struct cmsghdr align;
	} u = {};
	ssize_t ret;

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);

	ret = recvmsg(sockfd, &msg, 0);
	if (ret < 0)
		return -errno;
	if (ret != 1)
		return -EIO;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg)
		return -EINVAL;
	if (cmsg->cmsg_len != CMSG_LEN(sizeof(fds)))
		return -EINVAL;
	if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
		return -EINVAL;

	memcpy(fds, CMSG_DATA(cmsg), sizeof(fds));
	*fd = fds[0];
	return 0;
}

static int create_and_enter_userns(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	char map[64];
	int err;

	if (unshare(CLONE_NEWUSER))
		return -errno;

	err = write_file("/proc/self/setgroups", "deny", sizeof("deny") - 1);
	if (err && err != -ENOENT)
		return err;

	snprintf(map, sizeof(map), "0 %d 1", uid);
	err = write_file("/proc/self/uid_map", map, strlen(map));
	if (err)
		return err;

	snprintf(map, sizeof(map), "0 %d 1", gid);
	err = write_file("/proc/self/gid_map", map, strlen(map));
	if (err)
		return err;

	if (setgid(0))
		return -errno;
	if (setuid(0))
		return -errno;

	return 0;
}

static int set_delegate_mask(int fs_fd, const char *key, const char *mask_str)
{
	int err;

	err = sys_fsconfig(fs_fd, FSCONFIG_SET_STRING, key, mask_str, 0);
	if (err < 0)
		return -errno;

	return 0;
}

static int set_loopback_up(void)
{
	struct ifreq ifr = {};
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "lo");
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		close(fd);
		return -errno;
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		close(fd);
		return -errno;
	}

	close(fd);
	return 0;
}

static void raise_memlock_limit(void)
{
	struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim))
		fprintf(stderr, "warning: failed to raise RLIMIT_MEMLOCK: %s\n",
			strerror(errno));
}

static int child_main(int sockfd)
{
	char ack;
	char token_path[64];
	int err, fs_fd = -1, mnt_fd = -1;

	err = create_and_enter_userns();
	if (err) {
		fprintf(stderr, "failed to create user namespace: %s\n",
			strerror(-err));
		return 1;
	}

	if (unshare(CLONE_NEWNS | CLONE_NEWNET)) {
		err = -errno;
		fprintf(stderr, "failed to create mount/net namespace: %s\n",
			strerror(errno));
		return 1;
	}

	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
		err = -errno;
		fprintf(stderr, "failed to remount / private: %s\n", strerror(errno));
		return 1;
	}

	err = set_loopback_up();
	if (err) {
		fprintf(stderr, "failed to bring loopback up: %s\n",
			strerror(-err));
		return 1;
	}

	fs_fd = sys_fsopen("bpf", 0);
	if (fs_fd < 0) {
		err = -errno;
		fprintf(stderr, "fsopen(\"bpf\") failed: %s\n", strerror(errno));
		return 1;
	}

	err = sendfd(sockfd, fs_fd);
	if (err) {
		fprintf(stderr, "failed to send bpffs fs_fd: %s\n", strerror(-err));
		goto out;
	}

	if (read(sockfd, &ack, 1) != 1) {
		fprintf(stderr, "failed to receive parent ack\n");
		err = -EIO;
		goto out;
	}

	mnt_fd = sys_fsmount(fs_fd, 0, 0);
	if (mnt_fd < 0) {
		err = -errno;
		fprintf(stderr, "fsmount() failed: %s\n", strerror(errno));
		goto out;
	}

	snprintf(token_path, sizeof(token_path), "/proc/self/fd/%d", mnt_fd);

	{
		const char *argv[10];
		int argc = 0;

		argv[argc++] = "./token_trace";
		if (env.verbose)
			argv[argc++] = "-v";
		if (env.no_trigger)
			argv[argc++] = "-n";
		argv[argc++] = "-t";
		argv[argc++] = token_path;
		argv[argc++] = "-i";
		argv[argc++] = "lo";
		argv[argc] = NULL;

		execv("./token_trace", (char *const *)argv);
	}

	err = -errno;
	fprintf(stderr, "failed to exec ./token_trace: %s\n", strerror(errno));

out:
	if (mnt_fd >= 0)
		close(mnt_fd);
	if (fs_fd >= 0)
		close(fs_fd);
	return 1;
}

int main(int argc, char **argv)
{
	static const char *delegate_cmds =
		"prog_load:map_create:btf_load:link_create";
	int err, socks[2] = { -1, -1 }, fs_fd = -1, status;
	pid_t pid;
	char ack = 1;

	err = parse_args(argc, argv);
	if (err) {
		usage(argv[0]);
		return 1;
	}

	if (geteuid() != 0) {
		fprintf(stderr, "run this demo with sudo/root so the parent can configure delegated bpffs\n");
		return 1;
	}

	if (access("./token_trace", X_OK) != 0) {
		fprintf(stderr, "missing ./token_trace, run 'make' in this directory first\n");
		return 1;
	}

	raise_memlock_limit();

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, socks)) {
		fprintf(stderr, "socketpair failed: %s\n", strerror(errno));
		return 1;
	}

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork failed: %s\n", strerror(errno));
		return 1;
	}

	if (pid == 0) {
		close(socks[0]);
		return child_main(socks[1]);
	}

	close(socks[1]);

	err = recvfd(socks[0], &fs_fd);
	if (err) {
		fprintf(stderr, "failed to receive bpffs fs_fd: %s\n", strerror(-err));
		goto out;
	}

	err = set_delegate_mask(fs_fd, "delegate_cmds", delegate_cmds);
	if (err) {
		fprintf(stderr, "failed to set delegate_cmds: %s\n", strerror(-err));
		goto out;
	}
	err = set_delegate_mask(fs_fd, "delegate_maps", "array");
	if (err) {
		fprintf(stderr, "failed to set delegate_maps: %s\n", strerror(-err));
		goto out;
	}
	err = set_delegate_mask(fs_fd, "delegate_progs", "xdp:socket_filter");
	if (err) {
		fprintf(stderr, "failed to set delegate_progs: %s\n", strerror(-err));
		goto out;
	}
	err = set_delegate_mask(fs_fd, "delegate_attachs", "any");
	if (err) {
		fprintf(stderr, "failed to set delegate_attachs: %s\n", strerror(-err));
		goto out;
	}

	if (sys_fsconfig(fs_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0) {
		err = -errno;
		fprintf(stderr, "failed to materialize bpffs: %s\n", strerror(errno));
		goto out;
	}

	if (write(socks[0], &ack, 1) != 1) {
		err = -errno;
		fprintf(stderr, "failed to send parent ack: %s\n", strerror(errno));
		goto out;
	}

	err = 0;

out:
	if (fs_fd >= 0)
		close(fs_fd);
	close(socks[0]);

	if (waitpid(pid, &status, 0) < 0) {
		fprintf(stderr, "waitpid failed: %s\n", strerror(errno));
		return 1;
	}

	if (err)
		return 1;
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status)) {
		fprintf(stderr, "child terminated by signal %d\n", WTERMSIG(status));
		return 1;
	}

	return 1;
}
