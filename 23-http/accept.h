#ifndef BPF_HTTP_ACCEPT_TRACE_H
#define BPF_HTTP_ACCEPT_TRACE_H

#define MAX_MSG_SIZE 256

struct socket_data_event_t
{
  unsigned long long timestamp_ns;
  unsigned int pid;
  int fd;
  bool is_connection;
  unsigned int msg_size;
  unsigned long long pos;
  char msg[MAX_MSG_SIZE];
};

#endif // BPF_HTTP_ACCEPT_TRACE_H
