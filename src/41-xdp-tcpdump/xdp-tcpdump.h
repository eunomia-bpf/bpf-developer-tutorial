#ifndef __XDP_TCPDUMP_H
#define __XDP_TCPDUMP_H

#define MAX_TCP_HEADER_BYTES 60

struct tcp_event {
    unsigned int header_len;
    unsigned char header[MAX_TCP_HEADER_BYTES];
};

#endif /* __XDP_TCPDUMP_H */
