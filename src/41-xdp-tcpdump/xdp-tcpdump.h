#ifndef XDP_TCPDUMP_H_
#define XDP_TCPDUMP_H_

#define MAX_TCP_HEADER_BYTES 60

struct tcp_event {
    unsigned int header_len;
    unsigned char header[MAX_TCP_HEADER_BYTES];
};

#endif /* XDP_TCPDUMP_H_ */
