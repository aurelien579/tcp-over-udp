#ifndef TCP_H
#define TCP_H

#include "tcp-buffer.h"

#include <netinet/in.h>

#define MAX_DATA    20

struct tcp_packet
{
    uint8_t flags;
    uint16_t seq;
    uint16_t ack;
    uint8_t data[MAX_DATA];
} __attribute__((packed));

struct tcp_socket
{
    int fd;
    uint8_t flags;
    uint16_t next_recv_seq;
    uint16_t next_send_seq;
    struct tcp_buffer *buffer;
};

struct tcp_socket *tcp_socket(int reuseaddr);

void tcp_connect(struct tcp_socket *sock, struct sockaddr_in *addr);
struct tcp_socket *tcp_accept(struct tcp_socket *sock, struct sockaddr_in *addr);

ssize_t tcp_recv(struct tcp_socket *sock, char *buffer, size_t sz);
ssize_t tcp_send(struct tcp_socket *sock, const char *buffer, size_t sz);

#endif
