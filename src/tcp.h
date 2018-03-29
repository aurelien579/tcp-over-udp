#ifndef TCP_H
#define TCP_H

#include "tcp-buffer.h"
#include "send.h"

#include <netinet/in.h>

#define MAX_DATA    20

/* Packet flags */
#define F_PACKET_ACK 1
#define F_PACKET_SYN (1 << 1)

struct tcp_packet
{
    uint8_t flags;
    uint16_t seq;
    uint16_t ack;
    uint8_t data[MAX_DATA];
} __attribute__((packed));


#define PACKET_SIZE(data_size)  (sizeof(uint8_t) + 2*sizeof(uint16_t) + data_size)
#define DATA_SIZE(packet_size)  (packet_size - sizeof(uint8_t) - 2*sizeof(uint16_t))

struct tcp_socket
{
    int fd;
    uint8_t flags;
    uint16_t next_recv_seq;
    
    /* Send parameters */
    uint16_t snd_nxt;
    uint16_t snd_una;
    uint16_t snd_wnd;
    
    struct tcp_buffer *buffer;
    struct buffer *snd_buf;
};

struct tcp_socket *tcp_socket(int reuseaddr);

void tcp_connect(struct tcp_socket *sock, struct sockaddr_in *addr);
struct tcp_socket *tcp_accept(struct tcp_socket *sock, struct sockaddr_in *addr);

ssize_t tcp_recv(struct tcp_socket *sock, char *buffer, size_t sz);
ssize_t tcp_send(struct tcp_socket *sock, const char *buffer, size_t sz);

#endif
