#ifndef TCP_H
#define TCP_H

#include "buffer.h"
#include "segment.h"
#include "send.h"

#include <netinet/in.h>

#define IS_SET(val, bit)        (val & bit)


#define MAX_DATA    20

/* Packet flags */
#define F_PACKET_ACK 1
#define F_PACKET_SYN (1 << 1)
#define F_PACKET_FIN (1 << 2)

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
    int             fd;
    uint8_t         flags;
    
    /* Recv parameters */
    uint16_t        irs;        /* Initial receive sequence # */
    uint16_t        rcv_nxt;    /* Next sequence number to send */
    struct seglist *rcv_segs;   /* Received segments, used for reordering */
    struct buffer  *rcv_buf;
    
    /* Send parameters */
    uint16_t        snd_nxt;    /* Next sequence # to send */
    uint16_t        snd_una;    /* First unacknowledge sequence # */
    uint16_t        snd_wnd;    /* Send window size */
    struct buffer  *snd_buf;
};

struct tcp_socket *tcp_socket(int reuseaddr);
void tcp_close(struct tcp_socket *s);

void tcp_connect(struct tcp_socket *s, struct sockaddr_in *addr);
struct tcp_socket *tcp_accept(struct tcp_socket *s, struct sockaddr_in *addr);

ssize_t tcp_recv(struct tcp_socket *s, char *buffer, size_t sz);
ssize_t tcp_send(struct tcp_socket *s, const char *buffer, size_t sz);

#endif
