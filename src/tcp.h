#ifndef TCP_H
#define TCP_H

#include "buffer.h"
#include "segment.h"
#include "send.h"
#include "types.h"

#include <netinet/in.h>

#define IS_SET(val, bit)        (val & bit)


#define MAX_DATA    20

/* Packet flags */
#define F_PACKET_ACK 1
#define F_PACKET_SYN (1 << 1)
#define F_PACKET_FIN (1 << 2)

struct tcp_packet
{
    u8      flags;
    u16     seq;
    u16     ack;
    u8      data[MAX_DATA];
} __attribute__((packed));


#define PACKET_SIZE(data_size)  (sizeof(u8) + 2*sizeof(u16) + data_size)
#define DATA_SIZE(packet_size)  (packet_size - sizeof(u8) - 2*sizeof(u16))

struct tcp_socket
{
    int         fd;
    u8          flags;

    /* Recv parameters */
    u16         irs;        /* Initial receive sequence # */
    u16         rcv_nxt;    /* Next sequence number to send */
    SegList    *rcv_segs;   /* Received segments, used for reordering */
    Buffer     *rcv_buf;

    /* Send parameters */
    u16         snd_nxt;    /* Next sequence # to send */
    u16         snd_una;    /* First unacknowledge sequence # */
    u16         snd_wnd;    /* Send window size */
    Buffer     *snd_buf;
};

typedef struct tcp_socket Socket;
typedef struct tcp_packet Packet;

Socket *tcp_socket(int reuseaddr);
void tcp_close(Socket *s);

void tcp_connect(Socket *s, struct sockaddr_in *addr);
Socket *tcp_accept(Socket *s, struct sockaddr_in *addr);

ssize_t tcp_recv(Socket *s, char *buffer, size_t sz);
ssize_t tcp_send(Socket *s, const char *buffer, size_t sz);

#endif
