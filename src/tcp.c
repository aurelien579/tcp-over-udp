#include "tcp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define MAX_DATA    512

#define ACK 1
#define SYN (1 << 1)

#define IS_SET(val, bit)        (val & bit)

#define PACKET_SIZE(data_size)  (sizeof(uint8_t) + data_size)

struct tcp_packet
{
    uint8_t flags;
    char data[MAX_DATA];
} __attribute__((packed));

static inline void
tcp_log_error(const char *msg)
{
    fprintf(stderr, "[TCP] [ERROR] %s\n", msg);
}

static inline void
tcp_log_errno(const char *msg)
{
    fprintf(stderr, "[TCP] [ERROR] %s : %s\n", msg, strerror(errno));
}

static inline void
tcp_log(const char *msg)
{
    printf("[TCP] [INFO ] %s\n", msg);
}

static inline void
tcp_dump_packet(const struct tcp_packet *packet)
{
    printf("Packet : 0x%x\n", packet->flags);
}

static ssize_t
tcp_send_packet(int fd, struct tcp_packet *packet, size_t sz)
{
    return send(fd, packet, PACKET_SIZE(sz), 0);
}

static ssize_t
tcp_recv_packet(int fd, struct tcp_packet *packet)
{
    return recv(fd, packet, sizeof(struct tcp_packet), 0);
}

static ssize_t
tcp_recv_packet_from(int fd, struct tcp_packet *packet, struct sockaddr_in *addr)
{
    socklen_t addrlen = sizeof(struct sockaddr_in);
    return recvfrom(fd, packet, sizeof(struct tcp_packet), 0,
                    (struct sockaddr *) addr, &addrlen);
}

static int
tcp_recv_syn(int fd, struct tcp_packet *packet, struct sockaddr_in *addr)
{
    ssize_t sz;

    do {
        sz = tcp_recv_packet_from(fd, packet, addr);

        if (sz < 0) return -1;
    } while (!IS_SET(packet->flags, SYN));

    return 0;
}

static int
tcp_associate_socket(int fd, struct sockaddr_in *addr)
{
    return connect(fd, (struct sockaddr *) addr, sizeof(struct sockaddr_in));
}

static int
tcp_disassociate_socket(int fd)
{
    struct sockaddr_in addr;
    addr.sin_family = AF_UNSPEC;
    return tcp_associate_socket(fd, &addr);
}

static int
tcp_create_socket(struct sockaddr_in *addr)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    if (tcp_associate_socket(fd, addr) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}



void
tcp_connect(int fd, struct sockaddr_in *addr)
{
    struct tcp_packet recv_packet, send_packet;
    ssize_t sz;

    if (tcp_associate_socket(fd, addr) < 0) {
        tcp_log_errno("tcp_associate_socket in tcp_connect");
        return;
    }

    /* Send first SYN */
    send_packet.flags = SYN;
    sz = tcp_send_packet(fd, &send_packet, 0);
    if (sz < 0) {
        tcp_log_errno("tcp_send_packet in tcp_connect");
        return;
    }
    tcp_log("SYN sent");


    /* Receive SYN packet */
    recv_packet.flags = 0;
    if (tcp_recv_syn(fd, &recv_packet, addr) < 0) {
        tcp_log_errno("tcp_recv_syn in tcp_connect");
        return;
    }
    tcp_log("SYN received");


    /* ACK the received SYN */
    send_packet.flags = ACK;
    sz = tcp_send_packet(fd, &send_packet, 0);
    if (sz < 0) {
        tcp_log_errno("tcp_send_packet in tcp_connect");
        return;
    }
    tcp_log("ACK sent");


    /* Wait for the ACK if not already received */
    if (!IS_SET(recv_packet.flags, ACK)) {
        tcp_log("ACK was not present receiving it...");
        printf("flags : 0x%x\n", recv_packet.flags);

        recv_packet.flags = 0;
        sz = tcp_recv_packet(fd, &recv_packet);
        if (sz < 0) {
            tcp_log_errno("tcp_recv_packet in tcp_connect");
        }

        if (!IS_SET(recv_packet.flags, ACK)) {
            tcp_log_error("recv_packet does not have ACK flag in tcp_connect");
        }

        tcp_log("ACK received");
    }
}

/*
 * TODO: Handle simultaneous connections
 */
int
tcp_accept(int fd, struct sockaddr_in *addr)
{
    struct tcp_packet packet;
    ssize_t sz;

    /* Receive the SYN */
    if (tcp_recv_syn(fd, &packet, addr) < 0) {
        tcp_log_errno("tcp_recv_syn in tcp_accept");
        return -1;
    }
    tcp_log("SYN received");

    /* Associate the socket to the sender of the SYN */
    if (tcp_associate_socket(fd, addr) < 0) {
        tcp_log_errno("tcp_associate_socket in tcp_accept");
        return -1;
    }

    /* Send SYN + ACK */
    packet.flags = SYN | ACK;
    sz = tcp_send_packet(fd, &packet, 0);
    if (sz < 0) {
        tcp_log_errno("tcp_send_packet in tcp_accept");
        return -1;
    }
    tcp_log("SYN + ACK sent");


    /* Receive the ACK */
    sz = tcp_recv_packet(fd, &packet);
    if (sz < 0) {
        tcp_log_errno("tcp_recv_packet in tcp_accept");
        return -1;
    }

    tcp_log("ACK received");

    /* Disasociate the socket for future connections */
    if (tcp_disassociate_socket(fd) < 0) {
        tcp_log_errno("tcp_disassociate_socket in tcp_accept");
        return -1;
    }

    return tcp_create_socket(addr);
}
