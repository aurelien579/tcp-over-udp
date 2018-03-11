#include "tcp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define MAX_DATA    2

#define ACK 1
#define SYN (1 << 1)

#define IS_SET(val, bit)        (val & bit)

#define PACKET_SIZE(data_size)  (sizeof(uint8_t) + data_size)
#define DATA_SIZE(packet_size)  (packet_size - sizeof(uint8_t))

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
tcp_send_packet(int fd, struct tcp_packet *packet, size_t data_sz)
{
    return send(fd, packet, PACKET_SIZE(data_sz), 0);
}

static ssize_t
tcp_recv_packet(int fd, struct tcp_packet *packet)
{
    tcp_log("Receiving...");
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
tcp_create_socket(struct sockaddr_in *peeraddr, unsigned short *newport)
{
    struct sockaddr_in localaddr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    int fd;
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    /* Bind new socket to no address so a random port is actually bound */
    memset(&localaddr, 0, addrlen);
    localaddr.sin_family = AF_INET;
    
    if (bind(fd, (struct sockaddr *) &localaddr, addrlen) < 0) {
        close(fd);
        return -1;
    }
    
    if (getsockname(fd, (struct sockaddr *) &localaddr, &addrlen) < 0) {
        close(fd);
        return -1;
    }
    
    *newport = localaddr.sin_port;

    if (tcp_associate_socket(fd, peeraddr) < 0) {
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
    unsigned short newport;

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
    
    if (!IS_SET(recv_packet.flags, ACK)) {
        tcp_log_error("ACK not present in tcp_connect");
        return;
    }
    
    newport = *((unsigned short *) recv_packet.data);
    
    tcp_log("SYN + ACK received");


    /* ACK the received SYN */
    send_packet.flags = ACK;
    sz = tcp_send_packet(fd, &send_packet, 0);
    if (sz < 0) {
        tcp_log_errno("tcp_send_packet in tcp_connect");
        return;
    }
    tcp_log("ACK sent");
    
    /* Associate the socket with the new server port */
    addr->sin_port = newport;
    if (tcp_associate_socket(fd, addr) < 0) {
        tcp_log_errno("tcp_associate_socket to newport in tcp_connect");
        return;
    }
}

/*
 * TODO: Handle simultaneous connections
 */
int
tcp_accept(int fd, struct sockaddr_in *peer_addr)
{
    struct tcp_packet packet;
    ssize_t sz;
    int newfd;
    unsigned short newport;

    /* Receive the SYN */
    if (tcp_recv_syn(fd, &packet, peer_addr) < 0) {
        tcp_log_errno("tcp_recv_syn in tcp_accept");
        return -1;
    }
    tcp_log("SYN received");

    /* Associate the socket to the sender of the SYN */
    if (tcp_associate_socket(fd, peer_addr) < 0) {
        tcp_log_errno("tcp_associate_socket in tcp_accept");
        return -1;
    }
    
    /* Create a new socket bound on random port */
    newfd = tcp_create_socket(peer_addr, &newport);
    if (newfd < 0) {
        tcp_log_errno("tcp_create_socket in tcp_accept");
        return -1;
    }
    
    /* Send SYN + ACK with new port in data */
    packet.flags = SYN | ACK;
    *((short *) packet.data) = newport;
    
    sz = tcp_send_packet(fd, &packet, sizeof(short));
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

    return newfd;
}

ssize_t
tcp_send(int fd, const char *buffer, size_t sz)
{
    struct tcp_packet packet;
    size_t total_sz = 0;
    ssize_t sent_sz;
    
    while (sz > 0) {
        if (sz > MAX_DATA) {
            sent_sz = MAX_DATA;
        } else {
            sent_sz = sz;
        }
        
        memcpy(packet.data, buffer + total_sz, sent_sz);
        sent_sz = tcp_send_packet(fd, &packet, sent_sz);
        
        if (sent_sz < 0) {
            return total_sz;
        }
        
        total_sz += DATA_SIZE(sent_sz);
        sz -= DATA_SIZE(sent_sz);
    }
    
    return sent_sz;
}

ssize_t
tcp_recv(int fd, char *buffer, size_t sz)
{
    struct tcp_packet packet;
    ssize_t recv_sz;
    
    recv_sz = tcp_recv_packet(fd, &packet);
    
    if (recv_sz > 0) {
        if (sz < recv_sz)
            memcpy(buffer, packet.data, sz);
        else
            memcpy(buffer, packet.data, recv_sz);
    }
    
    return sz;
}
