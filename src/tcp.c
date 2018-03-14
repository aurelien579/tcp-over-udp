#include "tcp.h"
#include "tcp-log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define MAX_SOCKETS 20

/* Packet flags */
#define F_PACKET_ACK 1
#define F_PACKET_SYN (1 << 1)

/* Socket flags */
#define F_SOCKET_MUST_ACK   1


#define IS_SET(val, bit)        (val & bit)

#define PACKET_SIZE(data_size)  (sizeof(uint8_t) + data_size)
#define DATA_SIZE(packet_size)  (packet_size - sizeof(uint8_t))

static struct tcp_socket sockets[MAX_SOCKETS];
static size_t sockets_count = 0;

static ssize_t
tcp_send_packet(struct tcp_socket *sock, struct tcp_packet *packet, size_t data_sz)
{
    return send(sock->fd, packet, PACKET_SIZE(data_sz), 0);
}

static ssize_t
tcp_recv_packet(struct tcp_socket *sock, struct tcp_packet *packet)
{
    tcp_log("Receiving...");
    return recv(sock->fd, packet, sizeof(struct tcp_packet), 0);
}

static ssize_t
tcp_recv_packet_from(struct tcp_socket *sock, struct tcp_packet *packet, struct sockaddr_in *addr)
{
    socklen_t addrlen = sizeof(struct sockaddr_in);
    return recvfrom(sock->fd, packet, sizeof(struct tcp_packet), 0,
                    (struct sockaddr *) addr, &addrlen);
}

static int
tcp_recv_syn(struct tcp_socket *sock, struct tcp_packet *packet, struct sockaddr_in *addr)
{
    ssize_t sz;

    do {
        sz = tcp_recv_packet_from(sock, packet, addr);

        if (sz < 0) return -1;
    } while (!IS_SET(packet->flags, F_PACKET_SYN));

    return 0;
}

static int
tcp_associate_socket(struct tcp_socket *sock, struct sockaddr_in *addr)
{
    return connect(sock->fd, (struct sockaddr *) addr, sizeof(struct sockaddr_in));
}

static int
tcp_disassociate_socket(struct tcp_socket *sock)
{
    struct sockaddr_in addr;
    addr.sin_family = AF_UNSPEC;
    return tcp_associate_socket(sock, &addr);
}

static struct tcp_socket *
tcp_socket_new(int fd)
{
    struct tcp_socket *sock;
    
    if (sockets_count >= MAX_SOCKETS) {
        tcp_log_error("No more socket available");
        return NULL;
    }
    
    sock = &sockets[sockets_count++];
    memset(sock, 0, sizeof(struct tcp_socket));
    sock->fd = fd;
    
    return sock;
}

static struct tcp_socket *
tcp_create_socket(struct sockaddr_in *peeraddr, unsigned short *newport)
{
    struct sockaddr_in localaddr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct tcp_socket *sock;
    
    sock = tcp_socket(1);
    
    if (!sock) return NULL;

    /* Bind new socket to no address so a random port is actually bound */
    memset(&localaddr, 0, addrlen);
    localaddr.sin_family = AF_INET;
    
    if (bind(sock->fd, (struct sockaddr *) &localaddr, addrlen) < 0) {
        close(sock->fd);
        return NULL;
    }
    
    if (getsockname(sock->fd, (struct sockaddr *) &localaddr, &addrlen) < 0) {
        close(sock->fd);
        return NULL;
    }
    
    *newport = localaddr.sin_port;

    if (tcp_associate_socket(sock, peeraddr) < 0) {
        close(sock->fd);
        return NULL;
    }

    return sock;
}



struct tcp_socket *
tcp_socket(int reuseaddr)
{
    int fd, yes = 1;
        
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return NULL;
    }

    if (reuseaddr) {
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    }
    
    return tcp_socket_new(fd);
}

void
tcp_connect(struct tcp_socket *sock, struct sockaddr_in *addr)
{
    struct tcp_packet recv_packet, send_packet;
    ssize_t sz;
    unsigned short newport;

    if (tcp_associate_socket(sock, addr) < 0) {
        tcp_log_errno("tcp_associate_socket in tcp_connect");
        return;
    }

    /* Send first SYN */
    send_packet.flags = F_PACKET_SYN;
    sz = tcp_send_packet(sock, &send_packet, 0);
    if (sz < 0) {
        tcp_log_errno("tcp_send_packet in tcp_connect");
        return;
    }
    tcp_log("SYN sent");


    /* Receive SYN packet */
    recv_packet.flags = 0;
    if (tcp_recv_syn(sock, &recv_packet, addr) < 0) {
        tcp_log_errno("tcp_recv_syn in tcp_connect");
        return;
    }
    
    if (!IS_SET(recv_packet.flags, F_PACKET_ACK)) {
        tcp_log_error("ACK not present in tcp_connect");
        return;
    }
    
    newport = *((unsigned short *) recv_packet.data);
    
    tcp_log("SYN + ACK received");


    /* ACK the received SYN */
    send_packet.flags = F_PACKET_ACK;
    sz = tcp_send_packet(sock, &send_packet, 0);
    if (sz < 0) {
        tcp_log_errno("tcp_send_packet in tcp_connect");
        return;
    }
    tcp_log("ACK sent");
    
    /* Associate the socket with the new server port */
    addr->sin_port = newport;
    if (tcp_associate_socket(sock, addr) < 0) {
        tcp_log_errno("tcp_associate_socket to newport in tcp_connect");
        return;
    }
}

/*
 * TODO: Handle simultaneous connections
 */
struct tcp_socket *
tcp_accept(struct tcp_socket *sock, struct sockaddr_in *peer_addr)
{
    struct tcp_packet packet;
    ssize_t sz;
    struct tcp_socket *new_sock;
    unsigned short newport;

    /* Receive the SYN */
    if (tcp_recv_syn(sock, &packet, peer_addr) < 0) {
        tcp_log_errno("tcp_recv_syn in tcp_accept");
        return NULL;
    }
    tcp_log("SYN received");

    /* Associate the socket to the sender of the SYN */
    if (tcp_associate_socket(sock, peer_addr) < 0) {
        tcp_log_errno("tcp_associate_socket in tcp_accept");
        return NULL;
    }
    
    /* Create a new socket bound on random port */
    new_sock = tcp_create_socket(peer_addr, &newport);
    if (!new_sock) {
        tcp_log_errno("tcp_create_socket in tcp_accept");
        return NULL;
    }
    
    /* Send SYN + ACK with new port in data */
    packet.flags = F_PACKET_SYN | F_PACKET_ACK;
    *((short *) packet.data) = newport;
    
    sz = tcp_send_packet(sock, &packet, sizeof(short));
    if (sz < 0) {
        tcp_log_errno("tcp_send_packet in tcp_accept");
        return NULL;
    }
    tcp_log("SYN + ACK sent");


    /* Receive the ACK */
    sz = tcp_recv_packet(sock, &packet);
    if (sz < 0) {
        tcp_log_errno("tcp_recv_packet in tcp_accept");
        return NULL;
    }

    tcp_log("ACK received");

    /* Disasociate the socket for future connections */
    if (tcp_disassociate_socket(sock) < 0) {
        tcp_log_errno("tcp_disassociate_socket in tcp_accept");
        return NULL;
    }

    return new_sock;
}

ssize_t
tcp_send(struct tcp_socket *sock, const char *buffer, size_t sz)
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
        sent_sz = tcp_send_packet(sock, &packet, sent_sz);
        
        if (sent_sz < 0) {
            return total_sz;
        }
        
        total_sz += DATA_SIZE(sent_sz);
        sz -= DATA_SIZE(sent_sz);
    }
    
    return sent_sz;
}

ssize_t
tcp_recv(struct tcp_socket *sock, char *buffer, size_t sz)
{
    struct tcp_packet packet;
    ssize_t recv_sz;
    
    recv_sz = tcp_recv_packet(sock, &packet);
    
    if (recv_sz > 0) {
        if (sz < recv_sz)
            memcpy(buffer, packet.data, sz);
        else
            memcpy(buffer, packet.data, recv_sz);
    }
    
    return sz;
}
