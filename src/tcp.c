#include "tcp.h"
#include "log.h"
#include "buffer.h"
#include "segment.h"
#include "send.h"
#include "recv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define MAX_SOCKETS 20

#if LOG_LEVEL > LOG_DEBUG
    #define DEBUG(...)   tcp_log("TCP", __VA_ARGS__);
#else
    #define DEBUG(...)
#endif

#if LOG_LEVEL > ERROR
    #define ERROR(msg)      tcp_log_error("TCP", msg);
    #define ERRNO(msg)      tcp_log_errno("TCP", msg);
#else
    #define ERROR(msg)
    #define ERRNO(msg)
#endif

/* Socket flags */
#define F_SOCKET_MUST_ACK   1

static int tcp_associate_socket(Socket *s, struct sockaddr_in *addr)
{
    return connect(s->fd, (struct sockaddr *) addr, sizeof(struct sockaddr_in));
}

static int tcp_disassociate_socket(Socket *sock)
{
    struct sockaddr_in addr;
    addr.sin_family = AF_UNSPEC;
    return tcp_associate_socket(sock, &addr);
}

static Socket * tcp_socket_new(int fd)
{
    Socket *sock;

    sock = malloc(sizeof(Socket));
    memset(sock, 0, sizeof(Socket));

    sock->fd        = fd;

    sock->rcv_buf   = buffer_new(512, 0);
    sock->rcv_segs  = seglist_new();
    sock->rcv_nxt   = 0;
    sock->irs       = 0;

    sock->snd_nxt   = 0;
    sock->snd_una   = 0;
    sock->snd_wnd   = 50;
    sock->snd_buf   = buffer_new(512, 0);

    return sock;
}

static Socket * tcp_create_socket(struct sockaddr_in *peeraddr, u16 *newport)
{
    struct sockaddr_in localaddr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    Socket *sock;

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



Socket *tcp_socket(int reuseaddr)
{
    int fd, yes = 1;

    DEBUG("tcp_socket");

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return NULL;

    if (reuseaddr) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    return tcp_socket_new(fd);
}

void tcp_close(Socket *s)
{
    Packet p;

    p.flags = F_PACKET_FIN;
    p.ack   = 0;
    p.seq   = 0;

    send_packet(s, &p, 0);

    buffer_free(s->snd_buf);
    buffer_free(s->rcv_buf);
    seglist_free(s->rcv_segs);

    close(s->fd);
    free(s);
}

void tcp_connect(Socket *sock, struct sockaddr_in *addr)
{
    Packet recv_packet, snd_packet;
    i32 sz;
    u16 newport;

    memset(&snd_packet, 0, sizeof(snd_packet));

    if (tcp_associate_socket(sock, addr) < 0) {
        ERRNO("tcp_associate_socket in tcp_connect");
        return;
    }

    /* Send first SYN */
    snd_packet.flags = F_PACKET_SYN;
    sz = send_packet(sock, &snd_packet, 0);
    if (sz < 0) {
        ERRNO("tcp_send_packet in tcp_connect");
        return;
    }

    /* Receive SYN packet */
    recv_packet.flags = 0;
    if (recv_syn(sock, &recv_packet, addr) < 0) {
        ERRNO("tcp_recv_syn in tcp_connect");
        return;
    }

    if (!IS_SET(recv_packet.flags, F_PACKET_ACK)) {
        ERROR("ACK not present in tcp_connect");
        return;
    }

    newport = *((u16 *) recv_packet.data);

    /* ACK the received SYN */
    snd_packet.flags = F_PACKET_ACK;
    sz = send_packet(sock, &snd_packet, 0);
    if (sz < 0) {
        ERRNO("tcp_send_packet in tcp_connect");
        return;
    }

    /* Associate the socket with the new server port */
    addr->sin_port = newport;
    if (tcp_associate_socket(sock, addr) < 0) {
        ERRNO("tcp_associate_socket to newport in tcp_connect");
        return;
    }
}

/*
 * TODO: Handle simultaneous connections
 */
Socket *tcp_accept(Socket *sock, struct sockaddr_in *peer_addr)
{
    Packet packet;
    i32 sz;
    Socket *new_sock;
    u16 newport;

    /* Receive the SYN */
    if (recv_syn(sock, &packet, peer_addr) < 0) {
        ERRNO("tcp_recv_syn in tcp_accept");
        return NULL;
    }

    /* Associate the socket to the sender of the SYN */
    if (tcp_associate_socket(sock, peer_addr) < 0) {
        ERRNO("tcp_associate_socket in tcp_accept");
        return NULL;
    }

    /* Create a new socket bound on random port */
    new_sock = tcp_create_socket(peer_addr, &newport);
    if (!new_sock) {
        ERRNO("tcp_create_socket in tcp_accept");
        return NULL;
    }

    /* Send SYN + ACK with new port in data */
    packet.flags = F_PACKET_SYN | F_PACKET_ACK;
    *((u16 *) packet.data) = newport;

    sz = send_packet(sock, &packet, sizeof(u16));
    if (sz < 0) {
        ERRNO("tcp_send_packet in tcp_accept");
        return NULL;
    }

    /* Receive the ACK */
    sz = recv_packet(sock, &packet);
    if (sz < 0) {
        ERRNO("tcp_recv_packet in tcp_accept");
        return NULL;
    }

    /* Disasociate the socket for future connections */
    if (tcp_disassociate_socket(sock) < 0) {
        ERRNO("tcp_disassociate_socket in tcp_accept");
        return NULL;
    }

    return new_sock;
}

ssize_t tcp_send(Socket *sock, const char *in, size_t sz)
{
    buffer_write(sock->snd_buf, (const unsigned char *) in, sz);
    return send_queue_process(sock);
}

ssize_t tcp_recv(Socket *sock, char *out, size_t sz)
{
    i32 ret = recv_to_buffer(sock);
    if (ret < 0) return ret;

    return buffer_read(sock->snd_buf, (u8 *) out, sz, ERASE_DATA);
}
