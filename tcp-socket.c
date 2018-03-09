#include "tcp-socket.h"
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#define MAX_SOCKETS 20

struct tcp_socket
{
    int fd;
    uint8_t state;
    uint8_t flags;
    uint16_t expected_byte;
    uint16_t sequence_byte;
    struct sockaddr_in distant_addr;
};

static struct tcp_socket sockets[MAX_SOCKETS];

static int addr_equals(struct sockaddr_in *a, struct sockaddr_in *b)
{
    return (memcmp(&a->sin_addr, &b->sin_addr, sizeof(a->sin_addr)) == 0) &&
           (memcmp(&a->sin_port, &b->sin_port, sizeof(a->sin_port)) == 0);
}


struct tcp_socket *tcp_socket_new(int fd)
{
    if (fd >= MAX_SOCKETS) return NULL;

    struct tcp_socket *socket = &sockets[fd];

    memset(socket, 0, sizeof(struct tcp_socket));

    socket->fd = fd;
    socket->state = TCP_STATE_CLOSED;

    return socket;
}

void tcp_socket_close(struct tcp_socket *self)
{
    close(self->fd);
}

struct tcp_socket *tcp_socket_get(int fd)
{
    if (fd < MAX_SOCKETS) {
        return &sockets[fd];
    } else {
        return NULL;
    }
}

ssize_t tcp_socket_recv(struct tcp_socket *self, uint8_t *buffer, size_t sz)
{
    if (self->state == TCP_STATE_CLOSED) {
        printf("Trying to read closed socket\n");
        return -1;
    }

    struct sockaddr_in recv_addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);

    ssize_t recv_sz = recvfrom(self->fd, buffer, sz, 0,
                               (struct sockaddr *) &recv_addr, &addrlen);

    if (recv_sz < 0) {
        printf("recvfrom error : %s\n", strerror(errno));
        return -1;
    }

    if (self->state != TCP_STATE_LISTEN) {
        if (!addr_equals(&self->distant_addr, &recv_addr)) {
            printf("Invalid address\n");
            return -1;
        }
    } else {
        self->distant_addr = recv_addr;
    }

    return recv_sz;
}

ssize_t tcp_socket_send(struct tcp_socket *self, uint8_t *buffer, size_t sz)
{
    if (self->state == TCP_STATE_CLOSED || self->state == TCP_STATE_LISTEN) {
        printf("Invalid state\n");
        return -1;
    }

    return sendto(self->fd, buffer, sz, 0,
                 (struct sockaddr *) &self->distant_addr, sizeof(struct sockaddr));
}

uint8_t tcp_socket_get_flags(struct tcp_socket *self)
{
    return self->flags;
}

void tcp_socket_set_connecting(struct tcp_socket *self, struct sockaddr_in *addr)
{
    self->state = TCP_STATE_CONNECTING;
    self->distant_addr = *addr;
}

void tcp_socket_set_state(struct tcp_socket *self, uint8_t state)
{
    self->state = state;
}

void tcp_socket_set_port(struct tcp_socket *self, unsigned short port)
{
    self->distant_addr.sin_port = port;
}

void tcp_socket_set_flag(struct tcp_socket *self, uint8_t flag)
{
    self->flags |= flag;
}

void tcp_socket_unset_flag(struct tcp_socket *self, uint8_t flag)
{
    self->flags &= ~flag;
}

struct sockaddr_in tcp_socket_get_addr(struct tcp_socket *self)
{
    return self->distant_addr;
}

void tcp_socket_set_addr(struct tcp_socket *self, struct sockaddr_in *addr)
{
    self->distant_addr = *addr;
}

uint8_t tcp_socket_get_state(struct tcp_socket *self)
{
    return self->state;
}

unsigned short tcp_socket_get_local_port(struct tcp_socket *self)
{
    struct sockaddr_in local;
    socklen_t addrlen = sizeof(local);
    getsockname(self->fd, (struct sockaddr *) &local, &addrlen);
    return ntohs(local.sin_port);
}
