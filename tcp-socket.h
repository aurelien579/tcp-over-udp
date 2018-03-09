#ifndef TCP_SOCKET_H
#define TCP_SOCKET_H

#include <stdint.h>
#include <arpa/inet.h>

#define SOCKET_MUST_ACK         (1 << 2)

#define TCP_STATE_CLOSED        0
#define TCP_STATE_SYN_SENT      1
#define TCP_STATE_SYN_RCVD      2
#define TCP_STATE_LISTEN        3
#define TCP_STATE_ESTABLISHED   4
#define TCP_STATE_CONNECTING    5

struct tcp_socket;

struct tcp_socket *tcp_socket_new(int fd);
void tcp_socket_close(struct tcp_socket *self);

struct tcp_socket *tcp_socket_get(int fd);

ssize_t tcp_socket_recv(struct tcp_socket *self, uint8_t *buffer, size_t sz);
ssize_t tcp_socket_send(struct tcp_socket *self, uint8_t *buffer, size_t sz);

uint8_t tcp_socket_get_flags(struct tcp_socket *self);
void tcp_socket_set_flag(struct tcp_socket *self, uint8_t flag);
void tcp_socket_unset_flag(struct tcp_socket *self, uint8_t flag);

void tcp_socket_set_connecting(struct tcp_socket *self, struct sockaddr_in *addr);
void tcp_socket_set_state(struct tcp_socket *self, uint8_t state);
void tcp_socket_set_port(struct tcp_socket *self, unsigned short port);
unsigned short tcp_socket_get_local_port(struct tcp_socket *self);

struct sockaddr_in tcp_socket_get_addr(struct tcp_socket *self);
void tcp_socket_set_addr(struct tcp_socket *self, struct sockaddr_in *addr);

uint8_t tcp_socket_get_state(struct tcp_socket *self);

#endif
