#ifndef RECV_H
#define RECV_H

#include <sys/types.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

struct tcp_socket;
struct tcp_packet;

ssize_t recv_to_buffer(struct tcp_socket *sock);
ssize_t recv_packet(struct tcp_socket *sock, struct tcp_packet *packet);

int recv_syn(struct tcp_socket *s, struct tcp_packet *p, struct sockaddr_in *addr);

#endif
