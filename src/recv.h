#ifndef RECV_H
#define RECV_H

#include "types.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

typedef struct tcp_socket Socket;
typedef struct tcp_packet Packet;

i32 recv_to_buffer(Socket *sock);
i32 recv_packet(Socket *sock, Packet *packet);

i8 recv_syn(Socket *s, Packet *p, struct sockaddr_in *addr);

#endif
