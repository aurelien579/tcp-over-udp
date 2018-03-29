#ifndef SEND_BUFFER_H
#define SEND_BUFFER_H

#include <sys/types.h>
#include <stdint.h>

struct tcp_packet;
struct tcp_socket;

ssize_t send_packet(struct tcp_socket *sock, struct tcp_packet *packet, size_t data_sz);
int send_queue_process(struct tcp_socket *sock);

#endif
