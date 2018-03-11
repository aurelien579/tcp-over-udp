#ifndef TCP_H
#define TCP_H

#include <netinet/in.h>


void tcp_connect(int fd, struct sockaddr_in *addr);
int tcp_accept(int fd, struct sockaddr_in *addr);

ssize_t tcp_recv(int fd, char *buffer, size_t sz);
ssize_t tcp_send(int fd, const char *buffer, size_t sz);

#endif
