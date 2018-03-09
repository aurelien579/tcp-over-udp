#ifndef TCP_H
#define TCP_H

#include <arpa/inet.h>

int tcp_connect(int sockfd, struct sockaddr_in *addr);
int tcp_accept(int sockfd, struct sockaddr_in *addr);

ssize_t tcp_send(int sockfd, char *buffer, size_t sz);
ssize_t tcp_recv(int sockfd, char *buffer, size_t sz);

#endif
