#ifndef TCP_H
#define TCP_H

#include <netinet/in.h>


void tcp_connect(int fd, struct sockaddr_in *addr);
int tcp_accept(int fd, struct sockaddr_in *addr);

#endif
