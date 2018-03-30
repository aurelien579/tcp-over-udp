#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "utils.h"
#include "tcp.h"

void usage(const char *prog)
{
    printf("Usage : %s port\n", prog);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    struct tcp_socket *socket, *client_socket;
    struct sockaddr_in addr, clientaddr;
    short port;

    if (argc < 2) usage(argv[0]);

    port = (short) atoi(argv[1]);

    socket = tcp_socket(1);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(socket->fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) < 0) {
        panic_perror("bind");
    }

    client_socket = tcp_accept(socket, &clientaddr);
    char buffer[512];
    sleep(1);
    
    tcp_recv(client_socket, buffer, 512);
    printf("recv : %s\n", buffer);

    memset(buffer, 0, 512);

    tcp_recv(client_socket, buffer, 512);
    printf("recv : %s\n", buffer);
    
    
    
    memset(buffer, 0, 512);

    tcp_recv(client_socket, buffer, 512);
    printf("recv : %s\n", buffer);
    
    return EXIT_SUCCESS;
}
