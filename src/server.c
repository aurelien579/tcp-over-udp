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
    int sockfd, yes = 1;
    struct sockaddr_in addr, clientaddr;
    short port;

    if (argc < 2) usage(argv[0]);

    port = (short) atoi(argv[1]);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        panic_perror("socket");
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
        panic_perror("setsockopt");
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) < 0) {
        panic_perror("bind");
    }

    int client_sockfd = tcp_accept(sockfd, &clientaddr);
    printf("client_sockfd : %d\n", client_sockfd);

    /*char buffer[512];

    printf("client_sockfd : %d\n", client_sockfd);
    tcp_recv(client_sockfd, buffer, 512);
    printf("recv : %s\n", buffer);*/

    /*while (1) {
        char buffer[1024];
        while (recvfrom(sockfd, buffer, sizeof(buffer), 0,
               (struct sockaddr *) &clientaddr, &addrlen) > 0)
        {
            printf("UDP RECV FROM: %s\n", inet_ntoa(clientaddr.sin_addr));
            printf("UDP RECV DATA: %s\n", buffer);
        }
    }*/

    return EXIT_SUCCESS;
}
