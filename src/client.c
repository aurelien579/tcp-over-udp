#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils.h"
#include "tcp.h"

static void usage(const char *prog)
{
    printf("Usage: %s server_ip server_port\n", prog);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    int sockfd, yes = 1;
    struct sockaddr_in addr;
    short port;
    char *server_ip;

    if (argc < 3) usage(argv[0]);

    port = (short) atoi(argv[2]);
    server_ip = argv[1];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        panic_perror("socket");
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    addr.sin_family = AF_INET;
    if (!inet_aton(server_ip, &addr.sin_addr)) {
        return 0;
    }
    addr.sin_port = htons(port);

    tcp_connect(sockfd, &addr);
    if (tcp_send(sockfd, "TEST", 4) < 0) {
        printf("Error while sending\n");
    }

    close(sockfd);

    return EXIT_SUCCESS;
}