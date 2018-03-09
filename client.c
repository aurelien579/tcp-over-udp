#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

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
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
        panic_perror("setsockopt");
    }
    
    addr.sin_family = AF_INET;
    if (!inet_aton(server_ip, &addr.sin_addr)) {
        return 0;
    }    
    addr.sin_port = htons(port);
    
    tcp_connect(sockfd, &addr);
    tcp_send(sockfd, "TEST", 4);
    //sendto(sockfd, "TEST", 4, 0, (struct sockaddr *) &addr, addrlen);
    
    close(sockfd);
    
    return EXIT_SUCCESS;
}