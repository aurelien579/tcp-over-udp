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

#include "send.h"

static void usage(const char *prog)
{
    printf("Usage: %s server_ip server_port\n", prog);
    exit(EXIT_FAILURE);
}

void test_send(struct tcp_socket *sock, char *data, int seq, int ack, int flags)
{
    struct tcp_packet packet;

    strcpy((char *) packet.data, data);
    packet.seq = seq;
    packet.ack = ack;
    packet.flags = flags;

    send_packet(sock, &packet, strlen(data));
}

void test(struct tcp_socket *sock)
{
    test_send(sock, "TEST0", 0, 0, 0);
    test_send(sock, "TEST2", 10, 0, 0);
    test_send(sock, "TEST1", 5, 0, 0);
}

int main(int argc, char **argv)
{
    struct sockaddr_in addr;
    short port;
    char *server_ip;

    Socket *socket;

    if (argc < 3) usage(argv[0]);

    port = (short) atoi(argv[2]);
    server_ip = argv[1];

    socket = tcp_socket(1);

    addr.sin_family = AF_INET;
    if (!inet_aton(server_ip, &addr.sin_addr)) {
        return 0;
    }
    addr.sin_port = htons(port);

    tcp_connect(socket, &addr);
    test(socket);

    /*if (tcp_send(socket, "TEST", 4) < 0) {
        printf("Error while sending\n");
    }

    if (tcp_send(socket, "test", 4) < 0) {
        printf("Error while sending\n");
    }*/

    tcp_close(socket);

    return EXIT_SUCCESS;
}

