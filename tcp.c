#include "tcp.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "tcp-socket.h"

#define MAX_SOCKETS 20
#define MAX_DATA    512

#define ACK          (1 << 1)
#define SYN          (1 << 2)

#define TCP_PACKET_SIZE(data_size)  (sizeof(uint8_t) + data_size)
#define TCP_DATA_SIZE(packet_size)  (packet_size - sizeof(uint8_t))

#define ISSET(flags, flag)          (flags & flag)

struct tcp_packet
{
    uint8_t flags;
    uint8_t data[];
} __attribute__((packed));

static void
tcp_log(const char *msg)
{
    printf("[TCP] %s\n", msg);
}

static void
tcp_log_perror(const char *msg)
{
    printf("[TCP] %s : %s\n", msg, strerror(errno));
}

static void
tcp_dump(const uint8_t *data, size_t sz)
{
    for (int i = 0; i < sz; i++) {
        printf("%x ", data[i]);
    }
    printf("\n");
}

static void
tcp_dump_packet(const struct tcp_packet *packet, size_t data_size)
{
    printf("FLAGS: 0x%x\n", packet->flags);
    if (data_size == 0) return;

    printf("DATA: ");
    tcp_dump(packet->data, data_size);
}

static struct tcp_packet *
tcp_make_packet(uint8_t flags, size_t data_size)
{
    struct tcp_packet *packet = malloc(TCP_PACKET_SIZE(data_size));
    packet->flags = flags;
    return packet;
}

/**
 * @brief Receive a variable-size packet into @packet. @packet is allocated in
 *  this function.
 * @param sockfd
 * @param packet a pointer allocated in this function
 * @return total size of the packet or -1 on error
 */
static ssize_t
tcp_recv_packet(struct tcp_socket *socket, struct tcp_packet **packet, size_t sz)
{
    static struct tcp_packet *large_packet = NULL;

    if (TCP_DATA_SIZE(sz) > MAX_DATA) sz = TCP_PACKET_SIZE(MAX_DATA);

    if (!large_packet) large_packet = tcp_make_packet(0, MAX_DATA);

    ssize_t recv_sz = tcp_socket_recv(socket, (uint8_t *) large_packet, sz);

    if (recv_sz < 0) {
        free(large_packet);
        return -1;
    }

    *packet = tcp_make_packet(0, TCP_DATA_SIZE(recv_sz));
    memcpy(*packet, large_packet, recv_sz);

    return recv_sz;
}

static ssize_t
tcp_send_packet(struct tcp_socket *socket, struct tcp_packet *packet, size_t sz)
{
    printf("Sending packet : \n");
    tcp_dump_packet(packet, TCP_DATA_SIZE(sz));
    return tcp_socket_send(socket, (uint8_t *) packet, sz);
}

static int
tcp_send_syn(struct tcp_socket *socket)
{
    struct tcp_packet *packet = tcp_make_packet(SYN, 0);
    ssize_t size = tcp_send_packet(socket, packet, TCP_PACKET_SIZE(0));
    free(packet);

    return size >= 0;
}

/**
 * @brief Create a new socket on a free port. The new port is returned in @port
 * @param port output the port number in host byte order
 * @return the new socket file descriptor or -1 on error
 */
static int tcp_new_sockfd(unsigned short *port)
{
    int fd;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    if (bind(fd, (struct sockaddr *) &addr, addrlen) < 0) {
        close(fd);
        return -1;
    }

    if (getsockname(fd, (struct sockaddr *) &addr, &addrlen) < 0) {
        close(fd);
        return -1;
    }

    *port = ntohs(addr.sin_port);

    return fd;
}

static ssize_t
tcp_send_data(struct tcp_socket *socket, uint8_t *data, size_t sz)
{
    struct tcp_packet *packet = tcp_make_packet(0, sz);

    if (ISSET(tcp_socket_get_flags(socket), SOCKET_MUST_ACK)) {
        packet->flags |= ACK;
        tcp_socket_unset_flag(socket, SOCKET_MUST_ACK);
    }

    memcpy(packet->data, data, sz);

    ssize_t sz_sent = tcp_send_packet(socket, packet, TCP_PACKET_SIZE(sz));
    free(packet);

    return sz_sent;
}

static ssize_t
tcp_recv_data(struct tcp_socket *socket, uint8_t *data, size_t sz)
{
    struct tcp_packet *packet;

    ssize_t recvsz = tcp_recv_packet(socket, &packet, TCP_PACKET_SIZE(sz));
    if (recvsz < 0) {
        return -1;
    }

    tcp_socket_set_flag(socket, SOCKET_MUST_ACK);

    if (data && recvsz > 0) {
        memcpy(data, packet->data, TCP_DATA_SIZE(sz));
    }

    return recvsz;
}

int tcp_connect(int sockfd, struct sockaddr_in *addr)
{
    struct tcp_packet *packet;
    struct tcp_socket *socket = tcp_socket_new(sockfd);
    if (!socket) return -1;

    /* Initialize the distant address of the socket. Used in tcp_send_packet */
    tcp_socket_set_connecting(socket, addr);

    /* Send the first SYN packet */
    if (tcp_send_syn(socket) > 0) {
        tcp_socket_set_state(socket, TCP_STATE_SYN_SENT);
    } else {
        return -1;
    }
    /* Receive SYN|ACK and the new port number */
    ssize_t size = tcp_recv_packet(socket, &packet, TCP_PACKET_SIZE(MAX_DATA));
    if (size < 0) {
        return -1;
    }

    if (!ISSET(packet->flags, ACK) || !ISSET(packet->flags, SYN)) {
        printf("Client not connected. Flags : %d\n", packet->flags);
        return -1;
    }
    tcp_socket_set_flag(socket, SOCKET_MUST_ACK);

    unsigned short port = ntohs(*((unsigned short *)packet->data));
    tcp_socket_set_port(socket, port);

    free(packet);

    printf("Last ACK sent to : %d\n", ntohs(port));
    /* Send the last ACK packet */
    tcp_send_data(socket, NULL, 0);
    tcp_socket_set_state(socket, TCP_STATE_ESTABLISHED);

    return 1;
}

int tcp_accept(int sockfd, struct sockaddr_in *addr)
{
    struct tcp_packet *packet;
    struct tcp_socket *socket = tcp_socket_new(sockfd);
    if (!socket) return -1;

    tcp_socket_set_state(socket, TCP_STATE_LISTEN);

    /* Receive first SYN packet */
    ssize_t sz = tcp_recv_packet(socket, &packet, MAX_DATA);
    *addr = tcp_socket_get_addr(socket);

    if (!ISSET(packet->flags, SYN)) {
        printf("Incorrect packet received\n");
        return -1;
    }

    tcp_socket_set_state(socket, TCP_STATE_SYN_RCVD);

    free(packet);

    /* Create a new socket for that connection */
    unsigned short port;
    int new_fd = tcp_new_sockfd(&port);
    if (new_fd < 0) {
        return -1;
    }

    /* Send the SYN|ACK packet with the new port number inside */
    packet = tcp_make_packet(ACK | SYN, sizeof(unsigned short));
    *((unsigned short *) packet->data) = port;
    tcp_send_packet(socket, packet, TCP_PACKET_SIZE(sizeof(unsigned short)));

    struct tcp_socket *new_socket = tcp_socket_new(new_fd);

    free(packet);
    tcp_socket_set_addr(new_socket, addr);
    tcp_socket_set_port(new_socket, port);
    tcp_socket_set_state(new_socket, TCP_STATE_ESTABLISHED);

    /* Receive the last ACK packet */
    tcp_recv_packet(new_socket, &packet, MAX_DATA);

    printf("Last ACK received\n");
    tcp_dump_packet(packet, 0);
    if (!(packet->flags & ACK)) {
        printf("Incorrect packet received\n");
        return -1;
    }
    free(packet);

    tcp_socket_set_state(socket, TCP_STATE_ESTABLISHED);

    printf("Connection accepted\n");
    return new_fd;
}

ssize_t tcp_recv(int sockfd, uint8_t *buffer, size_t sz)
{
    struct tcp_socket *socket = tcp_socket_get(sockfd);

    if (tcp_socket_get_state(socket) != TCP_STATE_ESTABLISHED) {
        return -1;
    }

    return tcp_recv_data(socket, buffer, sz);
}

ssize_t tcp_send(int sockfd, uint8_t *buffer, size_t sz)
{
    struct tcp_socket *socket = tcp_socket_get(sockfd);

    if (tcp_socket_get_state(socket) != TCP_STATE_ESTABLISHED) {
        return -1;
    }

    return tcp_send_data(socket, buffer, sz);
}
