#include "tcp.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define MAX_SOCKETS 20
#define MAX_DATA    512

#define SOCKET_CONNECTED    1
#define SOCKET_ACK          (1 << 2)

#define ACK          (1 << 1)
#define SYN          (1 << 2)

#define TCP_PACKET_SIZE(data_size)  (sizeof(uint8_t) + data_size)
#define TCP_DATA_SIZE(packet_size)  (packet_size - sizeof(uint8_t))

#define TCP_STATE_CLOSED        0
#define TCP_STATE_SYN_SENT      1
#define TCP_STATE_SYN_RCVD      2
#define TCP_STATE_LISTEN        3
#define TCP_STATE_ESTABLISHED   4

#define ISSET(packet, flag)    ((packet)->flags & flag)

struct tcp_socket
{
    int fd;
    uint8_t state;
    uint8_t flags;
    uint16_t expected_byte;
    uint16_t sequence_byte;
    struct sockaddr_in distant_addr;
};

struct tcp_packet
{
    uint8_t flags;
    uint8_t data[];
} __attribute__((packed));

static struct tcp_socket sockets[MAX_SOCKETS];

static void tcp_log(const char *msg)
{
    printf("[TCP] %s\n", msg);
}

static void tcp_log_perror(const char *msg)
{
    printf("[TCP] %s : %s\n", msg, strerror(errno));
}

static void tcp_dump(const uint8_t *data, size_t sz)
{
    for (int i = 0; i < sz; i++) {
        printf("%x ", data[i]);
    }
    printf("\n");
}

static void tcp_dump_packet(const struct tcp_packet *packet, size_t data_size)
{
    printf("FLAGS: 0x%x\n", packet->flags);
    if (data_size == 0) return;
    
    printf("DATA: ");
    tcp_dump(packet->data, data_size);
}

static struct tcp_packet *tcp_make_packet(uint8_t flags, size_t data_size)
{
    struct tcp_packet *packet = malloc(TCP_PACKET_SIZE(data_size));
    packet->flags = flags;
    return packet;
}

static ssize_t tcp_send_packet(int sockfd, struct tcp_packet *packet, size_t data_size)
{
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct sockaddr *addr = (struct sockaddr *) &sockets[sockfd].distant_addr;
    
    return sendto(sockfd, packet, TCP_PACKET_SIZE(data_size), 0, addr, addrlen);
}

static int addr_equals(struct sockaddr_in *a, struct sockaddr_in *b)
{
    return (memcmp(&a->sin_addr, &b->sin_addr, sizeof(a->sin_addr)) == 0) &&
           (memcmp(&a->sin_port, &b->sin_port, sizeof(a->sin_port)) == 0);
}

static size_t tcp_recv_any_packet(int sockfd, struct tcp_packet **packet, struct sockaddr_in *addr)
{
    struct tcp_packet *large_packet = tcp_make_packet(0, MAX_DATA);
    
    socklen_t addrlen = sizeof(struct sockaddr_in);
    
    ssize_t recv_size = recvfrom(sockfd, large_packet, TCP_PACKET_SIZE(MAX_DATA),
                                 0, (struct sockaddr *) addr, &addrlen);
    
    if (recv_size < 0) {
        free(large_packet);
        return -1;
    }
            
    *packet = tcp_make_packet(0, TCP_DATA_SIZE(recv_size));
    memcpy(*packet, large_packet, recv_size);
    
    free(large_packet);
    
    return recv_size;
}

/**
 * @brief Receive a variable-size packet into @packet. @packet is allocated in
 *  this function.
 * @param sockfd
 * @param packet a pointer allocated in this function
 * @return total size of the packet or -1 on error
 */
static ssize_t tcp_recv_packet(int sockfd, struct tcp_packet **packet, size_t max_data)
{
    if (max_data > MAX_DATA) max_data = MAX_DATA;
    
    struct tcp_packet *large_packet = tcp_make_packet(0, max_data);
    
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    
    ssize_t recv_size = recvfrom(sockfd, large_packet, TCP_PACKET_SIZE(max_data),
                                 0, (struct sockaddr *) &addr, &addrlen);
    
    if (!addr_equals(&addr, &sockets[sockfd].distant_addr)) {
        printf("Packet received from invalid distant address : %d, %s:%d\n", sockfd,
               inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        printf("Expected : %s:%d\n", inet_ntoa(sockets[sockfd].distant_addr.sin_addr),
               ntohs(sockets[sockfd].distant_addr.sin_port));
        free(large_packet);
        return -1;
    }
    
    if (recv_size < 0) {
        free(large_packet);
        return -1;
    }
            
    *packet = tcp_make_packet(0, TCP_DATA_SIZE(recv_size));
    memcpy(*packet, large_packet, recv_size);
    
    free(large_packet);
    
    return recv_size;
}

static int tcp_send_syn(struct tcp_socket *socket)
{
    struct tcp_packet *packet = tcp_make_packet(SYN, 0);
    ssize_t size = tcp_send_packet(socket->fd, packet, 0);
    free(packet);
    
    return size > 0;
}

static int tcp_send_data(struct tcp_socket *socket, uint8_t *data, size_t sz)
{
    struct tcp_packet *packet = tcp_make_packet(0, sz);
    
    if (ISSET(socket, SOCKET_ACK)) {
        packet->flags |= ACK;
        socket->flags &= ~SOCKET_ACK;
    }
    
    memcpy(packet->data, data, sz);
    
    ssize_t sz_sent = tcp_send_packet(socket->fd, packet, sz);
    free(packet);
    
    return sz_sent > 0;
}

static ssize_t tcp_recv_data(struct tcp_socket *socket, uint8_t *data, size_t sz)
{
    struct tcp_packet *packet;
    
    ssize_t recvsz = tcp_recv_packet(socket->fd, &packet, sz);
    if (recvsz < 0) {
        return -1;
    }
    
    socket->flags |= SOCKET_ACK;
    if (data && recvsz > 0) {
        memcpy(data, packet->data, sz);        
    }
    
    return recvsz;
}

/**
 * @brief Create a new socket on a free port. The new port is returned in @port
 * @param port output the port number in host byte order
 * @return the new socket file descriptor or -1 on error
 */
static int tcp_new_socket(unsigned short *port)
{
    int new_sockfd;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    
    new_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (new_sockfd < 0) {
        tcp_log_perror("socket error");
        return -1;
    }
    
    if (bind(new_sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        tcp_log_perror("bind error");
        close(new_sockfd);
        return -1;
    }
    
    if (getsockname(new_sockfd, (struct sockaddr *) &addr, &addrlen) < 0) {
        tcp_log_perror("getsockname error");
        close(new_sockfd);
        return -1;
    }
    
    *port = ntohs(addr.sin_port);
    
    return new_sockfd;
}

int tcp_connect(int sockfd, struct sockaddr_in *addr)
{
    struct tcp_packet *packet;
    struct tcp_socket *socket = &sockets[sockfd];
    memset(socket, 0, sizeof(struct tcp_socket));
    socket->fd = sockfd;
        
    /* Initialize the distant address of the socket. Used in tcp_send_packet */
    socket->distant_addr = *addr;
    
    /* Send the first SYN packet */
    if (tcp_send_syn(socket) > 0) {
        socket->state = TCP_STATE_SYN_SENT;
    } else {
        return -1;
    }
    
    /* Receive SYN|ACK and the new port number */
    ssize_t size = tcp_recv_packet(sockfd, &packet, MAX_DATA);
    if (size < 0) {
        return -1;
    }
    
    if (!ISSET(packet, ACK) || !ISSET(packet, SYN)) {
        printf("Client not connected. Flags : %d\n", packet->flags);
        return -1;
    }
    
    unsigned short port = *((unsigned short *)packet->data);
    sockets[sockfd].distant_addr.sin_port = htons(port);
    
    free(packet);
    
    /* Send the last ACK packet */
    tcp_send_data(socket, NULL, 0);
    
    sockets[sockfd].flags |= SOCKET_CONNECTED;
    
    return 1;
}

int tcp_accept(int sockfd, struct sockaddr_in *addr)
{
    struct tcp_packet *packet;
    struct tcp_socket *socket;
    
    /* Receive first SYN packet */
    tcp_recv_any_packet(sockfd, &packet, addr);
    
    if (!ISSET(packet, SYN)) {
        printf("Incorrect packet received\n");
        return -1;
    }
        
    free(packet);
    
    /* Create a new socket for that connection */
    unsigned short port;
    int new_socket = tcp_new_socket(&port);
    if (new_socket < 0) {
        return -1;
    }
    
    socket = &sockets[new_socket];
    memset(socket, 0, sizeof(struct tcp_socket));
    socket->fd = sockfd;
    socket->state = TCP_STATE_SYN_RCVD;
    socket->distant_addr = *addr;   

    
    /* Send the SYN|ACK packet with the new port number inside */
    packet = tcp_make_packet(ACK | SYN, sizeof(unsigned short));
    *((unsigned short *) packet->data) = port;
    sendto(sockfd, packet, TCP_PACKET_SIZE(sizeof(unsigned short)), 0,
           (struct sockaddr *) addr, sizeof(struct sockaddr_in));
    free(packet);
    
    socket->state = TCP_STATE_ESTABLISHED;
    
    /* Receive the last ACK packet */
    tcp_recv_packet(new_socket, &packet, MAX_DATA);
    if (!((packet->flags & ACK) && (packet->flags & SYN))) {
        printf("Incorrect packet received\n");
        return -1;
    }
    free(packet);
    
    sockets[new_socket].flags |= SOCKET_CONNECTED;
    
    printf("Connection accepted\n");
    return new_socket;
}

ssize_t tcp_recv(int sockfd, char *buffer, size_t sz)
{
    if (!(sockets[sockfd].flags & SOCKET_CONNECTED)) {
        return -1;
    }

    struct sockaddr_in recvaddr;
    socklen_t addrlen = sizeof(struct sockaddr);
    ssize_t recvsz;
    
    if ((recvsz = recvfrom(sockfd, buffer, sz, 0, (struct sockaddr *) &recvaddr,
         &addrlen)) < 0)
    {
        return -1;
    }
    
    if (memcmp(&recvaddr, &sockets[sockfd].distant_addr, sizeof(struct sockaddr_in)) != 0) {
        printf("Packet received from invalid distant address : %d, %s\n", sockfd, inet_ntoa(recvaddr.sin_addr));
        return -1;
    }
    
    return recvsz;
}

ssize_t tcp_send(int sockfd, char *buffer, size_t sz)
{
    if (!(sockets[sockfd].flags & SOCKET_CONNECTED)) {
        return -1;
    }
    
    struct sockaddr *addr = (struct sockaddr *) &sockets[sockfd].distant_addr;
    socklen_t addrlen = sizeof(struct sockaddr);
    
    return sendto(sockfd, buffer, sz, 0, addr, addrlen);
}
