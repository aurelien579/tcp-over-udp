#include "send.h"
#include "buffer.h"
#include "tcp.h"
#include "utils.h"

#include <stdio.h>

static size_t
max_send_size(struct tcp_socket *sock)
{
    return (sock->snd_una + sock->snd_wnd) - sock->snd_nxt;
}

static ssize_t
send_next(struct tcp_socket *sock, size_t size)
{
    size = min(MAX_DATA, size);
    
    struct tcp_packet packet;
    
    /* Fill header */
    packet.flags = F_PACKET_ACK;
    packet.ack = sock->rcv_nxt;
    packet.seq = sock->snd_nxt;
    
    ssize_t ret = buffer_read(sock->snd_buf, packet.data, size, KEEP_DATA);
    if (ret < 0) return ret;
    
    size = min(ret, size);
    if (!size) return 0;
    
    ret = send(sock->fd, &packet, PACKET_SIZE(size), 0);
    if (ret < 0) return ret;
    
    sock->snd_nxt += DATA_SIZE(ret);
    
    return DATA_SIZE(ret);
}

ssize_t
send_packet(struct tcp_socket *sock, struct tcp_packet *packet, size_t data_sz)
{
    sock->snd_nxt += data_sz;
    return send(sock->fd, packet, PACKET_SIZE(data_sz), 0);
}

int
send_queue_process(struct tcp_socket *sock)
{
    size_t size = buffer_get_readable(sock->snd_buf);
    size = min(size, max_send_size(sock));
    
    printf("Sending size: %ld\n", size);
    
    while (size) {
        ssize_t ret = send_next(sock, size);
        if (ret < 0) return -1;
        size -= ret;
    }
    
    return 0;
}

void
send_queue_on_ack(struct tcp_socket *sock, size_t ack)
{
    buffer_set_keep_index(sock->snd_buf, ack);
}
