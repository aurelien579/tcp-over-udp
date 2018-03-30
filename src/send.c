#include "send.h"
#include "buffer.h"
#include "tcp.h"
#include "utils.h"

#include <stdio.h>

static u16 max_send_size(Socket *sock)
{
    return (sock->snd_una + sock->snd_wnd) - sock->snd_nxt;
}

static i32 send_next(Socket *sock, u16 size)
{
    size = min(MAX_DATA, size);

    Packet packet;

    /* Fill header */
    packet.flags = F_PACKET_ACK;
    packet.ack = sock->rcv_nxt;
    packet.seq = sock->snd_nxt;

    i32 ret = buffer_read(sock->snd_buf, packet.data, size, KEEP_DATA);
    if (ret < 0) return ret;

    size = min(ret, size);
    if (!size) return 0;

    ret = send(sock->fd, &packet, PACKET_SIZE(size), 0);
    if (ret < 0) return ret;

    sock->snd_nxt += DATA_SIZE(ret);

    return DATA_SIZE(ret);
}

i32 send_packet(Socket *sock, Packet *packet, u16 data_sz)
{
    sock->snd_nxt += data_sz;
    return send(sock->fd, packet, PACKET_SIZE(data_sz), 0);
}

i8 send_queue_process(Socket *sock)
{
    u16 size = buffer_get_readable(sock->snd_buf);
    size = min(size, max_send_size(sock));

    while (size) {
        i32 ret = send_next(sock, size);
        if (ret < 0) return -1;
        size -= ret;
    }

    return 0;
}

void send_queue_on_ack(Socket *sock, u16 ack)
{
    buffer_set_keep_index(sock->snd_buf, ack);
}
