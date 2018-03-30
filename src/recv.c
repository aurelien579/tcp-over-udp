#include "recv.h"
#include "tcp.h"
#include "buffer.h"
#include "segment.h"
#include "utils.h"
#include "log.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#if LOG_LEVEL > LOG_DEBUG
    #define DEBUG(...)   tcp_log("RCV", __VA_ARGS__)
#else
    #define DEBUG(...)
#endif

static i32 store_rcvd_data(Socket *s, u16 seq, const u8 *in, u16 len)
{
    if (len > buffer_get_free_space(s->snd_buf)) {
        return -1;
    }

    DEBUG("store_rcvd_data(seq=%d, len=%d)", seq, len);

    struct seg *current = seg_containing(s->rcv_segs, seq);
    struct seg *before  = seg_containing(s->rcv_segs, seq - 1);
    struct seg *after   = seg_containing(s->rcv_segs, seq + len);

    u16 first  = seq;
    u16 last   = seq + len - 1;
    u16 offset = 0;

    DEBUG("first  = %d", first);
    DEBUG("last   = %d", last);
    DEBUG("offset = %d", offset);

    /* Whole data in one segment => nothing to do */
    if (current) {
        return 0;
    }

    if (before) {
        first  = before->seq + before->len;
        offset = first - seq;
    }

    if (after) {
        last = after->seq - 1;
    }

    len = min(len, last - first + 1);

    i32 ret = buffer_write_at(s->snd_buf, first, in + offset, len);
    if (ret <= 0) return ret;

    if (!before && !after) {
        current = seglist_add(s->rcv_segs, first, len);
    } else if (before && !after){
        before->len += len;
        current      = before;
    } else if (!before && after) {
        after->seq = first;
        after->len += len;
        current = after;
    } else {
        before->len += after->len + len;
        seglist_del(s->rcv_segs, after);
        current = before;
    }

    DEBUG("Segments updated :");
#if LOG_LEVEL > LOG_DEBUG
    #ifdef LOG_FILE
        seglist_print(LOG_FILE, s->rcv_segs);
    #endif
#endif

    if (current->seq == s->irs) {
        buffer_set_next_write(s->snd_buf, current->seq + current->len);
    }

    return len;
}

i32 recv_packet(Socket *sock, Packet *packet)
{
    DEBUG("Receiving...");
    return recv(sock->fd, packet, sizeof(Packet), 0);
}

i32 recv_to_buffer(Socket *sock)
{
    Packet packet;

    i32 ret = recv_packet(sock, &packet);
    if (ret < 0) return ret;

    if (packet.flags & F_PACKET_ACK) {
        DEBUG("ACK received : %d", packet.ack);
        sock->snd_una = packet.ack;
    }

    sock->rcv_nxt += DATA_SIZE(ret);

    return store_rcvd_data(sock, packet.seq, packet.data, DATA_SIZE(ret));
}

i8 recv_syn(Socket *sock, Packet *packet, struct sockaddr_in *addr)
{
    i32 sz;
    socklen_t addrlen = sizeof(struct sockaddr_in);

    do {
        sz = recvfrom(sock->fd, packet, sizeof(Packet), 0,
                      (struct sockaddr *) addr, &addrlen);

        if (sz < 0) return -1;
    } while (!IS_SET(packet->flags, F_PACKET_SYN));

    return 0;
}
