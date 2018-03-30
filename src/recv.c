#include "recv.h"
#include "tcp.h"
#include "buffer.h"
#include "segment.h"
#include "utils.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#define RECV_DEBUG  0

static ssize_t
store_rcvd_data(struct tcp_socket *s, uint16_t seq, const uint8_t *in, uint16_t len)
{
    if (len > buffer_get_free_space(s->snd_buf)) {
        return -1;
    }

#if RECV_DEBUG
    printf("[DEBUG] store_rcvd_data(seq=%d, len=%d)\n", seq, len);
#endif

    struct seg *current = seg_containing(s->rcv_segs, seq);
    struct seg *before  = seg_containing(s->rcv_segs, seq - 1);
    struct seg *after   = seg_containing(s->rcv_segs, seq + len);

    uint16_t first  = seq;
    uint16_t last   = seq + len - 1;
    uint16_t offset = 0;

#if RECV_DEBUG
    printf("[DEBUG] first  = %d\n", first);
    printf("[DEBUG] last   = %d\n", last);
    printf("[DEBUG] offset = %d\n", offset);
#endif

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

    ssize_t ret = buffer_write_at(s->snd_buf, first, in + offset, len);
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

#if RECV_DEBUG
    printf("[DEBUG] Segments updated : \n\t");
    seglist_print(s->rcv_segs);
#endif    

    if (current->seq == s->irs) {
        buffer_set_next_write(s->snd_buf, current->seq + current->len);
    }

    return len;
}

ssize_t
recv_packet(struct tcp_socket *sock, struct tcp_packet *packet)
{
    printf("Receiving...\n");
    return recv(sock->fd, packet, sizeof(struct tcp_packet), 0);
}

ssize_t
recv_to_buffer(struct tcp_socket *sock)
{
    struct tcp_packet packet;
    
    ssize_t ret = recv_packet(sock, &packet);
    if (ret < 0) return ret;
    
    if (packet.flags & F_PACKET_ACK) {
        printf("ACK received : %d\n", packet.ack);
        sock->snd_una = packet.ack;
    }
    
    sock->rcv_nxt += DATA_SIZE(ret);

    return store_rcvd_data(sock, packet.seq, packet.data, DATA_SIZE(ret));
}

int
recv_syn(struct tcp_socket *sock, struct tcp_packet *packet, struct sockaddr_in *addr)
{
    ssize_t sz;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    
    do {
        sz = recvfrom(sock->fd, packet, sizeof(struct tcp_packet), 0,
                      (struct sockaddr *) addr, &addrlen);

        if (sz < 0) return -1;
    } while (!IS_SET(packet->flags, F_PACKET_SYN));

    return 0;
}
