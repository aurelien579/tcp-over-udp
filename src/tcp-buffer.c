#include "tcp-buffer.h"
#include "tcp-segment.h"
#include "utils.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

struct tcp_buffer
{
    uint16_t size;
    uint16_t next_read;
    uint16_t next_write;
    uint16_t initial_seq;
    struct tcp_segment_list *segments;
    uint8_t data[];
};

struct tcp_buffer *
tcp_buffer_new(uint16_t size, uint16_t seq)
{
    struct tcp_buffer *buf = malloc(sizeof(uint16_t) * 4 +
                                    sizeof(struct segment_list *) +
                                    size);
    
    buf->size = size;
    buf->next_read = seq;
    buf->next_write = seq;
    buf->segments = tcp_segment_list_new();
    buf->initial_seq = seq;
    
    /* Optional */
    memset(buf->data, 0, size);
    
    return buf;
}

uint16_t
tcp_buffer_get_unfilled_space(const struct tcp_buffer *buf)
{
    return buf->size - (buf->next_write - buf->next_read);
}

uint16_t
tcp_buffer_get_readable_size(const struct tcp_buffer *buf)
{
    int32_t readable = (int32_t) buf->next_write - buf->next_read;
    if (readable <= 0) {
        return 0;
    } else {
        return readable;
    }
}

ssize_t
tcp_buffer_write(struct tcp_buffer *buf,
                 uint16_t seq,
                 const uint8_t *in,
                 uint16_t len)
{
    printf("BUFFER: Write at %d, size %d\n", seq, len);
    if (seq - buf->next_read >= buf->size) {
        return -1;
    }
    
    if (len > tcp_buffer_get_unfilled_space(buf)) {
        return -1;
    }

    struct tcp_segment *current = tcp_segment_containing(buf->segments, seq);
    struct tcp_segment *before = tcp_segment_containing(buf->segments, seq - 1);
    struct tcp_segment *after = tcp_segment_containing(buf->segments, seq + len);

    uint16_t first_seq = seq;
    uint16_t last_seq = seq + len - 1;
    uint16_t in_offset = 0;
    
    /* Whole data in one segment => nothing to do */
    if (current) {
        printf("[BUFFER] [DEBUG] Nothing to do\n");
        return 0;
    }

    if (before) {
        in_offset = (before->seq + before->len) - first_seq;
        first_seq = before->seq + before->len;
    }

    if (after) {
        printf("last_seg\n");
        last_seq = after->seq - 1;
    }

    len = min(len, last_seq - first_seq + 1);

    /* Indexes in circular buffer */
    uint16_t first = first_seq % buf->size;
    uint16_t last = last_seq % buf->size;
#if 0
    printf("[BUFFER] [DEBUG] size_to_write: %d\n", size_to_write);
    printf("[BUFFER] [DEBUG] first: %d\n", first);
    printf("[BUFFER] [DEBUG] last: %d\n", last);
#endif // 0

    if (last >= first) {
#if 1
        printf("[BUFFER] [DEBUG] last > first\n");
#endif // 0

        memcpy(buf->data + first, in + in_offset, len);
    } else {
        uint16_t size_at_end = buf->size - first;
#if 0
        printf("[BUFFER] [DEBUG] last < first\n");
        printf("[BUFFER] [DEBUG] size_at_end: %d\n", size_at_end);
        printf("[BUFFER] [DEBUG] size_at_start: %d\n", size_to_write - size_at_end);
#endif // 0
        memcpy(buf->data + first, in, size_at_end);
        memcpy(buf->data, in + first, len - size_at_end);
    }


    if (!before && !after) {
        current = tcp_segment_list_add(buf->segments, first_seq, len);
    } else if (before && !after) {
        before->len += len;
        current = before;
    } else if (!before && after) {
        after->seq = first_seq;
        after->len += len;
        current = after;
    } else {
        tcp_segment_list_del(buf->segments, after);
        before->len += len;
        current = before;
    }

    printf("Segments updated : \n");
    tcp_segment_list_print(buf->segments);

    if (current->seq == buf->initial_seq) {
        buf->next_write = current->seq + current->len;
    }

    printf("ACK: %d\n", buf->next_write);

    return len;
}

ssize_t
tcp_buffer_read(struct tcp_buffer *buf, uint8_t *out, uint16_t len)
{
    printf("\n[BUFFER] [DEBUG] ENTERING: buffer_read\n");
    
    len = min(tcp_buffer_get_readable_size(buf), len);
    uint16_t first = buf->next_read % buf->size;
    uint16_t last = (buf->next_read + len) % buf->size;
    
#if 0
    printf("[BUFFER] [DEBUG] size_to_read: %d\n", size_to_read);
    printf("[BUFFER] [DEBUG] first: %d\n", first);
    printf("[BUFFER] [DEBUG] last: %d\n", last);
#endif // 0

    if (!len) {
        return 0;
    }

    if (last > first) {
#if 0
        printf("[BUFFER] [DEBUG] last > first\n");
#endif // 0
        memcpy(out, buf->data + first, len);
    } else {
        uint16_t size_at_end = buf->size - first;
#if 0
        printf("[BUFFER] [DEBUG] last <= first\n");
        printf("[BUFFER] [DEBUG] size_at_end: %d\n", size_at_end);
        printf("[BUFFER] [DEBUG] size_at_start: %d\n", size_to_read - size_at_end);
#endif // 0

        memcpy(out, buf->data + first, size_at_end);
        memcpy(out + first, buf->data, len - size_at_end);
    }

    buf->next_read += len;

    return len;
}
