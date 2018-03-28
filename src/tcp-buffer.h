#ifndef TCP_BUFFER_H
#define TCP_BUFFER_H

#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>

struct tcp_buffer;

struct tcp_buffer *tcp_buffer_new(uint16_t size, uint16_t seq);

ssize_t tcp_buffer_write(struct tcp_buffer *buf,
                         uint16_t seq,
                         const uint8_t *in,
                         uint16_t size);

ssize_t tcp_buffer_read(struct tcp_buffer *buf,
                        uint8_t *out,
                        uint16_t size);

#endif

