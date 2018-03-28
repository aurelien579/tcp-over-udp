#ifndef SEND_BUFFER_H
#define SEND_BUFFER_H

#include <stdint.h>

struct send_buffer;

struct send_buffer *send_buffer_new(struct socket *socket, size_t size);
int send_buffer_add(struct send_buffer *buffer, uint8_t *data, size_t size);
int send_buffer_process(struct send_buffer *buffer);

#endif
