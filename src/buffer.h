#ifndef BUFFER_H
#define BUFFER_H

#include <sys/types.h>

struct buffer;

struct buffer *buffer_new(size_t size, size_t start_index);
void buffer_free(struct buffer *self);

void buffer_dump(struct buffer *self, const char *filename);

size_t buffer_get_used_space(struct buffer *self);
size_t buffer_get_free_space(struct buffer *self);

/**
 * @brief Write @size bytes in the buffer. Return -1 on error, if there is no
 *   more free space
 * @return the number of bytes written or -1 on error
 */
ssize_t buffer_write(struct buffer *self, const unsigned char *in, size_t size);

/**
 * @brief Read at maximun @size bytes from the buffer in @out. No error when
 *   there is nothing to read, just return 0
 * @return the number of bytes read
 */
ssize_t buffer_read(struct buffer *self, unsigned char *out, size_t size);

/**
 * @brief Works like buffer_write but the start index is specified.
 * @return the number of bytes written or -1 on error
 */
ssize_t buffer_write_at(struct buffer *self, size_t index,
                        const unsigned char *in, size_t size);

/**
 * @brief Can advance in the buffer, when data has already been written using
 *   buffer_write_at. Error when trying to go backward in the buffer or when
 *   trying to go beyond maximun size.
 * @return the new next_wrte or -1 on error
 */
ssize_t buffer_set_next_write(struct buffer *self, size_t next_write);

#endif
