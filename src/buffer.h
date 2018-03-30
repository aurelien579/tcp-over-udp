#ifndef BUFFER_H
#define BUFFER_H

#include <sys/types.h>
#include "types.h"

/* Read flags */
#define ERASE_DATA     0
#define KEEP_DATA      1

typedef struct buffer Buffer;

Buffer *buffer_new(u16 size, u16 start_index);
void buffer_free(Buffer *self);

void buffer_dump(Buffer *self, const char *filename);

u16 buffer_get_used_space(Buffer *self);
u16 buffer_get_free_space(Buffer *self);


u16 buffer_get_readable(Buffer *self);

/**
 * @brief Write @size bytes in the buffer. Return -1 on error, if there is no
 *   more free space
 * @return the number of bytes written or -1 on error
 */
i32 buffer_write(Buffer *self, const u8 *in, u16 sz);


/**
 * @brief Read at maximun @size bytes from the buffer in @out. No error when
 *   there is nothing to read, just return 0.
 * @param flags
 *      ERASE_DATA  : Data won't be read again
 *      KEEP_DATA   : Data will be read again
 * @return the number of bytes read
 */
i32 buffer_read(Buffer *self, u8 *out, u16 size, u8 flags);


/**
 * @brief Advance the next_read cursor to erase data that have been read using
 *  the flag KEEP_DATA. Error when tring to move backward or after the
 *  next_write cursor
 * @return next_read or -1 on error
 */
i32 buffer_set_next_read(Buffer *self, u16 next_read);


/**
 * @brief Works like buffer_write but the start index is specified.
 * @return the number of bytes written or -1 on error
 */
i32 buffer_write_at(Buffer *self, u16 index, const u8 *in, u16 size);


/**
 * @brief Can advance in the buffer, when data has already been written using
 *   buffer_write_at. Error when trying to go backward in the buffer or when
 *   trying to go beyond maximun size.
 * @return the new next_wrte or -1 on error
 */
i32 buffer_set_next_write(Buffer *self, u16 next_write);


u16 buffer_get_last_written(Buffer *self);

i8 buffer_set_keep_index(Buffer *self, u16 kept);

#endif
