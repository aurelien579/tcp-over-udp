#include "buffer.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

struct buffer
{
    u16 size;
    u16 keep_index;   /* Start of the saved data */
    u16 next_write;
    u16 next_read;
    u8  data[];
};

Buffer *buffer_new(u16 size, u16 start_index)
{
    Buffer *self = malloc(size + 3 * sizeof(u16));

    self->size = size;
    self->next_write = start_index;
    self->next_read = start_index;
    self->keep_index = start_index;

    return self;
}

void buffer_free(Buffer *self)
{
    free(self);
}

void buffer_dump(Buffer *self, const char *filename)
{
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (fd < 0) return;

    write(fd, self->data, self->size);

    close(fd);
}

u16 buffer_get_used_space(Buffer *self)
{
    return self->next_write - self->keep_index;
}

u16 buffer_get_free_space(Buffer *self)
{
    return self->size - buffer_get_used_space(self);
}

u16 buffer_get_readable(Buffer *self)
{
    return self->next_write - self->next_read;
}

i32 buffer_write(Buffer *self, const u8 *in, u16 size)
{
    i32 written_size = buffer_write_at(self, self->next_write, in, size);
    if (written_size < 0) return written_size;

    buffer_set_next_write(self, self->next_write + written_size);

    return written_size;
}

i32 buffer_read(Buffer *self, u8 *out, u16 size, u8 flags)
{
    size = min(size, buffer_get_used_space(self));

    if (!size) return 0;

    u16 first = self->next_read % self->size;
    u16 last = (self->next_read + size) % self->size;

    if (first < last) {
        memcpy(out, self->data + first, size);
    } else {
        u16 at_end = self->size - first;
        u16 at_start = size - at_end;

        memcpy(out, self->data + first, at_end);
        memcpy(out + at_end, self->data, at_start);
    }

    if (!(flags & KEEP_DATA)) self->keep_index += size;

    self->next_read += size;

    return size;
}

i32 buffer_write_at(Buffer *self, u16 index, const u8 *in, u16 size)
{
    if (index < self->next_write) return -1;
    if (self->size < (index - self->keep_index) + size) return -1;

    u16 first = index % self->size;
    u16 last = (index + size) % self->size;

    if (first < last) {
        memcpy(self->data + first, in, size);
    } else {
        u16 at_end = self->size - first;
        u16 at_start = size - at_end;

        memcpy(self->data + first, in, at_end);
        memcpy(self->data, in + at_end, at_start);
    }

    return size;
}

i32 buffer_set_next_write(Buffer *self, u16 next_write)
{
    if (next_write < self->next_write) return -1;
    if (next_write - self->keep_index > self->size) return -1;

    self->next_write = next_write;

    return next_write;
}

i32 buffer_set_next_read(Buffer *self, u16 next_read)
{
    if (next_read < self->keep_index) return -1;
    if (next_read > self->next_write) return -1;

    self->next_read = next_read;

    return next_read;
}


u16 buffer_get_last_written(Buffer *self)
{
    return self->next_write - 1;
}

i8 buffer_set_keep_index(Buffer *self, u16 kept)
{
    if (kept > self->next_write) return -1;
    self->keep_index = kept;

    if (self->next_read < self->keep_index) {
        self->next_read = self->keep_index;
    }

    return 1;
}
