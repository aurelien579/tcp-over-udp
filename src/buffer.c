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
    size_t size;
    size_t next_write;
    size_t next_read;
    unsigned char data[];
};

struct buffer *
buffer_new(size_t size, size_t start_index)
{
    struct buffer *self = malloc(size + 3 * sizeof(size_t));

    self->size = size;
    self->next_write = start_index;
    self->next_read = start_index;

    return self;
}

void
buffer_free(struct buffer *self)
{
    free(self);}

void
buffer_dump(struct buffer *self, const char *filename)
{
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (fd < 0) return;
    
    write(fd, self->data, self->size);
    
    close(fd);
}

size_t
buffer_get_used_space(struct buffer *self)
{
    return self->next_write - self->next_read;
}

size_t
buffer_get_free_space(struct buffer *self)
{
    return self->size - buffer_get_used_space(self);
}

ssize_t
buffer_write(struct buffer *self, const unsigned char *in, size_t size)
{
    ssize_t written_size = buffer_write_at(self, self->next_write, in, size);
    if (written_size < 0) return written_size;
    
    buffer_set_next_write(self, self->next_write + written_size);
    
    return written_size;
}

ssize_t
buffer_read(struct buffer *self, unsigned char *out, size_t size)
{
    size = min(size, buffer_get_used_space(self));
    
    if (!size) return 0;
    
    size_t first = self->next_read % self->size;
    size_t last = (self->next_read + size) % self->size;
    
    if (first < last) {
        memcpy(out, self->data + first, size);
    } else {        
        size_t at_end = self->size - first;
        size_t at_start = size - at_end;
        
        memcpy(out, self->data + first, at_end);
        memcpy(out + at_end, self->data, at_start);
    }
    
    self->next_read += size;
    
    return size;
}

ssize_t
buffer_write_at(struct buffer *self, size_t index, const unsigned char *in,
                size_t size)
{
    if (index < self->next_write) return -1;
    if (self->size < (index - self->next_read) + size) return -1;
    
    size_t first = index % self->size;
    size_t last = (index + size) % self->size;    
    
    if (first < last) {
        memcpy(self->data + first, in, size);
    } else {        
        size_t at_end = self->size - first;
        size_t at_start = size - at_end;
        
        memcpy(self->data + first, in, at_end);
        memcpy(self->data, in + at_end, at_start);
    }

    return size;
}

ssize_t
buffer_set_next_write(struct buffer *self, size_t next_write)
{
    if (next_write < self->next_write) return -1;
    if (next_write - self->next_read > self->size) return -1;
    
    self->next_write = next_write;
    
    return next_write;
}
