#include "buffer.h"

int
main(int argc, char **argv)
{
    struct buffer *buffer = buffer_new(512, 0);
    char data[512];

    memset(data, 0, sizeof(data));

    buffer_write_at(buffer, 10, "TEST1", 5);
    buffer_write(buffer, "TEST2     ", 10);
    buffer_set_next_write(buffer, 15);

    buffer_read(buffer, data, 512, 1);
    printf("read: %s\n", data);

    buffer_write(buffer, "TEST3", 5);

    memset(data, 0, sizeof(data));
    buffer_read(buffer, data, 512, 0);
    printf("read: %s\n", data);

    buffer_dump(buffer, "dump");

    return 0;
}
