#ifndef TCP_LOG_H
#define TCP_LOG_H

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "tcp.h"

static inline void
tcp_log_error(const char *id, const char *msg)
{
    fprintf(stderr, "[%s] [ERROR] %s\n", id, msg);
}

static inline void
tcp_log_errno(const char *id, const char *msg)
{
    fprintf(stderr, "[%s] [ERROR] %s : %s\n", id, msg, strerror(errno));
}

static inline void
tcp_log(const char *id, const char *msg)
{
    printf("[%s] [INFO ] %s\n", id, msg);
}

static inline void
dump_packet(const struct tcp_packet *packet)
{
    printf("Packet : 0x%x\n", packet->flags);
}

#endif
