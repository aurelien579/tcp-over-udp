#ifndef TCP_LOG_H
#define TCP_LOG_H

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "tcp.h"

static inline void
tcp_log_error(const char *msg)
{
    fprintf(stderr, "[TCP] [ERROR] %s\n", msg);
}

static inline void
tcp_log_errno(const char *msg)
{
    fprintf(stderr, "[TCP] [ERROR] %s : %s\n", msg, strerror(errno));
}

static inline void
tcp_log(const char *msg)
{
    printf("[TCP] [INFO ] %s\n", msg);
}

static inline void
tcp_dump_packet(const struct tcp_packet *packet)
{
    printf("Packet : 0x%x\n", packet->flags);
}

#endif
