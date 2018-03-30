#ifndef TCP_LOG_H
#define TCP_LOG_H

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>

#include "tcp.h"

#define LOG_FATAL       0
#define LOG_WARNING     1
#define LOG_INFO        2
#define LOG_DEBUG       3

#ifndef LOG_LEVEL
#define LOG_LEVEL      (LOG_DEBUG + 1)
#endif

#define LOG_FILE        "log.txt"

static inline void tcp_log_error(const char *id, const char *msg)
{
    fprintf(stderr, "[%s] [ERROR] %s\n", id, msg);
}

static inline void tcp_log_errno(const char *id, const char *msg)
{
    fprintf(stderr, "[%s] [ERROR] %s : %s\n", id, msg, strerror(errno));
}

static inline void tcp_log(const char *id, const char *format, ...)
{
#ifdef LOG_FILE
    FILE *out = fopen(LOG_FILE, "a");
#else
    FILE *out = stdout;
#endif

    va_list args;
    va_start(args, format);
    
    char date_buf[32];
    time_t rawtime;
    struct tm *timeinfo;
    struct timeval tval;

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    gettimeofday(&tval, NULL);

    strftime(date_buf, sizeof(date_buf), "%H:%M:%S", timeinfo);

    fprintf(out, "%s.%04ld [%s] ", date_buf, tval.tv_usec * 1000,id);
    vfprintf(out, format, args);
    fprintf(out, "\n");

    va_end(args);

#ifdef LOG_FILE
    fclose(out);
#endif
}

static inline void dump_packet(const Packet *packet)
{
    printf("Packet : 0x%x\n", packet->flags);
}

#endif
