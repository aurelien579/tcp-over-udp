#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void panic(const char *msg)
{
    fprintf(stderr, "[PANIC] %s\n", msg);
    exit(EXIT_FAILURE);
}

void panic_perror(const char *msg)
{
    fprintf(stderr, "[PANIC] %s : %s\n", msg, strerror(errno));
    exit(EXIT_FAILURE);
}

int min(int a, int b)
{
    if (a < b) return a;
    else return b;
}

int max(int a, int b)
{
    if (a > b) return a;
    else return b;
}

