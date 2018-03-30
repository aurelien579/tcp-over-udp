#ifndef SEGMENT_H
#define SEGMENT_H

#include "types.h"

#define foreach(T, el, list, code)  \
do {                                \
    T *el = list->head;             \
    while (el) {                    \
        code;                       \
        el = el->next;              \
    }                               \
} while (0);                        \


struct seg
{
    struct seg *next;
    u16    seq;
    u16    len;
};

typedef struct seg Seg;


struct seglist
{
    Seg *head;
};

typedef struct seglist SegList;

SegList *seglist_new();
void seglist_free(SegList *lst);

Seg *seglist_add(SegList *lst, u16 seq, u16 len);

void seglist_del(SegList *lst, Seg *seg);

Seg *seglist_get_before(SegList *lst, u16 seq);
Seg *seglist_get_after(SegList *lst, u16 seq);

Seg *seg_containing(SegList *lst, u16 seq);

void seglist_print(const char *filename, SegList *lst);

#endif
