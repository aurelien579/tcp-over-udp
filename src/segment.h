#ifndef SEGMENT_H
#define SEGMENT_H

#include <stdint.h>

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
    uint16_t    seq;
    uint16_t    len;
};

struct seglist
{
    struct seg *head;
};

struct seglist *seglist_new();
void seglist_free(struct seglist *lst);

struct seg *seglist_add(struct seglist *lst, uint16_t seq, uint16_t len);

void seglist_del(struct seglist *lst, struct seg *seg);

struct seg *seglist_get_before(struct seglist *lst, uint16_t seq);
struct seg *seglist_get_after(struct seglist *lst, uint16_t seq);

struct seg *seg_containing(struct seglist *lst, uint16_t seq);

void seglist_print(struct seglist *lst);

#endif
