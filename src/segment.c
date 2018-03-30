#include "segment.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

static struct seg *
seg_new(uint16_t seq, uint16_t len, struct seg *next)
{
    struct seg *ck = malloc(sizeof(struct seg));
    ck->seq = seq;
    ck->len = len;
    ck->next = next;
    return ck;
}

struct seglist *
seglist_new()
{
    struct seglist *lst = malloc(sizeof(struct seglist));
    lst->head = NULL;
    return lst;
}

void seglist_free(struct seglist *lst)
{
    struct seg *cur = lst->head;
    struct seg *tmp = NULL;
    
    while (cur) {
        tmp = cur->next;
        free(cur);
        cur = tmp;
    }
    
    free(lst);
}

struct seg *
seglist_add(struct seglist *lst, uint16_t seq, uint16_t len)
{
    struct seg *head = lst->head;
    lst->head = seg_new(seq, len, head);
    return lst->head;
}

void
seglist_del(struct seglist *lst, struct seg *seg)
{
    struct seg *cur = lst->head;
    struct seg *prev = NULL;

    while (cur) {
        if (cur == seg) {
            if (prev) {
                prev->next = cur->next;
                free(cur);
                
                return;
            } else {
                lst->head = seg->next;
                free(seg);
                
                return;
            }
        }

        prev = cur;
        cur = cur->next;
    }
}

struct seg *
seg_containing(struct seglist *lst, uint16_t seq)
{
    foreach (struct seg, el, lst, {
        if (seq >= el->seq && seq < el->seq + el->len) {
            return el;
        }
    });

    return NULL;
}

struct seg *
seglist_get_before(struct seglist *lst, uint16_t seq)
{
    foreach (struct seg, el, lst, {
        if ((seq >= el->seq && seq < el->seq + el->len) ||
            el->seq + el->len - 1 <= seq)
        {
            return el;
        }
    });

    return NULL;
}

struct seg *
seglist_get_after(struct seglist *lst, uint16_t seq)
{
    foreach (struct seg, el, lst, {
        if ((seq >= el->seq && seq < el->seq + el->len) ||
            el->seq > seq)
        {
            return el;
        }
    });

    return NULL;
}

void
seglist_print(struct seglist *lst)
{
    foreach (struct seg, el, lst, {
        printf("{ %d - %d }, ", el->seq, el->seq + el->len - 1);
    });

    printf("\n");
}
