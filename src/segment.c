#include "segment.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

static Seg *seg_new(u16 seq, u16 len, Seg *next)
{
    Seg *ck = malloc(sizeof(Seg));
    ck->seq = seq;
    ck->len = len;
    ck->next = next;
    return ck;
}

SegList *seglist_new()
{
    SegList *lst = malloc(sizeof(SegList));
    lst->head = NULL;
    return lst;
}

void seglist_free(SegList *lst)
{
    Seg *cur = lst->head;
    Seg *tmp = NULL;

    while (cur) {
        tmp = cur->next;
        free(cur);
        cur = tmp;
    }

    free(lst);
}

Seg *seglist_add(SegList *lst, u16 seq, u16 len)
{
    Seg *head = lst->head;
    lst->head = seg_new(seq, len, head);
    return lst->head;
}

void seglist_del(SegList *lst, Seg *seg)
{
    Seg *cur = lst->head;
    Seg *prev = NULL;

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

Seg *seg_containing(SegList *lst, u16 seq)
{
    foreach (Seg, el, lst, {
        if (seq >= el->seq && seq < el->seq + el->len) {
            return el;
        }
    });

    return NULL;
}

Seg *seglist_get_before(SegList *lst, u16 seq)
{
    foreach (Seg, el, lst, {
        if ((seq >= el->seq && seq < el->seq + el->len) ||
            el->seq + el->len - 1 <= seq)
        {
            return el;
        }
    });

    return NULL;
}

Seg *seglist_get_after(SegList *lst, u16 seq)
{
    foreach (Seg, el, lst, {
        if ((seq >= el->seq && seq < el->seq + el->len) ||
            el->seq > seq)
        {
            return el;
        }
    });

    return NULL;
}

void seglist_print(const char *filename, SegList *lst)
{
    FILE *f = fopen(filename, "a");
    
    foreach (Seg, el, lst, {
        fprintf(f, "{ %d - %d }, ", el->seq, el->seq + el->len - 1);
    });

    fprintf(f, "\n");

    fclose(f);
}
