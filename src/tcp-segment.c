#include "tcp-segment.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

static struct tcp_segment *
tcp_segment_new(uint16_t seq, uint16_t len, struct tcp_segment *next)
{
    struct tcp_segment *ck = malloc(sizeof(struct tcp_segment));
    ck->seq = seq;
    ck->len = len;
    ck->next = next;
    return ck;
}

struct tcp_segment_list *
tcp_segment_list_new()
{
    struct tcp_segment_list *lst = malloc(sizeof(struct tcp_segment_list));
    lst->head = NULL;
    return lst;
}

struct tcp_segment *
tcp_segment_list_add(struct tcp_segment_list *lst, uint16_t seq, uint16_t len)
{
    struct tcp_segment *head = lst->head;
    lst->head = tcp_segment_new(seq, len, head);
    return lst->head;
}

void
tcp_segment_list_del(struct tcp_segment_list *lst, struct tcp_segment *seg)
{
    struct tcp_segment *cur = lst->head;
    struct tcp_segment *prev = NULL;

    while (cur) {
        if (cur == seg) {
            if (prev) {
                /* MEMORY LEAK !!!! */
                prev->next = cur->next;
                return;
            } else {
                /* MEMORY LEAK !!!! */
                lst->head = seg->next;
                return;
            }
        }

        prev = cur;
        cur = cur->next;
    }
}

struct tcp_segment *
tcp_segment_containing(struct tcp_segment_list *lst, uint16_t seq)
{
    foreach (struct tcp_segment, el, lst, {
        if (seq >= el->seq && seq < el->seq + el->len) {
            return el;
        }
    });

    return NULL;
}

struct tcp_segment *
tcp_segment_list_get_before(struct tcp_segment_list *lst, uint16_t seq)
{
    foreach (struct tcp_segment, el, lst, {
        if ((seq >= el->seq && seq < el->seq + el->len) ||
            el->seq + el->len - 1 <= seq)
        {
            return el;
        }
    });

    return NULL;
}

struct tcp_segment *
tcp_segment_list_get_after(struct tcp_segment_list *lst, uint16_t seq)
{
    foreach (struct tcp_segment, el, lst, {
        if ((seq >= el->seq && seq < el->seq + el->len) ||
            el->seq > seq)
        {
            return el;
        }
    });

    return NULL;
}

void
tcp_segment_list_print(struct tcp_segment_list *lst)
{
    foreach (struct tcp_segment, el, lst, {
        printf("{ %d - %d }, ", el->seq, el->seq + el->len - 1);
    });

    printf("\n");
}
