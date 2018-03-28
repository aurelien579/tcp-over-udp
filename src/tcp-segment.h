#ifndef TCP_SEGMENT_H
#define TCP_SEGMENT_H

#include <stdint.h>

#define foreach(T, el, list, code)  \
do {                                \
    T *el = list->head;             \
    while (el) {                    \
        code;                       \
        el = el->next;              \
    }                               \
} while (0);                        \


struct tcp_segment
{
    struct tcp_segment *next;
    uint16_t seq;
    uint16_t len;
};

struct tcp_segment_list
{
    struct tcp_segment *head;
};

struct tcp_segment_list *tcp_segment_list_new();
struct tcp_segment *tcp_segment_list_add(struct tcp_segment_list *lst, uint16_t seq, uint16_t len);
void tcp_segment_list_del(struct tcp_segment_list *lst, struct tcp_segment *seg);

struct tcp_segment *tcp_segment_list_get_before(struct tcp_segment_list *lst, uint16_t seq);
struct tcp_segment *tcp_segment_list_get_after(struct tcp_segment_list *lst, uint16_t seq);

struct tcp_segment *tcp_segment_containing(struct tcp_segment_list *lst, uint16_t seq);

void tcp_segment_list_print(struct tcp_segment_list *lst);

#endif
