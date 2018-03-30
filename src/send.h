#ifndef SEND_BUFFER_H
#define SEND_BUFFER_H

#include "types.h"

i32 send_packet(Socket *sock, Packet *packet, u16 data_sz);
i8 send_queue_process(Socket *sock);

#endif
