#pragma once
#include "../../../utils/asni_descriptors.h"
#include <stdint.h>
struct xchg {
    uint8_t *buffer;
    uint16_t plen;
    struct big_packet_metadata *metadata;
};

#define my_xchg xchg

static const int asni_header_size = 16;

#define DEBUG_XCHG 0
