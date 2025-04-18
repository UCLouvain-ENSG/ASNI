#pragma once
#include "asni_descriptors.h"
#include <stdint.h>
struct xchg {
    uint8_t *buffer;
    uint16_t plen;
#ifdef ASNI_MODE_XCHG
    uint32_t rss_hash;
#endif
};

#define my_xchg xchg

static const int asni_header_size = 16;

#define DEBUG_XCHG 0
