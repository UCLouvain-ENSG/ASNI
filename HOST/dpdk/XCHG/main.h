struct xchg {
    uint8_t* buffer;
    uint16_t plen;
};

#define my_xchg xchg

#ifdef HAVE_MINIMAL
struct descriptor {
    uint16_t data_len;
} __attribute__((packed));
#else
struct descriptor {
    uint32_t ip_src;
    uint32_t ip_dst;
    uint64_t timestamp;
    uint32_t data_len;
} __attribute__((packed));
#endif

static const int asq_header_size = 16;

#define DEBUG_XCHG 0
