/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <inttypes.h>
#include <rte_malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_xchg.h>

#include "main.h"

#define always_inline __rte_always_inline

// In this application, we represent bursts of packets as vectors (as opposed to
// something opaque, like a LL)
bool xchg_is_vec = true;

// Utils
static always_inline void
rte_xchg_free_large_packet(struct big_packet_metadata *metadata) {
    (metadata->refcnt)--;
    if (metadata->refcnt <= 0) {
        rte_mbuf_raw_free(metadata->mb);
        rte_mempool_put(metadata->metadata_pool,metadata);
    }
}

// RX and common

// Return the buffer length.
always_inline uint16_t xchg_get_len(struct xchg *xchg) {
    (void)xchg;
    return RTE_MBUF_DEFAULT_BUF_SIZE;
}

void xchg_rx_last_packet(struct xchg *xchg, struct xchg **xchgs) {
    (void)xchg;
    (void)xchgs;
}

/**
 * Pops the packet of the user provided buffers
 * Not much to do, the buffer have been already swapped above
 */
always_inline void xchg_rx_advance(struct xchg *xchg, struct xchg ***xchgs_p) {

    struct xchg **xchgs = *xchgs_p;
    // printf("Advance! %p = %p -> %p = %p\n",xchgs,*xchgs, xchgs+1,*(xchgs+1));
    xchgs++;
    *xchgs_p = xchgs;
}

// TX
// Little function to make the cast easier
static always_inline struct my_xchg *get_tx_buf(struct xchg *x) {
    return (struct my_xchg *)x;
}

// Return the real data length (as opposed to the buffer length, which is
// probably a constant)
always_inline uint16_t xchg_get_data_len(struct xchg *xchg) {
    return get_tx_buf(xchg)->plen;
}

// Nothing to do here
always_inline void xchg_tx_completed(struct rte_mbuf **elts, unsigned int part,
                                     unsigned int olx) {
    for (unsigned int i = 0; i < part; i++) {
        struct big_packet_metadata *metadata =
            (struct big_packet_metadata *)elts[i];
        rte_xchg_free_large_packet(metadata);
    }
}

// This was a flag used for testing/research purpose, in XCHG we never "free"
// the transmitted user, we give it back to the application
bool xchg_do_tx_free = true;

// Peek the next packet to be sent, do not advance yet
always_inline struct xchg *xchg_tx_next(struct xchg **xchgs) {
    struct my_xchg *pkt = (struct my_xchg *)*xchgs;
    // printf("Sending XCHG %p -> %p",pkt, pkt->buffer);
    rte_prefetch0(pkt);
    return (struct xchg *)pkt;
}

// Return the number of segments, 1 in this app
always_inline int xchg_nb_segs(struct xchg *xchg) {
    // struct rte_mbuf* pkt = (struct rte_mbuf*) xchg;
    return 1; // NB_SEGS(pkt);
}
/* Advance in the list of packets, that is now permanently moved by one.*/
always_inline void xchg_tx_advance(struct xchg ***xchgs_p) {
    struct my_xchg **pkts = (struct my_xchg **)(*xchgs_p);
    *xchgs_p = pkts + 1;
}

// Return the packet buffer address (not the data)
always_inline void *xchg_get_buffer_addr(struct xchg *xchg) {
    struct my_xchg *p = get_tx_buf(xchg);
    return p->buffer -
           RTE_PKTMBUF_HEADROOM; // Beauty of this : this app is not changing
                                 // the headroom. So we avoid some field
}

// Return the address of the packet buffer
always_inline void *xchg_get_buffer(struct xchg *xchg) {
    return get_tx_buf(xchg)->buffer;
}

// Return the mbuf backing the buffer, try not to touch it! This function should
// be copy-pasted
always_inline struct rte_mbuf *xchg_get_mbuf(struct xchg *xchg) {
    return (struct rte_mbuf *)(((uint8_t *)xchg_get_buffer_addr(xchg)) -
                               sizeof(struct rte_mbuf));
}

// The packet was sent always_inline, therefore no buffer is set up in the ring
// to be recovered later
always_inline void xchg_tx_sent_inline(struct xchg *xchg) {
#if DEBUG_XCHG
#endif
}

// Normal sending of the packet the mbuf backing the buffer of xchg must be set
// in elts
always_inline void xchg_tx_sent(struct rte_mbuf **elts, struct xchg **xchgs) {
    struct rte_mbuf *tmp = *elts;
    // struct rte_mbuf *mbuf = xchg_get_mbuf(*xchgs);

    if (tmp == 0) {
        get_tx_buf(*xchgs)->buffer = 0;
    } else {
        get_tx_buf(*xchgs)->buffer =
            ((uint8_t *)tmp) + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM;
#if DEBUG_XCHG
#endif
    }
    *elts = (struct rte_mbuf *)(*xchgs)->metadata;
}

// This is a testing/research parameter, it should always be false as in a XCHG
// driver, there's no reason to wait before doing the exchange of buffers
bool xchg_elts_vec = false;

always_inline void xchg_tx_sent_vec(struct rte_mbuf **elts, struct xchg **xchg,
                                    unsigned n) {
    assert(false);
}

/**
 * All the unused stuffs we don't use, let the compiler remove that and
 * always_inline the default case!
 */

always_inline void xchg_set_packet_type(struct xchg *xchg, uint32_t ptype){};

always_inline void xchg_set_rss_hash(struct xchg *xchg, uint32_t rss){};

always_inline void xchg_set_timestamp(struct xchg *xchg, uint64_t t){};

always_inline void xchg_set_flag(struct xchg *xchg, uint64_t f){};

always_inline void xchg_clear_flag(struct xchg *xchg, uint64_t f){};

always_inline void xchg_set_fdir_id(struct xchg *xchg, uint32_t mark){};

always_inline void xchg_set_vlan(struct xchg *xchg, uint32_t vlan){};

always_inline void xchg_set_len(struct xchg *xchg, uint16_t len){};

// Author say this should not change, so this should not change
always_inline void *xchg_buffer_from_elt(struct rte_mbuf *buf) {
    return ((unsigned char *)buf) + sizeof(struct rte_mbuf) +
           RTE_PKTMBUF_HEADROOM;
};

#ifdef HAVE_RTC
always_inline bool xchg_rtc_only() { return true; }
#else
always_inline bool xchg_rtc_only() { return false; }
#endif

#ifdef HAVE_NOCQE

always_inline bool xchg_read_len() { return false; }
always_inline bool xchg_need_hash() { return false; }

// Set data_length (the actual packet length)
always_inline void xchg_set_data_len(struct xchg *xchg, uint16_t len) {}

always_inline bool xchg_read_cqe() { return false; };
always_inline bool xchg_need_csum() { return false; };
always_inline bool xchg_need_vlan() { return false; };

always_inline void xchg_rx_finish_packet(struct xchg *xchg) {}

always_inline bool xchg_get_buffer_len(struct xchg *xchg) {
    if (likely(*xchg->buffer)) {
        // printf("Potential batch of %d...", *xchg->buffer);
        if (likely(*(xchg->buffer + asq_header_size +
                     (*xchg->buffer * sizeof(struct descriptor))) == 0x78)) {
            // printf("BUF %p Marker at %lu ok !\n",xchg->buffer,
            // asq_header_size +  (*xchg->buffer * sizeof(struct descriptor) ));
            *(xchg->buffer + asq_header_size +
              (*xchg->buffer * sizeof(struct descriptor))) = 0;
            return true;
        } else {
            // printf("BUF %p Marker at %lu not ok : %x !\n",xchg->buffer,
            // asq_header_size +  (*xchg->buffer * sizeof(struct descriptor) ),
            // *(xchg->buffer +  asq_header_size + (*xchg->buffer *
            // sizeof(struct descriptor) )));
        }
    }
    return false;
}

#else
/**
 * An internal helper to cast the xchg* pointer to the WritablePacket* pointer.
 */
always_inline bool xchg_get_buffer_len(struct xchg *xchg) {
    return xchg->plen;
}
static always_inline struct my_xchg *get_buf(struct xchg *x) {
    return (struct my_xchg *)x;
}

always_inline bool xchg_read_len() { return true; }
always_inline bool xchg_need_hash() { return true; }

// Set data_length (the actual packet length)
always_inline void xchg_set_data_len(struct xchg *xchg, uint16_t len) {
    // fprintf(stderr, "Setting length of %p to %d\n",xchg,len);
    get_buf(xchg)->plen = len;
}

// This functions is called "at the end of the for loop", when the driver has
// finished with a packet, and will start reading the next one. It's a chance to
// wrap up what we need to do. In this case we prefetch the packet data, and set
// a few Click stuffs.
always_inline void xchg_rx_finish_packet(struct xchg *xchg) {
    rte_prefetch0(get_buf(xchg)->buffer);
}

always_inline bool xchg_read_cqe() { return true; };
always_inline bool xchg_need_csum() { return true; };
always_inline bool xchg_need_vlan() { return true; };

#endif

/**
 * This function is called by the driver to advance in the RX ring.
 * Set a new buffer to replace in the ring if not canceled, and return the next
 * descriptor
 */
always_inline struct xchg *xchg_rx_next(struct rte_mbuf **rep,
                                        struct xchg **xchgs,
                                        struct rte_mempool *mp,
                                        int *advance_consumer) {
    if (xchg_rtc_only()) {

        printf("inside rtc_only\n");
        struct my_xchg *first = (struct my_xchg *)*xchgs;

        unsigned char *buffer = ((uint8_t *)*rep) + sizeof(struct rte_mbuf);

        if (first->buffer)
            *advance_consumer = 1;

        first->buffer = buffer + RTE_PKTMBUF_HEADROOM;

        rte_prefetch0(first->buffer);

        return (struct xchg *)first;
    } else {
        struct my_xchg *first = (struct my_xchg *)*xchgs;
        // User should be the one allocating packets here right? => this would
        // enable batch allocation which seems a bit faster
        void *fresh_buf;
        if (unlikely(first->buffer == 0)) {
            // Sometime, the user does not give us a buffer to exchange,
            // typically at initialization
            fresh_buf = rte_mbuf_raw_alloc(mp)->buf_addr;
            if (!fresh_buf) {
                printf("failed to allocate buffer\n");
            }
        } else {
            // We'll take the address of the buffer and put that in the ring
            fresh_buf = ((uint8_t *)first->buffer) - RTE_PKTMBUF_HEADROOM;
            // assert(*(((uint8_t*)fresh_buf) + RTE_PKTMBUF_HEADROOM) == 0x61);
        }

        // The freshly received buffer with the new packet data
        unsigned char *buffer = ((uint8_t *)*rep) + sizeof(struct rte_mbuf);

        // We set the address in the ring
        *rep = (struct rte_mbuf *)(((unsigned char *)fresh_buf) -
                                   sizeof(struct rte_mbuf));

        // We set the address of the new buffer data in the Packet object
        first->buffer = buffer + RTE_PKTMBUF_HEADROOM;

        return (struct xchg *)first;
    }
}

/**
 * Cancel the current receiving, this should cancel the last xchg_next.
 */
always_inline void xchg_rx_cancel(struct xchg *xchg, struct rte_mbuf *rep,
                                  int *advance_consumer) {
    if (!xchg_rtc_only()) {
        xchg->buffer = ((unsigned char *)rep) + sizeof(struct rte_mbuf) +
                       RTE_PKTMBUF_HEADROOM;
    } else { // RTC
        if (!*advance_consumer) {
            xchg->buffer = 0;
        }
    }
}
