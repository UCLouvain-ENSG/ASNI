#pragma once
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct big_packet_metadata {
    uint8_t refcnt;
    struct rte_mbuf *mb;
    struct rte_mempool *metadata_pool;
};

struct metadata_tx_asni {
    struct rte_mbuf *mb;
    struct rte_mbuf_ext_shared_info *shinfo;
    struct rte_mempool *ext_info_pool;
    struct rte_mempool *metadata_pool;
};

struct metadata_tx_asni_mica {
    struct rte_mbuf *mb;
    struct rte_mempool *metadata_pool;
    uint16_t refcnt;
};
#ifdef FAKE_DPDK_MODE_DMA
struct __attribute__((aligned(64)))
#endif
#if defined(FAKE_DPDK_MODE_DPDK_ASQ) ||                                        \
    defined(FAKE_DPDK_MODE_DPDK_ASQ_OFFLOAD_TX) ||                             \
    defined(FAKE_DPDK_MODE_DPDK_CLASSIC) ||                                    \
    defined(FAKE_DPDK_MODE_DPDK_ASQ_DPT) ||                                    \
    defined(FAKE_DPDK_MODE_DPDK_ASQ_HW_DP) ||                                  \
    defined(FAKE_DPDK_MODE_DPDK_ASQ_HW_DD) || defined(FAKE_DPDK_MODE_XCHG) ||  \
    defined(FAKE_DPDK_MODE_XCHG_ASNI)
struct __attribute__((packed))
#endif
#if defined(FAKE_DPDK_MODE_DPDK_BASELINE)
struct
#endif
    /* #ifdef XCHG */
    /* xchg { */
    /* #else */
    descriptor {
/* #endif */
#ifdef FAKE_DPDK_MODE_DPDK_BASELINE
    struct rte_mbuf;
#endif
/* #ifdef XCHG */
/*     uint8_t *buffer; */
/*     uint16_t plen; */
/*     struct big_packet_metadata *metadata; */
/* #endif */
#if defined(FAKE_DPDK_MODE_DPDK_ASQ_HW_DP) ||                                  \
    defined(FAKE_DPDK_MODE_DPDK_ASQ_HW_DD)
    uint16_t size;
    uint32_t rss_hash;
    void *payload;
    /* Plenty of space for other fields  */
    char padding3[36];
#else
#ifdef FAKE_DPDK_DESC_MAC_SRC
    unsigned char mac_src[6];
#endif
#ifdef FAKE_DPDK_DESC_MAC_DST
    unsigned char mac_dst[6];
#endif
#ifdef FAKE_DPDK_MODE_DMA
    volatile bool full;
#endif
#ifdef FAKE_DPDK_DESC_ETH_TYPE
    volatile uint16_t eth_type;
#endif
#ifdef FAKE_DPDK_DESC_IP_SRC
    volatile uint32_t ip_src;
#endif
#ifdef FAKE_DPDK_DESC_IP_DST
    volatile uint32_t ip_dst;
#endif
#ifdef FAKE_DPDK_DESC_PORT_SRC
    volatile uint16_t port_src;
#endif
#ifdef FAKE_DPDK_DESC_PORT_DST
    volatile uint16_t port_dst;
#endif
#ifdef FAKE_DPDK_DESC_IP_PROTO
    volatile uint8_t ip_proto;
#endif
#ifdef FAKE_DPDK_DESC_TIMESTAMP
    volatile uint64_t timestamp;
#endif
#ifdef FAKE_DPDK_DESC_SIZE
    volatile uint32_t size;
#endif
#ifdef FAKE_DPDK_DESC_PAYLOAD
    char *payload_ptr;
#endif
#ifdef FAKE_DPDK_DESC_HASH
    uint32_t rss_hash;
#endif
#ifdef FAKE_DPDK_DESC_OPAQUE
    void *opaque;
#endif
#ifdef FAKE_DPDK_DESC_MBUF
    struct rte_mbuf *mb;
#endif
#if defined(FAKE_DPDK_DESC_PAD)
    uint8_t padding[FAKE_DPDK_DESC_PAD];
#endif
#endif
};
