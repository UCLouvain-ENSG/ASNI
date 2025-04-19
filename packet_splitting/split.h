#include "asq_descriptors.h"
#include "consts.h"
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BURST_SIZE 64
#define NB_MBUF 2048
#define POOL_CACHE_SIZE 256

struct split_context {
    struct rte_mempool *ext_info_pool;
    struct rte_mempool *metadata_pool;
    struct rte_mempool *tx_mbuf_pool;
};

void split_packet(struct rte_mbuf *large_pkt, uint16_t port_id, uint16_t qid,
                  struct split_context *ctx, struct rte_mbuf **pkts_burst_tx);

static inline void free_large_packet(struct metadata_tx_asni *metadata) {
    rte_pktmbuf_free(metadata->mb);
    rte_mempool_put(metadata->ext_info_pool, metadata->shinfo);
    rte_mempool_put(metadata->metadata_pool, metadata);
}

static inline void free_cb(void *addr, void *opaque) {
    struct metadata_tx_asni *md = (struct metadata_tx_asni *)opaque;
    free_large_packet(md);
}

struct split_context *split_context_init(uint16_t qid) {
    printf("Creating split context for queue %d\n", qid);
    struct split_context *ctx =
        (struct split_context *)malloc(sizeof(struct split_context));
    if (unlikely(ctx == NULL)) {
        rte_exit(EXIT_FAILURE, "Failed to allocate split_context\n");
    }
    char ext_info_pool_name[128] = "X_EXT_INFO_POOL";
    char metadata_pool_name[128] = "X_METADATA_POOL";
    char tx_mbuf_pool_name[128] = "X_TX_MBUF_POOL";
    ext_info_pool_name[0] = '0' + qid;
    metadata_pool_name[0] = '0' + qid;
    tx_mbuf_pool_name[0] = '0' + qid;

    ctx->ext_info_pool = rte_mempool_create(
        ext_info_pool_name, NB_MBUF, sizeof(struct rte_mbuf_ext_shared_info), 0,
        0, NULL, NULL, NULL, NULL, 0, 0);
    if (ctx->ext_info_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create ext_info_pool\n");
    }
    ctx->metadata_pool = rte_mempool_create(metadata_pool_name, NB_MBUF,
                                            sizeof(struct metadata_tx_asni), 0,
                                            0, NULL, NULL, NULL, NULL, 0, 0);
    if (ctx->metadata_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create metadata_pool\n");
    }
    ctx->tx_mbuf_pool = rte_pktmbuf_pool_create(
        tx_mbuf_pool_name, NB_MBUF, POOL_CACHE_SIZE, 0, 256, rte_socket_id());
    if (ctx->tx_mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }
    return ctx;
}

void split_packet_no_dpt(struct rte_mbuf *large_pkt, uint16_t port_id,
                         uint16_t qid, struct split_context *ctx,
                         struct rte_mbuf **pkts_burst_tx) {
    struct rte_mbuf_ext_shared_info *ext_info;
    struct metadata_tx_asni *metadata;
    struct rte_mempool *ext_info_pool = ctx->ext_info_pool;
    struct rte_mempool *metadata_pool = ctx->metadata_pool;
    struct rte_mempool *tx_mbuf_pool = ctx->tx_mbuf_pool;
    uint32_t offset_desc = DESC_OFFSET;
    uint8_t *payload;
    uint8_t *data = rte_pktmbuf_mtod(large_pkt, uint8_t *);
    uint8_t nb_desc = *data;
    payload = data + offset_desc + (nb_desc * sizeof(struct descriptor));
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)data;
    int magic = *(int *)(&eth_hdr->src_addr.addr_bytes[1]);

    if (unlikely(nb_desc < 1 || nb_desc > 64 || magic != MAGIC)) {

        printf("=============\n");
        printf("received packet with wrong number of descriptors : %d, or "
               "wrong MAGIC : %d\n",
               nb_desc, magic);
        printf("Pkt len : %d\n", large_pkt->pkt_len);
        printf("=============\n");
    } else {

        if (rte_mempool_get(metadata_pool, (void **)&metadata) < 0) {
            rte_exit(EXIT_FAILURE, "Failed to allocate metadata\n");
        }
        if (rte_mempool_get(ext_info_pool, (void **)&ext_info) < 0) {
            rte_exit(EXIT_FAILURE, "Failed to allocate ext_info\n");
        }
        int nb_alloc_descriptors =
            rte_pktmbuf_alloc_bulk(tx_mbuf_pool, pkts_burst_tx, nb_desc);
        if (nb_alloc_descriptors != 0) {
            rte_exit(EXIT_FAILURE, "Failed to allocate descriptors\n");
        }

        metadata->mb = large_pkt;
        ext_info->fcb_opaque = metadata;
        ext_info->free_cb = free_cb;
        ext_info->refcnt = nb_desc;
        metadata->shinfo = ext_info;
        metadata->ext_info_pool = ext_info_pool;
        metadata->metadata_pool = metadata_pool;

        struct descriptor *desc = (struct descriptor *)(data + offset_desc);
        int length = desc->size;
        rte_pktmbuf_attach_extbuf(pkts_burst_tx[0], payload, 0, length,
                                  ext_info);
        pkts_burst_tx[0]->pkt_len = length;
        pkts_burst_tx[0]->data_len = length;

        for (uint8_t j = 1; j < nb_desc; j++) {
            payload += length;
            desc++;
            length = desc->size;
            rte_pktmbuf_attach_extbuf(pkts_burst_tx[j], payload, 0, length,
                                      ext_info);
            pkts_burst_tx[j]->pkt_len = length;
            pkts_burst_tx[j]->data_len = length;
        }
        const uint16_t sent =
            rte_eth_tx_burst(port_id, qid, pkts_burst_tx, nb_desc);

        for (int i = sent; i < nb_desc; i++) {
            rte_pktmbuf_free(pkts_burst_tx[i]);
        }
    }
}

#ifdef FAKE_DPDK_DESC_MBUF
void split_packet_dpt(struct rte_mbuf *desc_pkt, uint16_t port_id, uint16_t qid,
                      struct rte_mbuf **pkts_burst_tx) {

    uint32_t offset_desc = DESC_OFFSET;
    uint8_t *data = rte_pktmbuf_mtod(desc_pkt, uint8_t *);
    uint8_t nb_desc = *data;
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)data;
    int magic = *(int *)(&eth_hdr->src_addr.addr_bytes[1]);
    if (unlikely(nb_desc < 1 || nb_desc > 64 || magic != MAGIC)) {
        printf("=============\n");
        printf("received packet with wrong number of descriptors : %d, or "
               "wrong MAGIC : %d\n",
               nb_desc, magic);
        printf("Pkt len : %d\n", desc_pkt->pkt_len);
        printf("=============\n");
    } else {

        struct descriptor *desc = (struct descriptor *)(data + offset_desc);
        for (int i = 0; i < nb_desc; i++) {
            int length = desc->size;
            pkts_burst_tx[i] = desc->mb;
        }
        const uint16_t sent =
            rte_eth_tx_burst(port_id, 0, pkts_burst_tx, nb_desc);
        for (int i = sent; i < nb_desc; i++) {
            rte_pktmbuf_free(pkts_burst_tx[i]);
        }
    }
}
#endif
