#include "dpdk_utils2.h"
#include <getopt.h>
#include <inttypes.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>

struct rte_mempool *rte_pktmbuf_pool_create_with_given_memory(
    const char *name, unsigned int n, unsigned int cache_size,
    uint16_t priv_size, uint16_t data_room_size, int socket_id,
    char *memory_addr, size_t memory_size, size_t page_size) {
    struct rte_mempool *mp;
    struct rte_pktmbuf_pool_private mbp_priv;
    const char *mp_ops_name = NULL;
    unsigned elt_size;
    int ret;

    if (RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) != priv_size) {
        RTE_LOG(ERR, MBUF, "mbuf priv_size=%u is not aligned\n", priv_size);
        rte_errno = EINVAL;
        return NULL;
    }
    elt_size = sizeof(struct rte_mbuf) + (unsigned)priv_size +
               (unsigned)data_room_size;
    memset(&mbp_priv, 0, sizeof(mbp_priv));
    mbp_priv.mbuf_data_room_size = data_room_size;
    mbp_priv.mbuf_priv_size = priv_size;

    mp = rte_mempool_create_empty(name, n, elt_size, cache_size,
                                  sizeof(struct rte_pktmbuf_pool_private),
                                  socket_id, 0);
    if (mp == NULL)
        return NULL;

    if (mp_ops_name == NULL)
        mp_ops_name = rte_mbuf_best_mempool_ops();
    ret = rte_mempool_set_ops_byname(mp, mp_ops_name, NULL);
    if (ret != 0) {
        RTE_LOG(ERR, MBUF, "error setting mempool handler\n");
        rte_mempool_free(mp);
        rte_errno = -ret;
        return NULL;
    }
    rte_pktmbuf_pool_init(mp, &mbp_priv);

    ret = rte_mempool_populate_virt(mp, memory_addr, memory_size, page_size,
                                    NULL, NULL);
    if (ret < 0) {
        rte_mempool_free(mp);
        rte_errno = -ret;
        return NULL;
    }

    rte_mempool_obj_iter(mp, rte_pktmbuf_init, NULL);
    return mp;
}

void rte_pktmbuf_set_addr(struct rte_mempool *mp, void *opaque_arg, void *_m,
                          __rte_unused unsigned i) {
    uint64_t addr = (uint64_t)opaque_arg;
    // printf("lkey : %u\n",lkey);
    struct rte_mbuf *m = _m;
    m->buf_addr = (void *)addr;
}

void rte_pktmbuf_set_l4_len(struct rte_mempool *mp, void *opaque_arg, void *_m,
                            __rte_unused unsigned i) {
    uint64_t addr = (uint64_t)opaque_arg;
    // printf("lkey : %u\n",lkey);
    struct rte_mbuf *m = _m;
    m->l4_len = addr;
}
void rte_pktmbuf_set_priv_size(struct rte_mempool *mp, void *opaque_arg,
                               void *_m, __rte_unused unsigned i) {
    uint64_t addr = (uint64_t)opaque_arg;
    // printf("lkey : %u\n",lkey);
    struct rte_mbuf *m = _m;
    m->priv_size = addr;
}
void rte_pktmbuf_set_dynfield1(struct rte_mempool *mp, void *opaque_arg,
                               void *_m, __rte_unused unsigned i) {
    uint64_t addr = (uint64_t)opaque_arg;
    // printf("lkey : %u\n",lkey);
    struct rte_mbuf *m = _m;
    m->dynfield1[0] = addr;
}

int large_mtu_port_init(uint16_t port, struct rte_mempool *mbuf_pool,
                        uint16_t rx_rings, uint16_t tx_rings,
                        uint16_t mtu_size,uint16_t nb_desc) {
    uint16_t nb_rxd = nb_desc;
    uint16_t nb_txd = nb_desc;
    int retval;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    static struct rte_eth_conf port_conf = {
        .rxmode =
            {
                .offloads = RTE_ETH_RX_OFFLOAD_SCATTER,
                .mtu = 32000,
            },
        .txmode =
            {
                .mq_mode = RTE_ETH_MQ_TX_NONE,
                .offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS,
            },
    };

    //	static struct rte_eth_conf port_conf;
    //        memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n", port,
               strerror(-retval));
        return retval;
    }
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
        printf("fast free enabled\n");
    }
    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;
    retval = rte_eth_dev_set_mtu(port, 9800);
    if (retval != 0)
        return retval;
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;
    printf("nb_rxd : %d\n", nb_rxd);
    printf("nb_txd : %d\n", nb_txd);
    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (uint16_t q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(
            port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per user port. */
    for (uint16_t q = 0; q < tx_rings; q++) {
        retval =
            rte_eth_tx_queue_setup(port, q, nb_txd, SOCKET_ID_ANY, &txconf);
        if (retval < 0)
            return retval;
    }

    /* Starting Ethernet port. 8< */
    retval = rte_eth_dev_start(port);
    /* >8 End of starting of ethernet port. */
    if (retval < 0)
        return retval;

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    /* End of setting RX port in promiscuous mode. */
    if (retval != 0)
        return retval;

    return 0;
}

int normal_mtu_port_init(uint16_t port, struct rte_mempool *mbuf_pool,
                         uint16_t rx_rings, uint16_t tx_rings) {
    uint16_t nb_rxd = RTE_RX_DESC_DEFAULT;
    uint16_t nb_txd = RTE_TX_DESC_DEFAULT;
    int retval;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    static struct rte_eth_conf port_conf = {
        .rxmode =
            {
                .offloads = 0,
            },
        .txmode =
            {
                .offloads = 0,
            },
    };

    //	static struct rte_eth_conf port_conf;
    //        memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n", port,
               strerror(-retval));
        return retval;
    }

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (uint16_t q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(
            port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (uint16_t q = 0; q < tx_rings; q++) {
        retval =
            rte_eth_tx_queue_setup(port, q, nb_txd, SOCKET_ID_ANY, &txconf);
        if (retval < 0)
            return retval;
    }

    /* Starting Ethernet port. 8< */
    retval = rte_eth_dev_start(port);
    /* >8 End of starting of ethernet port. */
    if (retval < 0)
        return retval;

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    /* End of setting RX port in promiscuous mode. */
    if (retval != 0)
        return retval;

    return 0;
}

int split_port_init(uint16_t port, struct rte_mempool *mbuf_pool,
                    uint16_t rx_rings, uint16_t tx_rings) {
    uint16_t nb_rxd = RTE_RX_DESC_DEFAULT;
    uint16_t nb_txd = RTE_TX_DESC_DEFAULT;
    int retval;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    static struct rte_eth_conf port_conf = {
        .rxmode =
            {
                .offloads = RTE_ETH_RX_OFFLOAD_SCATTER,
            },
        .txmode =
            {
                .offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS,
            },
    };

    //	static struct rte_eth_conf port_conf;
    //        memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n", port,
               strerror(-retval));
        return retval;
    }

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_set_mtu(port, 9800);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (uint16_t q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(
            port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (uint16_t q = 0; q < tx_rings; q++) {
        retval =
            rte_eth_tx_queue_setup(port, q, nb_txd, SOCKET_ID_ANY, &txconf);
        if (retval < 0)
            return retval;
    }

    /* Starting Ethernet port. 8< */
    retval = rte_eth_dev_start(port);
    /* >8 End of starting of ethernet port. */
    if (retval < 0)
        return retval;

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    /* End of setting RX port in promiscuous mode. */
    if (retval != 0)
        return retval;

    return 0;
}
