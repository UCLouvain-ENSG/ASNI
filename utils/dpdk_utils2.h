#include "consts.h"
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_hexdump.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_mbuf_pool_ops.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>

#define rte_ether_addr_PRT_FMT "%02X:%02X:%02X:%02X:%02X:%02X"

#define RTE_ETHER_ADDR_BYTES(mac_addrs)                                        \
    ((mac_addrs)->addr_bytes[0]), ((mac_addrs)->addr_bytes[1]),                \
        ((mac_addrs)->addr_bytes[2]), ((mac_addrs)->addr_bytes[3]),            \
        ((mac_addrs)->addr_bytes[4]), ((mac_addrs)->addr_bytes[5])

#define RTE_ETHER_ADDR_FMT_SIZE 18

struct rte_mempool *rte_pktmbuf_pool_create_with_given_memory(
    const char *name, unsigned int n, unsigned int cache_size,
    uint16_t priv_size, uint16_t data_room_size, int socket_id,
    char *memory_addr, size_t memory_size, size_t page_size);

void rte_pktmbuf_set_iova(struct rte_mempool *mp, void *opaque_arg, void *_m,
                          __rte_unused unsigned i);

void rte_pktmbuf_set_addr(struct rte_mempool *mp, void *opaque_arg, void *_m,
                          __rte_unused unsigned i);

int large_mtu_port_init(uint16_t port, struct rte_mempool *mbuf_pool,
                        uint16_t rx_rings, uint16_t tx_rings,
                        uint16_t mtu_size,uint16_t nb_desc);

int normal_mtu_port_init(uint16_t port, struct rte_mempool *mbuf_pool,
                         uint16_t rx_rings, uint16_t tx_rings);

void rte_pktmbuf_set_shared_info(struct rte_mempool *mp, void *opaque_arg,
                                 void *_m, __rte_unused unsigned i);

void rte_pktmbuf_set_next(struct rte_mempool *mp, void *opaque_arg, void *_m,
                          __rte_unused unsigned i);

void rte_pktmbuf_set_l4_len(struct rte_mempool *mp, void *opaque_arg, void *_m,
                            __rte_unused unsigned i);

void rte_pktmbuf_set_priv_size(struct rte_mempool *mp, void *opaque_arg,
                               void *_m, __rte_unused unsigned i);

void rte_pktmbuf_set_dynfield1(struct rte_mempool *mp, void *opaque_arg,
                               void *_m, __rte_unused unsigned i);
