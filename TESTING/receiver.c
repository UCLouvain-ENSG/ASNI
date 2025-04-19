

#include "test_utils.h"
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_errno.h>

uint16_t port = 0;

struct rte_mempool *huge_mbuf_pool;

static int job(void *arg) {
    struct rte_mbuf *bufs[32];

    uint16_t nb_rx;
    while (1) {
        nb_rx = rte_eth_rx_burst(port, 0, bufs, 32);
        if (nb_rx == 0) {
            continue;
        }
        for (int i = 0; i < nb_rx; i++) {
            printf("pkt_len : %d\n", bufs[i]->pkt_len);
            printf("data_len : %d\n", bufs[i]->data_len);
            rte_pktmbuf_free(bufs[i]);
        }
    }
}

int main(int argc, char *argv[]) {
    // args
    uint16_t portid;
    uint16_t lcore_id;
    int ret;
    /* Initializion the Environment Abstraction Layer (EAL). 8< */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    argc -= ret;
    argv += ret;
    port = atoi(argv[1]);
    printf("port : %d\n", port);
    /* >8 End of initialization the Environment Abstraction Layer (EAL). */
    /* Allocates mempool to hold the mbufs. 8< */
    huge_mbuf_pool =
        rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                                HUGE_MBUF_DATA_SIZE, rte_socket_id());

    if (huge_mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool : %d\n", rte_errno);

    /* Initializing all ports. 8< */
    ret = port_init_testing(port, huge_mbuf_pool, 1, 64);
    if (ret != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 ",error : %s \n", port,
                 rte_strerror(ret));

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_remote_launch(job, NULL, lcore_id);
    }
    rte_eal_mp_wait_lcore();

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}
