
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

struct rte_mempool *huge_mbuf_pool;

uint16_t port = 0;

static int job(void *arg) {
    struct rte_mbuf *pkt;
    int pkt_size;
    uint16_t nb_tx;
    while (1) {
        printf("Enter pkt_size to send : ");
        scanf("%d", &pkt_size);
        pkt = rte_pktmbuf_alloc(huge_mbuf_pool);
        if (pkt == NULL) {
            printf("Failed to allocate huge mbuf\n");
            return -1;
        }

        pkt->data_len = pkt_size;
        pkt->pkt_len = pkt_size;
        nb_tx = rte_eth_tx_burst(port, 0, &pkt, 1);
        if (unlikely(nb_tx != 1)) {
            printf("failed to send packet\n");
            rte_pktmbuf_free(pkt);
        } else {
            printf("pkt_sent => \n");
            printf("pkt_len : %d\n", pkt->pkt_len);
            printf("pkt_data : %d\n", pkt->data_len);
            printf("nb_segs : %d\n", pkt->nb_segs);
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
    if (port_init_testing(port, huge_mbuf_pool,1,64) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", port);

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_remote_launch(job, NULL, lcore_id);
    }
    rte_eal_mp_wait_lcore();

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}
