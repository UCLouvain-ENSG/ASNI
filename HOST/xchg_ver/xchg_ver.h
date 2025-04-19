#include "asq_descriptors.h"
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
/*doca imports*/
#include "consts.h"
#include <rte_xchg.h>
// #include <doca_argp.h>
// #include <doca_dev.h>
// #include <doca_dma.h>
// #include <doca_error.h>
// #include <doca_log.h>
// #include <doca_mmap.h>

struct xchg_state {
    struct rte_ether_addr macAddr1;
    int nb_core;
    int port;
    struct rte_mbuf **waiting_buffer;
    uint8_t nb_waiting_buffer;
    struct rte_mempool *mbuf_pool;
};

void xchg_run(void *state, int (*app)(void *));
struct xchg_state *xchg_init(int argc, char **argv);

#define XCHG_ASNI_FOR_EACH_PACKET(state, descriptor, force_quit)               \
    printf("inside xchg_asni \n");                                             \
    printf("burst size: %d\n", BURST_SIZE);                                    \
    struct xchg_state *xchg_state = (struct xchg_state *)state;                \
    struct my_xchg *pkts_burst[BURST_SIZE];                                    \
    struct my_xchg pkts_burst_store[BURST_SIZE] = {0};                         \
    printf("sizeof(struct my_xchg): %lu\n", sizeof(struct my_xchg));           \
    for (int i = 0; i < BURST_SIZE; i++) {                                     \
        pkts_burst[i] = &pkts_burst_store[i];                                  \
        pkts_burst[i]->buffer = 0;                                             \
    }                                                                          \
    char *payload;                                                             \
    while (!*force_quit) {                                                     \
        uint16_t nb_rx = rte_eth_rx_burst_xchg(0, rte_lcore_id() - 1,          \
                                               pkts_burst, BURST_SIZE);        \
        for (int i = 0; i < nb_rx; i++) {                                      \
            uint32_t offset_desc = 16;                                         \
            uint8_t *data = pkts_burst[i]->buffer;                             \
            uint8_t nb_desc = *data;                                           \
            payload =                                                          \
                data + offset_desc + (nb_desc * sizeof(struct descriptor));    \
            if (unlikely(nb_desc < 1 || nb_desc > 64)) {                       \
                printf("Invalid descriptor number: %d\n", nb_desc);            \
            } else {                                                           \
                struct descriptor *descriptor =                                \
                    (struct descriptor *)(data + offset_desc);                 \
                for (uint8_t j = 1; j < nb_desc; j++) {

#define XCHG_ASNI_FOR_EACH_PACKET_END()                                        \
    descriptor = (struct descriptor *)(descriptor + 1);                        \
    int length = descriptor->size;                                             \
    payload += length;                                                         \
    }                                                                          \
    }                                                                          \
    }                                                                          \
    }

#define XCHG_FOR_EACH_PACKET(state, descriptor, force_quit)                    \
    struct xchg_state *xchg_state = (struct xchg_state *)state;                \
    struct my_xchg *pkts_burst[BURST_SIZE];                                    \
    struct my_xchg pkts_burst_store[BURST_SIZE] = {0};                         \
    printf("burst size: %d\n", BURST_SIZE);                                    \
    printf("sizeof(struct my_xchg): %lu\n", sizeof(struct my_xchg));           \
    printf("before for loop\n");                                               \
    printf("running xchg\n");                                                  \
    for (int i = 0; i < BURST_SIZE; i++) {                                     \
        pkts_burst[i] = &pkts_burst_store[i];                                  \
        pkts_burst[i]->buffer = 0;                                             \
    }                                                                          \
    for (int i = 0; i < BURST_SIZE; i++) {                                     \
        pkts_burst[i]->buffer = 0;                                             \
    }                                                                          \
    char *payload;                                                             \
    while (!*force_quit) {                                                     \
        uint16_t nb_rx = rte_eth_rx_burst_xchg(                                \
            xchg_state->port, rte_lcore_id() - 1, pkts_burst, BURST_SIZE);     \
        for (int i = 0; i < nb_rx; i++) {                                      \
            struct my_xchg *descriptor = pkts_burst[i];

#define XCHG_FOR_EACH_PACKET_END()                                             \
    }                                                                          \
    }
