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

#ifdef NO_PREFETCH_DESC
#define PREFETCH_DESC(addr)
#else
#define PREFETCH_DESC(addr) rte_prefetch0(addr)
#endif

#ifdef NO_PREFETCH_PAYLOAD
#define PREFETCH_PAYLOAD(addr)
#else
#define PREFETCH_PAYLOAD(addr) rte_prefetch0(addr)
#endif

#if DEBUG_XCHG
#define MAGIC_SET() int magic = *(int *)(&eth_hdr->src_addr.addr_bytes[1]);
#define MAGIC_CHECK() || magic != MAGIC
#define WAIT_DEBUG() usleep(100000)
#else
#define MAGIC_SET()
#define MAGIC_CHECK()
#define WAIT_DEBUG()
#endif


#ifdef NO_PREFETCH_PAYLOAD
#define XCHG_ASNI_FOR_EACH_PACKET(state, descriptor, force_quit)               \
    printf("inside xchg_asni23 \n");                                           \
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
    INIT_CYCLE_VARS();                                                         \
    INIT_DEBUG_VAR();                                                          \
    while (!*force_quit) {                                                     \
        START_CYCLE();                                                         \
        uint16_t nb_rx = rte_eth_rx_burst_xchg(0, rte_lcore_id() - 1,          \
                                               pkts_burst, BURST_SIZE);        \
        if (nb_rx == 0) {                                                      \
            WAIT_DEBUG() \
            continue;                                                          \
        }                                                                      \
        START_CYCLE_PROCESSING();                                              \
        for (int i = 0; i < nb_rx; i++) {                                      \
            uint32_t offset_desc = 16;                                         \
            uint8_t *data = pkts_burst[i]->buffer;                             \
            uint8_t nb_desc = *(data);                                         \
            struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)data;      \
            MAGIC_SET();          \
            payload =                                                          \
                data + offset_desc + (nb_desc * sizeof(struct descriptor));    \
            if (unlikely(nb_desc < 1 || nb_desc > 64 MAGIC_CHECK())) {     \
                printf("Invalid descriptor number: %d\n", nb_desc);            \
            } else {                                                           \
                struct descriptor *descriptor_vec =                                \
                    (struct descriptor *)(data + offset_desc);                 \
                for (uint8_t j = 0; j < nb_desc; j++) {                        \
                    struct descriptor *descriptor = &descriptor_vec[j];\
                    PREFETCH_DESC((descriptor + 1));

#define XCHG_ASNI_FOR_EACH_PACKET_END()                                        \
    }                                                                          \
    }                                                                          \
    PROCESSED_PACKETS();                                                       \
    }                                                                          \
    END_CYCLE();                                                               \
    }                                                                          \
    PRINT_DEBUG();                                                             \
    PRINT_CYCLES();
#else
#define XCHG_ASNI_FOR_EACH_PACKET(state, descriptor, force_quit)               \
    printf("inside xchg_asni23 \n");                                           \
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
    INIT_CYCLE_VARS();                                                         \
    INIT_DEBUG_VAR();                                                          \
    while (!*force_quit) {                                                     \
        START_CYCLE();                                                         \
        uint16_t nb_rx = rte_eth_rx_burst_xchg(0, rte_lcore_id() - 1,          \
                                               pkts_burst, BURST_SIZE);        \
        if (nb_rx == 0) {                                                      \
            WAIT_DEBUG() \
            continue;                                                          \
        }                                                                      \
        START_CYCLE_PROCESSING();                                              \
        for (int i = 0; i < nb_rx; i++) {                                      \
            uint32_t offset_desc = 16;                                         \
            uint8_t *data = pkts_burst[i]->buffer;                             \
            uint8_t nb_desc = *(data);                                         \
            struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)data;      \
            MAGIC_SET();          \
            payload =                                                          \
                data + offset_desc + (nb_desc * sizeof(struct descriptor));    \
            if (unlikely(nb_desc < 1 || nb_desc > 64 MAGIC_CHECK())) {     \
                printf("Invalid descriptor number: %d\n", nb_desc);            \
            } else {                                                           \
                struct descriptor *descriptor =                                \
                    (struct descriptor *)(data + offset_desc);                 \
                for (uint8_t j = 0; j < nb_desc; j++) {                        \
                    int length = descriptor->size;                             \
                    char *next_payload = payload + length;                     \
                    struct descriptor *next_descriptor = descriptor + 1;       \
                    PREFETCH_DESC(next_descriptor);                            \
                    PREFETCH_PAYLOAD(next_payload);

#define XCHG_ASNI_FOR_EACH_PACKET_END()                                        \
    descriptor = next_descriptor;                                              \
    payload = next_payload;                                                    \
    }                                                                          \
    }                                                                          \
    PROCESSED_PACKETS();                                                       \
    }                                                                          \
    END_CYCLE();                                                               \
    }                                                                          \
    PRINT_DEBUG();                                                             \
    PRINT_CYCLES();

#endif


#define XCHG_BURST_SIZE 32

#define XCHG_FOR_EACH_PACKET(state, descriptor, force_quit)                    \
    struct xchg_state *xchg_state = (struct xchg_state *)state;                \
    struct my_xchg *pkts_burst[XCHG_BURST_SIZE];                               \
    struct my_xchg pkts_burst_store[XCHG_BURST_SIZE] = {0};                    \
    printf("burst size: %d\n", XCHG_BURST_SIZE);                               \
    printf("sizeof(struct my_xchg): %lu\n", sizeof(struct my_xchg));           \
    printf("running for loop\n");                                              \
    printf("running xchg23\n");                                                \
    for (int i = 0; i < XCHG_BURST_SIZE; i++) {                                \
        pkts_burst[i] = &pkts_burst_store[i];                                  \
        pkts_burst[i]->buffer = 0;                                             \
    }                                                                          \
    for (int i = 0; i < XCHG_BURST_SIZE; i++) {                                \
        pkts_burst[i]->buffer = 0;                                             \
    }                                                                          \
    char *payload;                                                             \
    INIT_CYCLE_VARS();                                                         \
    while (!*force_quit) {                                                     \
        START_CYCLE();                                                         \
        uint16_t nb_desc =                                                     \
            rte_eth_rx_burst_xchg(xchg_state->port, rte_lcore_id() - 1,        \
                                  pkts_burst, XCHG_BURST_SIZE);                \
        if (nb_desc == 0) {                                                    \
            continue;                                                          \
        }                                                                      \
        START_CYCLE_PROCESSING();                                              \
        for (int i = 0; i < nb_desc; i++) {                                    \
            struct my_xchg *descriptor = pkts_burst[i];                        \
            char *payload = descriptor->buffer;

#define XCHG_FOR_EACH_PACKET_END()                                             \
    }                                                                          \
    END_CYCLE();                                                               \
    PROCESSED_PACKETS();                                                       \
    }                                                                          \
    PRINT_CYCLES();
