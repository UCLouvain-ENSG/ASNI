

#pragma once

#include "asq_descriptors.h"
#include "dgu_utils.h"
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
#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>
#define DEBUG 0
#define PREV_DESC true

#if  defined(FAKE_DPDK_DESC_PAD) && defined(FAKE_DPDK_MODE_DPDK_BASELINE)
#include <rte_mbuf_dyn.h>
extern int dynfield_offset;
extern struct rte_mempool*  pad_pool;
#endif

#define debug_printf(fmt, ...)                                                 \
    do {                                                                       \
        if (DEBUG)                                                             \
            fprintf(stderr, fmt, __VA_ARGS__);                                 \
    } while (0)

#define RX_RING_SIZE_BASELINE 4096
#define RTE_MBUF_SIZE 2048 + 128

#define RTE_HUGE_MBUF_SIZE 32768

#define NUM_MBUFS 32767
#define NUM_DEFAULT_MBUFS 8191
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32
#define NUM_PORTS 1

struct baseline_state {
    struct rte_ether_addr macAddr1;
    int nb_core;
    int port;
    struct rte_mbuf **waiting_buffer;
    uint8_t nb_waiting_buffer;
    struct rte_mempool *mbuf_pool;
};

struct baseline_iterator {
    // Pointer to the mbif for later free
    struct rte_mbuf **buf;
    // Total number of packets received
    uint16_t nb_packets;
    // Actual number of packets received
    uint8_t actual_pkt_received;
    // Array of descriptors segments
    struct descriptor **desc;
    // Number of descriptors in each segment
    uint8_t *nb_desc;
    // Current descriptor segment
    uint8_t current_segment;
    // Current packet within the current descriptor segment
    uint8_t current_packet;
};

/**
 * @brief Initializes baseline environment.
 *
 * @param argc [in]: command line arguments size
 * @param argv [in]: array of command line arguments
 *
 * @return baseline state containing everything needed to use receive
 * descriptors
 */
struct baseline_state *baseline_init(int argc, char **argv);

/**
 * Runs the application.
 *
 * @param state [in]: baseline state
 * @param app [in]: function ptr towards the application to run
 */
void baseline_run(void *state, int (*app)(void *));

/**
 * @brief Returns descriptors that have been received by the NIC. No assumption
 * can be made on the total number of descriptors received, you must use the
 * value returned by this function.
 *
 * @param state [in]: baseline state
 * @param rx_buffer [out]: array of descriptors that have been received by the
 * NIC (Must be allocated)
 *
 * @return: Number of descriptors received
 */
void baseline_rx(struct baseline_state *state,
                 struct baseline_iterator *iterator);

struct baseline_iterator *baseline_init_iterator(uint16_t burst_size);

struct descriptor *baseline_get_next(struct baseline_iterator *iterator);

#ifdef HAVE_MPRQ

            //if (RTE_MBUF_HAS_EXTBUF(bufs[i])) printf("MPRQ LEN %d %d\n",bufs[i]->pkt_len,bufs[i]->data_len);\
            //printf("MPRQ LEN %d %d -> %p (%d), %p, %d\n",bufs[i]->pkt_len,bufs[i]->data_len,payload,(char*)payload - (char*)bufs[i]->buf_addr,bufs[i]->next,bufs[i]->nb_segs);

#define BASELINE_FOR_EACH_PACKET(state, descriptor, force_quit)                \
    printf("inside for each sw MPRQ\n");                                            \
    struct baseline_state *baseline_state = (struct baseline_state *)state;    \
    struct rte_mbuf *bufs[BURST_SIZE];                                         \
    INIT_CYCLE_VARS();                                                         \
    while (!*force_quit) {                                                     \
        START_CYCLE();                                                         \
        uint16_t nb_desc = rte_eth_rx_burst(                                   \
            baseline_state->port, rte_lcore_id() - 1, bufs, BURST_SIZE);       \
        if (nb_desc == 0) {                                                    \
            continue;                                                          \
        }                                                                      \
        START_CYCLE_PROCESSING();                                              \
        for (int i = 0; i < nb_desc; i++) {                                    \
            struct descriptor *descriptor = (struct descriptor *)(bufs[i]);    \
            char *payload = rte_pktmbuf_mtod(bufs[i], char *);                 \
            (void)payload;
#else
#define BASELINE_FOR_EACH_PACKET(state, descriptor, force_quit)                \
    printf("inside for each sw\n");                                            \
    struct baseline_state *baseline_state = (struct baseline_state *)state;    \
    struct rte_mbuf *bufs[BURST_SIZE];                                         \
    INIT_CYCLE_VARS();                                                         \
    while (!*force_quit) {                                                     \
        START_CYCLE();                                                         \
        uint16_t nb_desc = rte_eth_rx_burst(                                   \
            baseline_state->port, rte_lcore_id() - 1, bufs, BURST_SIZE);       \
        if (nb_desc == 0) {                                                    \
            continue;                                                          \
        }                                                                      \
        START_CYCLE_PROCESSING();                                              \
        for (int i = 0; i < nb_desc; i++) {                                    \
            struct descriptor *descriptor = (struct descriptor *)(bufs[i]);    \
            char *payload = rte_pktmbuf_mtod(bufs[i], char *);                 \
            (void)payload;
#endif

#define BASELINE_FOR_EACH_PACKET_END()                                         \
    }                                                                          \
    rte_pktmbuf_free_bulk(bufs, nb_desc);                                      \
    END_CYCLE();                                                               \
    PROCESSED_PACKETS();                                                       \
    }                                                                          \
    PRINT_CYCLES();
