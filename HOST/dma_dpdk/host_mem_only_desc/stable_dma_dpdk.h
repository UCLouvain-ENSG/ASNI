#pragma once
#include <arpa/inet.h>
#include <ctype.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utils.h>

/*doca imports*/
#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>

#include "asq_descriptors.h"
#include "consts.h"
#include "dma_common.h"
#include "dma_exchange.h"
#include "dma_jobs.h"
#include "doca_utils.h"
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <signal.h>

#include "fake_dpdk.h"

// #define debug printf
#define debug

struct stable_dma_dpdk_dma_state {
    char **src_buffers_desc;
    size_t *src_buffers_size_desc;
    char **src_buffers_payloads;
    size_t *src_buffers_size_payloads;
    uint8_t nb_cores;
    char pci_addr[128];
    uint8_t burst_size;
    uint8_t last_polled_core;
    uint64_t *cores_positions;
    struct dma_resources *resources;
};

struct stable_dma_dpdk_iterator {
    struct descriptor **desc;
    uint8_t nb_packets;
    uint8_t current_packet;
};

#define DESCRIPTOR_NB                                                          \
    2048 /* The number of descriptor in the ring (MAX uint16_t max val or      \
            change head-tail to uint16_t) */

/**
 * @brief Initializes EAL and DMA.
 *
 * @param argc [in]: command line arguments size
 * @param argv [in]: array of command line arguments
 * @param nb_core [in]: number of cores to use
 * @param burst_size [in]: burst size to use
 *
 * @return DMA state containing everything needed to use receive descriptors
 */
struct stable_dma_dpdk_dma_state *stable_dma_dpdk_init(int argc, char **argv,
                                                       uint8_t nb_core,
                                                       uint8_t burst_size);

/**
 * @brief Returns a burst of descriptors that have been received by the NIC.
 *
 * @param dma_state [in]: DMA state
 * @param iterator [out]: iterator to fill with the burst of descriptors
 *
 * @return: Fills the rx_buffer with a burst of descriptors
 */
void stable_dma_dpdk_rx(struct stable_dma_dpdk_dma_state *dma_state,
                        struct stable_dma_dpdk_iterator *iterator);

/**
 * @brief Frees the DMA state.
 *
 * @param dma_state [in]: DMA state to free
 */
void stable_dma_dpdk_free(struct stable_dma_dpdk_dma_state *dma_state);

/**
 * @brief allocates a new iterator
 *
 * @param burst_size [in]: burst size to use
 *
 * @return: iterator to use with `stable_dma_dpdk_get_next`
 */
struct stable_dma_dpdk_iterator *
stable_dma_dpdk_init_iterator(uint16_t burst_size);

/**
 * @brief Returns the next descriptor. If no more descriptors are available,
 * returns NULL
 *
 * @param iterator [in]: iterator containing all the info required to iterate
 * over descriptors
 *
 * @return: Next descriptor or NULL if no more descriptors are available
 */
struct descriptor *
stable_dma_dpdk_get_next(struct stable_dma_dpdk_iterator *iterator);

#ifdef HAVE_CYCLE

#define STABLE_DMA_DPDK_FOR_EACH_PACKET(state, descriptor, force_quit)         \
    struct stable_dma_dpdk_dma_state *dma_state =                              \
        (struct stable_dma_dpdk_dma_state *)state;                             \
    uint64_t start_cycle = 0;                                                  \
    uint64_t end_cycle = 0;                                                    \
    uint64_t total_usefull_cycles = 0;                                         \
    uint64_t pkt_processed = 0;                                                \
    struct descriptor **descriptors =                                          \
        (struct descriptor **)dma_state->src_buffers_desc;                     \
    while (!*force_quit) {                                                     \
        for (uint8_t core = 0; core < dma_state->nb_cores; core++) {           \
            for (uint32_t descriptor_index = 0;                                \
                 descriptor_index < DESCRIPTOR_NB; descriptor_index++) {       \
                struct descriptor *descriptor =                                \
                    &descriptors[core][descriptor_index];                      \
                if (!descriptors[core][descriptor_index].full) {               \
                    end_cycle = rte_get_tsc_cycles();                          \
                    if (start_cycle != 0) {                                    \
                        total_usefull_cycles += end_cycle - start_cycle;       \
                        start_cycle = 0;                                       \
                    }                                                          \
                    continue;                                                  \
                }                                                              \
                if (start_cycle == 0) {                                        \
                    start_cycle = rte_get_tsc_cycles();                        \
                }                                                              \
                pkt_processed++;

#define STABLE_DMA_DPDK_FOR_EACH_PACKET_END()                                  \
    descriptors[core][descriptor_index].full = false;                          \
    }                                                                          \
    }                                                                          \
    }                                                                          \
    printf("RESULT-CYCLES-PER-PACKET-TOTAL-HOST %lf\n",                        \
           (double)total_usefull_cycles / (double)pkt_processed);

#else
#define STABLE_DMA_DPDK_FOR_EACH_PACKET(state, descriptor, force_quit)         \
    struct stable_dma_dpdk_dma_state *dma_state =                              \
        (struct stable_dma_dpdk_dma_state *)state;                             \
    struct descriptor **descriptors =                                          \
        (struct descriptor **)dma_state->src_buffers_desc;                     \
    while (!*force_quit) {                                                     \
        for (uint8_t core = 0; core < dma_state->nb_cores; core++) {           \
            for (uint32_t descriptor_index = 0;                                \
                 descriptor_index < DESCRIPTOR_NB; descriptor_index++) {       \
                struct descriptor *descriptor =                                \
                    &descriptors[core][descriptor_index];                      \
                if (!descriptors[core][descriptor_index].full)                 \
                    continue;

#define STABLE_DMA_DPDK_FOR_EACH_PACKET_END()                                  \
    descriptors[core][descriptor_index].full = false;                          \
    }                                                                          \
    }                                                                          \
    }
#endif

#define STABLE_DMA_DPDK_GET_BURST_SIZE(state)                                  \
    struct stable_dma_dpdk_dma_state *dma_state =                              \
        (struct stable_dma_dpdk_dma_state *)state;                             \
    return dma_state->burst_size;

#define STABLE_DMA_DPDK_RX_BURST(state, buffers, nb_desc)                      \
    nb_desc = dma_state->burst_size;                                           \
    struct stable_dma_dpdk_dma_state *dma_state =                              \
        (struct stable_dma_dpdk_dma_state *)state;                             \
    struct descriptor **descriptors =                                          \
        (struct descriptor **)dma_state->src_buffers_desc;                     \
    uint32_t packets_received = 0;                                             \
    while (packets_received < dma_state->burst_size) {                         \
        for (uint8_t core = 0; core < dma_state->nb_cores; core++) {           \
            for (uint32_t descriptor_index = 0;                                \
                 descriptor_index < DESCRIPTOR_NB; descriptor_index++) {       \
                struct descriptor *descriptor =                                \
                    &descriptors[core][descriptor_index];                      \
                if (!descriptors[core][descriptor_index].full)                 \
                    continue;                                                  \
                buffers[packets_received] = descriptor;                        \
                packets_received++;                                            \
                descriptors[core][descriptor_index].full = false;              \
                if (packets_received == burst_size)                            \
                    return packets_received;                                   \
            }                                                                  \
        }                                                                      \
    }
