#pragma once

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include <stdint.h>
#include <stdlib.h>

/*
 * @brief The int function, which does initialization and calls the per-lcore
 * functions.
 *
 * @param argc The number of arguments.
 * @param argv The arguments.
 * @param nf Function to call on each core. (void (*nf)(void))
 */
int fake_io_launch(int argc, char *argv[], void (*nf)(void));

#define BATCH_SIZE 32

#define ENABLED_PORTS                                                          \
    { 0, 0 }                // Enabled ports
#define ENABLED_PORTS_LEN 2 // Number of enabled ports

#ifdef ASNI_IO_XCHG
#include "asni_descriptors.h"
#include "rte_xchg.h"
#endif

// Ensure that only one IO backend is selected
#if defined(ASNI_IO_XCHG) && defined(ASNI_IO_DPDK)
#error                                                                         \
    "Only one IO backend can be selected. Either ASNI_IO_XCHG or ASNI_IO_DPDK"
#endif

#ifdef ASNI_IO_XCHG

struct xchg {
    uint8_t *buffer;
    uint16_t plen;
    struct big_packet_metadata *metadata;
};

#define my_xchg xchg

#define always_inline __rte_always_inline

static void xchg_free_large_packet(struct big_packet_metadata *metadata) {
    (metadata->refcnt)--;
    if (metadata->refcnt <= 0) {
        // printf("Freeing packets\n");
        rte_mbuf_raw_free(metadata->mb);
        rte_free(metadata);
    }
}
#endif

/**
 * INIT Functions
 */

/**
 * @brief Fake DPDK IO state, contains different pointers for the abstraction.
 * It is only needed for the XCHG implementation, but is asked for both for API
 * compatibility.
 */
struct io_state {
#ifdef ASNI_IO_XCHG
    struct xchg *pkts_burst_store;
    struct xchg *rx_pkts_burst[BATCH_SIZE];
    struct xchg *tx_pkts_burst[BATCH_SIZE];
#endif
#if defined(ASNI_IO_ASNI_OFFLOAD_TX)
    struct rte_mbuf *rx_pkts_burst[BATCH_SIZE];
#endif
#if defined(ASNI_IO_DPDK)
    struct rte_mbuf *mbufs_to_send[BATCH_SIZE];
#endif
    uint16_t tx_count;
};

/**
 * @brief Intializes the IO state for XCHG implementation.
 *
 * @param state The state to initialize. (Pointer to an allocated struct)
 */
#define ASNI_IO_INIT_XCHG(state)                                          \
    struct io_state *state = rte_zmalloc(NULL, sizeof(struct io_state), 0);    \
    struct io_state *xchg_state = (struct io_state *)state;                    \
    xchg_state->pkts_burst_store =                                             \
        rte_zmalloc(NULL, sizeof(struct xchg) * BATCH_SIZE, 0);                \
    xchg_state->tx_count = 0;                                                  \
    for (int i = 0; i < BATCH_SIZE; i++) {                                     \
        xchg_state->tx_pkts_burst[i] =                                         \
            rte_zmalloc(NULL, sizeof(struct xchg), 0);                         \
    }                                                                          \
    for (int i = 0; i < BATCH_SIZE; i++) {                                     \
        xchg_state->rx_pkts_burst[i] = &(state->pkts_burst_store[i]);          \
        xchg_state->rx_pkts_burst[i]->buffer = 0;                              \
    }

/**
 * @brief Intializes the IO state for DPDK implementation.
 *
 * @param state The state to initialize. (Pointer to an allocated struct)
 */
#define ASNI_IO_INIT_DPDK(state)                                          \
    struct io_state *state = rte_zmalloc(NULL, sizeof(struct io_state), 0);    \
    struct io_state *dpdk_state = (struct io_state *)state;                    \
    dpdk_state->tx_count = 0;

#define ASNI_IO_INIT_ASNI_OFFLOAD_TX(state)                               \
    struct io_state *state = rte_zmalloc(NULL, sizeof(struct io_state), 0);    \
    struct io_state *asni_offload_tx_state = (struct io_state *)state;         \
    asni_offload_tx_state->tx_count = 0;

/**
 *
 * RX/TX Functions
 *
 */

/**
 * @brief Handles the RX burst for XCHG implementation.
 */
#define ASNI_IO_RX_BURST_DPDK(port, queue, descriptors, burst_size,       \
                                   rx_count, state)                            \
    struct rte_mbuf *descriptors[burst_size];                                  \
    uint16_t rx_count = rte_eth_rx_burst(port, queue, descriptors, burst_size);

/**
 * @brief Handles the RX burst for DPDK implementation.
 */

#define ASNI_IO_RX_BURST_ASNI_OFFLOAD_TX(port, queue, descriptors,        \
                                              burst_size, rx_count, state)     \
    struct io_state *asni_offload_tx_state = (struct io_state *)state;         \
    uint16_t rx_count = rte_eth_rx_burst(                                      \
        port, queue, asni_offload_tx_state->rx_pkts_burst, burst_size);        \
    struct rte_mbuf **descriptors = asni_offload_tx_state->rx_pkts_burst;

#define ASNI_IO_RX_BURST_XCHG(port, queue, descriptors, burst_size,       \
                                   rx_count, state)                            \
    struct io_state *xchg_state = (struct io_state *)state;                    \
    uint16_t rx_count = rte_eth_rx_burst_xchg(                                 \
        port, queue, xchg_state->rx_pkts_burst, burst_size);                   \
    struct xchg **descriptors = xchg_state->rx_pkts_burst;

/**
 * @brief Handles the TX burst for XCHG implementation.
 */
#define ASNI_IO_TX_BURST_DPDK(port, queue, burst_size, tx_count, state)   \
    struct io_state *dpdk_state = (struct io_state *)state;                    \
    uint16_t tx_count = rte_eth_tx_burst(port, queue, state->mbufs_to_send,    \
                                         dpdk_state->tx_count);                \
    for (uint16_t unset_packet_index = tx_count;                               \
         unset_packet_index < dpdk_state->tx_count; unset_packet_index++) {    \
        rte_pktmbuf_free(state->mbufs_to_send[unset_packet_index]);            \
    }                                                                          \
    dpdk_state->tx_count = 0;

/**
 * @brief Handles the TX burst for DPDK implementation.
 */

#define ASNI_IO_TX_BURST_ASNI_OFFLOAD_TX(port, queue, burst_size,         \
                                              tx_count_dummy, state)           \
    struct io_state *asni_offload_tx_state = (struct io_state *)state;         \
    uint16_t tx_count =                                                        \
        rte_eth_tx_burst(port, queue, asni_offload_tx_state->rx_pkts_burst,    \
                         asni_offload_tx_state->tx_count);                     \
    for (uint16_t unset_packet_index = tx_count;                               \
         unset_packet_index < asni_offload_tx_state->tx_count;                 \
         unset_packet_index++) {                                               \
        rte_pktmbuf_free(                                                      \
            asni_offload_tx_state->rx_pkts_burst[unset_packet_index]);         \
    }                                                                          \
    asni_offload_tx_state->tx_count = 0;

#define ASNI_IO_TX_BURST_XCHG(port, queue, burst_size, tx_count, state)   \
    struct io_state *xchg_state_tx = (struct io_state *)state;                 \
    uint16_t tx_count = rte_eth_tx_burst_xchg(                                 \
        port, queue, xchg_state_tx->tx_pkts_burst, xchg_state_tx->tx_count);   \
    for (uint16_t unset_packet_index = tx_count;                               \
         unset_packet_index < burst_size; unset_packet_index++) {              \
        xchg_free_large_packet(                                                \
            state->tx_pkts_burst[unset_packet_index]->metadata);               \
    }                                                                          \
    xchg_state_tx->tx_count = 0;

/**
 * @brief Setup metadata, only needed for XCHG implementation.
 */
#define ASNI_IO_SETUP_METADATA_XCHG(descriptor, nb_desc, metadata)        \
    struct big_packet_metadata *metadata =                                     \
        rte_zmalloc(NULL, sizeof(struct big_packet_metadata), 0);              \
    metadata->refcnt = nb_desc;                                                \
    metadata->mb = xchg_get_mbuf(descriptor);

/**
 * @brief Setup metadata, only needed for XCHG implementation. Dummy function.
 */
#define ASNI_IO_SETUP_METADATA_DPDK(descriptor, nb_desc, metadata)

#define ASNI_IO_SETUP_METADATA_OFFLOADED_TX(descriptor, nb_desc, metadata)

/**
 * @brief Implicitly frees the descriptor for DPDK implementation. The free is
 * called implicit because it is not performed in all implementations.
 */
#define ASNI_IO_FREE_IMPLICIT_DPDK(descriptor)                            \
    rte_pktmbuf_free(descriptor);

/**
 * @brief Explicitly frees the descriptor for XCHG implementation. Which is
 * forbidden (XCHG does not allow explicit frees). Dummy function.
 */
#define ASNI_IO_FREE_IMPLICIT_XCHG(descriptor)

/**
 * @brief Signals that you finished processing the packet for DPDK
 * implementation. Useless in DPDK, but needed for API compatibility.
 */
#define ASNI_IO_END_PROCESS_DPDK(descriptor)

/**
 * @brief Signals that you finished processing the packet for XCHG
 * implementation.
 */
#define ASNI_IO_END_PROCESS_XCHG(descriptor)                              \
    ((struct xchg *)descriptor)->buffer = 0;

/**
 * @brief Enqueues the descriptor for DPDK implementation.
 */
#define ASNI_IO_TX_ENQUEUE_DPDK(state, descriptor, size, metadata,        \
                                     payload)                                  \
    struct io_state *dpdk_state = (struct io_state *)state;                    \
    dpdk_state->mbufs_to_send[dpdk_state->tx_count] = descriptor;              \
    dpdk_state->tx_count++;

/**
 * @brief Enqueues the descriptor for XCHG implementation.
 */
#define ASNI_IO_TX_ENQUEUE_XCHG(state, descriptor, size, metadata,        \
                                     payload)                                  \
    struct io_state *xchg_state = (struct io_state *)state;                    \
    xchg_state->tx_pkts_burst[xchg_state->tx_count]->buffer = payload;         \
    xchg_state->tx_pkts_burst[xchg_state->tx_count]->metadata = metadata;      \
    xchg_state->tx_pkts_burst[xchg_state->tx_count]->plen = size;              \
    xchg_state->tx_count++;

/**
 *
 * DATA Functions
 *
 */

/**
 * @brief Return the payload pointer for XCHG implementation.
 */
#define ASNI_IO_GET_PAYLOAD_PTR_XCHG(descriptor, payload)                 \
    struct xchg *xchg_descriptor = (struct xchg *)descriptor;                  \
    payload = xchg_descriptor->buffer;

/**
 * @brief Returns the payload pointer for DPDK implementation.
 */
#define ASNI_IO_GET_PAYLOAD_PTR_DPDK(descriptor, payload)                 \
    payload = rte_pktmbuf_mtod(descriptor, void *);

#define ASNI_IO_GET_PAYLOAD_PTR_ASNI_OFFLOAD_TX(descriptor, payload)       \
    payload = rte_pktmbuf_mtod((struct rte_mbuf *)descriptor, void *);
/**
 * @brief Returns the payload size for XCHG implementation.
 */
#define ASNI_IO_GET_PAYLOAD_SIZE_XCHG(descriptor, payload_size, payload)  \
    payload_size = descriptor->plen;

/**
 * @brief Returns the payload size for DPDK implementation.
 */
#define ASNI_IO_GET_PAYLOAD_SIZE_DPDK(descriptor, payload_size, payload)  \
    payload_size = rte_pktmbuf_pkt_len(descriptor);

/**
 * @brief Implicitly returns the payload for XCHG implementation.
 */
#define ASNI_IO_GET_IMPLICIT_PAYLOAD_PTR_XCHG(descriptor, payload)        \
    payload = ((struct xchg *)descriptor)->buffer;

/**
 * @brief Implicitly returns the payload for DPDK implementation. Dummy
 * function.
 */
#define ASNI_IO_GET_IMPLICIT_PAYLOAD_PTR_DPDK(descriptor, payload)

/**
 * @brief Implicitly returns the payload size for XCHG implementation.
 */
#define ASNI_IO_GET_IMPLICIT_PAYLOAD_SIZE_XCHG(descriptor, size)          \
    size = ((struct xchg *)descriptor)->plen;

/**
 * @brief Implicitly returns the payload size for DPDK implementation. Dummy
 * function.
 */
#define ASNI_IO_GET_IMPLICIT_PAYLOAD_SIZE_DPDK(descriptor, size)

/**
 * ASNI_IO API
 */

#ifdef ASNI_IO_XCHG

typedef struct xchg fake_dpdk_io_descriptor;
#define fake_dpdk_io_metadata big_packet_metadata

#define ASNI_IO_INIT(state) ASNI_IO_INIT_XCHG(state)
#define ASNI_IO_RX_BURST(port, queue, descriptors, burst_size, rx_count,  \
                              state)                                           \
    ASNI_IO_RX_BURST_XCHG(port, queue, descriptors, burst_size, rx_count, \
                               state)
#define ASNI_IO_TX_BURST(port, queue, burst_size, tx_count, state)        \
    ASNI_IO_TX_BURST_XCHG(port, queue, burst_size, tx_count, state)

#define ASNI_IO_TX_BURST_LATE(port, queue, burst_size, tx_count, state)

#define ASNI_IO_SETUP_METADATA(descriptor, nb_desc, metadata)             \
    ASNI_IO_SETUP_METADATA_XCHG(descriptor, nb_desc, metadata)
#define ASNI_IO_FREE_IMPLICIT(descriptor)                                 \
    ASNI_IO_FREE_IMPLICIT_XCHG(descriptor)
#define ASNI_IO_END_PROCESS(descriptor)                                   \
    ASNI_IO_END_PROCESS_XCHG(descriptor)
#define ASNI_IO_TX_ENQUEUE(state, descriptor, size, metadata, payload)    \
    ASNI_IO_TX_ENQUEUE_XCHG(state, descriptor, size, metadata, payload)
#define ASNI_IO_GET_PAYLOAD_PTR(descriptor, payload)                      \
    ASNI_IO_GET_PAYLOAD_PTR_XCHG(descriptor, payload)
#define ASNI_IO_GET_PAYLOAD_SIZE(descriptor, payload_size, payload)       \
    ASNI_IO_GET_PAYLOAD_SIZE_XCHG(descriptor, payload_size, payload)
#define ASNI_IO_GET_IMPLICIT_PAYLOAD_PTR(descriptor, ptr)                 \
    ASNI_IO_GET_IMPLICIT_PAYLOAD_PTR_XCHG(descriptor, ptr)
#define ASNI_IO_GET_IMPLICIT_PAYLOAD_SIZE(descriptor, size)               \
    ASNI_IO_GET_IMPLICIT_PAYLOAD_SIZE_XCHG(descriptor, size)

#endif

#ifdef ASNI_IO_DPDK

typedef struct rte_mbuf fake_dpdk_io_descriptor;
struct fake_dpdk_io_metadata;

#define ASNI_IO_INIT(state) ASNI_IO_INIT_DPDK(state)
#define ASNI_IO_RX_BURST(port, queue, descriptors, burst_size, rx_count,  \
                              state)                                           \
    ASNI_IO_RX_BURST_DPDK(port, queue, descriptors, burst_size, rx_count, \
                               state)
#define ASNI_IO_TX_BURST(port, queue, burst_size, tx_count, state)        \
    ASNI_IO_TX_BURST_DPDK(port, queue, burst_size, tx_count, state)

#define ASNI_IO_TX_BURST_LATE(port, queue, burst_size, tx_count, state)

#define ASNI_IO_SETUP_METADATA(descriptor, nb_desc, metadata)             \
    ASNI_IO_SETUP_METADATA_DPDK(descriptor, nb_desc, metadata)
#define ASNI_IO_FREE_IMPLICIT(descriptor)                                 \
    ASNI_IO_FREE_IMPLICIT_DPDK(descriptor)
#define ASNI_IO_END_PROCESS(descriptor)                                   \
    ASNI_IO_END_PROCESS_DPDK(descriptor)
#define ASNI_IO_TX_ENQUEUE(state, descriptor, size, metadata, payload)    \
    ASNI_IO_TX_ENQUEUE_DPDK(state, descriptor, size, metadata, payload)
#define ASNI_IO_GET_PAYLOAD_PTR(descriptor, payload)                      \
    ASNI_IO_GET_PAYLOAD_PTR_DPDK(descriptor, payload)
#define ASNI_IO_GET_PAYLOAD_SIZE(descriptor, payload_size, payload)       \
    ASNI_IO_GET_PAYLOAD_SIZE_DPDK(descriptor, payload_size, payload)
#define ASNI_IO_GET_IMPLICIT_PAYLOAD_PTR(descriptor, payload)             \
    ASNI_IO_GET_IMPLICIT_PAYLOAD_PTR_DPDK(descriptor, payload)
#define ASNI_IO_GET_IMPLICIT_PAYLOAD_SIZE(descriptor, size)               \
    ASNI_IO_GET_IMPLICIT_PAYLOAD_SIZE_DPDK(descriptor, size)

#endif

#ifdef ASNI_IO_ASNI_OFFLOAD_TX

typedef struct xchg fake_dpdk_io_descriptor;
#define fake_dpdk_io_metadata big_packet_metadata

#define ASNI_IO_INIT(state) ASNI_IO_INIT_DPDK(state)
#define ASNI_IO_RX_BURST(port, queue, descriptors, burst_size, rx_count,  \
                              state)                                           \
    ASNI_IO_RX_BURST_ASNI_OFFLOAD_TX(port, queue, descriptors,            \
                                          burst_size, rx_count, state)

#define ASNI_IO_TX_BURST_LATE(port, queue, burst_size, tx_count, state)   \
    ASNI_IO_TX_BURST_ASNI_OFFLOAD_TX(port, queue, burst_size, tx_count,   \
                                          state)

#define ASNI_IO_TX_BURST(port, queue, burst_size, tx_count, state)

#define ASNI_IO_SETUP_METADATA(descriptor, nb_desc, metadata)

#define ASNI_IO_FREE_IMPLICIT(descriptor)                                 \
    ASNI_IO_FREE_IMPLICIT_XCHG(descriptor)

#define ASNI_IO_END_PROCESS(descriptor)                                   \
    ASNI_IO_END_PROCESS_DPDK(descriptor)

#define ASNI_IO_TX_ENQUEUE(state, descriptor, size, metadata, payload)

#define ASNI_IO_GET_PAYLOAD_PTR(descriptor, payload)                      \
    ASNI_IO_GET_PAYLOAD_PTR_ASNI_OFFLOAD_TX(descriptor, payload)
#define ASNI_IO_GET_PAYLOAD_SIZE(descriptor, payload_size, payload)       \
    ASNI_IO_GET_PAYLOAD_SIZE_DPDK(descriptor, payload_size, payload)
#define ASNI_IO_GET_IMPLICIT_PAYLOAD_PTR(descriptor, ptr)                 \
    ASNI_IO_GET_IMPLICIT_PAYLOAD_PTR_XCHG(descriptor, ptr)
#define ASNI_IO_GET_IMPLICIT_PAYLOAD_SIZE(descriptor, size)               \
    ASNI_IO_GET_IMPLICIT_PAYLOAD_SIZE_XCHG(descriptor, size)

#endif
