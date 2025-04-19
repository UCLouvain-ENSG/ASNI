#pragma once

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
// #include <doca_argp.h>
// #include <doca_dev.h>
// #include <doca_dma.h>
// #include <doca_error.h>
// #include <doca_log.h>
// #include <doca_mmap.h>
#include "fake_dpdk/fake_io.h"

#define DEBUG 0
#define PREV_DESC true

#define debug_printf(fmt, ...)                                                 \
    do {                                                                       \
        if (DEBUG)                                                             \
            fprintf(stderr, fmt, __VA_ARGS__);                                 \
    } while (0)

#define RX_RING_SIZE 1024
#define RTE_MBUF_SIZE 2048 + 128

#define MTU 65279

#define NUM_MBUFS 32767
#define NUM_HUGE_MBUFS 8191
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE_ASNI_H 16
#define NUM_PORTS 1

struct custom_header {
    char padding1[2];
    uint32_t size;
    char padding2[2];
    uint32_t dst_ip;
    /* Plenty of space for other fields  */
    char padding3[38];
} __attribute__((packed));

struct asq_state {
    struct rte_ether_addr macAddr1;
    int nb_core;
    int light;
    int port;
    struct rte_mbuf **waiting_buffer;
    uint8_t nb_waiting_buffer;
    struct rte_mempool *mbuf_pool;
};

struct asq_iterator {
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
 * @brief Initializes ASQ environment.
 *
 * @param argc [in]: command line arguments size
 * @param argv [in]: array of command line arguments
 *
 * @return ASQ state containing everything needed to use receive descriptors
 */
struct asq_state *asq_init(int argc, char **argv);

struct asq_state *asq_init_dpt(int argc, char **argv);
/**
 * Runs the application.
 *
 * @param state [in]: ASQ state
 * @param app [in]: function ptr towards the application to run
 */
void asq_run(void *state, int (*app)(void *));

/**
 * @brief Returns descriptors that have been received by the NIC. No assumption
 * can be made on the total number of descriptors received, you must use the
 * value returned by this function.
 *
 * @param state [in]: ASQ state
 * @param rx_buffer [out]: array of descriptors that have been received by the
 * NIC (Must be allocated)
 *
 * @return: Number of descriptors received
 */
void asq_rx(struct asq_state *state, struct asq_iterator *iterator);

struct asq_iterator *asq_init_iterator(uint16_t burst_size);

struct descriptor *asq_get_next(struct asq_iterator *iterator);

#ifdef HAVE_CYCLE
#define INIT_CYCLE_VARS()                                                      \
    uint64_t total_usefull_cycles = 0;                                         \
    uint64_t processing_cycles = 0;                                            \
    uint64_t pkt_processed = 0;                                                \
    uint64_t start_cycle = 0;                                                  \
    uint64_t start_cycle_processing = 0;                                       \
    uint64_t end_cycle = 0;
#define START_CYCLE() start_cycle = rte_get_tsc_cycles();
#define START_CYCLE_PROCESSING() start_cycle_processing = rte_get_tsc_cycles();
#define PROCESSED_PACKETS() pkt_processed += nb_desc;
#define END_CYCLE()                                                            \
    end_cycle = rte_get_tsc_cycles();                                          \
    total_usefull_cycles += end_cycle - start_cycle;                           \
    processing_cycles += end_cycle - start_cycle_processing;
#define PRINT_CYCLES()                                                         \
    printf("RESULT-CYCLES-PER-PACKET-TOTAL-HOST %lf\n",                        \
           (double)total_usefull_cycles / (double)pkt_processed);              \
    printf("RESULT-CYCLES-PER-PACKET-PROCESSING-HOST %lf\n",                   \
           (double)processing_cycles / (double)pkt_processed);                 \
    printf("RESULT-CYCLES-PER-PACKET-IO-HOST %lf\n",                           \
           (double)(total_usefull_cycles - processing_cycles) /                \
               (double)pkt_processed);
#else
#define INIT_CYCLE_VARS()
#define START_CYCLE()
#define START_CYCLE_PROCESSING()
#define PROCESSED_PACKETS()
#define END_CYCLE()
#define PRINT_CYCLES()
#endif

#ifdef ASNI_DEBUG
#define INIT_DEBUG_VAR()                                                       \
    uint64_t burst_size_debug = 0;                                             \
    uint64_t nb_rx_debug = 0;
#define INC_BURST() burst_size_debug += nb_rx;
#define INC_NB_RX() nb_rx_debug++;
#define PRINT_DEBUG()                                                          \
    printf("RESULT-AVERAGE-BURST-SIZE %lf\n",                                  \
           (double)burst_size_debug / (double)nb_rx_debug);
#else
#define INIT_DEBUG_VAR()
#define PRINT_DEBUG()
#define INC_BURST()
#define INC_NB_RX()
#endif

#define ASQ_FOR_EACH_PACKET(state, descriptor, force_quit)                     \
    printf("inside for each sw\n");                                            \
    struct asq_state *asq_state = (struct asq_state *)state;                   \
    struct rte_mbuf *bufs[BURST_SIZE_ASNI_H];                                  \
    char *payload;                                                             \
    INIT_CYCLE_VARS();                                                         \
    INIT_DEBUG_VAR();                                                          \
    while (!*force_quit) {                                                     \
        START_CYCLE();                                                         \
        uint16_t nb_rx = rte_eth_rx_burst(asq_state->port, rte_lcore_id() - 1, \
                                          bufs, BURST_SIZE_ASNI_H);            \
        if (nb_rx == 0) {                                                      \
            continue;                                                          \
        }                                                                      \
        INC_BURST();                                                           \
        INC_NB_RX();                                                           \
        START_CYCLE_PROCESSING();                                              \
        for (int i = 0; i < nb_rx; i++) {                                      \
            uint32_t offset_desc = DESC_OFFSET;                                \
            uint8_t *data = rte_pktmbuf_mtod(bufs[i], uint8_t *);              \
            uint8_t nb_desc = *data;                                           \
            payload = (char *)(data + offset_desc +                            \
                               (nb_desc * sizeof(struct descriptor)));         \
            struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)data;      \
            int magic = *(int *)(&eth_hdr->src_addr.addr_bytes[1]);            \
            if (unlikely(nb_desc < 1 || nb_desc > 64 || magic != MAGIC)) {     \
                printf("Invalid packet nb_desc: %d,is_magic_right : %d\n",     \
                       nb_desc, magic == MAGIC);                               \
            } else {                                                           \
                struct descriptor *descriptor =                                \
                    (struct descriptor *)(data + offset_desc);                 \
                for (uint8_t j = 0; j < nb_desc; j++) {                        \
                    int length = descriptor->size;                             \
                    char *next_payload = payload + length;                     \
                    struct descriptor *next_descriptor = descriptor + 1;       \
                    rte_prefetch0(next_descriptor);                            \
                    rte_prefetch0(next_payload);

#define ASQ_FOR_EACH_PACKET_END()                                              \
    descriptor = next_descriptor;                                              \
    payload = next_payload;                                                    \
    }                                                                          \
    PROCESSED_PACKETS();                                                       \
    }                                                                          \
    }                                                                          \
    rte_pktmbuf_free_bulk(bufs, nb_rx);                                        \
    END_CYCLE();                                                               \
    }                                                                          \
    PRINT_DEBUG();                                                             \
    PRINT_CYCLES();

#define ASQ_HW_DP_FOR_EACH_PACKET(state, descriptor, force_quit)               \
    printf("inside for each hw_dp\n");                                         \
    printf("sizeof(struct descriptor) : %ld\n", sizeof(struct descriptor));    \
    struct asq_state *asq_state = (struct asq_state *)state;                   \
    struct rte_mbuf *bufs[BURST_SIZE_ASNI_H];                                  \
    char *payload;                                                             \
    INIT_CYCLE_VARS();                                                         \
    INIT_DEBUG_VAR();                                                          \
    while (!*force_quit) {                                                     \
        START_CYCLE();                                                         \
        uint16_t nb_rx = rte_eth_rx_burst(                                     \
            asq_state->port, (rte_lcore_id() - 1), bufs, BURST_SIZE_ASNI_H);   \
        if (nb_rx == 0) {                                                      \
            continue;                                                          \
        }                                                                      \
        START_CYCLE_PROCESSING();                                              \
        for (int i = 0; i < nb_rx; i++) {                                      \
            uint8_t *data = rte_pktmbuf_mtod(bufs[i], uint8_t *);              \
            uint8_t nb_desc = *(data);                                         \
            struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)data;      \
            int magic = *(int *)(&eth_hdr->src_addr.addr_bytes[1]);            \
            if (unlikely(nb_desc < 1 || nb_desc > 64 || magic != MAGIC)) {     \
            } else {                                                           \
                struct descriptor *descriptor =                                \
                    (struct descriptor *)(data + DESC_OFFSET);                 \
                payload = (char *)(descriptor + 1);                            \
                for (uint8_t j = 0; j < nb_desc; j++) {                        \
                    int length = descriptor->size;                             \
                    struct descriptor *next_descriptor =                       \
                        (struct descriptor *)(((char *)(descriptor + 1)) +     \
                                              length);                         \
                    char *next_payload = (char *)(next_descriptor + 1);        \
                    rte_prefetch0(next_descriptor);                            \
                    rte_prefetch0(next_payload);

#define ASQ_HW_DP_FOR_EACH_PACKET_END()                                        \
    descriptor = next_descriptor;                                              \
    payload = next_payload;                                                    \
    (void)payload;                                                             \
    }                                                                          \
    }                                                                          \
    PROCESSED_PACKETS();                                                       \
    }                                                                          \
    rte_pktmbuf_free_bulk(bufs, nb_rx);                                        \
    END_CYCLE();                                                               \
    }                                                                          \
    PRINT_DEBUG();                                                             \
    PRINT_CYCLES();

#define ASQ_FOR_EACH_PACKET_PP(state, descriptor, force_quit)                  \
    printf("inside for each pp\n");                                            \
    printf("sizeof(struct descriptor) : %ld\n", sizeof(struct descriptor));    \
    struct asq_state *asq_state = (struct asq_state *)state;                   \
    struct rte_mbuf *bufs[BURST_SIZE_ASNI_H];                                  \
    char *payload;                                                             \
    INIT_CYCLE_VARS();                                                         \
    INIT_DEBUG_VAR();                                                          \
    while (!*force_quit) {                                                     \
        START_CYCLE();                                                         \
        uint16_t nb_rx = rte_eth_rx_burst(                                     \
            asq_state->port, (rte_lcore_id() - 1), bufs, BURST_SIZE_ASNI_H);   \
        if (nb_rx == 0) {                                                      \
            continue;                                                          \
        }                                                                      \
        START_CYCLE_PROCESSING();                                              \
        for (int i = 0; i < nb_rx; i++) {                                      \
            uint8_t *data = rte_pktmbuf_mtod(bufs[i], uint8_t *);              \
            uint8_t nb_desc = *(data);                                         \
            struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)data;      \
            int magic = *(int *)(&eth_hdr->src_addr.addr_bytes[1]);            \
            if (unlikely(nb_desc < 1 || nb_desc > 64 || magic != MAGIC)) {     \
            } else {                                                           \
                payload = (char *)(data + DESC_OFFSET);                        \
                for (uint8_t j = 0; j < nb_desc; j++) {                        \
                    struct rte_ether_hdr *eth_hdr =                            \
                        (struct rte_ether_hdr *)payload;                       \
                    struct rte_ipv4_hdr *ip_hdr =                              \
                        (struct rte_ipv4_hdr *)(eth_hdr + 1);                  \
                    int length = sizeof(struct rte_ether_hdr) +                \
                                 htons(ip_hdr->total_length);                  \
                    char *next_payload = payload + length;                     \
                    rte_prefetch0(next_payload);                               \
                    descriptor->size = length;

#define ASQ_FOR_EACH_PACKET_PP_END()                                           \
    payload = next_payload;                                                    \
    (void)payload;                                                             \
    }                                                                          \
    PROCESSED_PACKETS();                                                       \
    }                                                                          \
    }                                                                          \
    rte_pktmbuf_free_bulk(bufs, nb_rx);                                        \
    END_CYCLE();                                                               \
    }                                                                          \
    PRINT_DEBUG();                                                             \
    PRINT_CYCLES();

#define ASQ_FOR_EACH_PACKET_PP_EXP_DESC(state, descriptor, force_quit)         \
    printf("inside for each pp exp desc\n");                                   \
    printf("sizeof(struct descriptor) : %ld\n", sizeof(struct descriptor));    \
    struct asq_state *asq_state = (struct asq_state *)state;                   \
    struct rte_mbuf *bufs[BURST_SIZE_ASNI_H];                                  \
    char *payload;                                                             \
    struct descriptor exp_descs[64];                                           \
    INIT_CYCLE_VARS();                                                         \
    INIT_DEBUG_VAR();                                                          \
    while (!*force_quit) {                                                     \
        START_CYCLE();                                                         \
        uint16_t nb_rx = rte_eth_rx_burst(                                     \
            asq_state->port, (rte_lcore_id() - 1), bufs, BURST_SIZE_ASNI_H);   \
        if (nb_rx == 0) {                                                      \
            continue;                                                          \
        }                                                                      \
        for (int i = 0; i < nb_rx; i++) {                                      \
            uint8_t *data = rte_pktmbuf_mtod(bufs[i], uint8_t *);              \
            uint8_t nb_desc = *(data);                                         \
            struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)data;      \
            int magic = *(int *)(&eth_hdr->src_addr.addr_bytes[1]);            \
            if (unlikely(nb_desc < 1 || nb_desc > 64 || magic != MAGIC)) {     \
            } else {                                                           \
                payload = (char *)(data + DESC_OFFSET);                        \
                for (uint8_t j = 0; j < nb_desc; j++) {                        \
                    struct rte_ether_hdr *eth_hdr =                            \
                        (struct rte_ether_hdr *)payload;                       \
                    struct rte_ipv4_hdr *ip_hdr =                              \
                        (struct rte_ipv4_hdr *)(eth_hdr + 1);                  \
                    int length = sizeof(struct rte_ether_hdr) +                \
                                 htons(ip_hdr->total_length);                  \
                    exp_descs[j].size = length;                                \
                    exp_descs[j].payload_ptr = payload;                        \
                    payload += length;                                         \
                }                                                              \
                START_CYCLE_PROCESSING();                                      \
                for (uint8_t k = 0; k < nb_desc; k++) {                        \
                    descriptor = &exp_descs[k];                                \
                    payload = exp_descs[k].payload_ptr;                        \
                    char *next_payload = exp_descs[k % nb_desc].payload_ptr;   \
                    rte_prefetch0(&exp_descs[k % nb_desc]);                    \
                    rte_prefetch0(next_payload);

#define ASQ_FOR_EACH_PACKET_PP_EXP_DESC_END()                                  \
    (void)payload;                                                             \
    }                                                                          \
    PROCESSED_PACKETS();                                                       \
    }                                                                          \
    }                                                                          \
    rte_pktmbuf_free_bulk(bufs, nb_rx);                                        \
    END_CYCLE();                                                               \
    }                                                                          \
    PRINT_DEBUG();                                                             \
    PRINT_CYCLES();

#ifdef FAKE_DPDK_MODE_DPDK_ASQ

typedef struct descriptor asq_descriptor_t;

#endif

#define PROCESS_BURST_ASQ(port, queue, batch_size, descriptors, rx_count,      \
                          state, metadata, payload_head)                       \
    uint8_t looping = 1;                                                       \
    uint16_t io_rx_count = 0;                                                  \
    void **io_descriptors;                                                     \
    while (looping) {                                                          \
        FAKE_DPDK_IO_RX_BURST(port, queue, fake_dpdk_io_descriptors,           \
                              batch_size, fake_dpdk_io_rx_count, state);       \
        if (likely(fake_dpdk_io_rx_count > 0)) {                               \
            io_descriptors = fake_dpdk_io_descriptors;                         \
            io_rx_count = fake_dpdk_io_rx_count;                               \
            break;                                                             \
        }                                                                      \
    }                                                                          \
    uint32_t offset_desc = DESC_OFFSET;                                        \
    for (int asq_packet_index = 0; asq_packet_index < io_rx_count;             \
         asq_packet_index++) {                                                 \
        uint8_t *data;                                                         \
        FAKE_DPDK_IO_GET_PAYLOAD_PTR(io_descriptors[asq_packet_index], data);  \
        uint8_t rx_count = *data;                                              \
        descriptors = data + offset_desc;                                      \
        payload_head =                                                         \
            data + offset_desc + rx_count * sizeof(struct descriptor);         \
        FAKE_DPDK_IO_SETUP_METADATA(io_descriptors[asq_packet_index],          \
                                    rx_count, metadata);

#define PROCESS_BURST_ASQ_END()                                                \
    FAKE_DPDK_IO_END_PROCESS(io_descriptors[asq_packet_index]);                \
    }

#define PROCESS_BURST_PAYLOAD_NEXT_ASQ(descriptor, payload_head)               \
    payload_head += descriptor.size;

#define PROCESS_BURST_GET_PAYLOAD_ASQ(descriptor, payload, payload_head)       \
    payload = payload_head;

#ifdef FAKE_DPDK_DESC_ETH_TYPE
#define PROCESS_BURST_GET_ETH_TYPE_ASQ(descriptor, eth_type, payload)          \
    eth_type = descriptor.eth_type;
#else
#define PROCESS_BURST_GET_ETH_TYPE_ASQ(descriptor, eth_type, payload)          \
    eth_type = rte_be_to_cpu_16(((struct rte_ether_hdr *)payload)->ether_type);
#endif

#ifdef FAKE_DPDK_DESC_IP_SRC
#define PROCESS_BURST_GET_IP_SRC_ASQ(descriptor, ip_src, payload)              \
    ip_src = descriptor.ip_src;
#else
#define PROCESS_BURST_GET_IP_SRC_ASQ(descriptor, ip_src, payload)              \
    ip_src = ((struct rte_ipv4_hdr *)(payload + sizeof(struct rte_ether_hdr))) \
                 ->src_addr;
#endif

#ifdef FAKE_DPDK_DESC_IP_DST
#define PROCESS_BURST_GET_IP_DST_ASQ(descriptor, ip_dst, payload)              \
    ip_dst = descriptor.ip_dst;
#else
#define PROCESS_BURST_GET_IP_DST_ASQ(descriptor, ip_dst, payload)              \
    ip_dst = ((struct rte_ipv4_hdr *)(payload + sizeof(struct rte_ether_hdr))) \
                 ->dst_addr;
#endif

#ifdef FAKE_DPDK_DESC_PORT_SRC
#define PROCESS_BURST_GET_PORT_SRC_ASQ(descriptor, port_src, payload)          \
    port_src = descriptor.port_src;
#else
#define PROCESS_BURST_GET_PORT_SRC_ASQ(descriptor, port_src, payload)          \
    port_src =                                                                 \
        ((struct rte_udp_hdr *)(payload + sizeof(struct rte_ether_hdr) +       \
                                sizeof(struct rte_ipv4_hdr)))                  \
            ->src_port;
#endif

#ifdef FAKE_DPDK_DESC_PORT_DST
#define PROCESS_BURST_GET_PORT_DST_ASQ(descriptor, port_dst, payload)          \
    port_dst = descriptor.port_dst;
#else
#define PROCESS_BURST_GET_PORT_DST_ASQ(descriptor, port_dst, payload)          \
    port_dst =                                                                 \
        ((struct rte_udp_hdr *)(payload + sizeof(struct rte_ether_hdr) +       \
                                sizeof(struct rte_ipv4_hdr)))                  \
            ->dst_port;
#endif

#ifdef FAKE_DPDK_DESC_IP_PROTO
#define PROCESS_BURST_GET_IP_PROTO_ASQ(descriptor, ip_proto, payload)          \
    ip_proto = descriptor.ip_proto;
#else
#define PROCESS_BURST_GET_IP_PROTO_ASQ(descriptor, ip_proto, payload)          \
    ip_proto =                                                                 \
        ((struct rte_ipv4_hdr *)(payload + sizeof(struct rte_ether_hdr)))      \
            ->next_proto_id;
#endif

#define PROCESS_BURST_GET_SIZE_ASQ(descriptor, size) size = descriptor.size;

#define PROCESS_BURST_GET_IMPLICIT_SIZE_ASQ(descriptor, size)                  \
    size = descriptor.size;

#ifdef FAKE_DPDK_MODE_DPDK_ASQ

#define PROCESS_BURST(port, queue, batch_size, descriptors, rx_count, state,   \
                      metadata, payload_head)                                  \
    PROCESS_BURST_ASQ(port, queue, batch_size, descriptors, rx_count, state,   \
                      metadata, payload_head)
#define PROCESS_BURST_END() PROCESS_BURST_ASQ_END()
#define PROCESS_BURST_PAYLOAD_NEXT(descriptor, payload_head)                   \
    PROCESS_BURST_PAYLOAD_NEXT_ASQ(descriptor, payload_head)
#define PROCESS_BURST_GET_PAYLOAD(descriptor, payload, payload_head)           \
    PROCESS_BURST_GET_PAYLOAD_ASQ(descriptor, payload, payload_head)
#define PROCESS_BURST_GET_ETH_TYPE(descriptor, eth_type, payload)              \
    PROCESS_BURST_GET_ETH_TYPE_ASQ(descriptor, eth_type, payload)
#define PROCESS_BURST_GET_IP_SRC(descriptor, ip_src, payload)                  \
    PROCESS_BURST_GET_IP_SRC_ASQ(descriptor, ip_src, payload)
#define PROCESS_BURST_GET_IP_DST(descriptor, ip_dst, payload)                  \
    PROCESS_BURST_GET_IP_DST_ASQ(descriptor, ip_dst, payload)
#define PROCESS_BURST_GET_PORT_SRC(descriptor, port_src, payload)              \
    PROCESS_BURST_GET_PORT_SRC_ASQ(descriptor, port_src, payload)
#define PROCESS_BURST_GET_PORT_DST(descriptor, port_dst, payload)              \
    PROCESS_BURST_GET_PORT_DST_ASQ(descriptor, port_dst, payload)
#define PROCESS_BURST_GET_IP_PROTO(descriptor, ip_proto, payload)              \
    PROCESS_BURST_GET_IP_PROTO_ASQ(descriptor, ip_proto, payload)
#define PROCESS_BURST_GET_SIZE(descriptor, size)                               \
    PROCESS_BURST_GET_SIZE_ASQ(descriptor, size)
#define PROCESS_BURST_GET_IMPLICIT_SIZE(descriptor, size)                      \
    PROCESS_BURST_GET_IMPLICIT_SIZE_ASQ(descriptor, size)

#endif

#ifdef FAKE_DPDK_MODE_DPDK_CLASSIC

typedef struct rte_mbuf *asq_descriptor_t;

#endif

#define PROCESS_BURST_CLASSIC(port, queue, batch_size, descriptors, rx_count,  \
                              state, metadata, payload_head)                   \
    uint8_t looping = 1;                                                       \
    uint16_t io_rx_count = 0;                                                  \
    void **io_descriptors;                                                     \
    while (looping) {                                                          \
        FAKE_DPDK_IO_RX_BURST(port, queue, fake_dpdk_io_descriptors,           \
                              batch_size, fake_dpdk_io_rx_count, state);       \
        if (likely(fake_dpdk_io_rx_count > 0)) {                               \
            io_descriptors = fake_dpdk_io_descriptors;                         \
            io_rx_count = fake_dpdk_io_rx_count;                               \
            break;                                                             \
        }                                                                      \
    }                                                                          \
    descriptors = io_descriptors;                                              \
    uint16_t rx_count = io_rx_count;                                           \
    payload_head = NULL;                                                       \
    uint8_t metadata;

#define PROCESS_BURST_CLASSIC_END()

#define PROCESS_BURST_PAYLOAD_NEXT_CLASSIC(descriptor, payload_head)

#define PROCESS_BURST_GET_PAYLOAD_CLASSIC(descriptor, payload, payload_head)   \
    payload = rte_pktmbuf_mtod(descriptor, char *);

#define PROCESS_BURST_GET_ETH_TYPE_CLASSIC(descriptor, eth_type, payload)      \
    eth_type = rte_be_to_cpu_16(((struct rte_ether_hdr *)payload)->ether_type);

#define PROCESS_BURST_GET_IP_SRC_CLASSIC(descriptor, ip_src, payload)          \
    ip_src = ((struct rte_ipv4_hdr *)(payload + sizeof(struct rte_ether_hdr))) \
                 ->src_addr;

#define PROCESS_BURST_GET_IP_DST_CLASSIC(descriptor, ip_dst, payload)          \
    ip_dst = ((struct rte_ipv4_hdr *)(payload + sizeof(struct rte_ether_hdr))) \
                 ->dst_addr;

#define PROCESS_BURST_GET_PORT_SRC_CLASSIC(descriptor, port_src, payload)      \
    port_src =                                                                 \
        ((struct rte_udp_hdr *)(payload + sizeof(struct rte_ether_hdr) +       \
                                sizeof(struct rte_ipv4_hdr)))                  \
            ->src_port;

#define PROCESS_BURST_GET_PORT_DST_CLASSIC(descriptor, port_dst, payload)      \
    port_dst =                                                                 \
        ((struct rte_udp_hdr *)(payload + sizeof(struct rte_ether_hdr) +       \
                                sizeof(struct rte_ipv4_hdr)))                  \
            ->dst_port;

#define PROCESS_BURST_GET_IP_PROTO_CLASSIC(descriptor, ip_proto, payload)      \
    ip_proto =                                                                 \
        ((struct rte_ipv4_hdr *)(payload + sizeof(struct rte_ether_hdr)))      \
            ->next_proto_id;

#define PROCESS_BURST_GET_SIZE_CLASSIC(descriptor, size)                       \
    size = rte_pktmbuf_pkt_len(descriptor);

#define PROCESS_BURST_GET_IMPLICIT_SIZE_CLASSIC(descriptor, size)

#ifdef FAKE_DPDK_MODE_DPDK_CLASSIC

#define PROCESS_BURST(port, queue, batch_size, descriptors, rx_count, state,   \
                      metadata, payload_head)                                  \
    PROCESS_BURST_CLASSIC(port, queue, batch_size, descriptors, rx_count,      \
                          state, metadata, payload_head)
#define PROCESS_BURST_END() PROCESS_BURST_CLASSIC_END()
#define PROCESS_BURST_PAYLOAD_NEXT(descriptor, payload_head)                   \
    PROCESS_BURST_PAYLOAD_NEXT_CLASSIC(descriptor, payload_head)
#define PROCESS_BURST_GET_PAYLOAD(descriptor, payload, payload_head)           \
    PROCESS_BURST_GET_PAYLOAD_CLASSIC(descriptor, payload, payload_head)
#define PROCESS_BURST_GET_ETH_TYPE(descriptor, eth_type, payload)              \
    PROCESS_BURST_GET_ETH_TYPE_CLASSIC(descriptor, eth_type, payload)
#define PROCESS_BURST_GET_IP_SRC(descriptor, ip_src, payload)                  \
    PROCESS_BURST_GET_IP_SRC_CLASSIC(descriptor, ip_src, payload)
#define PROCESS_BURST_GET_IP_DST(descriptor, ip_dst, payload)                  \
    PROCESS_BURST_GET_IP_DST_CLASSIC(descriptor, ip_dst, payload)
#define PROCESS_BURST_GET_PORT_SRC(descriptor, port_src, payload)              \
    PROCESS_BURST_GET_PORT_SRC_CLASSIC(descriptor, port_src, payload)
#define PROCESS_BURST_GET_PORT_DST(descriptor, port_dst, payload)              \
    PROCESS_BURST_GET_PORT_DST_CLASSIC(descriptor, port_dst, payload)
#define PROCESS_BURST_GET_IP_PROTO(descriptor, ip_proto, payload)              \
    PROCESS_BURST_GET_IP_PROTO_CLASSIC(descriptor, ip_proto, payload)
#define PROCESS_BURST_GET_SIZE(descriptor, size)                               \
    PROCESS_BURST_GET_SIZE_CLASSIC(descriptor, size)
#define PROCESS_BURST_GET_IMPLICIT_SIZE(descriptor, size)                      \
    PROCESS_BURST_GET_IMPLICIT_SIZE_CLASSIC(descriptor, size)

#endif

#ifdef FAKE_DPDK_MODE_DPDK_ASQ_OFFLOAD_TX
typedef struct descriptor asq_descriptor_t;
#endif

#define PROCESS_BURST_ASQ_OFFLOAD_TX(port, queue, batch_size, descriptors,     \
                                     rx_count, state, metadata, payload_head)  \
    uint8_t looping = 1;                                                       \
    uint16_t io_rx_count = 0;                                                  \
    void **io_descriptors;                                                     \
    while (looping) {                                                          \
        FAKE_DPDK_IO_RX_BURST(port, queue, fake_dpdk_io_descriptors,           \
                              batch_size, fake_dpdk_io_rx_count, state);       \
        if (likely(fake_dpdk_io_rx_count > 0)) {                               \
            io_descriptors = fake_dpdk_io_descriptors;                         \
            io_rx_count = fake_dpdk_io_rx_count;                               \
            state->tx_count = io_rx_count;                                     \
            break;                                                             \
        }                                                                      \
    }                                                                          \
    uint32_t offset_desc = 16;                                                 \
    for (int asq_packet_index = 0; asq_packet_index < io_rx_count;             \
         asq_packet_index++) {                                                 \
        uint8_t *data;                                                         \
        FAKE_DPDK_IO_GET_PAYLOAD_PTR(io_descriptors[asq_packet_index], data);  \
        uint8_t rx_count = *data;                                              \
        descriptors = data + offset_desc;                                      \
        payload_head =                                                         \
            data + offset_desc + rx_count * sizeof(struct descriptor);         \
        FAKE_DPDK_IO_SETUP_METADATA(io_descriptors[asq_packet_index],          \
                                    rx_count, metadata);

#define PROCESS_BURST_ASQ_OFFLOAD_TX_END()                                     \
    FAKE_DPDK_IO_END_PROCESS(io_descriptors[asq_packet_index]);                \
    }

#define PROCESS_BURST_PAYLOAD_NEXT_ASQ_OFFLOAD_TX(descriptor, payload_head)    \
    payload_head += descriptor.size;

#define PROCESS_BURST_GET_PAYLOAD_ASQ_OFFLOAD_TX(descriptor, payload,          \
                                                 payload_head)                 \
    payload = payload_head;

#ifdef FAKE_DPDK_DESC_ETH_TYPE
#define PROCESS_BURST_GET_ETH_TYPE_ASQ(descriptor, eth_type, payload)          \
    eth_type = descriptor.eth_type;
#else
#define PROCESS_BURST_GET_ETH_TYPE_ASQ_OFFLOAD_TX(descriptor, eth_type,        \
                                                  payload)                     \
    eth_type = rte_be_to_cpu_16(((struct rte_ether_hdr *)payload)->ether_type);
#endif

#ifdef FAKE_DPDK_DESC_IP_SRC
#define PROCESS_BURST_GET_IP_SRC_ASQ_OFFLOAD_TX(descriptor, ip_src, payload)   \
    ip_src = descriptor.ip_src;
#else
#define PROCESS_BURST_GET_IP_SRC_ASQ(descriptor, ip_src, payload)              \
    ip_src = ((struct rte_ipv4_hdr *)(payload + sizeof(struct rte_ether_hdr))) \
                 ->src_addr;
#endif

#ifdef FAKE_DPDK_DESC_IP_DST
#define PROCESS_BURST_GET_IP_DST_ASQ(descriptor, ip_dst, payload)              \
    ip_dst = descriptor.ip_dst;
#else
#define PROCESS_BURST_GET_IP_DST_ASQ(descriptor, ip_dst, payload)              \
    ip_dst = ((struct rte_ipv4_hdr *)(payload + sizeof(struct rte_ether_hdr))) \
                 ->dst_addr;
#endif

#ifdef FAKE_DPDK_DESC_PORT_SRC
#define PROCESS_BURST_GET_PORT_SRC_ASQ(descriptor, port_src, payload)          \
    port_src = descriptor.port_src;
#else
#define PROCESS_BURST_GET_PORT_SRC_ASQ(descriptor, port_src, payload)          \
    port_src =                                                                 \
        ((struct rte_udp_hdr *)(payload + sizeof(struct rte_ether_hdr) +       \
                                sizeof(struct rte_ipv4_hdr)))                  \
            ->src_port;
#endif

#ifdef FAKE_DPDK_DESC_PORT_DST
#define PROCESS_BURST_GET_PORT_DST_ASQ(descriptor, port_dst, payload)          \
    port_dst = descriptor.port_dst;
#else
#define PROCESS_BURST_GET_PORT_DST_ASQ(descriptor, port_dst, payload)          \
    port_dst =                                                                 \
        ((struct rte_udp_hdr *)(payload + sizeof(struct rte_ether_hdr) +       \
                                sizeof(struct rte_ipv4_hdr)))                  \
            ->dst_port;
#endif

#ifdef FAKE_DPDK_DESC_IP_PROTO
#define PROCESS_BURST_GET_IP_PROTO_ASQ(descriptor, ip_proto, payload)          \
    ip_proto = descriptor.ip_proto;
#else
#define PROCESS_BURST_GET_IP_PROTO_ASQ(descriptor, ip_proto, payload)          \
    ip_proto =                                                                 \
        ((struct rte_ipv4_hdr *)(payload + sizeof(struct rte_ether_hdr)))      \
            ->next_proto_id;
#endif

#define PROCESS_BURST_GET_SIZE_ASQ(descriptor, size) size = descriptor.size;

#define PROCESS_BURST_GET_IMPLICIT_SIZE_ASQ(descriptor, size)                  \
    size = descriptor.size;

#ifdef FAKE_DPDK_MODE_DPDK_ASQ_OFFLOAD_TX

#define PROCESS_BURST(port, queue, batch_size, descriptors, rx_count, state,   \
                      metadata, payload_head)                                  \
    PROCESS_BURST_ASQ_OFFLOAD_TX(port, queue, batch_size, descriptors,         \
                                 rx_count, state, metadata, payload_head)
#define PROCESS_BURST_END() PROCESS_BURST_ASQ_OFFLOAD_TX_END()
#define PROCESS_BURST_PAYLOAD_NEXT(descriptor, payload_head)                   \
    PROCESS_BURST_PAYLOAD_NEXT_ASQ(descriptor, payload_head)
#define PROCESS_BURST_GET_PAYLOAD(descriptor, payload, payload_head)           \
    payload = payload_head;
#define PROCESS_BURST_GET_ETH_TYPE(descriptor, eth_type, payload)              \
    PROCESS_BURST_GET_ETH_TYPE_ASQ(descriptor, eth_type, payload)
#define PROCESS_BURST_GET_IP_SRC(descriptor, ip_src, payload)                  \
    PROCESS_BURST_GET_IP_SRC_ASQ(descriptor, ip_src, payload)
#define PROCESS_BURST_GET_IP_DST(descriptor, ip_dst, payload)                  \
    PROCESS_BURST_GET_IP_DST_ASQ(descriptor, ip_dst, payload)
#define PROCESS_BURST_GET_PORT_SRC(descriptor, port_src, payload)              \
    PROCESS_BURST_GET_PORT_SRC_ASQ(descriptor, port_src, payload)
#define PROCESS_BURST_GET_PORT_DST(descriptor, port_dst, payload)              \
    PROCESS_BURST_GET_PORT_DST_ASQ(descriptor, port_dst, payload)
#define PROCESS_BURST_GET_IP_PROTO(descriptor, ip_proto, payload)              \
    PROCESS_BURST_GET_IP_PROTO_ASQ(descriptor, ip_proto, payload)
#define PROCESS_BURST_GET_SIZE(descriptor, size)                               \
    PROCESS_BURST_GET_SIZE_ASQ(descriptor, size)
#define PROCESS_BURST_GET_IMPLICIT_SIZE(descriptor, size)                      \
    PROCESS_BURST_GET_IMPLICIT_SIZE_ASQ(descriptor, size)

#endif
