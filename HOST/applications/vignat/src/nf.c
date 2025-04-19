#include "nf.h"
#include "dgu_utils.h"
#include <stdio.h>

#if defined(WITH_ASQ) && defined(FAKE_DPDK_IO_DPDK)
#error "ASQ is not supported with DPDK IO yet"
#endif

static volatile uint8_t force_quit = 0;

static void signal_handler(int signum) {
    if (force_quit) {
        printf("Caught signal %d again, performing forced quit\n", signum);
        exit(0);
    }
    if (signum == SIGINT || signum == SIGTERM || signum == SIGKILL) {
        printf("\n\nSignal %d received, preparing to exit\n", signum);

        // Get port stats
        struct rte_eth_stats new_stats;
        dgu_print_xstats();
        rte_eth_stats_get(0, &new_stats);
        // Print stats
        printf("\nNumber of received packets : %ld"
               "\nNumber of missed packets : %ld"
               "\nNumber of queued RX packets : %ld"
               "\nNumber of dropped queued packet : %ld\n\n",
               (long)new_stats.ipackets, (long)new_stats.imissed,
               (long)new_stats.q_ipackets[0], (long)new_stats.q_errors[0]);

        force_quit = true;
    }
}

// NFOS declares its own main method
#ifdef NFOS
#define MAIN nf_main
#else // NFOS
#define MAIN main
#endif // NFOS

// Unverified support for batching, useful for performance comparisons
#ifndef VIGOR_BATCH_SIZE
#define VIGOR_BATCH_SIZE 32
#endif

// More elaborate loop shape with annotations for verification
#ifdef KLEE_VERIFICATION
#define VIGOR_LOOP_BEGIN                                                       \
    unsigned _vigor_lcore_id = 0; /* no multicore support for now */           \
    vigor_time_t _vigor_start_time = start_time();                             \
    int _vigor_loop_termination = klee_int("loop_termination");                \
    unsigned VIGOR_DEVICES_COUNT = rte_eth_dev_count_avail();                  \
    while (klee_induce_invariants() & _vigor_loop_termination) {               \
        nf_loop_iteration_border(_vigor_lcore_id, _vigor_start_time);          \
        vigor_time_t VIGOR_NOW = current_time();                               \
        /* concretize the device to avoid leaking symbols into DPDK */         \
        uint16_t VIGOR_DEVICE =                                                \
            klee_range(0, VIGOR_DEVICES_COUNT, "VIGOR_DEVICE");                \
        concretize_devices(&VIGOR_DEVICE, VIGOR_DEVICES_COUNT);                \
        stub_hardware_receive_packet(VIGOR_DEVICE);
#define VIGOR_LOOP_END                                                         \
    stub_hardware_reset_receive(VIGOR_DEVICE);                                 \
    nf_loop_iteration_border(_vigor_lcore_id, VIGOR_NOW);                      \
    }
#else // KLEE_VERIFICATION
#define VIGOR_LOOP_BEGIN                                                       \
    while (1) {                                                                \
        vigor_time_t VIGOR_NOW = current_time();                               \
        unsigned VIGOR_DEVICES_COUNT = rte_eth_dev_count_avail();              \
        for (uint16_t VIGOR_DEVICE = 0; VIGOR_DEVICE < VIGOR_DEVICES_COUNT;    \
             VIGOR_DEVICE++) {
#define VIGOR_LOOP_END                                                         \
    }                                                                          \
    }
#endif // KLEE_VERIFICATION

#if VIGOR_BATCH_SIZE == 1
// Queue sizes for receiving/transmitting packets
// NOT powers of 2 so that ixgbe doesn't use vector stuff
// but they have to be multiples of 8, and at least 32,
// otherwise the driver refuses to work
// static const uint16_t RX_QUEUE_SIZE = 96;
// static const uint16_t TX_QUEUE_SIZE = 96;
#else
// Do the opposite: we want batching!
// static const uint16_t RX_QUEUE_SIZE = 128;
// static const uint16_t TX_QUEUE_SIZE = 128;
#endif

// Buffer count for mempools
// static const unsigned MEMPOOL_BUFFER_COUNT = 256;

// Send the given packet to all devices except the packet's own
void flood(struct rte_mbuf *packet, uint16_t nb_devices) {
    rte_mbuf_refcnt_set(packet, nb_devices - 1);
    int total_sent = 0;
    uint16_t skip_device = packet->port;
    for (uint16_t device = 0; device < nb_devices; device++) {
        if (device != skip_device) {
            total_sent += rte_eth_tx_burst(device, 0, &packet, 1);
        }
    }
    // should not happen, but in case we couldn't transmit, ensure the packet is
    // freed
    if (total_sent != nb_devices - 1) {
        rte_mbuf_refcnt_set(packet, 1);
        rte_pktmbuf_free(packet);
    }
}

// Main worker method (for now used on a single thread...)
void worker_main(void) {

    // Setup signal for SIGINT
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    NF_INFO("Running on core %u\n", rte_lcore_id());

    if (!nf_init()) {
        NF_INFO("Could not initialize NF");
        rte_exit(EXIT_FAILURE, "Error initializing NF");
    }

    NF_INFO("Core %u forwarding packets with batching of %d", rte_lcore_id(),
            VIGOR_BATCH_SIZE);

    NF_INFO("Running with batches, this code is unverified!");

    uint16_t ports[] = ENABLED_PORTS;

    FAKE_DPDK_IO_INIT(state);
    printf("EVENT server_ready\n");
    while (!force_quit) {
        unsigned VIGOR_DEVICES_COUNT = ENABLED_PORTS_LEN;
        for (uint16_t device = 0; device < VIGOR_DEVICES_COUNT; device++) {
            uint16_t VIGOR_DEVICE = ports[device];
            asq_descriptor_t *descriptors;
            uint8_t *payload_head;
            PROCESS_BURST(VIGOR_DEVICE, 0, VIGOR_BATCH_SIZE, descriptors,
                          rx_count, state, metadata, payload_head);
            for (uint16_t n = 0; n < rx_count; n++) {
                uint8_t *payload;
                PROCESS_BURST_GET_PAYLOAD(descriptors[n], payload,
                                          payload_head);
                uint16_t eth_type;
                PROCESS_BURST_GET_ETH_TYPE(descriptors[n], eth_type, payload);
                uint8_t ip_proto;
                PROCESS_BURST_GET_IP_PROTO(descriptors[n], ip_proto, payload);
                uint32_t ip_src;
                PROCESS_BURST_GET_IP_SRC(descriptors[n], ip_src, payload);
                uint32_t ip_dst;
                PROCESS_BURST_GET_IP_DST(descriptors[n], ip_dst, payload);
                uint16_t port_src;
                PROCESS_BURST_GET_PORT_SRC(descriptors[n], port_src, payload);
                uint16_t port_dst;
                PROCESS_BURST_GET_PORT_DST(descriptors[n], port_dst, payload);
                uint16_t dst_device = nf_process(
                    VIGOR_DEVICE, payload, eth_type, ip_proto, ip_src, ip_dst,
                    port_src, port_dst, current_time());
                if (dst_device != EXPLICIT_DROP
#ifdef NO_SEND_BACK
                    && dst_device != VIGOR_DEVICE
#endif
                ) {
                    uint16_t size;
                    PROCESS_BURST_GET_IMPLICIT_SIZE(descriptors[n], size);
                    FAKE_DPDK_IO_TX_ENQUEUE(state, descriptors[n], size,
                                            metadata, payload);
                } else {
                    FAKE_DPDK_IO_FREE_IMPLICIT(descriptors[n]);
                }
                PROCESS_BURST_PAYLOAD_NEXT(descriptors[n], payload_head);
            }
            FAKE_DPDK_IO_TX_BURST(ports[1 - device], 0, rx_count, tx_count,
                                  state);
            PROCESS_BURST_END();
            FAKE_DPDK_IO_TX_BURST_LATE(ports[1 - device], 0, 0, 0, state);
        }
    }
}
