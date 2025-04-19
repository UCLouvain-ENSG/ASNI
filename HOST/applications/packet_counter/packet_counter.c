#include "packet_counter.h"
#include "asq_descriptors.h"

#define NB_CORES 1
#define BURST_SIZE 32

bool force_quit = false;

static void signal_handler(int signum) {
    if (force_quit) {
        printf("\nForcing exit\n");
        exit(0);
        return;
    }
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit\nPress again to "
               "force exit\n",
               signum);
        force_quit = true;
    }
}

static int app(struct fake_dpdk_state *fake_dpdk_state) {
    printf("Starting application\n");
    uint64_t bytes = 0;
    uint64_t packets = 0;
    uint64_t start = 0;
    uint8_t start_flag = 0;
    uint64_t nb_packet_received = 0;
    // Start iterating over the packets
    printf("sizeof(descriptor) : %ld\n", sizeof(struct descriptor));
    FAKE_DPDK_FOR_EACH_PACKET(descriptor);
    {
        if (unlikely(start_flag == 0)) {
            printf("Starting timer\n");
            start = rte_get_tsc_cycles();
            start_flag = 1;
        }
        // printf("Received packet of size %d\n", descriptor->size);
        // printf("sizeof(descriptor)2 : %d\n", sizeof(struct descriptor));
        // printf("before desc\n");
#if defined(FAKE_DPDK_MODE_DPDK_BASELINE)
        bytes += descriptor->pkt_len;
#else
        bytes += descriptor->size;
#endif
        nb_packet_received++;
        /* printf("size : %d\n", descriptor->size); */
        // printf("after desc\n");
        packets++;
    }
    FAKE_DPDK_FOR_EACH_PACKET_END();
    // When CTRL+C is pressed, the application will stop and execute the
    // following code
    double time_elapsed =
        (double)(rte_get_tsc_cycles() - start) / rte_get_tsc_hz();
    printf("RESULT-Throughput %fGbps\n",
           ((bytes * 8) / time_elapsed) / 1000000000);
    double mpps = (double)(packets / time_elapsed) / 1000000;
    printf("Packet rate : %fMpps\n", mpps);
    printf("Packets received : %ld\n", nb_packet_received);
    struct rte_eth_stats stats = {0};
    rte_eth_stats_get(0, &stats);
    // Print stats
    printf("=====================\n");
    printf("PORT %d : \n", 0);
    printf("\nNumber of received packets : %ld"
           "\nNumber off missed packets : %ld"
           "\nNumber of erroneous received packets : %ld"
           "\nNumber of packets transmitted : %ld"
           "\nNumber of tx errors : %ld\n\n",
           stats.ipackets, stats.imissed, stats.ierrors, stats.opackets,
           stats.oerrors);
    if (rte_lcore_id() == 1) {
        for (int i = 0; i < rte_lcore_count() - 1; i++) {
            printf("\nReceived %ld packets on queue : %d\n", stats.q_ibytes[i],
                   i);
        }
        printf("RESULT-NIC-DROPPED-HOST %lu\n", stats.imissed);
    }

    return 0;
}

int main(int argc, char const *argv[]) {
    // Setup interrupts
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    fake_dpdk_init(argc, (char **)argv, NB_CORES, BURST_SIZE,
                   (int (*)(void *))app, &force_quit);
    return 0;
}
