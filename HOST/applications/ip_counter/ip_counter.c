#include "packet_counter.h"

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
    // Start iterating over the packets
    FAKE_DPDK_FOR_EACH_PACKET(descriptor) {
        if (unlikely(start_flag == 0)) {
            printf("Starting timer\n");
            start = rte_get_tsc_cycles();
            start_flag = 1;
        }
        // printf("Received packet of size %d\n", descriptor->size);
        bytes += descriptor->size;
        packets++;
    }
    FAKE_DPDK_FOR_EACH_PACKET_END();
    // When CTRL+C is pressed, the application will stop and execute the
    // following code
    double time_elapsed =
        (double)(rte_get_tsc_cycles() - start) / rte_get_tsc_hz();
    printf("RESULT-Throughput: %fGbps\n",
           ((bytes * 8) / time_elapsed) / 1000000000);
    double mpps = (double)(packets / time_elapsed) / 1000000;
    printf("Packet rate : %fMpps\n", mpps);
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
