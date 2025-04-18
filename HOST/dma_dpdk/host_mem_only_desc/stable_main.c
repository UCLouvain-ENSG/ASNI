#include "stable_dma_dpdk.h"

static volatile bool force_quit = false;

static void signal_handler(int signum) {
    if (force_quit){
        printf("\nForcing exit\n");
        exit(0);
        return;
    }
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit\nPress again to force exit\n", signum);
        force_quit = true;
    }
}

#define NB_CORE 7
#define BURST_SIZE 32

/*
 * Sample main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int main(int argc, char **argv) {
    // Setup interrupts
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Init environment
    // stable_dma_dpdk_init(argc, argv);
    // Prepare DMA memory
    struct stable_dma_dpdk_dma_state *state = stable_dma_dpdk_init(argc, argv, NB_CORE, BURST_SIZE);
    if (state == NULL) {
        printf("Unable to setup DMA\n");
        return EXIT_FAILURE;
    }
    // Infinite loop to read the descriptors
    struct descriptor rx_buffer[32];
    uint64_t start = 0;
    uint8_t start_flag = 0;
    uint64_t total_bytes = 0;
    while (!force_quit){
        stable_dma_dpdk_rx(state, rx_buffer);
        if(start_flag == 0){
            printf("Starting timer\n");
            start = rte_get_tsc_cycles();
            start_flag = 1;
        }
        for (uint8_t i = 0; i < 32; i++){
            total_bytes += rx_buffer[i].size;
        }
    }
    double time_elapsed = (double)(rte_get_tsc_cycles() - start) / rte_get_tsc_hz();
    printf("RESULT-THROUGHPUT %fGbps\n", ((total_bytes * 8) / time_elapsed) / 1000000000);
    stable_dma_dpdk_free(state);
    return EXIT_SUCCESS;
}
