#include "l2fwd.h"

#define NB_CORES 7
#define BURST_SIZE 32

bool force_quit = false;

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

static int app(struct fake_dpdk_state *fake_dpdk_state){
    printf("Starting application\n");
    struct fake_dpdk_packet_iterator *iterator = fake_dpdk_init_packet_iterator(BURST_SIZE);;
    struct fake_dpdk_descriptor *desc;
    while (!*fake_dpdk_state->force_quit){
        fake_dpdk_rx_burst(fake_dpdk_state, iterator);
        while((desc = fake_dpdk_get_next(iterator)) != NULL){
            printf("Source mac: %02x:%02x:%02x:%02x:%02x:%02x\n", desc->mac_src[0], desc->mac_src[1], desc->mac_src[2], desc->mac_src[3], desc->mac_src[4], desc->mac_src[5]);
        }
    }
    printf("Finished\n");
    return 0;
}

int main(int argc, char const *argv[])
{    
    // Setup interrupts
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    fake_dpdk_init(argc, (char **)argv, NB_CORES, BURST_SIZE, (int (*)(void *)) app, &force_quit);
    return 0;
}
