#include "router.h"

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

#define FIB_SIZE 4

const uint8_t fib[FIB_SIZE][6] = {
    // Forwards 192.168.0.0/24 towards port 0
    {192, 168, 0, 0, 24, 0},
    {10, 0, 0, 0, 8, 1},
    {10, 128, 0, 0, 9, 2},
    {0,   0,  0,0,  0, 0} // Default
};

/**
 * @brief Takes the human readable fib and converts it to a more efficient format
 * 
 * @param fib : human readable fib
 * @param computed_fib : efficient fib, must be a uint32_t[FIB_SIZE][3] array. At the end of the function, 
 * computed_fib[i][0] contains the ip address, computed_fib[i][1] contains the mask and computed_fib[i][2] 
 * contains the port
*/
void compute_fib(uint32_t **computed_fib){
    for (uint8_t i = 0; i < FIB_SIZE; i++){
        computed_fib[i][0] = fib[i][0] << 24 | fib[i][1] << 16 | fib[i][2] << 8 | fib[i][3];
        computed_fib[i][1] = 0;
        for (uint8_t j = 0; j < fib[i][4]; j++)
            computed_fib[i][1] |= 1 << (31 - j);
        computed_fib[i][2] = fib[i][5];
    }
} 

uint32_t *lpm(uint32_t ip, uint32_t **computed_fib){
    uint32_t *best_match = NULL;
    for (uint8_t i = 0; i < FIB_SIZE; i++){
        if ((ip | computed_fib[i][1]) == ip ){
            if (best_match == NULL || computed_fib[i][1] > best_match[1])
                best_match = computed_fib[i];
        }
    }
    return best_match;
}

static int app(struct fake_dpdk_state *fake_dpdk_state){
    printf("Starting application\n");
    struct fake_dpdk_packet_iterator *iterator = fake_dpdk_init_packet_iterator(BURST_SIZE);
    struct fake_dpdk_descriptor *desc;
    // Get a fib version that can be used with bitwise operations
    uint32_t **computed_fib = malloc(sizeof(uint32_t *) * FIB_SIZE);
    if (computed_fib == NULL){
        printf("Error: malloc failed\n");
        exit(1);
    }
    for (uint8_t i = 0; i < FIB_SIZE; i++){
        computed_fib[i] = malloc(sizeof(uint32_t) * 3);
        if (computed_fib[i] == NULL){
            printf("Error: malloc failed\n");
            exit(1);
        }
    }
        
    compute_fib((uint32_t **)computed_fib);
    while (!*fake_dpdk_state->force_quit){
        // For each packet
        fake_dpdk_rx_burst(fake_dpdk_state, iterator);
        while((desc = fake_dpdk_get_next(iterator)) != NULL){
            // Find the best match in the fib
            uint32_t *best_match = lpm(desc->ip_dst,  (uint32_t **)computed_fib);
            // Now forward the packet to the port best_match[2]
            printf("Forwarding packet to port %d\n", best_match[2]);
        }
    }
    printf("Exiting application\n");
    return 0;
}

int main(int argc, char const *argv[]){    
    // Setup interrupts
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    fake_dpdk_init(argc, (char **)argv, NB_CORES, BURST_SIZE, (int (*)(void *)) app, &force_quit);
    return 0;
}
