/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include "stable_dma_dpdk.h"
#include <doca_pe.h>
#include <stddef.h>
#include <stdint.h>

DOCA_LOG_REGISTER(MAIN);

void stable_dma_dpdk_rx(struct stable_dma_dpdk_dma_state *dma_state,
                        struct stable_dma_dpdk_iterator *iterator) {
#ifdef DFAKE_DPDK_MODE_DMA

    // Get the descriptors
    struct descriptor **descriptors =
        (struct descriptor **)dma_state->src_buffers_desc;
    // Loop until we gather a burst
    uint8_t found_burst = 0;
    int rx_counter = 0;
    iterator->current_packet = 0;
    while (!found_burst) {
        // Iterate over each core starting from the last polled one (Avoid
        // giving priority to the first cores)
        for (uint8_t core_offset = 0; core_offset < dma_state->nb_cores;
             core_offset++) {
            uint8_t core = (dma_state->last_polled_core + core_offset) %
                           dma_state->nb_cores;
            // Iterate over the descriptors of the core
            while (descriptors[core][dma_state->cores_positions[core]].full &&
                   rx_counter < dma_state->burst_size) {
                // Copy the descriptor to the rx_buffer
                iterator->desc[rx_counter] =
                    &descriptors[core][dma_state->cores_positions
                                           [core]]; // Could lead to contention
                descriptors[core][dma_state->cores_positions[core]].full = 0;
                dma_state->cores_positions[core]++;
                if (dma_state->cores_positions[core] == DESCRIPTOR_NB)
                    dma_state->cores_positions[core] = 0;
                rx_counter++;
            }
            if (rx_counter == dma_state->burst_size) {
                found_burst = 1;
                // Save last polled core for next time
                dma_state->last_polled_core = core;
                break;
            }
        }
    }
#endif
}

struct descriptor *
stable_dma_dpdk_get_next(struct stable_dma_dpdk_iterator *iterator) {
    // Check if we finished the burst
    if (iterator->current_packet == iterator->nb_packets) {
        return NULL;
    }
    // Return the next descriptor
    struct descriptor *desc = iterator->desc[iterator->current_packet];
    iterator->current_packet++;
    return desc;
}

struct stable_dma_dpdk_dma_state *stable_dma_dpdk_init(int argc, char **argv,
                                                       uint8_t nb_core,
                                                       uint8_t burst_size) {
    char pci_addr[128] = {0};
    /* Create a logger backend that prints to the standard output */
    doca_error_t result = doca_log_backend_create_standard();
    if (result != DOCA_SUCCESS)
        if (result != DOCA_SUCCESS) {
            printf("Unable to create logger backend: %s\n",
                   doca_error_get_descr(result));
            return NULL;
        }
    // init EAL, necessary for rte_cycles
    int res = rte_eal_init(argc, argv);
    if (res < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    argc -= res;
    argv += res;
    int c;
    while ((c = getopt(argc, argv, "c:p:")) != -1)
        switch (c) {
        case 'p':
            strcpy(pci_addr, optarg);
            break;
        case 'c':
            nb_core = atoi(optarg);
            printf("Using %d cores\n", nb_core);
            break;
        case '?':
            if (optopt == 'c')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint(optopt))
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
            return NULL;
        default:
            break;
            abort();
        }
    if (pci_addr == NULL) {
        fprintf(stderr, "You should specify the pci_addr with the -p option\n");
    }
    struct stable_dma_dpdk_dma_state *dma_state =
        (struct stable_dma_dpdk_dma_state *)calloc(
            1, sizeof(struct stable_dma_dpdk_dma_state));
    // Init pci_addr
    strcpy(dma_state->pci_addr, pci_addr);
    // Init DMA
    dma_state->nb_cores = nb_core;
    dma_state->burst_size = burst_size;
    dma_state->last_polled_core = 0;
    dma_state->src_buffers_desc = (char **)calloc(nb_core, sizeof(char *));
    dma_state->src_buffers_size_desc =
        (size_t *)calloc(nb_core, sizeof(size_t));
    dma_state->src_buffers_payloads = (char **)calloc(nb_core, sizeof(char *));
    dma_state->src_buffers_size_payloads =
        (size_t *)calloc(nb_core, sizeof(size_t));
    dma_state->cores_positions =
        (uint64_t *)calloc(dma_state->nb_cores, sizeof(uint64_t));
    dma_state->resources = calloc(nb_core, sizeof(struct dma_resources));

    int udp_port = 0;
    for (int index = 0; index < nb_core; index++) {
        dma_state->src_buffers_size_desc[index] =
            sizeof(struct descriptor) * DESCRIPTOR_NB;
        dma_state->src_buffers_desc[index] = (char *)rte_malloc(
            NULL, dma_state->src_buffers_size_desc[index], 0x1000);
        // temporary
        dma_state->src_buffers_size_payloads[index] = PAYLOAD_ARRAY_SIZE;
        dma_state->src_buffers_payloads[index] = (char *)rte_malloc(
            NULL, dma_state->src_buffers_size_payloads[index], 0x1000);

        result = dma_export_memory(
            dma_state->pci_addr, dma_state->src_buffers_desc[index],
            dma_state->src_buffers_size_desc[index], udp_port++);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to create DMA engine: %s",
                         doca_error_get_descr(result));
            return NULL;
        }
        usleep(100000);
        /* DOCA : Open the relevant DOCA device */
        result = dma_export_memory(
            dma_state->pci_addr, dma_state->src_buffers_payloads[index],
            dma_state->src_buffers_size_payloads[index], udp_port++);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to create DMA engine: %s",
                         doca_error_get_descr(result));
            return NULL;
        }
        usleep(100000);
    }
    return dma_state;
}

void stable_dma_dpdk_free(struct stable_dma_dpdk_dma_state *dma_state) {
    for (int index = 0; index < dma_state->nb_cores; index++) {
        rte_free(dma_state->src_buffers_desc[index]);
        rte_free(dma_state->src_buffers_payloads[index]);
    }
    free(dma_state->src_buffers_desc);
    free(dma_state->src_buffers_size_desc);
    free(dma_state->src_buffers_payloads);
    free(dma_state->src_buffers_size_payloads);
    free(dma_state->cores_positions);
    free(dma_state);
}

struct stable_dma_dpdk_iterator *
stable_dma_dpdk_init_iterator(uint16_t burst_size) {
    struct stable_dma_dpdk_iterator *iterator =
        malloc(sizeof(struct stable_dma_dpdk_iterator));
    iterator->desc = calloc(burst_size, sizeof(struct descriptor *));
    iterator->nb_packets = burst_size;
    iterator->current_packet = 0;
    return iterator;
}
